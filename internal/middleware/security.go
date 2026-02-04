package middleware

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type contextKey string

const cspNonceKey contextKey = "cspNonce"

// GetCSPNonce retrieves the CSP nonce from the request context.
func GetCSPNonce(r *http.Request) string {
	if nonce, ok := r.Context().Value(cspNonceKey).(string); ok {
		return nonce
	}
	return ""
}

// SecurityHeaders adds security headers to all responses (Fix #8).
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Generate a per-request nonce for inline scripts
		nonceBytes := make([]byte, 16)
		if _, err := rand.Read(nonceBytes); err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		nonce := hex.EncodeToString(nonceBytes)

		// Store nonce in request context for handlers to pass to templates
		ctx := context.WithValue(r.Context(), cspNonceKey, nonce)
		r = r.WithContext(ctx)

		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("X-XSS-Protection", "0")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; "+
				fmt.Sprintf("script-src 'self' 'nonce-%s'; ", nonce)+
				"script-src-attr 'unsafe-inline'; "+
				"style-src 'self' 'unsafe-inline'; "+
				"font-src 'self'; "+
				"img-src 'self' data: https:; "+
				"connect-src 'self' https://geocoding-api.open-meteo.com https://api.open-meteo.com")
		next.ServeHTTP(w, r)
	})
}

// csrfTokenLength is the number of random bytes used to generate a CSRF token.
// The token is hex-encoded, so the resulting string is twice this length.
const csrfTokenLength = 32

// csrfCookieName is the name of the cookie that holds the CSRF token.
const csrfCookieName = "dashgate_csrf"

// csrfHeaderName is the HTTP header that the client must set to prove it can
// read the CSRF cookie (same-origin policy prevents cross-origin reads).
const csrfHeaderName = "X-CSRF-Token"

// generateCSRFToken produces a cryptographically random hex-encoded token.
func generateCSRFToken() (string, error) {
	b := make([]byte, csrfTokenLength)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// CSRFProtection implements the double-submit cookie pattern for CSRF defence.
//
// On every response (all methods) the middleware ensures a csrf_token cookie
// exists. On state-changing methods (POST/PUT/DELETE/PATCH) it verifies that
// the X-CSRF-Token request header matches the cookie value using constant-time
// comparison. Requests authenticated via API key (Authorization header) are
// exempt because they do not rely on ambient cookie credentials.
func CSRFProtection(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip CSRF entirely for health check endpoint (called by Docker
		// healthcheck without cookies, would needlessly generate tokens).
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}

		// --- Ensure the CSRF cookie is present on every response ---
		existingToken := ""
		if cookie, err := r.Cookie(csrfCookieName); err == nil && cookie.Value != "" {
			existingToken = cookie.Value
		}

		if existingToken == "" {
			// Generate a new token and set the cookie
			token, err := generateCSRFToken()
			if err != nil {
				log.Printf("CSRF: failed to generate token: %v", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			existingToken = token
			http.SetCookie(w, &http.Cookie{
				Name:     csrfCookieName,
				Value:    token,
				Path:     "/",
				HttpOnly: false, // JS must be able to read this
				Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
				SameSite: http.SameSiteLaxMode,
			})
		}

		// --- Validate on state-changing methods ---
		if r.Method == "POST" || r.Method == "PUT" || r.Method == "DELETE" || r.Method == "PATCH" {
			// Skip CSRF check for API key authenticated requests.
			// These use explicit credentials (not ambient cookies) so
			// they are not vulnerable to CSRF.
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") || strings.HasPrefix(authHeader, "ApiKey ") {
				next.ServeHTTP(w, r)
				return
			}

			// Also enforce origin/referer checks as defence in depth
			origin := r.Header.Get("Origin")
			if origin != "" {
				if !isSameOrigin(r, origin) {
					log.Printf("CSRF: blocked cross-origin %s request from %s", r.Method, origin)
					http.Error(w, "Forbidden: cross-origin request blocked", http.StatusForbidden)
					return
				}
			} else {
				referer := r.Header.Get("Referer")
				if referer != "" && !isSameOrigin(r, referer) {
					log.Printf("CSRF: blocked cross-origin %s request from referer %s", r.Method, referer)
					http.Error(w, "Forbidden: cross-origin request blocked", http.StatusForbidden)
					return
				}
			}

			// Double-submit cookie validation: the X-CSRF-Token header
			// must match the cookie value. Because a cross-origin page
			// cannot read our SameSite cookie, it cannot forge the header.
			// Check against ALL cookies with the CSRF name to handle
			// browsers that may send duplicate cookies from stale sessions.
			headerToken := r.Header.Get(csrfHeaderName)
			if headerToken == "" {
				log.Printf("CSRF: missing %s header on %s %s", csrfHeaderName, r.Method, r.URL.Path)
				http.Error(w, "Forbidden: missing CSRF token", http.StatusForbidden)
				return
			}

			valid := false
			for _, c := range r.Cookies() {
				if c.Name == csrfCookieName {
					if subtle.ConstantTimeCompare([]byte(headerToken), []byte(c.Value)) == 1 {
						valid = true
						break
					}
				}
			}
			if !valid {
				log.Printf("CSRF: token mismatch on %s %s", r.Method, r.URL.Path)
				http.Error(w, "Forbidden: invalid CSRF token", http.StatusForbidden)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func isSameOrigin(r *http.Request, originOrReferer string) bool {
	// Extract host from the origin/referer URL
	checkHost := ""
	if strings.HasPrefix(originOrReferer, "http://") || strings.HasPrefix(originOrReferer, "https://") {
		// Remove scheme
		after := strings.SplitN(originOrReferer, "://", 2)
		if len(after) == 2 {
			// Get host (before any path)
			hostPart := strings.SplitN(after[1], "/", 2)[0]
			checkHost = hostPart
		}
	}

	// Get the request host
	requestHost := r.Host
	if requestHost == "" {
		requestHost = r.URL.Host
	}

	return strings.EqualFold(checkHost, requestHost)
}

// RateLimiter implements per-IP rate limiting for login attempts (Fix #5).
type RateLimiter struct {
	mu       sync.Mutex
	attempts map[string]*attemptRecord
	limit    int
	window   time.Duration
}

type attemptRecord struct {
	count   int
	resetAt time.Time
}

// NewRateLimiter creates a rate limiter with the given limit and window.
// The cleanup goroutine stops when the provided context is cancelled.
func NewRateLimiter(limit int, window time.Duration, ctx context.Context) *RateLimiter {
	rl := &RateLimiter{
		attempts: make(map[string]*attemptRecord),
		limit:    limit,
		window:   window,
	}
	go rl.cleanup(ctx)
	return rl
}

func (rl *RateLimiter) cleanup(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rl.mu.Lock()
			now := time.Now()
			for ip, record := range rl.attempts {
				if now.After(record.resetAt) {
					delete(rl.attempts, ip)
				}
			}
			// Prevent unbounded growth
			if len(rl.attempts) > 10000 {
				rl.attempts = make(map[string]*attemptRecord)
			}
			rl.mu.Unlock()
		}
	}
}

// LimitPath returns middleware that rate-limits requests to specific paths.
func (rl *RateLimiter) LimitPath(paths []string, next http.Handler) http.Handler {
	pathSet := make(map[string]bool, len(paths))
	for _, p := range paths {
		pathSet[p] = true
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only rate limit POST to specific paths
		if r.Method == "POST" && pathSet[r.URL.Path] {
			ip := extractIP(r)

			rl.mu.Lock()
			record, exists := rl.attempts[ip]
			if !exists || time.Now().After(record.resetAt) {
				rl.attempts[ip] = &attemptRecord{
					count:   1,
					resetAt: time.Now().Add(rl.window),
				}
				rl.mu.Unlock()
			} else {
				record.count++
				if record.count > rl.limit {
					remaining := time.Until(record.resetAt)
					rl.mu.Unlock()
					log.Printf("Rate limit exceeded for IP %s on %s", ip, r.URL.Path)
					w.Header().Set("Retry-After", strings.TrimRight(remaining.Round(time.Second).String(), "s"))
					http.Error(w, "Too many attempts. Please try again later.", http.StatusTooManyRequests)
					return
				}
				rl.mu.Unlock()
			}
		}
		next.ServeHTTP(w, r)
	})
}

// MaxBodySize limits the request body size for non-GET/HEAD/OPTIONS requests
// to prevent denial-of-service via oversized payloads.
func MaxBodySize(maxBytes int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" && r.Method != "HEAD" && r.Method != "OPTIONS" && r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
		}
		next.ServeHTTP(w, r)
	})
}

func extractIP(r *http.Request) string {
	// Use RemoteAddr as the authoritative source.
	// X-Forwarded-For is not trusted because any client can spoof it,
	// allowing rate limit bypass. In a reverse proxy setup, the proxy's
	// IP will be rate-limited, which is acceptable since the proxy
	// should handle upstream rate limiting.
	ip := r.RemoteAddr
	if host, _, err := net.SplitHostPort(ip); err == nil {
		ip = host
	}
	return ip
}

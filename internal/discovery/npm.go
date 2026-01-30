package discovery

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"dashgate/internal/models"
	"dashgate/internal/server"
	"dashgate/internal/urlvalidation"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// InitNPMDiscovery checks environment variables and system config,
// then starts the NPM (Nginx Proxy Manager) discovery loop if enabled.
func InitNPMDiscovery(app *server.App) {
	envURL := os.Getenv("NPM_URL")
	envEmail := os.Getenv("NPM_EMAIL")
	envPassword := os.Getenv("NPM_PASSWORD")

	if envURL != "" {
		app.SysConfigMu.Lock()
		app.SystemConfig.NPMUrl = envURL
		app.SysConfigMu.Unlock()
	}
	if envEmail != "" {
		app.SysConfigMu.Lock()
		app.SystemConfig.NPMEmail = envEmail
		app.SysConfigMu.Unlock()
	}
	if envPassword != "" {
		app.SysConfigMu.Lock()
		app.SystemConfig.NPMPassword = envPassword
		app.SysConfigMu.Unlock()
	}

	if envURL != "" && envEmail != "" && envPassword != "" && os.Getenv("NPM_DISCOVERY") == "true" {
		app.NPMDiscoveryEnvOverride = true
		StartNPMDiscoveryLoop(app)
		app.SysConfigMu.RLock()
		log.Printf("NPM discovery enabled (via environment variable, API: %s)", app.SystemConfig.NPMUrl)
		app.SysConfigMu.RUnlock()
	} else if app.SystemConfig.NPMDiscoveryEnabled && app.SystemConfig.NPMUrl != "" && app.SystemConfig.NPMEmail != "" && app.SystemConfig.NPMPassword != "" {
		StartNPMDiscoveryLoop(app)
		app.SysConfigMu.RLock()
		log.Printf("NPM discovery enabled (via database config, API: %s)", app.SystemConfig.NPMUrl)
		app.SysConfigMu.RUnlock()
	}
}

// StartNPMDiscoveryLoop starts the background goroutine that periodically
// discovers NPM proxy hosts. It is safe to call if already running.
func StartNPMDiscoveryLoop(app *server.App) {
	app.DiscoveryMu.Lock()
	defer app.DiscoveryMu.Unlock()

	if app.NPMDiscovery.Stop != nil {
		return // Already running
	}

	app.NPMDiscovery.Enabled = true
	app.NPMDiscovery.Stop = make(chan struct{})

	app.NPMDiscovery.Wg.Add(1)
	go func() {
		defer app.NPMDiscovery.Wg.Done()
		defer func() {
			if r := recover(); r != nil {
				log.Printf("NPM discovery goroutine panicked: %v", r)
			}
		}()
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		DiscoverNPMApps(app) // Initial discovery
		for {
			select {
			case <-app.NPMDiscovery.Stop:
				return
			case <-ticker.C:
				DiscoverNPMApps(app)
			}
		}
	}()
}

// StopNPMDiscoveryLoop stops the NPM discovery background loop,
// clears all discovered apps, and resets the NPM token.
func StopNPMDiscoveryLoop(app *server.App) {
	app.DiscoveryMu.Lock()
	if app.NPMDiscovery.Stop != nil {
		close(app.NPMDiscovery.Stop)
		app.NPMDiscovery.Stop = nil
	}
	app.DiscoveryMu.Unlock()

	app.NPMDiscovery.Wg.Wait()

	app.DiscoveryMu.Lock()
	app.NPMDiscovery.Enabled = false
	app.NPMDiscovery.ClearApps()
	// Also clear the token
	app.NPMTokenMu.Lock()
	app.NPMToken = ""
	app.NPMTokenExpiry = time.Time{}
	app.NPMTokenMu.Unlock()
	app.DiscoveryMu.Unlock()
}

// NPMRefreshToken authenticates with the NPM API and stores a new token.
func NPMRefreshToken(app *server.App) error {
	app.SysConfigMu.RLock()
	npmURL := app.SystemConfig.NPMUrl
	npmEmail := app.SystemConfig.NPMEmail
	npmPassword := app.SystemConfig.NPMPassword
	app.SysConfigMu.RUnlock()

	if err := urlvalidation.ValidateDiscoveryURL(npmURL); err != nil {
		return fmt.Errorf("NPM SSRF protection: %w", err)
	}

	payload := map[string]string{
		"identity": npmEmail,
		"secret":   npmPassword,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal token request: %w", err)
	}

	resp, err := app.HTTPClient.Post(npmURL+"/api/tokens", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to request token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("token request failed with status: %d", resp.StatusCode)
	}

	var tokenResp struct {
		Token   string `json:"token"`
		Expires string `json:"expires"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 10*1024*1024)).Decode(&tokenResp); err != nil { // 10MB limit
		return fmt.Errorf("failed to decode token response: %w", err)
	}

	app.NPMTokenMu.Lock()
	app.NPMToken = tokenResp.Token
	// Parse expiry time, default to 1 hour if parsing fails
	if expiry, err := time.Parse(time.RFC3339, tokenResp.Expires); err == nil {
		app.NPMTokenExpiry = expiry
	} else {
		app.NPMTokenExpiry = time.Now().Add(1 * time.Hour)
	}
	app.NPMTokenMu.Unlock()

	return nil
}

// NPMGetToken returns a valid NPM API token, refreshing it if expired or
// about to expire (within 5 minutes).
// Holds the write lock for the entire check-and-refresh to prevent TOCTOU races.
func NPMGetToken(app *server.App) (string, error) {
	app.NPMTokenMu.Lock()
	defer app.NPMTokenMu.Unlock()

	// Check if token is still valid (with 5 minute buffer)
	if app.NPMToken != "" && time.Now().Add(5*time.Minute).Before(app.NPMTokenExpiry) {
		return app.NPMToken, nil
	}

	// Refresh token while still holding the lock to prevent concurrent refreshes
	if err := npmRefreshTokenLocked(app); err != nil {
		return "", err
	}

	return app.NPMToken, nil
}

// npmRefreshTokenLocked performs the actual token refresh.
// The caller must hold app.NPMTokenMu.Lock().
func npmRefreshTokenLocked(app *server.App) error {
	app.SysConfigMu.RLock()
	npmURL := app.SystemConfig.NPMUrl
	npmEmail := app.SystemConfig.NPMEmail
	npmPassword := app.SystemConfig.NPMPassword
	app.SysConfigMu.RUnlock()

	if err := urlvalidation.ValidateDiscoveryURL(npmURL); err != nil {
		return fmt.Errorf("NPM SSRF protection: %w", err)
	}

	payload := map[string]string{
		"identity": npmEmail,
		"secret":   npmPassword,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal token request: %w", err)
	}

	resp, err := app.HTTPClient.Post(npmURL+"/api/tokens", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to request token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("token request failed with status: %d", resp.StatusCode)
	}

	var tokenResp struct {
		Token   string `json:"token"`
		Expires string `json:"expires"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&tokenResp); err != nil {
		return fmt.Errorf("failed to decode token response: %w", err)
	}

	if tokenResp.Token == "" {
		return fmt.Errorf("NPM returned empty token")
	}

	app.NPMToken = tokenResp.Token
	if expiry, err := time.Parse(time.RFC3339, tokenResp.Expires); err == nil {
		app.NPMTokenExpiry = expiry
	} else {
		app.NPMTokenExpiry = time.Now().Add(1 * time.Hour)
	}

	return nil
}

// DiscoverNPMApps queries the NPM API for proxy hosts and updates
// the NPMDiscovery manager with the results.
func DiscoverNPMApps(app *server.App) {
	app.DiscoveryMu.RLock()
	enabled := app.NPMDiscovery.Enabled
	app.DiscoveryMu.RUnlock()
	if !enabled {
		return
	}

	app.SysConfigMu.RLock()
	npmURL := app.SystemConfig.NPMUrl
	app.SysConfigMu.RUnlock()

	if npmURL == "" {
		return
	}

	if err := urlvalidation.ValidateDiscoveryURL(npmURL); err != nil {
		log.Printf("NPM discovery SSRF protection: %v", err)
		return
	}

	token, err := NPMGetToken(app)
	if err != nil {
		log.Printf("NPM discovery error (token): %v", err)
		return
	}

	req, err := http.NewRequest("GET", npmURL+"/api/nginx/proxy-hosts", nil)
	if err != nil {
		log.Printf("NPM discovery error (request): %v", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := app.HTTPClient.Do(req)
	if err != nil {
		log.Printf("NPM discovery error: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("NPM discovery error: status %d", resp.StatusCode)
		return
	}

	var proxyHosts []struct {
		ID            int      `json:"id"`
		DomainNames   []string `json:"domain_names"`
		ForwardHost   string   `json:"forward_host"`
		ForwardPort   int      `json:"forward_port"`
		ForwardScheme string   `json:"forward_scheme"`
		SSLForced     bool     `json:"ssl_forced"`
		Enabled       bool     `json:"enabled"`
		Meta          struct {
			NginxOnline bool    `json:"nginx_online"`
			NginxErr    *string `json:"nginx_err"`
		} `json:"meta"`
	}

	if err := json.NewDecoder(io.LimitReader(resp.Body, 10*1024*1024)).Decode(&proxyHosts); err != nil { // 10MB limit
		log.Printf("NPM discovery decode error: %v", err)
		return
	}

	var apps []models.App
	for _, host := range proxyHosts {
		if len(host.DomainNames) == 0 {
			continue
		}

		domain := host.DomainNames[0]

		// Determine protocol
		protocol := "http"
		if host.SSLForced {
			protocol = "https"
		}

		// Create app name from domain
		name := domain
		parts := strings.Split(domain, ".")
		if len(parts) > 0 {
			name = cases.Title(language.English).String(strings.ReplaceAll(parts[0], "-", " "))
		}

		// Determine status
		status := "offline"
		if host.Enabled && host.Meta.NginxOnline {
			status = "online"
		}

		upstream := fmt.Sprintf("%s://%s:%d", host.ForwardScheme, host.ForwardHost, host.ForwardPort)

		a := models.App{
			Name:        name,
			URL:         fmt.Sprintf("%s://%s", protocol, domain),
			Description: fmt.Sprintf("Discovered via NPM (proxied to %s)", upstream),
			Status:      status,
		}

		apps = append(apps, a)
	}

	app.NPMDiscovery.SetApps(apps)

	log.Printf("NPM discovery found %d apps", len(apps))
}

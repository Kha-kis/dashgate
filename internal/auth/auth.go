package auth

import (
	"context"
	"net/http"
	"strings"

	"dashgate/internal/models"
	"dashgate/internal/server"
)

// contextKey is an unexported type for context keys in this package.
type contextKey string

const userContextKey contextKey = "user"

// GetAuthenticatedUser resolves the current user from the request using all
// configured authentication methods, tried in order: API key, proxy headers,
// then session cookie.
func GetAuthenticatedUser(app *server.App, r *http.Request) *models.AuthenticatedUser {
	app.SysConfigMu.RLock()
	proxyAuthEnabled := app.SystemConfig.ProxyAuthEnabled
	localAuthEnabled := app.SystemConfig.LocalAuthEnabled
	ldapAuthEnabled := app.SystemConfig.LDAPAuthEnabled
	oidcAuthEnabled := app.SystemConfig.OIDCAuthEnabled
	authMode := app.AuthConfig.Mode
	app.SysConfigMu.RUnlock()

	// Check API key first (for API requests)
	if user := GetAPIKeyUser(app, r); user != nil {
		return user
	}

	// Check proxy headers (Authelia, etc.)
	if proxyAuthEnabled || authMode == models.AuthModeAuthelia || authMode == models.AuthModeHybrid {
		if user := GetAutheliaUser(app, r); user != nil {
			return user
		}
	}

	// Check session cookie (local users, LDAP users, OIDC users)
	if localAuthEnabled || ldapAuthEnabled || oidcAuthEnabled ||
		authMode == models.AuthModeLocal || authMode == models.AuthModeHybrid {
		if user := GetLocalUser(app, r); user != nil {
			return user
		}
	}

	return nil
}

// CheckIsAdmin returns true if the given group list contains a configured admin group.
// Comparison is case-insensitive.
func CheckIsAdmin(app *server.App, groups []string) bool {
	app.SysConfigMu.RLock()
	configured := app.SystemConfig.AdminGroup
	app.SysConfigMu.RUnlock()

	// Build set of admin group names from config, with defaults
	adminGroups := make(map[string]bool)
	if configured == "" {
		configured = "admin"
	}
	for _, g := range strings.Split(configured, ",") {
		g = strings.TrimSpace(g)
		if g != "" {
			adminGroups[strings.ToLower(g)] = true
		}
	}

	for _, g := range groups {
		if adminGroups[strings.ToLower(g)] {
			return true
		}
	}
	return false
}

// RequireAuth is middleware that ensures the request has an authenticated user.
// If not, it redirects to /login (local/hybrid mode) or returns 401.
func RequireAuth(app *server.App, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := GetAuthenticatedUser(app, r)
		if user == nil {
			app.SysConfigMu.RLock()
			mode := app.AuthConfig.Mode
			app.SysConfigMu.RUnlock()
			if mode == models.AuthModeLocal || mode == models.AuthModeHybrid {
				// Redirect to login page
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		// Store user in context
		ctx := context.WithValue(r.Context(), userContextKey, user)
		next(w, r.WithContext(ctx))
	}
}

// RequireAdmin is middleware that ensures the request has an authenticated admin user.
func RequireAdmin(app *server.App, next http.HandlerFunc) http.HandlerFunc {
	return RequireAuth(app, func(w http.ResponseWriter, r *http.Request) {
		user := GetUserFromContext(r)
		if user == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if !user.IsAdmin {
			http.Error(w, "Forbidden: Admin access required", http.StatusForbidden)
			return
		}
		next(w, r)
	})
}

// GetUserFromContext extracts the authenticated user stored in the request context.
func GetUserFromContext(r *http.Request) *models.AuthenticatedUser {
	if user, ok := r.Context().Value(userContextKey).(*models.AuthenticatedUser); ok {
		return user
	}
	return nil
}

// UserFromContext extracts the authenticated user from a context value directly.
func UserFromContext(ctx context.Context) *models.AuthenticatedUser {
	if u, ok := ctx.Value(userContextKey).(*models.AuthenticatedUser); ok {
		return u
	}
	return nil
}

// WithUser sets the authenticated user on the request context and returns a
// shallow copy of the request with the updated context. Exported for tests.
func WithUser(r *http.Request, user *models.AuthenticatedUser) *http.Request {
	ctx := context.WithValue(r.Context(), userContextKey, user)
	return r.WithContext(ctx)
}

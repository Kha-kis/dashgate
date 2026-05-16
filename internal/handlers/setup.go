package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"dashgate/internal/database"
	"dashgate/internal/middleware"
	"dashgate/internal/server"
)

// SetupHandler handles the first-time setup wizard.
// GET serves the setup page; POST creates the initial configuration.
func SetupHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			// Check if setup is needed
			if !database.NeedsSetup(app) {
				http.Redirect(w, r, "/", http.StatusFound)
				return
			}

			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			data := map[string]interface{}{
				"CSPNonce": middleware.GetCSPNonce(r),
				"Version":  app.Version,
			}
			if err := app.GetTemplates().ExecuteTemplate(w, "setup.html", data); err != nil {
				log.Printf("Template error: %v", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
			return
		}

		if r.Method != http.MethodPost {
			respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}

		// Only allow setup if not completed
		if !database.NeedsSetup(app) {
			respondError(w, http.StatusBadRequest, "Setup already completed")
			return
		}

		var req struct {
			// Auth providers (new multi-provider mode)
			ProxyAuthEnabled bool `json:"proxyAuthEnabled"`
			LocalAuthEnabled bool `json:"localAuthEnabled"`
			LDAPAuthEnabled  bool `json:"ldapAuthEnabled"`
			OIDCAuthEnabled  bool `json:"oidcAuthEnabled"`
			// Admin user (for local auth)
			Username    string `json:"username"`
			Password    string `json:"password"`
			Email       string `json:"email"`
			DisplayName string `json:"displayName"`
			// Session & security settings
			SessionDays    int    `json:"sessionDays"`
			AdminGroup     string `json:"adminGroup"`
			TrustedProxies string `json:"trustedProxies"`
			// LDAP settings
			LDAPServer       string `json:"ldapServer"`
			LDAPBindDN       string `json:"ldapBindDN"`
			LDAPBindPassword string `json:"ldapBindPassword"`
			LDAPBaseDN       string `json:"ldapBaseDN"`
			LDAPUserFilter   string `json:"ldapUserFilter"`
			LDAPUserAttr     string `json:"ldapUserAttr"`
			LDAPEmailAttr    string `json:"ldapEmailAttr"`
			LDAPDisplayAttr  string `json:"ldapDisplayAttr"`
			LDAPStartTLS     bool   `json:"ldapStartTLS"`
			LDAPSkipVerify   bool   `json:"ldapSkipVerify"`
			// OIDC settings
			OIDCDisplayName  string `json:"oidcDisplayName"`
			OIDCIssuer       string `json:"oidcIssuer"`
			OIDCClientID     string `json:"oidcClientID"`
			OIDCClientSecret string `json:"oidcClientSecret"`
			OIDCRedirectURL  string `json:"oidcRedirectURL"`
			OIDCScopes       string `json:"oidcScopes"`
			OIDCGroupsClaim  string `json:"oidcGroupsClaim"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, "Invalid request body")
			return
		}

		// Validate at least one auth provider is enabled
		if !req.ProxyAuthEnabled && !req.LocalAuthEnabled && !req.LDAPAuthEnabled && !req.OIDCAuthEnabled {
			respondError(w, http.StatusBadRequest, "At least one authentication provider must be enabled")
			return
		}

		// Set admin group early so CreateAdminUser can use it
		app.SysConfigMu.Lock()
		app.SystemConfig.AdminGroup = req.AdminGroup
		if app.SystemConfig.AdminGroup == "" {
			app.SystemConfig.AdminGroup = "admin"
		}
		app.SysConfigMu.Unlock()

		// If local auth, require admin credentials
		if req.LocalAuthEnabled {
			if req.Username == "" || req.Password == "" {
				respondError(w, http.StatusBadRequest, "Username and password required for local auth")
				return
			}

			if len(req.Password) < 8 {
				respondError(w, http.StatusBadRequest, "Password must be at least 8 characters")
				return
			}

			// Create admin user
			if err := database.CreateAdminUser(app, req.Username, req.Password, req.Email, req.DisplayName); err != nil {
				if strings.Contains(err.Error(), "UNIQUE") {
					respondError(w, http.StatusConflict, "Username or email already exists")
				} else {
					log.Printf("Error creating admin user: %v", err)
					respondError(w, http.StatusInternalServerError, "Failed to create admin user")
				}
				return
			}
		}

		// Save system config
		app.SysConfigMu.Lock()
		app.SystemConfig.SetupCompleted = true
		// Auto-detect HTTPS: check TLS or X-Forwarded-Proto from reverse proxy
		isHTTPS := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
		app.SystemConfig.CookieSecure = isHTTPS
		if req.SessionDays > 0 {
			app.SystemConfig.SessionDays = req.SessionDays
		} else {
			app.SystemConfig.SessionDays = 7
		}

		// Set provider flags
		app.SystemConfig.ProxyAuthEnabled = req.ProxyAuthEnabled
		app.SystemConfig.LocalAuthEnabled = req.LocalAuthEnabled
		app.SystemConfig.LDAPAuthEnabled = req.LDAPAuthEnabled
		app.SystemConfig.OIDCAuthEnabled = req.OIDCAuthEnabled

		// Set security settings (AdminGroup already set above before CreateAdminUser)
		app.SystemConfig.TrustedProxies = req.TrustedProxies

		// Set LDAP settings if enabled
		if req.LDAPAuthEnabled {
			app.SystemConfig.LDAPServer = req.LDAPServer
			app.SystemConfig.LDAPBindDN = req.LDAPBindDN
			app.SystemConfig.LDAPBindPassword = req.LDAPBindPassword
			app.SystemConfig.LDAPBaseDN = req.LDAPBaseDN
			app.SystemConfig.LDAPUserFilter = req.LDAPUserFilter
			if app.SystemConfig.LDAPUserFilter == "" {
				app.SystemConfig.LDAPUserFilter = "(uid=%s)"
			}
			app.SystemConfig.LDAPUserAttr = req.LDAPUserAttr
			if app.SystemConfig.LDAPUserAttr == "" {
				app.SystemConfig.LDAPUserAttr = "uid"
			}
			app.SystemConfig.LDAPEmailAttr = req.LDAPEmailAttr
			if app.SystemConfig.LDAPEmailAttr == "" {
				app.SystemConfig.LDAPEmailAttr = "mail"
			}
			app.SystemConfig.LDAPDisplayAttr = req.LDAPDisplayAttr
			if app.SystemConfig.LDAPDisplayAttr == "" {
				app.SystemConfig.LDAPDisplayAttr = "cn"
			}
			app.SystemConfig.LDAPStartTLS = req.LDAPStartTLS
			app.SystemConfig.LDAPSkipVerify = req.LDAPSkipVerify
		}

		// Set OIDC display name (always saved, even if OIDC is not enabled,
		// so the value persists if OIDC is enabled later)
		app.SystemConfig.OIDCDisplayName = req.OIDCDisplayName

		// Set OIDC settings if enabled
		if req.OIDCAuthEnabled {
			app.SystemConfig.OIDCIssuer = req.OIDCIssuer
			app.SystemConfig.OIDCClientID = req.OIDCClientID
			app.SystemConfig.OIDCClientSecret = req.OIDCClientSecret
			app.SystemConfig.OIDCRedirectURL = req.OIDCRedirectURL
			app.SystemConfig.OIDCScopes = req.OIDCScopes
			if app.SystemConfig.OIDCScopes == "" {
				app.SystemConfig.OIDCScopes = "openid profile email groups"
			}
			app.SystemConfig.OIDCGroupsClaim = req.OIDCGroupsClaim
			if app.SystemConfig.OIDCGroupsClaim == "" {
				app.SystemConfig.OIDCGroupsClaim = "groups"
			}
		}
		app.SysConfigMu.Unlock()

		if err := database.SaveSystemConfig(app); err != nil {
			log.Printf("Error saving system config: %v", err)
			respondError(w, http.StatusInternalServerError, "Failed to save configuration")
			return
		}

		// Determine redirect based on what's enabled
		redirect := "/"
		if req.LocalAuthEnabled || req.LDAPAuthEnabled || req.OIDCAuthEnabled {
			// If any login-based auth is enabled, redirect to login
			redirect = "/login"
		}

		respondJSON(w, http.StatusOK, map[string]interface{}{
			"status":   "ok",
			"redirect": redirect,
		})
	}
}

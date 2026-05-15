package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"

	"dashgate/internal/auth"
	"dashgate/internal/database"
	"dashgate/internal/server"
)

// SystemConfigHandler routes GET/PUT requests for the system configuration.
func SystemConfigHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			getSystemConfigHandler(app, w, r)
		case http.MethodPut:
			updateSystemConfigHandler(app, w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func getSystemConfigHandler(app *server.App, w http.ResponseWriter, r *http.Request) {
	app.SysConfigMu.RLock()
	response := map[string]interface{}{
		// General settings
		"sessionDays":    app.SystemConfig.SessionDays,
		"cookieSecure":   app.SystemConfig.CookieSecure,
		"setupCompleted": app.SystemConfig.SetupCompleted,
		"adminGroup":     app.SystemConfig.AdminGroup,
		"trustedProxies": app.SystemConfig.TrustedProxies,

		// Auth providers enabled
		"proxyAuthEnabled": app.SystemConfig.ProxyAuthEnabled,
		"localAuthEnabled": app.SystemConfig.LocalAuthEnabled,
		"ldapAuthEnabled":  app.SystemConfig.LDAPAuthEnabled,
		"oidcAuthEnabled":  app.SystemConfig.OIDCAuthEnabled,
		"apiKeyEnabled":    app.SystemConfig.APIKeyEnabled,

		// LDAP settings (excluding password)
		"ldapServer":      app.SystemConfig.LDAPServer,
		"ldapBindDN":      app.SystemConfig.LDAPBindDN,
		"ldapBaseDN":      app.SystemConfig.LDAPBaseDN,
		"ldapUserFilter":  app.SystemConfig.LDAPUserFilter,
		"ldapGroupFilter": app.SystemConfig.LDAPGroupFilter,
		"ldapUserAttr":    app.SystemConfig.LDAPUserAttr,
		"ldapEmailAttr":   app.SystemConfig.LDAPEmailAttr,
		"ldapDisplayAttr": app.SystemConfig.LDAPDisplayAttr,
		"ldapGroupAttr":   app.SystemConfig.LDAPGroupAttr,
		"ldapStartTLS":    app.SystemConfig.LDAPStartTLS,
		"ldapSkipVerify":  app.SystemConfig.LDAPSkipVerify,

		// OIDC settings (excluding secret)
		"oidcDisplayName": app.SystemConfig.OIDCDisplayName,
		"oidcIssuer":      app.SystemConfig.OIDCIssuer,
		"oidcClientID":    app.SystemConfig.OIDCClientID,
		"oidcRedirectURL": app.SystemConfig.OIDCRedirectURL,
		"oidcScopes":      app.SystemConfig.OIDCScopes,
		"oidcGroupsClaim": app.SystemConfig.OIDCGroupsClaim,
	}

	// Set defaults
	if app.SystemConfig.SessionDays == 0 {
		response["sessionDays"] = 7
	}
	app.SysConfigMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func updateSystemConfigHandler(app *server.App, w http.ResponseWriter, r *http.Request) {
	var req struct {
		// General settings
		SessionDays    int    `json:"sessionDays"`
		CookieSecure   bool   `json:"cookieSecure"`
		AdminGroup     string `json:"adminGroup"`
		TrustedProxies string `json:"trustedProxies"`

		// Auth providers
		ProxyAuthEnabled bool `json:"proxyAuthEnabled"`
		LocalAuthEnabled bool `json:"localAuthEnabled"`
		LDAPAuthEnabled  bool `json:"ldapAuthEnabled"`
		OIDCAuthEnabled  bool `json:"oidcAuthEnabled"`
		APIKeyEnabled    bool `json:"apiKeyEnabled"`

		// LDAP settings
		LDAPServer       string `json:"ldapServer"`
		LDAPBindDN       string `json:"ldapBindDN"`
		LDAPBindPassword string `json:"ldapBindPassword"`
		LDAPBaseDN       string `json:"ldapBaseDN"`
		LDAPUserFilter   string `json:"ldapUserFilter"`
		LDAPGroupFilter  string `json:"ldapGroupFilter"`
		LDAPUserAttr     string `json:"ldapUserAttr"`
		LDAPEmailAttr    string `json:"ldapEmailAttr"`
		LDAPDisplayAttr  string `json:"ldapDisplayAttr"`
		LDAPGroupAttr    string `json:"ldapGroupAttr"`
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
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Check if enabling local auth without users
	app.SysConfigMu.RLock()
	currentlyDisabled := !app.SystemConfig.LocalAuthEnabled
	app.SysConfigMu.RUnlock()

	if req.LocalAuthEnabled && currentlyDisabled {
		var count int
		if err := app.DB.QueryRow("SELECT COUNT(*) FROM users").Scan(&count); err == nil && count == 0 {
			http.Error(w, "Cannot enable local auth without local users. Create a local user first.", http.StatusBadRequest)
			return
		}
	}

	app.SysConfigMu.Lock()
	// Update general settings
	if req.SessionDays > 0 {
		app.SystemConfig.SessionDays = req.SessionDays
	}
	app.SystemConfig.CookieSecure = req.CookieSecure
	if req.AdminGroup != "" {
		app.SystemConfig.AdminGroup = req.AdminGroup
	}
	app.SystemConfig.TrustedProxies = req.TrustedProxies

	// Update provider flags
	app.SystemConfig.ProxyAuthEnabled = req.ProxyAuthEnabled
	app.SystemConfig.LocalAuthEnabled = req.LocalAuthEnabled
	app.SystemConfig.LDAPAuthEnabled = req.LDAPAuthEnabled
	app.SystemConfig.OIDCAuthEnabled = req.OIDCAuthEnabled
	app.SystemConfig.APIKeyEnabled = req.APIKeyEnabled

	// Update LDAP settings
	app.SystemConfig.LDAPServer = req.LDAPServer
	app.SystemConfig.LDAPBindDN = req.LDAPBindDN
	if req.LDAPBindPassword != "" {
		app.SystemConfig.LDAPBindPassword = req.LDAPBindPassword
	}
	app.SystemConfig.LDAPBaseDN = req.LDAPBaseDN
	app.SystemConfig.LDAPUserFilter = req.LDAPUserFilter
	app.SystemConfig.LDAPGroupFilter = req.LDAPGroupFilter
	app.SystemConfig.LDAPUserAttr = req.LDAPUserAttr
	app.SystemConfig.LDAPEmailAttr = req.LDAPEmailAttr
	app.SystemConfig.LDAPDisplayAttr = req.LDAPDisplayAttr
	app.SystemConfig.LDAPGroupAttr = req.LDAPGroupAttr
	app.SystemConfig.LDAPStartTLS = req.LDAPStartTLS
	app.SystemConfig.LDAPSkipVerify = req.LDAPSkipVerify

	// Update OIDC settings
	app.SystemConfig.OIDCDisplayName = req.OIDCDisplayName
	app.SystemConfig.OIDCIssuer = req.OIDCIssuer
	app.SystemConfig.OIDCClientID = req.OIDCClientID
	if req.OIDCClientSecret != "" {
		app.SystemConfig.OIDCClientSecret = req.OIDCClientSecret
	}
	app.SystemConfig.OIDCRedirectURL = req.OIDCRedirectURL
	app.SystemConfig.OIDCScopes = req.OIDCScopes
	app.SystemConfig.OIDCGroupsClaim = req.OIDCGroupsClaim

	app.SystemConfig.SetupCompleted = true
	app.SysConfigMu.Unlock()

	if err := database.SaveSystemConfig(app); err != nil {
		log.Printf("Error saving system config: %v", err)
		http.Error(w, "Failed to save configuration", http.StatusInternalServerError)
		return
	}

	adminUser := auth.GetUserFromContext(r)
	adminName := ""
	if adminUser != nil {
		adminName = adminUser.Username
	}
	database.LogAudit(app, adminName, "system_config_updated", "System configuration updated", r.RemoteAddr)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "updated"})
}

// AuditLogHandler returns the recent audit log entries as JSON.
func AuditLogHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		limit := 100
		if l := r.URL.Query().Get("limit"); l != "" {
			if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 1000 {
				limit = n
			}
		}

		entries, err := database.GetAuditLogs(app, limit)
		if err != nil {
			log.Printf("Error fetching audit logs: %v", err)
			http.Error(w, "Failed to fetch audit logs", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(entries)
	}
}

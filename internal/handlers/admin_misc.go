package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"dashgate/internal/auth"
	"dashgate/internal/config"
	"dashgate/internal/database"
	"dashgate/internal/server"
)

// AdminAppsHandler returns all apps with their current group mappings.
func AdminAppsHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}

		type AppWithGroups struct {
			Name     string   `json:"name"`
			URL      string   `json:"url"`
			Icon     string   `json:"icon"`
			Category string   `json:"category"`
			Groups   []string `json:"groups"`
		}

		app.ConfigMu.RLock()
		var apps []AppWithGroups
		for _, cat := range app.Config.Categories {
			for _, a := range cat.Apps {
				apps = append(apps, AppWithGroups{
					Name:     a.Name,
					URL:      a.URL,
					Icon:     a.Icon,
					Category: cat.Name,
					Groups:   config.GetAppGroups(app, a),
				})
			}
		}
		app.ConfigMu.RUnlock()

		respondJSON(w, http.StatusOK, apps)
	}
}

// AdminAppMappingHandler updates the group mapping for a specific app.
func AdminAppMappingHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}

		var req struct {
			AppURL string   `json:"appUrl"`
			Groups []string `json:"groups"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, "Invalid request body")
			return
		}

		if req.AppURL == "" {
			respondError(w, http.StatusBadRequest, "App URL required")
			return
		}

		// Verify the app exists
		app.ConfigMu.RLock()
		found := false
		for _, cat := range app.Config.Categories {
			for _, a := range cat.Apps {
				if a.URL == req.AppURL {
					found = true
					break
				}
			}
		}
		app.ConfigMu.RUnlock()

		if !found {
			respondError(w, http.StatusNotFound, "App not found")
			return
		}

		// Update the mapping
		app.MappingsMu.Lock()
		if len(req.Groups) == 0 {
			delete(app.AppMappings, req.AppURL)
		} else {
			app.AppMappings[req.AppURL] = req.Groups
		}
		app.MappingsMu.Unlock()

		// Save to file
		if err := config.SaveAppMappings(app); err != nil {
			log.Printf("Error saving app mappings: %v", err)
			respondError(w, http.StatusInternalServerError, "Failed to save mappings")
			return
		}

		respondJSON(w, http.StatusOK, map[string]string{"status": "updated"})
	}
}

// BackupHandler exports users, preferences, and system config as a JSON download.
func BackupHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}

		backup := map[string]interface{}{
			"version":   "1.0",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		}

		// Export users (without password hashes for security)
		rows, err := database.ListUsers(app)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "Failed to export users")
			return
		}
		defer rows.Close()

		var users []map[string]interface{}
		for rows.Next() {
			var id int
			var username, email, displayName, groups, createdAt string
			if err := rows.Scan(&id, &username, &email, &displayName, &groups, &createdAt); err != nil {
				log.Printf("Error scanning user row during backup: %v", err)
				continue
			}
			users = append(users, map[string]interface{}{
				"id":          id,
				"username":    username,
				"email":       email,
				"displayName": displayName,
				"groups":      groups,
				"createdAt":   createdAt,
			})
		}
		if err := rows.Err(); err != nil {
			log.Printf("Error iterating user rows during backup: %v", err)
			respondError(w, http.StatusInternalServerError, "Failed to export users")
			return
		}
		backup["users"] = users

		// Export user preferences
		rows2, err := database.ListPreferences(app)
		if err == nil {
			defer rows2.Close()
			var prefs []map[string]interface{}
			for rows2.Next() {
				var userID int
				var preferences string
				if err := rows2.Scan(&userID, &preferences); err != nil {
					log.Printf("Error scanning user preferences row during backup: %v", err)
					continue
				}
				prefs = append(prefs, map[string]interface{}{
					"userId":      userID,
					"preferences": preferences,
				})
			}
			if err := rows2.Err(); err != nil {
				log.Printf("Error iterating user preferences rows during backup: %v", err)
			}
			backup["userPreferences"] = prefs
		}

		// Export system config (excluding secrets)
		app.SysConfigMu.RLock()
		backup["systemConfig"] = map[string]interface{}{
			"sessionDays":      app.SystemConfig.SessionDays,
			"cookieSecure":     app.SystemConfig.CookieSecure,
			"proxyAuthEnabled": app.SystemConfig.ProxyAuthEnabled,
			"localAuthEnabled": app.SystemConfig.LocalAuthEnabled,
			"ldapAuthEnabled":  app.SystemConfig.LDAPAuthEnabled,
			"oidcAuthEnabled":  app.SystemConfig.OIDCAuthEnabled,
			"apiKeyEnabled":    app.SystemConfig.APIKeyEnabled,
			"ldapServer":       app.SystemConfig.LDAPServer,
			"ldapBindDN":       app.SystemConfig.LDAPBindDN,
			"ldapBaseDN":       app.SystemConfig.LDAPBaseDN,
			"ldapUserFilter":   app.SystemConfig.LDAPUserFilter,
			"ldapUserAttr":     app.SystemConfig.LDAPUserAttr,
			"ldapEmailAttr":    app.SystemConfig.LDAPEmailAttr,
			"ldapDisplayAttr":  app.SystemConfig.LDAPDisplayAttr,
			"ldapStartTLS":     app.SystemConfig.LDAPStartTLS,
			"ldapSkipVerify":   app.SystemConfig.LDAPSkipVerify,
			"oidcIssuer":       app.SystemConfig.OIDCIssuer,
			"oidcClientID":     app.SystemConfig.OIDCClientID,
			"oidcRedirectURL":  app.SystemConfig.OIDCRedirectURL,
			"oidcScopes":       app.SystemConfig.OIDCScopes,
			"oidcGroupsClaim":  app.SystemConfig.OIDCGroupsClaim,
		}
		app.SysConfigMu.RUnlock()

		adminUser := auth.GetUserFromContext(r)
		adminName := ""
		if adminUser != nil {
			adminName = adminUser.Username
		}
		database.LogAudit(app, adminName, "backup_created", fmt.Sprintf("Backup exported with %d users", len(users)), r.RemoteAddr)

		// Set headers for file download
		respondJSON(w, http.StatusOK, backup)
	}
}

// RestoreHandler restores system config and user preferences from a backup JSON file.
func RestoreHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}

		var backup map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&backup); err != nil {
			respondError(w, http.StatusBadRequest, "Invalid backup file")
			return
		}

		// Validate backup version
		version, _ := backup["version"].(string)
		if version != "1.0" {
			respondError(w, http.StatusBadRequest, "Unsupported backup version")
			return
		}

		// Validate system config if present
		if sysConfig, ok := backup["systemConfig"].(map[string]interface{}); ok {
			// Validate that auth-related fields have correct types when present
			authBoolFields := []string{"proxyAuthEnabled", "localAuthEnabled", "ldapAuthEnabled", "oidcAuthEnabled"}
			for _, field := range authBoolFields {
				if v, exists := sysConfig[field]; exists {
					if _, isBool := v.(bool); !isBool {
						respondError(w, http.StatusBadRequest, fmt.Sprintf("Invalid type for %s: expected boolean", field))
						return
					}
				}
			}

			// Validate string fields have correct types when present
			stringFields := []string{"ldapServer", "ldapBindDN", "ldapBaseDN", "ldapUserFilter", "ldapUserAttr", "ldapEmailAttr", "ldapDisplayAttr", "oidcIssuer", "oidcClientID", "oidcRedirectURL", "oidcScopes", "oidcGroupsClaim"}
			for _, field := range stringFields {
				if v, exists := sysConfig[field]; exists {
					if _, isStr := v.(string); !isStr {
						respondError(w, http.StatusBadRequest, fmt.Sprintf("Invalid type for %s: expected string", field))
						return
					}
				}
			}

			// Ensure at least one auth method is enabled
			proxyAuth, _ := sysConfig["proxyAuthEnabled"].(bool)
			localAuth, _ := sysConfig["localAuthEnabled"].(bool)
			ldapAuth, _ := sysConfig["ldapAuthEnabled"].(bool)
			oidcAuth, _ := sysConfig["oidcAuthEnabled"].(bool)

			// Only reject if all four auth fields are explicitly present and all false
			_, hasProxy := sysConfig["proxyAuthEnabled"]
			_, hasLocal := sysConfig["localAuthEnabled"]
			_, hasLDAP := sysConfig["ldapAuthEnabled"]
			_, hasOIDC := sysConfig["oidcAuthEnabled"]

			if hasProxy && hasLocal && hasLDAP && hasOIDC && !proxyAuth && !localAuth && !ldapAuth && !oidcAuth {
				respondError(w, http.StatusBadRequest, "Backup rejected: at least one authentication method must be enabled (localAuthEnabled, proxyAuthEnabled, ldapAuthEnabled, or oidcAuthEnabled)")
				return
			}
		}

		// Validate user records if present
		if users, ok := backup["users"].([]interface{}); ok {
			for i, u := range users {
				user, ok := u.(map[string]interface{})
				if !ok {
					respondError(w, http.StatusBadRequest, fmt.Sprintf("Invalid user record at index %d: expected object", i))
					return
				}
				username, _ := user["username"].(string)
				if strings.TrimSpace(username) == "" {
					respondError(w, http.StatusBadRequest, fmt.Sprintf("Invalid user record at index %d: username must be a non-empty string", i))
					return
				}
			}
		}

		restored := map[string]int{
			"users":           0,
			"userPreferences": 0,
			"systemConfig":    0,
		}

		// Restore system config (excluding secrets - those need to be re-entered)
		if sysConfig, ok := backup["systemConfig"].(map[string]interface{}); ok {
			app.SysConfigMu.Lock()
			if v, ok := sysConfig["sessionDays"].(float64); ok {
				app.SystemConfig.SessionDays = int(v)
			}
			if v, ok := sysConfig["cookieSecure"].(bool); ok {
				app.SystemConfig.CookieSecure = v
			}
			if v, ok := sysConfig["proxyAuthEnabled"].(bool); ok {
				app.SystemConfig.ProxyAuthEnabled = v
			}
			if v, ok := sysConfig["localAuthEnabled"].(bool); ok {
				app.SystemConfig.LocalAuthEnabled = v
			}
			if v, ok := sysConfig["ldapAuthEnabled"].(bool); ok {
				app.SystemConfig.LDAPAuthEnabled = v
			}
			if v, ok := sysConfig["oidcAuthEnabled"].(bool); ok {
				app.SystemConfig.OIDCAuthEnabled = v
			}
			if v, ok := sysConfig["apiKeyEnabled"].(bool); ok {
				app.SystemConfig.APIKeyEnabled = v
			}
			if v, ok := sysConfig["ldapServer"].(string); ok {
				app.SystemConfig.LDAPServer = v
			}
			if v, ok := sysConfig["ldapBindDN"].(string); ok {
				app.SystemConfig.LDAPBindDN = v
			}
			if v, ok := sysConfig["ldapBaseDN"].(string); ok {
				app.SystemConfig.LDAPBaseDN = v
			}
			if v, ok := sysConfig["ldapUserFilter"].(string); ok {
				app.SystemConfig.LDAPUserFilter = v
			}
			if v, ok := sysConfig["oidcIssuer"].(string); ok {
				app.SystemConfig.OIDCIssuer = v
			}
			if v, ok := sysConfig["oidcClientID"].(string); ok {
				app.SystemConfig.OIDCClientID = v
			}
			if v, ok := sysConfig["oidcRedirectURL"].(string); ok {
				app.SystemConfig.OIDCRedirectURL = v
			}
			app.SysConfigMu.Unlock()

			if err := database.SaveSystemConfig(app); err != nil {
				log.Printf("Error restoring system config: %v", err)
			} else {
				restored["systemConfig"] = 1
			}
		}

		// Restore user preferences
		if prefs, ok := backup["userPreferences"].([]interface{}); ok {
			for _, p := range prefs {
				if pref, ok := p.(map[string]interface{}); ok {
					userIdFloat, ok := pref["userId"].(float64)
					if !ok {
						continue // skip malformed entry
					}
					userId := int(userIdFloat)

					prefsStr, ok := pref["preferences"].(string)
					if !ok {
						continue
					}
					if err := database.SavePreferencesByUserID(app, userId, prefsStr); err == nil {
						restored["userPreferences"]++
					}
				}
			}
		}

		adminUser := auth.GetUserFromContext(r)
		adminName := ""
		if adminUser != nil {
			adminName = adminUser.Username
		}
		database.LogAudit(app, adminName, "backup_restored", fmt.Sprintf("Restored: users=%d, prefs=%d, config=%d", restored["users"], restored["userPreferences"], restored["systemConfig"]), r.RemoteAddr)

		respondJSON(w, http.StatusOK, map[string]interface{}{
			"status":   "restored",
			"restored": restored,
			"note":     "Passwords and secrets were not restored for security. Please re-enter them in settings.",
		})
	}
}

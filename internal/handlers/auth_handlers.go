package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"dashgate/internal/auth"
	"dashgate/internal/database"
	"dashgate/internal/middleware"
	"dashgate/internal/models"
	"dashgate/internal/server"
)

// LoginHandler handles GET (render login page) and POST (authenticate user).
func LoginHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			// Check if any login method is available
			app.SysConfigMu.RLock()
			loginAvailable := app.SystemConfig.LocalAuthEnabled || app.SystemConfig.LDAPAuthEnabled || app.SystemConfig.OIDCAuthEnabled ||
				app.AuthConfig.Mode == models.AuthModeLocal || app.AuthConfig.Mode == models.AuthModeHybrid
			app.SysConfigMu.RUnlock()

			if !loginAvailable {
				http.Redirect(w, r, "/", http.StatusFound)
				return
			}

			// Check if already logged in
			if user := auth.GetAuthenticatedUser(app, r); user != nil {
				http.Redirect(w, r, "/", http.StatusFound)
				return
			}

			// Pass auth options to template
			app.SysConfigMu.RLock()
			data := map[string]interface{}{
				"OIDCEnabled":     app.SystemConfig.OIDCAuthEnabled && app.OIDCProvider != nil,
				"LDAPEnabled":     app.SystemConfig.LDAPAuthEnabled && app.LDAPAuth != nil,
				"OIDCDisplayName": app.SystemConfig.OIDCDisplayName,
				"CSPNonce":        middleware.GetCSPNonce(r),
				"Version":         app.Version,
			}
			app.SysConfigMu.RUnlock()

			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			if err := app.GetTemplates().ExecuteTemplate(w, "login.html", data); err != nil {
				log.Printf("Template error: %v", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
			return
		}

		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Handle login POST
		if app.DB == nil {
			http.Error(w, "Database not available", http.StatusServiceUnavailable)
			return
		}

		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		if req.Username == "" || req.Password == "" {
			http.Error(w, "Username and password required", http.StatusBadRequest)
			return
		}

		var authUser *models.AuthenticatedUser
		var userID int

		// Try local auth first
		app.SysConfigMu.RLock()
		localEnabled := app.SystemConfig.LocalAuthEnabled || app.AuthConfig.Mode == models.AuthModeLocal || app.AuthConfig.Mode == models.AuthModeHybrid
		app.SysConfigMu.RUnlock()

		if localEnabled {
			var passwordHash, email, displayName, groupsJSON string
			err := app.DB.QueryRow(
				"SELECT id, password_hash, COALESCE(email, ''), COALESCE(display_name, username), COALESCE(groups, '[]') FROM users WHERE username = ?",
				req.Username,
			).Scan(&userID, &passwordHash, &email, &displayName, &groupsJSON)

			if err == nil {
				if auth.CheckPassword(req.Password, passwordHash) {
					// Local auth successful
					var groups []string
					json.Unmarshal([]byte(groupsJSON), &groups)

					authUser = &models.AuthenticatedUser{
						Username:    req.Username,
						DisplayName: displayName,
						Email:       email,
						Groups:      groups,
						Source:      "local",
					}
					authUser.IsAdmin = auth.CheckIsAdmin(app, authUser.Groups)
				}
			}
		}

		// Try LDAP auth if local failed and LDAP is enabled
		app.SysConfigMu.RLock()
		ldapEnabled := app.SystemConfig.LDAPAuthEnabled && app.LDAPAuth != nil
		app.SysConfigMu.RUnlock()

		if authUser == nil && ldapEnabled {
			ldapUser, err := auth.AuthenticateLDAP(app, req.Username, req.Password)
			if err == nil {
				authUser = ldapUser

				// Create or update local user record for LDAP user using upsert to avoid race conditions
				groupsJSON, _ := json.Marshal(authUser.Groups)
				_, err = app.DB.Exec(
					`INSERT INTO users (username, email, password_hash, display_name, groups)
					 VALUES (?, ?, 'LDAP_USER', ?, ?)
					 ON CONFLICT(username) DO UPDATE SET
					   email = excluded.email,
					   display_name = excluded.display_name,
					   groups = excluded.groups,
					   updated_at = ?`,
					req.Username, authUser.Email, authUser.DisplayName, string(groupsJSON), time.Now(),
				)
				if err != nil {
					log.Printf("Failed to upsert LDAP user: %v", err)
					http.Error(w, "Internal server error", http.StatusInternalServerError)
					return
				}
				err = app.DB.QueryRow("SELECT id FROM users WHERE username = ?", req.Username).Scan(&userID)
				if err != nil {
					log.Printf("Failed to retrieve LDAP user ID: %v", err)
					http.Error(w, "Internal server error", http.StatusInternalServerError)
					return
				}
			}
		}

		if authUser == nil {
			http.Error(w, "Invalid username or password", http.StatusUnauthorized)
			return
		}

		// Invalidate any existing sessions for this user to prevent session fixation
		database.InvalidateUserSessions(app, userID)

		// Create session
		token, err := auth.GenerateSessionToken()
		if err != nil {
			log.Printf("Error generating session token: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		app.SysConfigMu.RLock()
		sessionDuration := app.AuthConfig.SessionDuration
		cookieName := app.AuthConfig.CookieName
		cookieSecure := app.AuthConfig.CookieSecure
		app.SysConfigMu.RUnlock()

		expiresAt := time.Now().Add(time.Duration(sessionDuration) * 24 * time.Hour)
		_, err = app.DB.Exec(
			"INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, ?)",
			userID, token, expiresAt,
		)
		if err != nil {
			log.Printf("Error creating session: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Set cookie
		http.SetCookie(w, &http.Cookie{
			Name:     cookieName,
			Value:    token,
			Path:     "/",
			Expires:  expiresAt,
			HttpOnly: true,
			Secure:   cookieSecure,
			SameSite: http.SameSiteLaxMode,
		})

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "redirect": "/"})
	}
}

// LogoutHandler deletes the user's session and clears the cookie.
func LogoutHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		app.SysConfigMu.RLock()
		cookieName := app.AuthConfig.CookieName
		cookieSecure := app.AuthConfig.CookieSecure
		app.SysConfigMu.RUnlock()

		// Get session cookie
		cookie, err := r.Cookie(cookieName)
		if err == nil && app.DB != nil {
			// Delete session from database
			if _, execErr := app.DB.Exec("DELETE FROM sessions WHERE token = ?", cookie.Value); execErr != nil {
				log.Printf("Error deleting session during logout: %v", execErr)
			}
		}

		// Clear cookie
		http.SetCookie(w, &http.Cookie{
			Name:     cookieName,
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   cookieSecure,
			SameSite: http.SameSiteLaxMode,
		})

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}
}

// AuthMeHandler returns the currently authenticated user as JSON.
func AuthMeHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		user := auth.GetAuthenticatedUser(app, r)
		if user == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(user)
	}
}

// AuthConfigHandler returns which auth methods are enabled (public, no secrets).
func AuthConfigHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		app.SysConfigMu.RLock()
		cfg := map[string]interface{}{
			"localEnabled":    app.SystemConfig.LocalAuthEnabled,
			"ldapEnabled":     app.SystemConfig.LDAPAuthEnabled,
			"oidcEnabled":     app.SystemConfig.OIDCAuthEnabled,
			"proxyEnabled":    app.SystemConfig.ProxyAuthEnabled,
			"oidcDisplayName": app.SystemConfig.OIDCDisplayName,
		}
		app.SysConfigMu.RUnlock()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cfg)
	}
}

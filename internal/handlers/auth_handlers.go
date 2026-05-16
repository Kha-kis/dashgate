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
				respondError(w, http.StatusInternalServerError, "Internal Server Error")
			}
			return
		}

		if r.Method != http.MethodPost {
			respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}

		// Handle login POST
		if app.DB == nil {
			respondError(w, http.StatusServiceUnavailable, "Database not available")
			return
		}

		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, "Invalid request body")
			return
		}

		if req.Username == "" || req.Password == "" {
			respondError(w, http.StatusBadRequest, "Username and password required")
			return
		}

		var authUser *models.AuthenticatedUser
		var userID int

		// Try local auth first
		app.SysConfigMu.RLock()
		localEnabled := app.SystemConfig.LocalAuthEnabled || app.AuthConfig.Mode == models.AuthModeLocal || app.AuthConfig.Mode == models.AuthModeHybrid
		app.SysConfigMu.RUnlock()

		if localEnabled {
			user, err := database.GetUserByUsername(app, req.Username)
			if err == nil {
				if auth.CheckPassword(req.Password, user.PasswordHash) {
					var groups []string
					json.Unmarshal([]byte(user.GroupsJSON), &groups)

					authUser = &models.AuthenticatedUser{
						Username:    req.Username,
						DisplayName: user.DisplayName,
						Email:       user.Email,
						Groups:      groups,
						Source:      "local",
					}
					authUser.IsAdmin = auth.CheckIsAdmin(app, authUser.Groups)
					userID = user.ID
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
				if err := database.UpsertLDAPUser(app, req.Username, authUser.Email, authUser.DisplayName, string(groupsJSON)); err != nil {
					log.Printf("Failed to upsert LDAP user: %v", err)
					respondError(w, http.StatusInternalServerError, "Internal server error")
					return
				}
				userID, err = database.GetUserIDByUsername(app, req.Username)
				if err != nil {
					log.Printf("Failed to retrieve LDAP user ID: %v", err)
					respondError(w, http.StatusInternalServerError, "Internal server error")
					return
				}
			}
		}

		if authUser == nil {
			respondError(w, http.StatusUnauthorized, "Invalid username or password")
			return
		}

		// Invalidate any existing sessions for this user to prevent session fixation
		database.InvalidateUserSessions(app, userID)

		// Create session
		token, err := auth.GenerateSessionToken()
		if err != nil {
			log.Printf("Error generating session token: %v", err)
			respondError(w, http.StatusInternalServerError, "Internal server error")
			return
		}

		app.SysConfigMu.RLock()
		sessionDuration := app.AuthConfig.SessionDuration
		cookieName := app.AuthConfig.CookieName
		cookieSecure := app.AuthConfig.CookieSecure
		app.SysConfigMu.RUnlock()

		expiresAt := time.Now().Add(time.Duration(sessionDuration) * 24 * time.Hour)
		if err := database.CreateSession(app, userID, token, expiresAt); err != nil {
			log.Printf("Error creating session: %v", err)
			respondError(w, http.StatusInternalServerError, "Internal server error")
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

		respondJSON(w, http.StatusOK, map[string]string{"status": "ok", "redirect": "/"})
	}
}

// LogoutHandler deletes the user's session and clears the cookie.
func LogoutHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
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
			database.DeleteSession(app, cookie.Value)
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

		respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// AuthMeHandler returns the currently authenticated user as JSON.
func AuthMeHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}

		user := auth.GetAuthenticatedUser(app, r)
		if user == nil {
			respondError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}

		respondJSON(w, http.StatusOK, user)
	}
}

// AuthConfigHandler returns which auth methods are enabled (public, no secrets).
func AuthConfigHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
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

		respondJSON(w, http.StatusOK, cfg)
	}
}

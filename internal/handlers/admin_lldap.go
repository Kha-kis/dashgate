package handlers

import (
	"log"
	"net/http"

	"dashgate/internal/auth"
	"dashgate/internal/database"
	"dashgate/internal/lldap"
	"dashgate/internal/server"
)

// AdminCheckHandler returns the admin status of the authenticated user
// and general system state information.
func AdminCheckHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())

		needsSetup := database.NeedsSetup(app)

		app.SysConfigMu.RLock()
		response := map[string]interface{}{
			"isAdmin":          user.IsAdmin,
			"lldapEnabled":     app.LLDAPConfig != nil,
			"authMode":         string(app.AuthConfig.Mode),
			"localAuthEnabled": app.DB != nil,
			"needsSetup":       needsSetup,
			"setupCompleted":   app.SystemConfig.SetupCompleted,
			"user":             user,
		}
		app.SysConfigMu.RUnlock()

		respondJSON(w, http.StatusOK, response)
	}
}

// AdminLLDAPUsersHandler returns a read-only list of users from the LLDAP directory.
func AdminLLDAPUsersHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if app.LLDAPConfig == nil {
			respondError(w, http.StatusServiceUnavailable, "LLDAP not configured")
			return
		}

		if r.Method != http.MethodGet {
			respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}

		users, err := lldap.ListUsers(app)
		if err != nil {
			log.Printf("LLDAP operation failed: %v", err)
			respondError(w, http.StatusInternalServerError, "Internal server error")
			return
		}
		respondJSON(w, http.StatusOK, users)
	}
}

// AdminLLDAPGroupsHandler returns a read-only list of groups from the LLDAP directory.
func AdminLLDAPGroupsHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if app.LLDAPConfig == nil {
			respondError(w, http.StatusServiceUnavailable, "LLDAP not configured")
			return
		}

		if r.Method != http.MethodGet {
			respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}

		groups, err := lldap.ListGroups(app)
		if err != nil {
			log.Printf("LLDAP operation failed: %v", err)
			respondError(w, http.StatusInternalServerError, "Internal server error")
			return
		}
		respondJSON(w, http.StatusOK, groups)
	}
}

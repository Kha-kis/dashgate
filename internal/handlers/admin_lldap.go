package handlers

import (
	"encoding/json"
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

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

// AdminLLDAPUsersHandler returns a read-only list of users from the LLDAP directory.
func AdminLLDAPUsersHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if app.LLDAPConfig == nil {
			http.Error(w, "LLDAP not configured", http.StatusServiceUnavailable)
			return
		}

		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		users, err := lldap.ListUsers(app)
		if err != nil {
			log.Printf("LLDAP operation failed: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(users)
	}
}

// AdminLLDAPGroupsHandler returns a read-only list of groups from the LLDAP directory.
func AdminLLDAPGroupsHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if app.LLDAPConfig == nil {
			http.Error(w, "LLDAP not configured", http.StatusServiceUnavailable)
			return
		}

		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		groups, err := lldap.ListGroups(app)
		if err != nil {
			log.Printf("LLDAP operation failed: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(groups)
	}
}

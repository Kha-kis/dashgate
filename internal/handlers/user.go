package handlers

import (
	"encoding/json"
	"log"
	"net/http"

	"dashgate/internal/auth"
	"dashgate/internal/database"
	"dashgate/internal/server"
)

// UserPreferencesHandler handles GET (load) and PUT (save) for user preferences.
func UserPreferencesHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetAuthenticatedUser(app, r)
		if user == nil {
			respondError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}

		// Get user ID from database
		var userID int
		userID, err := database.GetUserIDByUsername(app, user.Username)
		if err != nil {
			// User might be from LDAP/OIDC, create a preferences record with username as key
			userID = 0 // Will use username-based lookup
		}

		switch r.Method {
		case http.MethodGet:
			var preferences string
			if userID > 0 {
				preferences, err = database.GetPreferences(app, userID)
			} else {
				// For external users (LDAP/OIDC), use username column lookup
				preferences, err = database.GetPreferencesByUsername(app, user.Username)
			}

			if err != nil {
				// Return empty preferences
				preferences = "{}"
			}

			var prefObj interface{}
			json.Unmarshal([]byte(preferences), &prefObj)
			respondJSON(w, http.StatusOK, prefObj)

		case http.MethodPut:
			var prefs map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&prefs); err != nil {
				respondError(w, http.StatusBadRequest, "Invalid request body")
				return
			}

			prefsJSON, _ := json.Marshal(prefs)

			if userID > 0 {
				err = database.SavePreferencesByUserID(app, userID, string(prefsJSON))
			} else {
				err = database.SavePreferencesByUsername(app, user.Username, string(prefsJSON))
			}

			if err != nil {
				log.Printf("Error saving preferences: %v", err)
				respondError(w, http.StatusInternalServerError, "Failed to save preferences")
				return
			}

			respondJSON(w, http.StatusOK, map[string]string{"status": "saved"})

		default:
			respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	}
}

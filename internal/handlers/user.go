package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"

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
		if user.Source == "apikey" {
			respondError(w, http.StatusForbidden, "API keys cannot access user preferences")
			return
		}

		userID, err := database.GetUserIDByUsername(app, user.Username)
		if err != nil {
			log.Printf("Error looking up preference user: %v", err)
			respondError(w, http.StatusInternalServerError, "Failed to load user")
			return
		}

		switch r.Method {
		case http.MethodGet:
			preferences, err := database.GetPreferences(app, userID)

			if err != nil {
				// Return empty preferences
				preferences = "{}"
			}

			var prefObj interface{}
			json.Unmarshal([]byte(preferences), &prefObj)
			respondJSON(w, http.StatusOK, prefObj)

		case http.MethodPut:
			// Browser writes carry their original account identity so an old tab
			// cannot apply a queued edit after another tab changes the session.
			if expectedSource := r.Header.Get("X-DashGate-Expected-Source"); expectedSource != "" {
				source, err := url.QueryUnescape(expectedSource)
				if err != nil || source != user.Source {
					respondError(w, http.StatusConflict, "Signed-in account changed")
					return
				}
			}
			if expectedUsername := r.Header.Get("X-DashGate-Expected-Username"); expectedUsername != "" {
				username, err := url.QueryUnescape(expectedUsername)
				if err != nil || username != user.Username {
					respondError(w, http.StatusConflict, "Signed-in account changed")
					return
				}
			}
			var prefs map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&prefs); err != nil {
				respondError(w, http.StatusBadRequest, "Invalid request body")
				return
			}

			prefsJSON, _ := json.Marshal(prefs)

			err = database.SavePreferencesByUserID(app, userID, string(prefsJSON))

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

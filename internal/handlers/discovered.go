package handlers

import (
	"encoding/json"
	"net/http"

	"dashgate/internal/auth"
	"dashgate/internal/database"
	"dashgate/internal/discovery"
	"dashgate/internal/models"
	"dashgate/internal/server"
)

// DiscoveredAppsHandler returns the list of Docker-discovered apps.
func DiscoveredAppsHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetAuthenticatedUser(app, r)
		if user == nil {
			respondError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}

		if r.Method != http.MethodGet {
			respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}

		apps := app.DockerDiscovery.GetApps()
		respondJSON(w, http.StatusOK, apps)
	}
}

// BulkDiscoveredAppsRequest is the request body for bulk operations.
type BulkDiscoveredAppsRequest struct {
	URLs     []string `json:"urls"`
	Action   string   `json:"action"` // "show" - configure apps with category and groups
	Category string   `json:"category,omitempty"`
	Groups   []string `json:"groups,omitempty"`
}

// BulkDiscoveredAppsHandler handles bulk operations on discovered apps.
func BulkDiscoveredAppsHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}

		var req BulkDiscoveredAppsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, "Invalid JSON: "+err.Error())
			return
		}

		if len(req.URLs) == 0 {
			respondError(w, http.StatusBadRequest, "No URLs provided")
			return
		}

		// Limit batch size to prevent abuse
		const maxBulkURLs = 100
		if len(req.URLs) > maxBulkURLs {
			respondError(w, http.StatusBadRequest, "Too many URLs (max 100)")
			return
		}

		// Validate action
		if req.Action != "show" {
			respondError(w, http.StatusBadRequest, "Invalid action: "+req.Action)
			return
		}

		// Get all raw discovered apps to find sources
		rawApps := discovery.GetAllRawDiscoveredApps(app)
		urlToSource := make(map[string]string)
		for _, a := range rawApps {
			urlToSource[a.URL] = a.Source
		}

		// Build overrides based on action
		var overrides []*models.DiscoveredAppOverride
		for _, url := range req.URLs {
			existing := database.GetDiscoveredOverride(app, url)
			if existing == nil {
				existing = &models.DiscoveredAppOverride{
					URL:    url,
					Source: urlToSource[url],
					Groups: []string{},
				}
			}

			existing.Hidden = false
			if req.Category != "" {
				existing.Category = req.Category
			}
			if len(req.Groups) > 0 {
				existing.Groups = req.Groups
			}

			overrides = append(overrides, existing)
		}

		// Save all overrides in a batch
		if err := database.SaveDiscoveredOverridesBatch(app, overrides); err != nil {
			respondError(w, http.StatusInternalServerError, "Failed to save: "+err.Error())
			return
		}

		respondJSON(w, http.StatusOK, map[string]interface{}{
			"status":  "ok",
			"updated": len(overrides),
		})
	}
}

// AdminDiscoveredAppsHandler manages discovered app overrides (GET/PUT/DELETE).
func AdminDiscoveredAppsHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			// Return active discovered apps + stale overrides
			rawApps := discovery.GetAllRawDiscoveredApps(app)
			allOverrides := database.GetAllDiscoveredOverrides(app)

			// Track which override URLs are still actively discovered
			activeURLs := make(map[string]bool)
			for _, dApp := range rawApps {
				activeURLs[dApp.URL] = true
			}

			// Find stale overrides (configured but no longer discovered)
			var stale []models.DiscoveredAppOverride
			for url, override := range allOverrides {
				if !activeURLs[url] {
					stale = append(stale, *override)
				}
			}

			response := map[string]interface{}{
				"active": rawApps,
				"stale":  stale,
			}
			respondJSON(w, http.StatusOK, response)

		case http.MethodPut:
			var o models.DiscoveredAppOverride
			if err := json.NewDecoder(r.Body).Decode(&o); err != nil {
				respondError(w, http.StatusBadRequest, "Invalid JSON: "+err.Error())
				return
			}
			if o.URL == "" {
				respondError(w, http.StatusBadRequest, "URL is required")
				return
			}
			if o.Groups == nil {
				o.Groups = []string{}
			}
			if err := database.SaveDiscoveredOverride(app, &o); err != nil {
				respondError(w, http.StatusInternalServerError, "Failed to save: "+err.Error())
				return
			}
			respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})

		case http.MethodDelete:
			url := r.URL.Query().Get("url")
			if url == "" {
				respondError(w, http.StatusBadRequest, "URL parameter required")
				return
			}
			if err := database.DeleteDiscoveredOverride(app, url); err != nil {
				respondError(w, http.StatusInternalServerError, "Failed to delete: "+err.Error())
				return
			}
			respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})

		default:
			respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	}
}

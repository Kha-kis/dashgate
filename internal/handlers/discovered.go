package handlers

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

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
			ignored, err := database.ListIgnoredDiscoveredApps(app)
			if err != nil {
				respondError(w, http.StatusInternalServerError, "Failed to load ignored apps")
				return
			}

			response := map[string]interface{}{
				"active":  rawApps,
				"stale":   stale,
				"ignored": ignored,
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

// IgnoredDiscoveredAppsHandler dismisses discovered inbox entries or restores saved dismissals.
func IgnoredDiscoveredAppsHandler(app *server.App) http.HandlerFunc {
	type actionRequest struct {
		Action string                        `json:"action"`
		Items  []models.IgnoredDiscoveredApp `json:"items"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}
		var req actionRequest
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, "Invalid request")
			return
		}
		var extra interface{}
		if err := dec.Decode(&extra); err != io.EOF {
			respondError(w, http.StatusBadRequest, "Invalid request")
			return
		}
		if (req.Action != "dismiss" && req.Action != "restore") || len(req.Items) == 0 || len(req.Items) > 100 {
			respondError(w, http.StatusBadRequest, "Invalid action or item count (max 100)")
			return
		}
		for _, item := range req.Items {
			if strings.TrimSpace(item.Source) == "" || strings.TrimSpace(item.URL) == "" || len(item.Source) > 64 || len(item.URL) > 4096 {
				respondError(w, http.StatusBadRequest, "Source and URL are required")
				return
			}
		}
		var err error
		if req.Action == "dismiss" {
			// Resolve every pair against the current raw scan. Never trust a client name or
			// allow a configured visible app to be removed from the inbox.
			current := make(map[string]models.DiscoveredAppWithOverride)
			for _, found := range discovery.GetAllRawDiscoveredApps(app) {
				current[found.Source+"\x00"+found.URL] = found
			}
			validated := make([]models.IgnoredDiscoveredApp, 0, len(req.Items))
			for _, item := range req.Items {
				found, ok := current[item.Source+"\x00"+item.URL]
				if !ok || (found.Override != nil && !found.Override.Hidden) {
					respondError(w, http.StatusBadRequest, "Item is not an actionable discovered app")
					return
				}
				validated = append(validated, models.IgnoredDiscoveredApp{Source: found.Source, URL: found.URL, Name: found.Name})
			}
			err = database.DismissDiscoveredApps(app, validated)
		} else {
			err = database.RestoreIgnoredDiscoveredApps(app, req.Items)
		}
		if err != nil {
			respondError(w, http.StatusInternalServerError, "Failed to update ignored apps")
			return
		}
		respondJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "updated": len(req.Items)})
	}
}

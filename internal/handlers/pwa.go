package handlers

import (
	"encoding/json"
	"net/http"
	"path/filepath"

	"dashgate/internal/middleware"
	"dashgate/internal/server"
)

// ManifestHandler returns the PWA web app manifest as JSON.
func ManifestHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		app.ConfigMu.RLock()
		title := app.Config.Title
		app.ConfigMu.RUnlock()

		manifest := map[string]interface{}{
			"name":             title,
			"short_name":       "DashGate",
			"description":      "Self-hosted app gateway",
			"start_url":        "/",
			"scope":            "/",
			"display":          "standalone",
			"orientation":      "any",
			"background_color": "#000000",
			"theme_color":      "#000000",
			"icons": []map[string]interface{}{
				{
					"src":     "/static/branding/dashgate-192.png",
					"sizes":   "192x192",
					"type":    "image/png",
					"purpose": "any maskable",
				},
				{
					"src":     "/static/branding/dashgate-512.png",
					"sizes":   "512x512",
					"type":    "image/png",
					"purpose": "any maskable",
				},
			},
			"categories": []string{"utilities", "productivity"},
			"shortcuts": []map[string]interface{}{
				{
					"name":  "Search",
					"url":   "/?search=1",
					"icons": []map[string]interface{}{{"src": "/static/branding/dashgate-192.png", "sizes": "192x192"}},
				},
			},
		}

		w.Header().Set("Content-Type", "application/manifest+json")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		json.NewEncoder(w).Encode(manifest)
	}
}

// OfflineHandler serves the PWA offline fallback page.
func OfflineHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		data := map[string]interface{}{
			"CSPNonce": middleware.GetCSPNonce(r),
			"Version":  app.Version,
		}
		app.GetTemplates().ExecuteTemplate(w, "offline.html", data)
	}
}

// ServiceWorkerHandler serves the service worker JavaScript file.
func ServiceWorkerHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("Service-Worker-Allowed", "/")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		// Serve from the static directory adjacent to the templates directory
		swPath := filepath.Join(filepath.Dir(app.TemplateDir), "static", "sw.js")
		http.ServeFile(w, r, swPath)
	}
}

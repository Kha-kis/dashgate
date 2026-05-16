package handlers

import (
	"bytes"
	"log"
	"net/http"
	"strings"

	"dashgate/internal/auth"
	"dashgate/internal/config"
	"dashgate/internal/database"
	"dashgate/internal/discovery"
	"dashgate/internal/health"
	"dashgate/internal/models"
	"dashgate/internal/server"
)

// filterAppsByGroups returns only the categories (and apps within them) that the
// user is allowed to see based on their group membership. Admins see all apps.
// Apps with no groups assigned are only visible to admins.
func filterAppsByGroups(sApp *server.App, categories []models.Category, userGroups []string, isAdmin bool) []models.Category {
	groupSet := make(map[string]bool)
	for _, g := range userGroups {
		groupSet[strings.TrimSpace(g)] = true
	}

	var filtered []models.Category
	for _, cat := range categories {
		var filteredApps []models.App
		for _, a := range cat.Apps {
			// Admins see everything
			if isAdmin {
				a.Status = health.GetHealthStatus(sApp, a.URL)
				filteredApps = append(filteredApps, a)
				continue
			}
			appGroups := config.GetAppGroups(sApp, a)
			// No groups assigned = admin-only
			if len(appGroups) == 0 {
				continue
			}
			for _, requiredGroup := range appGroups {
				if groupSet[requiredGroup] {
					a.Status = health.GetHealthStatus(sApp, a.URL)
					filteredApps = append(filteredApps, a)
					break
				}
			}
		}
		if len(filteredApps) > 0 {
			filtered = append(filtered, models.Category{
				Name: cat.Name,
				Apps: filteredApps,
			})
		}
	}
	return filtered
}

// DashboardHandler serves the main DashGate page. It redirects to /setup if
// first-time setup is needed, and to /login if no user is authenticated.
func DashboardHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}

		// Check if first-time setup is needed
		if database.NeedsSetup(app) {
			http.Redirect(w, r, "/setup", http.StatusFound)
			return
		}

		user := auth.GetAuthenticatedUser(app, r)
		if user == nil {
			if app.AuthConfig.Mode == models.AuthModeLocal || app.AuthConfig.Mode == models.AuthModeHybrid {
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
			respondError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}

		app.ConfigMu.RLock()
		categories := make([]models.Category, len(app.Config.Categories))
		copy(categories, app.Config.Categories)
		app.ConfigMu.RUnlock()

		filteredCategories := filterAppsByGroups(app, categories, user.Groups, user.IsAdmin)

		// Build set of config app URLs to prevent duplicates with discovered apps
		configURLs := make(map[string]bool)
		for _, cat := range filteredCategories {
			for _, a := range cat.Apps {
				configURLs[a.URL] = true
			}
		}

		// Add discovered apps that have overrides (opt-in model)
		userGroupSet := make(map[string]bool)
		for _, g := range user.Groups {
			userGroupSet[strings.TrimSpace(g)] = true
		}

		rawDiscovered := discovery.GetAllRawDiscoveredApps(app)
		discoveredByCategory := make(map[string][]models.App)

		for _, dApp := range rawDiscovered {
			// Skip if already in config apps
			if configURLs[dApp.URL] {
				continue
			}
			// Skip if no override (not configured = not shown)
			if dApp.Override == nil {
				continue
			}
			// Skip if hidden
			if dApp.Override.Hidden {
				continue
			}
			// Check group access (admins see all; no groups = visible to all)
			if !user.IsAdmin && len(dApp.Override.Groups) > 0 {
				hasAccess := false
				for _, g := range dApp.Override.Groups {
					if userGroupSet[g] {
						hasAccess = true
						break
					}
				}
				if !hasAccess {
					continue
				}
			}

			// Apply overrides
			name := dApp.Name
			if dApp.Override.NameOverride != "" {
				name = dApp.Override.NameOverride
			}
			appURL := dApp.URL
			if dApp.Override.URLOverride != "" {
				appURL = dApp.Override.URLOverride
			}
			icon := dApp.Icon
			if dApp.Override.IconOverride != "" {
				icon = dApp.Override.IconOverride
			}
			desc := dApp.Description
			if dApp.Override.DescriptionOverride != "" {
				desc = dApp.Override.DescriptionOverride
			}

			category := dApp.Override.Category
			if category == "" {
				category = "Discovered"
			}

			a := models.App{
				Name:        name,
				URL:         appURL,
				Icon:        icon,
				Description: desc,
				Groups:      dApp.Override.Groups,
				Status:      health.GetHealthStatus(app, appURL),
			}
			discoveredByCategory[category] = append(discoveredByCategory[category], a)
		}

		// Merge discovered apps into existing categories or create new ones
		for catName, apps := range discoveredByCategory {
			merged := false
			for i, cat := range filteredCategories {
				if cat.Name == catName {
					filteredCategories[i].Apps = append(filteredCategories[i].Apps, apps...)
					merged = true
					break
				}
			}
			if !merged {
				filteredCategories = append(filteredCategories, models.Category{
					Name: catName,
					Apps: apps,
				})
			}
		}

		app.ConfigMu.RLock()
		title := app.Config.Title
		app.ConfigMu.RUnlock()

		data := models.TemplateData{
			Title:      title,
			User:       user.DisplayName,
			Categories: filteredCategories,
			Version:    app.Version,
		}

		// Render template to buffer first to avoid partial writes on error
		var buf bytes.Buffer
		if err := app.GetTemplates().ExecuteTemplate(&buf, "index.html", data); err != nil {
			log.Printf("Template error: %v", err)
			respondError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		buf.WriteTo(w)
	}
}

// HealthHandler returns a simple 200 OK response for liveness probes.
func HealthHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		respondJSON(w, http.StatusOK, map[string]string{
			"status":  "ok",
			"version": app.Version,
		})
	}
}

// APIHealthHandler returns JSON with the user's visible apps and their health statuses.
func APIHealthHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetAuthenticatedUser(app, r)
		if user == nil {
			respondError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}

		app.ConfigMu.RLock()
		categories := make([]models.Category, len(app.Config.Categories))
		copy(categories, app.Config.Categories)
		app.ConfigMu.RUnlock()

		filteredCategories := filterAppsByGroups(app, categories, user.Groups, user.IsAdmin)

		respondJSON(w, http.StatusOK, filteredCategories)
	}
}

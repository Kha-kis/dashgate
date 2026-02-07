package discovery

import (
	"dashgate/internal/models"
	"dashgate/internal/server"
)

// GetAllRawDiscoveredApps collects apps from all enabled discovery sources
// with source tags and any user-defined overrides attached.
func GetAllRawDiscoveredApps(app *server.App) []models.DiscoveredAppWithOverride {
	var result []models.DiscoveredAppWithOverride

	addApps := func(apps []models.App, source string) {
		for _, a := range apps {
			result = append(result, models.DiscoveredAppWithOverride{
				Name:        a.Name,
				URL:         a.URL,
				Icon:        a.Icon,
				Description: a.Description,
				Source:      source,
				Override:    getDiscoveredOverride(app, a.URL),
			})
		}
	}

	if app.DockerDiscovery.Enabled {
		addApps(app.DockerDiscovery.GetApps(), "docker")
	}
	if app.TraefikDiscovery.Enabled {
		addApps(app.TraefikDiscovery.GetApps(), "traefik")
	}
	if app.NginxDiscovery.Enabled {
		addApps(app.NginxDiscovery.GetApps(), "nginx")
	}
	if app.NPMDiscovery.Enabled {
		addApps(app.NPMDiscovery.GetApps(), "npm")
	}
	if app.CaddyDiscovery.Enabled {
		addApps(app.CaddyDiscovery.GetApps(), "caddy")
	}
	if app.UnraidDiscovery.Enabled {
		addApps(app.UnraidDiscovery.GetApps(), "unraid")
	}

	return result
}

// getDiscoveredOverride returns a copy of the override for the given URL, or nil.
func getDiscoveredOverride(app *server.App, url string) *models.DiscoveredAppOverride {
	app.DiscoveredOverridesMu.RLock()
	defer app.DiscoveredOverridesMu.RUnlock()
	if o, ok := app.DiscoveredOverrides[url]; ok {
		// Return a copy
		cp := *o
		cp.Groups = append([]string{}, o.Groups...)
		return &cp
	}
	return nil
}

package discovery

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"dashgate/internal/models"
	"dashgate/internal/server"
	"dashgate/internal/urlvalidation"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// InitTraefikDiscovery checks environment variables and system config,
// then starts the Traefik discovery loop if enabled.
func InitTraefikDiscovery(app *server.App) {
	envURL := os.Getenv("TRAEFIK_URL")
	if envURL != "" {
		app.SysConfigMu.Lock()
		app.SystemConfig.TraefikURL = envURL
		app.SysConfigMu.Unlock()
	}
	// Also check for auth env vars
	if envUser := os.Getenv("TRAEFIK_USERNAME"); envUser != "" {
		app.SysConfigMu.Lock()
		app.SystemConfig.TraefikUsername = envUser
		app.SysConfigMu.Unlock()
	}
	if envPass := os.Getenv("TRAEFIK_PASSWORD"); envPass != "" {
		app.SysConfigMu.Lock()
		app.SystemConfig.TraefikPassword = envPass
		app.SysConfigMu.Unlock()
	}

	if envURL != "" && os.Getenv("TRAEFIK_DISCOVERY") == "true" {
		app.TraefikDiscoveryEnvOverride = true
		StartTraefikDiscoveryLoop(app)
		app.SysConfigMu.RLock()
		log.Printf("Traefik discovery enabled (via environment variable, API: %s)", app.SystemConfig.TraefikURL)
		app.SysConfigMu.RUnlock()
	} else if app.SystemConfig.TraefikDiscoveryEnabled && app.SystemConfig.TraefikURL != "" {
		StartTraefikDiscoveryLoop(app)
		app.SysConfigMu.RLock()
		log.Printf("Traefik discovery enabled (via database config, API: %s)", app.SystemConfig.TraefikURL)
		app.SysConfigMu.RUnlock()
	}
}

// StartTraefikDiscoveryLoop starts the background goroutine that periodically
// discovers Traefik routers. It is safe to call if already running.
func StartTraefikDiscoveryLoop(app *server.App) {
	app.DiscoveryMu.Lock()
	defer app.DiscoveryMu.Unlock()

	if app.TraefikDiscovery.Stop != nil {
		return // Already running
	}

	app.TraefikDiscovery.Enabled = true
	app.TraefikDiscovery.Stop = make(chan struct{})

	app.TraefikDiscovery.Wg.Add(1)
	go func() {
		defer app.TraefikDiscovery.Wg.Done()
		defer func() {
			if r := recover(); r != nil {
				log.Printf("Traefik discovery goroutine panicked: %v", r)
			}
		}()
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		DiscoverTraefikApps(app) // Initial discovery
		for {
			select {
			case <-app.TraefikDiscovery.Stop:
				return
			case <-ticker.C:
				DiscoverTraefikApps(app)
			}
		}
	}()
}

// StopTraefikDiscoveryLoop stops the Traefik discovery background loop
// and clears all discovered apps.
func StopTraefikDiscoveryLoop(app *server.App) {
	app.DiscoveryMu.Lock()
	if app.TraefikDiscovery.Stop != nil {
		close(app.TraefikDiscovery.Stop)
		app.TraefikDiscovery.Stop = nil
	}
	app.DiscoveryMu.Unlock()

	app.TraefikDiscovery.Wg.Wait()

	app.DiscoveryMu.Lock()
	app.TraefikDiscovery.Enabled = false
	app.TraefikDiscovery.ClearApps()
	app.DiscoveryMu.Unlock()
}

// DiscoverTraefikApps queries the Traefik API for HTTP routers and updates
// the TraefikDiscovery manager with the results.
func DiscoverTraefikApps(app *server.App) {
	app.DiscoveryMu.RLock()
	enabled := app.TraefikDiscovery.Enabled
	app.DiscoveryMu.RUnlock()
	if !enabled {
		return
	}

	app.SysConfigMu.RLock()
	traefikURL := app.SystemConfig.TraefikURL
	traefikUsername := app.SystemConfig.TraefikUsername
	traefikPassword := app.SystemConfig.TraefikPassword
	app.SysConfigMu.RUnlock()

	if traefikURL == "" {
		return
	}

	if err := urlvalidation.ValidateDiscoveryURL(traefikURL); err != nil {
		log.Printf("Traefik discovery SSRF protection: %v", err)
		return
	}

	req, err := http.NewRequest("GET", traefikURL+"/api/http/routers", nil)
	if err != nil {
		log.Printf("Traefik discovery error creating request: %v", err)
		return
	}

	// Add basic auth if credentials are configured
	if traefikUsername != "" && traefikPassword != "" {
		req.SetBasicAuth(traefikUsername, traefikPassword)
	}

	resp, err := app.HTTPClient.Do(req)
	if err != nil {
		log.Printf("Traefik discovery error: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		log.Printf("Traefik discovery error: authentication required or invalid credentials")
		return
	}

	var routers []models.TraefikRouter
	if err := json.NewDecoder(io.LimitReader(resp.Body, 10*1024*1024)).Decode(&routers); err != nil { // 10MB limit
		log.Printf("Traefik router decode error: %v", err)
		return
	}

	var apps []models.App
	for _, r := range routers {
		// Skip internal traefik routers
		if strings.HasPrefix(r.Name, "api@") || strings.HasPrefix(r.Name, "dashboard@") {
			continue
		}

		// Extract host from rule (e.g., "Host(`example.com`)")
		host := ExtractHost(r.Rule)
		if host == "" {
			continue
		}

		// Determine protocol based on entry points
		protocol := "https"
		for _, ep := range r.EntryPoints {
			if ep == "web" || ep == "http" {
				protocol = "http"
				break
			}
		}

		name := r.Service
		if name == "" {
			name = strings.Split(r.Name, "@")[0]
		}
		// Clean up name
		name = strings.ReplaceAll(name, "-", " ")
		name = cases.Title(language.English).String(name)

		a := models.App{
			Name:        name,
			URL:         fmt.Sprintf("%s://%s", protocol, host),
			Description: fmt.Sprintf("Discovered via Traefik (%s)", r.Provider),
		}

		if r.Status == "enabled" {
			a.Status = "online"
		} else {
			a.Status = "offline"
		}

		apps = append(apps, a)
	}

	app.TraefikDiscovery.SetApps(apps)

	log.Printf("Traefik discovery found %d apps", len(apps))
}

// ExtractHost parses a Traefik Host rule and returns the first hostname.
// For example, "Host(`example.com`)" returns "example.com".
func ExtractHost(rule string) string {
	// Parse Host(`example.com`) or Host(`example.com`, `www.example.com`)
	if strings.Contains(rule, "Host(") {
		start := strings.Index(rule, "Host(`")
		if start == -1 {
			return ""
		}
		start += 6
		end := strings.Index(rule[start:], "`")
		if end == -1 {
			return ""
		}
		return rule[start : start+end]
	}
	return ""
}

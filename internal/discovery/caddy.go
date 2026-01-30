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

// InitCaddyDiscovery checks environment variables and system config,
// then starts the Caddy discovery loop if enabled.
func InitCaddyDiscovery(app *server.App) {
	if cu := os.Getenv("CADDY_ADMIN_URL"); cu != "" {
		app.SysConfigMu.Lock()
		app.SystemConfig.CaddyAdminURL = cu
		app.SysConfigMu.Unlock()
	}
	// Also check for auth env vars
	if envUser := os.Getenv("CADDY_USERNAME"); envUser != "" {
		app.SysConfigMu.Lock()
		app.SystemConfig.CaddyUsername = envUser
		app.SysConfigMu.Unlock()
	}
	if envPass := os.Getenv("CADDY_PASSWORD"); envPass != "" {
		app.SysConfigMu.Lock()
		app.SystemConfig.CaddyPassword = envPass
		app.SysConfigMu.Unlock()
	}

	if os.Getenv("CADDY_DISCOVERY") == "true" {
		app.CaddyDiscoveryEnvOverride = true
		StartCaddyDiscoveryLoop(app)
		app.SysConfigMu.RLock()
		log.Printf("Caddy discovery enabled (via environment variable, API: %s)", app.SystemConfig.CaddyAdminURL)
		app.SysConfigMu.RUnlock()
	} else if app.SystemConfig.CaddyDiscoveryEnabled && app.SystemConfig.CaddyAdminURL != "" {
		StartCaddyDiscoveryLoop(app)
		app.SysConfigMu.RLock()
		log.Printf("Caddy discovery enabled (via database config, API: %s)", app.SystemConfig.CaddyAdminURL)
		app.SysConfigMu.RUnlock()
	}
}

// StartCaddyDiscoveryLoop starts the background goroutine that periodically
// discovers Caddy reverse proxy routes. It is safe to call if already running.
func StartCaddyDiscoveryLoop(app *server.App) {
	app.DiscoveryMu.Lock()
	defer app.DiscoveryMu.Unlock()

	if app.CaddyDiscovery.Stop != nil {
		return // Already running
	}

	app.CaddyDiscovery.Enabled = true
	app.CaddyDiscovery.Stop = make(chan struct{})

	app.CaddyDiscovery.Wg.Add(1)
	go func() {
		defer app.CaddyDiscovery.Wg.Done()
		defer func() {
			if r := recover(); r != nil {
				log.Printf("Caddy discovery goroutine panicked: %v", r)
			}
		}()
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		DiscoverCaddyApps(app) // Initial discovery
		for {
			select {
			case <-app.CaddyDiscovery.Stop:
				return
			case <-ticker.C:
				DiscoverCaddyApps(app)
			}
		}
	}()
}

// StopCaddyDiscoveryLoop stops the Caddy discovery background loop
// and clears all discovered apps.
func StopCaddyDiscoveryLoop(app *server.App) {
	app.DiscoveryMu.Lock()
	if app.CaddyDiscovery.Stop != nil {
		close(app.CaddyDiscovery.Stop)
		app.CaddyDiscovery.Stop = nil
	}
	app.DiscoveryMu.Unlock()

	app.CaddyDiscovery.Wg.Wait()

	app.DiscoveryMu.Lock()
	app.CaddyDiscovery.Enabled = false
	app.CaddyDiscovery.ClearApps()
	app.DiscoveryMu.Unlock()
}

// DiscoverCaddyApps queries the Caddy admin API for server configurations
// and updates the CaddyDiscovery manager with discovered reverse proxy routes.
func DiscoverCaddyApps(app *server.App) {
	app.DiscoveryMu.RLock()
	enabled := app.CaddyDiscovery.Enabled
	app.DiscoveryMu.RUnlock()
	if !enabled {
		return
	}

	app.SysConfigMu.RLock()
	caddyAdminURL := app.SystemConfig.CaddyAdminURL
	caddyUsername := app.SystemConfig.CaddyUsername
	caddyPassword := app.SystemConfig.CaddyPassword
	app.SysConfigMu.RUnlock()

	if caddyAdminURL == "" {
		return
	}

	if err := urlvalidation.ValidateDiscoveryURL(caddyAdminURL); err != nil {
		log.Printf("Caddy discovery SSRF protection: %v", err)
		return
	}

	req, err := http.NewRequest("GET", caddyAdminURL+"/config/apps/http/servers/", nil)
	if err != nil {
		log.Printf("Caddy discovery error creating request: %v", err)
		return
	}

	// Add basic auth if credentials are configured
	if caddyUsername != "" && caddyPassword != "" {
		req.SetBasicAuth(caddyUsername, caddyPassword)
	}

	resp, err := app.HTTPClient.Do(req)
	if err != nil {
		log.Printf("Caddy discovery error: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		log.Printf("Caddy discovery error: authentication required or invalid credentials")
		return
	}

	if resp.StatusCode != http.StatusOK {
		log.Printf("Caddy discovery error: status %d", resp.StatusCode)
		return
	}

	// Parse the Caddy config response using flexible structure
	var servers map[string]json.RawMessage

	if err := json.NewDecoder(io.LimitReader(resp.Body, 10*1024*1024)).Decode(&servers); err != nil { // 10MB limit
		log.Printf("Caddy discovery decode error: %v", err)
		return
	}

	var apps []models.App
	seenHosts := make(map[string]bool)

	for _, serverRaw := range servers {
		var srv struct {
			Listen []string `json:"listen"`
			Routes []struct {
				Match  []map[string]interface{} `json:"match"`
				Handle []json.RawMessage        `json:"handle"`
			} `json:"routes"`
		}
		if err := json.Unmarshal(serverRaw, &srv); err != nil {
			continue
		}

		// Determine if HTTPS based on listen addresses
		isHTTPS := false
		for _, listen := range srv.Listen {
			if strings.Contains(listen, ":443") || strings.Contains(listen, "https") {
				isHTTPS = true
				break
			}
		}

		for _, route := range srv.Routes {
			// Extract hosts from match
			var hosts []string
			for _, match := range route.Match {
				if hostList, ok := match["host"].([]interface{}); ok {
					for _, h := range hostList {
						if host, ok := h.(string); ok {
							hosts = append(hosts, host)
						}
					}
				}
			}

			// Skip routes with no host match
			if len(hosts) == 0 {
				continue
			}

			// Extract upstream from handle (recursively check for reverse_proxy)
			upstream := FindReverseProxyUpstream(route.Handle)

			for _, host := range hosts {
				if host == "" || seenHosts[host] {
					continue
				}
				seenHosts[host] = true

				// Create app name from hostname
				name := host
				parts := strings.Split(host, ".")
				if len(parts) > 0 {
					name = cases.Title(language.English).String(strings.ReplaceAll(parts[0], "-", " "))
				}

				protocol := "http"
				if isHTTPS {
					protocol = "https"
				}

				description := "Discovered via Caddy"
				if upstream != "" {
					description = fmt.Sprintf("Discovered via Caddy (proxied to %s)", upstream)
				}

				a := models.App{
					Name:        name,
					URL:         fmt.Sprintf("%s://%s", protocol, host),
					Description: description,
					Status:      "online", // Caddy manages its own health
				}

				apps = append(apps, a)
			}
		}
	}

	app.CaddyDiscovery.SetApps(apps)

	log.Printf("Caddy discovery found %d apps", len(apps))
}

// FindReverseProxyUpstream recursively searches Caddy handler configuration
// for reverse_proxy handlers and returns the first upstream dial address found.
func FindReverseProxyUpstream(handles []json.RawMessage) string {
	for _, handleRaw := range handles {
		var handle map[string]interface{}
		if err := json.Unmarshal(handleRaw, &handle); err != nil {
			continue
		}

		handler, _ := handle["handler"].(string)

		// Direct reverse_proxy handler
		if handler == "reverse_proxy" {
			if upstreams, ok := handle["upstreams"].([]interface{}); ok && len(upstreams) > 0 {
				if upstream, ok := upstreams[0].(map[string]interface{}); ok {
					if dial, ok := upstream["dial"].(string); ok {
						return dial
					}
				}
			}
		}

		// Check nested routes inside subroute handler
		if handler == "subroute" {
			if routes, ok := handle["routes"].([]interface{}); ok {
				for _, r := range routes {
					if route, ok := r.(map[string]interface{}); ok {
						if nestedHandles, ok := route["handle"].([]interface{}); ok {
							var rawHandles []json.RawMessage
							for _, h := range nestedHandles {
								if b, err := json.Marshal(h); err == nil {
									rawHandles = append(rawHandles, b)
								}
							}
							if upstream := FindReverseProxyUpstream(rawHandles); upstream != "" {
								return upstream
							}
						}
					}
				}
			}
		}
	}
	return ""
}

package discovery

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"dashgate/internal/models"
	"dashgate/internal/server"
	"dashgate/internal/urlvalidation"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

const unraidGraphQLQuery = `{
  docker {
    containers {
      id
      names
      state
      labels
      image
      autoStart
    }
  }
}`

// InitUnraidDiscovery checks environment variables and system config,
// then starts the Unraid discovery loop if enabled.
func InitUnraidDiscovery(app *server.App) {
	envURL := os.Getenv("UNRAID_URL")
	envAPIKey := os.Getenv("UNRAID_API_KEY")

	if envURL != "" {
		app.SysConfigMu.Lock()
		app.SystemConfig.UnraidURL = envURL
		app.SysConfigMu.Unlock()
	}
	if envAPIKey != "" {
		app.SysConfigMu.Lock()
		app.SystemConfig.UnraidAPIKey = envAPIKey
		app.SysConfigMu.Unlock()
	}

	if envURL != "" && envAPIKey != "" && os.Getenv("UNRAID_DISCOVERY") == "true" {
		app.UnraidDiscoveryEnvOverride = true
		StartUnraidDiscoveryLoop(app)
		app.SysConfigMu.RLock()
		log.Printf("Unraid discovery enabled (via environment variable, API: %s)", app.SystemConfig.UnraidURL)
		app.SysConfigMu.RUnlock()
	} else if app.SystemConfig.UnraidDiscoveryEnabled && app.SystemConfig.UnraidURL != "" && app.SystemConfig.UnraidAPIKey != "" {
		StartUnraidDiscoveryLoop(app)
		app.SysConfigMu.RLock()
		log.Printf("Unraid discovery enabled (via database config, API: %s)", app.SystemConfig.UnraidURL)
		app.SysConfigMu.RUnlock()
	}
}

// StartUnraidDiscoveryLoop starts the background goroutine that periodically
// discovers Unraid containers. It is safe to call if already running.
func StartUnraidDiscoveryLoop(app *server.App) {
	app.DiscoveryMu.Lock()
	defer app.DiscoveryMu.Unlock()

	if app.UnraidDiscovery.Stop != nil {
		return // Already running
	}

	app.UnraidDiscovery.Enabled = true
	app.UnraidDiscovery.Stop = make(chan struct{})

	app.UnraidDiscovery.Wg.Add(1)
	go func() {
		defer app.UnraidDiscovery.Wg.Done()
		defer func() {
			if r := recover(); r != nil {
				log.Printf("Unraid discovery goroutine panicked: %v", r)
			}
		}()
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		DiscoverUnraidApps(app) // Initial discovery
		for {
			select {
			case <-app.UnraidDiscovery.Stop:
				return
			case <-ticker.C:
				DiscoverUnraidApps(app)
			}
		}
	}()
}

// StopUnraidDiscoveryLoop stops the Unraid discovery background loop
// and clears all discovered apps.
func StopUnraidDiscoveryLoop(app *server.App) {
	app.DiscoveryMu.Lock()
	if app.UnraidDiscovery.Stop != nil {
		close(app.UnraidDiscovery.Stop)
		app.UnraidDiscovery.Stop = nil
	}
	app.DiscoveryMu.Unlock()

	app.UnraidDiscovery.Wg.Wait()

	app.DiscoveryMu.Lock()
	app.UnraidDiscovery.Enabled = false
	app.UnraidDiscovery.ClearApps()
	app.DiscoveryMu.Unlock()
}

// DiscoverUnraidApps queries the Unraid GraphQL API and updates
// the UnraidDiscovery manager with the results.
func DiscoverUnraidApps(app *server.App) {
	app.DiscoveryMu.RLock()
	enabled := app.UnraidDiscovery.Enabled
	app.DiscoveryMu.RUnlock()
	if !enabled {
		return
	}

	app.SysConfigMu.RLock()
	unraidURL := app.SystemConfig.UnraidURL
	apiKey := app.SystemConfig.UnraidAPIKey
	app.SysConfigMu.RUnlock()

	if unraidURL == "" || apiKey == "" {
		return
	}

	apps, err := queryUnraidContainers(app.HTTPClient, unraidURL, apiKey)
	if err != nil {
		log.Printf("Unraid discovery error: %v", err)
		return
	}

	app.UnraidDiscovery.SetApps(apps)
	log.Printf("Unraid discovery found %d app(s)", len(apps))
}

// queryUnraidContainers queries the Unraid GraphQL API and returns discovered apps.
func queryUnraidContainers(client *http.Client, unraidURL, apiKey string) ([]models.App, error) {
	if err := urlvalidation.ValidateDiscoveryURL(unraidURL); err != nil {
		return nil, fmt.Errorf("Unraid SSRF protection: %w", err)
	}

	graphqlEndpoint := strings.TrimSuffix(unraidURL, "/") + "/graphql"

	payload := map[string]string{
		"query": unraidGraphQLQuery,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal query: %w", err)
	}

	req, err := http.NewRequest("POST", graphqlEndpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", apiKey)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("authentication failed (status %d)", resp.StatusCode)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var gqlResp models.UnraidGraphQLResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 10*1024*1024)).Decode(&gqlResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if len(gqlResp.Errors) > 0 {
		return nil, fmt.Errorf("GraphQL error: %s", gqlResp.Errors[0].Message)
	}

	var apps []models.App
	for _, container := range gqlResp.Data.Docker.Containers {
		// Extract WebUI URL from labels
		webUIRaw := container.Labels["net.unraid.docker.webui"]
		if webUIRaw == "" {
			continue
		}

		// Get container name (use first name, strip leading slash if present)
		name := "Unknown"
		if len(container.Names) > 0 {
			name = strings.TrimPrefix(container.Names[0], "/")
			r := strings.NewReplacer("-", " ", "_", " ")
			name = cases.Title(language.English).String(r.Replace(name))
		}

		// Map state to status
		status := "offline"
		if strings.ToUpper(container.State) == "RUNNING" {
			status = "online"
		}

		// Process the WebUI URL - it may contain [IP] placeholder
		webUIURL := processUnraidWebUIURL(webUIRaw, unraidURL)

		// Extract icon from labels
		icon := processUnraidIconURL(container.Labels["net.unraid.docker.icon"], unraidURL)

		a := models.App{
			Name:        name,
			URL:         webUIURL,
			Icon:        icon,
			Description: fmt.Sprintf("Discovered via Unraid (image: %s)", container.Image),
			Status:      status,
		}

		apps = append(apps, a)
	}

	return apps, nil
}

// processUnraidWebUIURL handles the WebUI URL from Unraid, replacing [IP] placeholder.
func processUnraidWebUIURL(webUIURL, unraidURL string) string {
	// Parse the Unraid server URL to get the host
	parsed, err := url.Parse(unraidURL)
	if err != nil {
		return webUIURL
	}

	// Replace [IP] with the Unraid server IP
	host := parsed.Hostname()
	result := strings.ReplaceAll(webUIURL, "[IP]", host)

	// Strip [PORT:xxx] placeholders (CA template syntax), leaving just the default port value
	for {
		start := strings.Index(result, "[PORT:")
		if start == -1 {
			break
		}
		end := strings.Index(result[start:], "]")
		if end == -1 {
			break
		}
		defaultPort := result[start+6 : start+end]
		result = result[:start] + defaultPort + result[start+end+1:]
	}

	return result
}

// processUnraidIconURL processes the icon URL from Unraid container labels.
// Relative paths (common in CA templates) are resolved against the Unraid server URL.
func processUnraidIconURL(iconURL, unraidURL string) string {
	if iconURL == "" {
		return ""
	}
	if strings.HasPrefix(iconURL, "http://") || strings.HasPrefix(iconURL, "https://") {
		return iconURL
	}
	// Resolve relative paths against the Unraid server (e.g., /state/plugins/... icons)
	if strings.HasPrefix(iconURL, "/") {
		return strings.TrimSuffix(unraidURL, "/") + iconURL
	}
	return ""
}

// TestUnraidConnection tests the connection to an Unraid server.
func TestUnraidConnection(client *http.Client, unraidURL, apiKey string) (int, error) {
	apps, err := queryUnraidContainers(client, unraidURL, apiKey)
	if err != nil {
		return 0, err
	}
	return len(apps), nil
}

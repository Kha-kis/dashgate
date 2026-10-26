package discovery

import (
	"bytes"
	"encoding/json"
	"errors"
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

var (
	errUnraidInvalid     = errors.New("invalid configuration")
	errUnraidUnreachable = errors.New("unreachable")
	errUnraidAuth        = errors.New("upstream authentication")
	errUnraidBadResponse = errors.New("bad response")
	errUnraidDecode      = errors.New("decode failed")
)

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
	} else {
		app.SysConfigMu.RLock()
		dbEnabled := app.SystemConfig.UnraidDiscoveryEnabled
		dbURL := app.SystemConfig.UnraidURL
		dbAPIKey := app.SystemConfig.UnraidAPIKey
		app.SysConfigMu.RUnlock()
		if dbEnabled && dbURL != "" && dbAPIKey != "" {
			StartUnraidDiscoveryLoop(app)
			log.Printf("Unraid discovery enabled (via database config, API: %s)", dbURL)
		}
	}
}

// StartUnraidDiscoveryLoop starts the background goroutine that periodically
// discovers Unraid containers. It is safe to call if already running.
func StartUnraidDiscoveryLoop(app *server.App) {
	app.DiscoveryMu.Lock()
	defer app.DiscoveryMu.Unlock()

	if app.UnraidDiscovery.Stop != nil || app.UnraidDiscovery.StopClosing {
		return // Already running
	}

	app.UnraidDiscovery.Enabled = true
	app.UnraidDiscovery.EnableScan()
	app.UnraidDiscovery.Stop = make(chan struct{})
	stop := app.UnraidDiscovery.Stop

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
			case <-stop:
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
	if app.UnraidDiscovery.Stop != nil && !app.UnraidDiscovery.StopClosing {
		app.UnraidDiscovery.StopClosing = true
		app.UnraidDiscovery.DisableScan()
		close(app.UnraidDiscovery.Stop)
	}
	app.DiscoveryMu.Unlock()

	app.UnraidDiscovery.Wg.Wait()

	app.DiscoveryMu.Lock()
	if app.UnraidDiscovery.StopClosing {
		app.UnraidDiscovery.Stop = nil
		app.UnraidDiscovery.Enabled = false
		app.UnraidDiscovery.DisableScan()
		app.UnraidDiscovery.StopClosing = false
	}
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
	app.UnraidDiscovery.RunScan(func() (server.DiscoveryScanResult, string) { return scanUnraidApps(app) })
}

func scanUnraidApps(app *server.App) (server.DiscoveryScanResult, string) {

	app.SysConfigMu.RLock()
	unraidURL := app.SystemConfig.UnraidURL
	apiKey := app.SystemConfig.UnraidAPIKey
	app.SysConfigMu.RUnlock()

	if unraidURL == "" || apiKey == "" {
		return server.DiscoveryScanResult{}, "missing_config"
	}

	apps, err := queryUnraidContainers(app.HTTPClient, unraidURL, apiKey)
	if err != nil {
		log.Printf("Unraid discovery error: %v", err)
		switch {
		case errors.Is(err, errUnraidInvalid):
			return server.DiscoveryScanResult{}, "invalid_config"
		case errors.Is(err, errUnraidAuth):
			return server.DiscoveryScanResult{}, "upstream_auth"
		case errors.Is(err, errUnraidDecode):
			return server.DiscoveryScanResult{}, "decode_failed"
		case errors.Is(err, errUnraidBadResponse):
			return server.DiscoveryScanResult{}, "bad_response"
		default:
			return server.DiscoveryScanResult{}, "unreachable"
		}
	}

	log.Printf("Unraid discovery found %d app(s)", len(apps))
	return server.DiscoveryScanResult{Apps: apps}, ""
}

// queryUnraidContainers queries the Unraid GraphQL API and returns discovered apps.
func queryUnraidContainers(client *http.Client, unraidURL, apiKey string) ([]models.App, error) {
	if err := urlvalidation.ValidateDiscoveryURL(unraidURL); err != nil {
		return nil, fmt.Errorf("%w: Unraid SSRF protection: %v", errUnraidInvalid, err)
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
		return nil, fmt.Errorf("%w: failed to create request: %v", errUnraidInvalid, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", apiKey)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: request failed: %v", errUnraidUnreachable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("%w: authentication failed (status %d)", errUnraidAuth, resp.StatusCode)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: API returned status %d", errUnraidBadResponse, resp.StatusCode)
	}

	var gqlResp models.UnraidGraphQLResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 10*1024*1024)).Decode(&gqlResp); err != nil {
		return nil, fmt.Errorf("%w: failed to decode response: %v", errUnraidDecode, err)
	}

	if len(gqlResp.Errors) > 0 {
		return nil, fmt.Errorf("%w: GraphQL error: %s", errUnraidBadResponse, gqlResp.Errors[0].Message)
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

	// Validate the constructed URL is well-formed
	if _, err := url.Parse(result); err != nil {
		// If the URL is malformed, return the original raw value as a fallback
		return webUIURL
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

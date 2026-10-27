package discovery

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"dashgate/internal/models"
	"dashgate/internal/server"
	"dashgate/internal/urlvalidation"
)

// InitDockerDiscovery checks environment variables and system config,
// then starts the Docker discovery loop if enabled.
func InitDockerDiscovery(app *server.App) {
	// Check for env var override first
	if sp := os.Getenv("DOCKER_SOCKET"); sp != "" {
		app.SysConfigMu.Lock()
		app.SystemConfig.DockerSocketPath = sp
		app.SysConfigMu.Unlock()
	}

	if os.Getenv("DOCKER_DISCOVERY") == "true" {
		app.DockerDiscoveryEnvOverride = true
		StartDockerDiscoveryLoop(app)
		log.Println("Docker discovery enabled (via environment variable)")
	} else if app.SystemConfig.DockerDiscoveryEnabled {
		// Load from database config if no env var
		StartDockerDiscoveryLoop(app)
		log.Println("Docker discovery enabled (via database config)")
	}
}

// StartDockerDiscoveryLoop starts the background goroutine that periodically
// discovers Docker containers. It is safe to call if already running.
func StartDockerDiscoveryLoop(app *server.App) {
	app.DiscoveryMu.Lock()
	defer app.DiscoveryMu.Unlock()

	if app.DockerDiscovery.Stop != nil || app.DockerDiscovery.StopClosing {
		return // Already running
	}

	app.DockerDiscovery.Enabled = true
	app.DockerDiscovery.EnableScan()
	app.DockerDiscovery.Stop = make(chan struct{})
	stop := app.DockerDiscovery.Stop

	app.DockerDiscovery.Wg.Add(1)
	go func() {
		defer app.DockerDiscovery.Wg.Done()
		defer func() {
			if r := recover(); r != nil {
				log.Printf("Docker discovery goroutine panicked: %v", r)
			}
		}()
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		DiscoverDockerApps(app) // Initial discovery
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				DiscoverDockerApps(app)
			}
		}
	}()
}

// StopDockerDiscoveryLoop stops the Docker discovery background loop
// and clears all discovered apps.
func StopDockerDiscoveryLoop(app *server.App) {
	app.DiscoveryMu.Lock()
	if app.DockerDiscovery.Stop != nil && !app.DockerDiscovery.StopClosing {
		app.DockerDiscovery.StopClosing = true
		app.DockerDiscovery.DisableScan()
		close(app.DockerDiscovery.Stop)
	}
	app.DiscoveryMu.Unlock()

	app.DockerDiscovery.Wg.Wait()

	app.DiscoveryMu.Lock()
	if app.DockerDiscovery.StopClosing {
		app.DockerDiscovery.Stop = nil
		app.DockerDiscovery.Enabled = false
		app.DockerDiscovery.DisableScan()
		app.DockerDiscovery.StopClosing = false
	}
	app.DiscoveryMu.Unlock()
}

// DiscoverDockerApps queries the Docker API for containers with dashgate labels
// and updates the DockerDiscovery manager with the results.
func DiscoverDockerApps(app *server.App) {
	app.DiscoveryMu.RLock()
	enabled := app.DockerDiscovery.Enabled
	app.DiscoveryMu.RUnlock()
	if !enabled {
		return
	}
	app.DockerDiscovery.RunScan(func() (server.DiscoveryScanResult, string) {
		return scanDockerApps(app)
	})
}

func scanDockerApps(app *server.App) (server.DiscoveryScanResult, string) {

	app.SysConfigMu.RLock()
	socketPath := app.SystemConfig.DockerSocketPath
	app.SysConfigMu.RUnlock()

	if socketPath == "" {
		socketPath = "/var/run/docker.sock"
	}

	var client *http.Client
	var apiURL string

	// Check if socket path is a TCP/HTTP URL (for Windows Docker Desktop TCP mode or remote Docker)
	if strings.HasPrefix(socketPath, "tcp://") || strings.HasPrefix(socketPath, "http://") {
		// Use TCP connection
		apiURL = strings.TrimPrefix(socketPath, "tcp://")
		if !strings.HasPrefix(apiURL, "http://") {
			apiURL = "http://" + apiURL
		}
		if err := urlvalidation.ValidateDiscoveryURL(apiURL); err != nil {
			log.Printf("Docker discovery SSRF protection: %v", err)
			return server.DiscoveryScanResult{}, "invalid_config"
		}
		client = &http.Client{Timeout: 10 * time.Second}
	} else if strings.HasPrefix(socketPath, "npipe://") {
		// Windows named pipe - not supported in this build
		log.Printf("Docker discovery: Windows named pipes (npipe://) are not supported. Please use tcp://localhost:2375 instead (enable in Docker Desktop settings).")
		return server.DiscoveryScanResult{}, "invalid_config"
	} else {
		// Use Unix socket (Linux/macOS)
		if _, err := os.Stat(socketPath); err != nil {
			log.Printf("Docker socket unavailable at %s: %v", socketPath, err)
			return server.DiscoveryScanResult{}, "missing_config"
		}
		client = &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return net.Dial("unix", socketPath)
				},
			},
			Timeout: 10 * time.Second,
		}
		apiURL = "http://localhost"
	}

	resp, err := client.Get(apiURL + "/containers/json?all=true")
	if err != nil {
		log.Printf("Docker discovery error: %v", err)
		return server.DiscoveryScanResult{}, "unreachable"
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Docker discovery error: API returned status %d", resp.StatusCode)
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return server.DiscoveryScanResult{}, "upstream_auth"
		}
		return server.DiscoveryScanResult{}, "bad_response"
	}

	var containers []models.DockerContainer
	if err := json.NewDecoder(io.LimitReader(resp.Body, 10*1024*1024)).Decode(&containers); err != nil { // 10MB limit
		log.Printf("Docker container decode error: %v", err)
		return server.DiscoveryScanResult{}, "decode_failed"
	}

	var apps []models.App
	for _, c := range containers {
		if a := dockerContainerApp(c); a != nil {
			apps = append(apps, *a)
		}
	}

	if len(apps) == 0 && len(containers) > 0 {
		log.Printf("Docker discovery: found %d containers, 0 with eligible discovery labels", len(containers))
	} else {
		log.Printf("Docker discovery: found %d apps (from %d containers)", len(apps), len(containers))
	}
	return server.DiscoveryScanResult{Apps: apps}, ""
}

// dockerContainerApp maps one explicitly labeled Docker container to a route.
// DashGate labels have priority, including an explicit disabled value.
func dockerContainerApp(c models.DockerContainer) *models.App {
	if enabled, present := c.Labels["dashgate.enable"]; present {
		if enabled != "true" {
			return nil
		}
		name := c.Labels["dashgate.name"]
		if name == "" {
			if len(c.Names) == 0 {
				return nil
			}
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		appURL := c.Labels["dashgate.url"]
		if appURL == "" {
			return nil
		}
		a := &models.App{Name: name, URL: appURL, Icon: c.Labels["dashgate.icon"], Description: c.Labels["dashgate.description"]}
		if groups := c.Labels["dashgate.groups"]; groups != "" {
			a.Groups = strings.Split(groups, ",")
			for i := range a.Groups {
				a.Groups[i] = strings.TrimSpace(a.Groups[i])
			}
		}
		if deps := c.Labels["dashgate.depends_on"]; deps != "" {
			a.DependsOn = strings.Split(deps, ",")
			for i := range a.DependsOn {
				a.DependsOn[i] = strings.TrimSpace(a.DependsOn[i])
			}
		}
		setDockerStatus(a, c.State)
		return a
	}

	if _, present := c.Labels["homarr.name"]; present {
		if _, hidden := c.Labels["homarr.hide"]; hidden {
			return nil
		}
		return dockerLabelApp(c.Labels["homarr.name"], c.Labels["homarr.href"], c.Labels["homarr.description"], c.State)
	}
	return dockerLabelApp(c.Labels["homepage.name"], c.Labels["homepage.href"], c.Labels["homepage.description"], c.State)
}

func dockerLabelApp(rawName, rawURL, description, state string) *models.App {
	name := strings.TrimSpace(rawName)
	appURL := strings.TrimSpace(rawURL)
	if name == "" || appURL == "" {
		return nil
	}
	parsed, err := url.Parse(appURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" || parsed.User != nil {
		return nil
	}
	// Third-party labels supply display metadata only, never DashGate access
	// groups, health URLs, widgets, or icon assets.
	a := &models.App{Name: name, URL: appURL, Description: description}
	setDockerStatus(a, state)
	return a
}

func setDockerStatus(a *models.App, state string) {
	if state == "running" {
		a.Status = "online"
	} else {
		a.Status = "offline"
	}
}

package discovery

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
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

	if app.DockerDiscovery.Stop != nil {
		return // Already running
	}

	app.DockerDiscovery.Enabled = true
	app.DockerDiscovery.Stop = make(chan struct{})

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
			case <-app.DockerDiscovery.Stop:
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
	if app.DockerDiscovery.Stop != nil {
		close(app.DockerDiscovery.Stop)
		app.DockerDiscovery.Stop = nil
	}
	app.DiscoveryMu.Unlock()

	app.DockerDiscovery.Wg.Wait()

	app.DiscoveryMu.Lock()
	app.DockerDiscovery.Enabled = false
	app.DockerDiscovery.ClearApps()
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
			return
		}
		client = &http.Client{Timeout: 10 * time.Second}
	} else if strings.HasPrefix(socketPath, "npipe://") {
		// Windows named pipe - not supported in this build
		log.Printf("Docker discovery: Windows named pipes (npipe://) are not supported. Please use tcp://localhost:2375 instead (enable in Docker Desktop settings).")
		return
	} else {
		// Use Unix socket (Linux/macOS)
		if _, err := os.Stat(socketPath); os.IsNotExist(err) {
			log.Printf("Docker socket not found at %s", socketPath)
			return
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
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Docker discovery error: API returned status %d", resp.StatusCode)
		return
	}

	var containers []models.DockerContainer
	if err := json.NewDecoder(io.LimitReader(resp.Body, 10*1024*1024)).Decode(&containers); err != nil { // 10MB limit
		log.Printf("Docker container decode error: %v", err)
		return
	}

	var apps []models.App
	for _, c := range containers {
		// Check if container has dashgate labels
		if c.Labels["dashgate.enable"] != "true" {
			continue
		}

		name := c.Labels["dashgate.name"]
		if name == "" {
			// Use container name if no label
			if len(c.Names) > 0 {
				name = strings.TrimPrefix(c.Names[0], "/")
			} else {
				continue
			}
		}

		url := c.Labels["dashgate.url"]
		if url == "" {
			continue
		}

		a := models.App{
			Name:        name,
			URL:         url,
			Icon:        c.Labels["dashgate.icon"],
			Description: c.Labels["dashgate.description"],
		}

		// Parse groups
		if groups := c.Labels["dashgate.groups"]; groups != "" {
			a.Groups = strings.Split(groups, ",")
			for i := range a.Groups {
				a.Groups[i] = strings.TrimSpace(a.Groups[i])
			}
		}

		// Parse dependencies
		if deps := c.Labels["dashgate.depends_on"]; deps != "" {
			a.DependsOn = strings.Split(deps, ",")
			for i := range a.DependsOn {
				a.DependsOn[i] = strings.TrimSpace(a.DependsOn[i])
			}
		}

		// Set status based on container state
		if c.State == "running" {
			a.Status = "online"
		} else {
			a.Status = "offline"
		}

		apps = append(apps, a)
	}

	app.DockerDiscovery.SetApps(apps)

	log.Printf("Docker discovery found %d apps", len(apps))
}

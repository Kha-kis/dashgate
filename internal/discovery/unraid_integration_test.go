//go:build integration

package discovery

import (
	"net/http"
	"os"
	"testing"
	"time"
)

func TestUnraidIntegration(t *testing.T) {
	unraidURL := os.Getenv("UNRAID_URL")
	apiKey := os.Getenv("UNRAID_API_KEY")

	if unraidURL == "" || apiKey == "" {
		t.Skip("UNRAID_URL and UNRAID_API_KEY required for integration test")
	}

	client := &http.Client{Timeout: 10 * time.Second}

	apps, err := queryUnraidContainers(client, unraidURL, apiKey)
	if err != nil {
		t.Fatalf("queryUnraidContainers failed: %v", err)
	}

	t.Logf("Found %d apps with WebUI URLs", len(apps))
	for _, app := range apps {
		t.Logf("  %-20s %-10s %s (icon: %s)", app.Name, app.Status, app.URL, app.Icon)
	}

	if len(apps) == 0 {
		t.Log("WARNING: No apps found. Are there Docker containers with net.unraid.docker.webui labels?")
	}

	// Verify app properties
	for _, app := range apps {
		if app.Name == "" || app.Name == "Unknown" {
			t.Errorf("app has empty/unknown name")
		}
		if app.URL == "" {
			t.Errorf("app %s has empty URL", app.Name)
		}
		if app.Status != "online" && app.Status != "offline" {
			t.Errorf("app %s has invalid status: %s", app.Name, app.Status)
		}
	}
}

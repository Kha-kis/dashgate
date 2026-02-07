package discovery

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"dashgate/internal/models"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// queryUnraidContainersNoSSRF is a test helper that bypasses SSRF validation.
func queryUnraidContainersNoSSRF(client *http.Client, graphqlEndpoint, apiKey string) ([]models.App, error) {
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
		webUIRaw := container.Labels["net.unraid.docker.webui"]
		if webUIRaw == "" {
			continue
		}

		name := "Unknown"
		if len(container.Names) > 0 {
			name = strings.TrimPrefix(container.Names[0], "/")
			r := strings.NewReplacer("-", " ", "_", " ")
		name = cases.Title(language.English).String(r.Replace(name))
		}

		status := "offline"
		if strings.ToUpper(container.State) == "RUNNING" {
			status = "online"
		}

		icon := processUnraidIconURL(container.Labels["net.unraid.docker.icon"], "")

		apps = append(apps, models.App{
			Name:   name,
			URL:    webUIRaw,
			Icon:   icon,
			Status: status,
		})
	}

	return apps, nil
}

func makeContainer(id string, names []string, state string, labels map[string]string, image string) models.UnraidContainer {
	return models.UnraidContainer{
		ID:     id,
		Names:  names,
		State:  state,
		Labels: labels,
		Image:  image,
	}
}

func TestQueryUnraidContainers(t *testing.T) {
	tests := []struct {
		name           string
		apiKey         string
		responseStatus int
		responseBody   interface{}
		wantApps       int
		wantErr        bool
	}{
		{
			name:           "successful response with containers",
			apiKey:         "test-api-key",
			responseStatus: http.StatusOK,
			responseBody: models.UnraidGraphQLResponse{
				Data: struct {
					Docker struct {
						Containers []models.UnraidContainer `json:"containers"`
					} `json:"docker"`
				}{
					Docker: struct {
						Containers []models.UnraidContainer `json:"containers"`
					}{
						Containers: []models.UnraidContainer{
							makeContainer("abc123", []string{"/plex"}, "RUNNING",
								map[string]string{
									"net.unraid.docker.webui": "http://[IP]:32400/web",
									"net.unraid.docker.icon":  "https://example.com/plex.png",
								}, "plexinc/pms-docker:latest"),
							makeContainer("def456", []string{"/sonarr"}, "RUNNING",
								map[string]string{
									"net.unraid.docker.webui": "http://[IP]:8989",
								}, "linuxserver/sonarr:latest"),
							makeContainer("ghi789", []string{"/redis"}, "RUNNING",
								map[string]string{}, "redis:alpine"), // No WebUI label
						},
					},
				},
			},
			wantApps: 2,
			wantErr:  false,
		},
		{
			name:           "empty containers list",
			apiKey:         "test-api-key",
			responseStatus: http.StatusOK,
			responseBody: models.UnraidGraphQLResponse{
				Data: struct {
					Docker struct {
						Containers []models.UnraidContainer `json:"containers"`
					} `json:"docker"`
				}{
					Docker: struct {
						Containers []models.UnraidContainer `json:"containers"`
					}{
						Containers: []models.UnraidContainer{},
					},
				},
			},
			wantApps: 0,
			wantErr:  false,
		},
		{
			name:           "invalid API key",
			apiKey:         "wrong-key",
			responseStatus: http.StatusUnauthorized,
			responseBody:   nil,
			wantApps:       0,
			wantErr:        true,
		},
		{
			name:           "GraphQL error response",
			apiKey:         "test-api-key",
			responseStatus: http.StatusOK,
			responseBody: map[string]interface{}{
				"errors": []map[string]string{
					{"message": "Not authorized"},
				},
			},
			wantApps: 0,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("expected POST method, got %s", r.Method)
				}
				if r.URL.Path != "/graphql" {
					t.Errorf("expected /graphql path, got %s", r.URL.Path)
				}
				if apiKey := r.Header.Get("x-api-key"); apiKey != "test-api-key" {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				if ct := r.Header.Get("Content-Type"); ct != "application/json" {
					t.Errorf("expected Content-Type application/json, got %s", ct)
				}

				w.WriteHeader(tt.responseStatus)
				if tt.responseBody != nil {
					json.NewEncoder(w).Encode(tt.responseBody)
				}
			}))
			defer server.Close()

			client := &http.Client{}
			apps, err := queryUnraidContainersNoSSRF(client, server.URL+"/graphql", tt.apiKey)

			if (err != nil) != tt.wantErr {
				t.Errorf("queryUnraidContainers() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if len(apps) != tt.wantApps {
				t.Errorf("queryUnraidContainers() got %d apps, want %d", len(apps), tt.wantApps)
			}
		})
	}
}

func TestProcessUnraidWebUIURL(t *testing.T) {
	tests := []struct {
		name      string
		webUIURL  string
		unraidURL string
		want      string
	}{
		{
			name:      "replace [IP] placeholder",
			webUIURL:  "http://[IP]:32400/web",
			unraidURL: "http://192.168.1.100",
			want:      "http://192.168.1.100:32400/web",
		},
		{
			name:      "no placeholder",
			webUIURL:  "http://192.168.1.100:8989",
			unraidURL: "http://192.168.1.100",
			want:      "http://192.168.1.100:8989",
		},
		{
			name:      "hostname URL",
			webUIURL:  "http://[IP]:9000",
			unraidURL: "http://tower.local",
			want:      "http://tower.local:9000",
		},
		{
			name:      "URL with port",
			webUIURL:  "http://[IP]:8080",
			unraidURL: "http://192.168.1.100:8443",
			want:      "http://192.168.1.100:8080",
		},
		{
			name:      "PORT placeholder with default",
			webUIURL:  "http://[IP]:[PORT:8080]/",
			unraidURL: "http://192.168.1.100",
			want:      "http://192.168.1.100:8080/",
		},
		{
			name:      "PORT placeholder in complex URL",
			webUIURL:  "https://[IP]:[PORT:32400]/web/index.html",
			unraidURL: "http://tower.local",
			want:      "https://tower.local:32400/web/index.html",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := processUnraidWebUIURL(tt.webUIURL, tt.unraidURL)
			if got != tt.want {
				t.Errorf("processUnraidWebUIURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProcessUnraidIconURL(t *testing.T) {
	tests := []struct {
		name      string
		url       string
		unraidURL string
		want      string
	}{
		{"https URL", "https://example.com/icon.png", "http://tower.local", "https://example.com/icon.png"},
		{"http URL", "http://example.com/icon.png", "http://tower.local", "http://example.com/icon.png"},
		{"empty", "", "http://tower.local", ""},
		{"relative path resolved", "/state/plugins/dynamix.docker.manager/images/plex.png", "http://192.168.1.100", "http://192.168.1.100/state/plugins/dynamix.docker.manager/images/plex.png"},
		{"relative path with trailing slash", "/icons/app.png", "http://tower.local/", "http://tower.local/icons/app.png"},
		{"non-relative non-http", "data:image/png;base64,abc", "http://tower.local", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := processUnraidIconURL(tt.url, tt.unraidURL)
			if got != tt.want {
				t.Errorf("processUnraidIconURL(%q, %q) = %q, want %q", tt.url, tt.unraidURL, got, tt.want)
			}
		})
	}
}

func TestContainerStateMapping(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-api-key") != "test-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		resp := models.UnraidGraphQLResponse{
			Data: struct {
				Docker struct {
					Containers []models.UnraidContainer `json:"containers"`
				} `json:"docker"`
			}{
				Docker: struct {
					Containers []models.UnraidContainer `json:"containers"`
				}{
					Containers: []models.UnraidContainer{
						makeContainer("1", []string{"/running-app"}, "RUNNING",
							map[string]string{"net.unraid.docker.webui": "http://localhost:8080"}, "img:latest"),
						makeContainer("2", []string{"/paused-app"}, "PAUSED",
							map[string]string{"net.unraid.docker.webui": "http://localhost:8081"}, "img:latest"),
						makeContainer("3", []string{"/exited-app"}, "EXITED",
							map[string]string{"net.unraid.docker.webui": "http://localhost:8082"}, "img:latest"),
					},
				},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := &http.Client{}
	apps, err := queryUnraidContainersNoSSRF(client, server.URL+"/graphql", "test-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(apps) != 3 {
		t.Fatalf("expected 3 apps, got %d", len(apps))
	}

	expectedStatuses := map[string]string{
		"Running App": "online",
		"Paused App":  "offline",
		"Exited App":  "offline",
	}

	for _, app := range apps {
		expected, ok := expectedStatuses[app.Name]
		if !ok {
			t.Errorf("unexpected app name: %q", app.Name)
			continue
		}
		if app.Status != expected {
			t.Errorf("app %s: got status %s, want %s", app.Name, app.Status, expected)
		}
	}
}

func TestTestUnraidConnectionHelper(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-api-key") != "valid-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		resp := models.UnraidGraphQLResponse{
			Data: struct {
				Docker struct {
					Containers []models.UnraidContainer `json:"containers"`
				} `json:"docker"`
			}{
				Docker: struct {
					Containers []models.UnraidContainer `json:"containers"`
				}{
					Containers: []models.UnraidContainer{
						makeContainer("1", []string{"/app1"}, "RUNNING",
							map[string]string{"net.unraid.docker.webui": "http://localhost:8080"}, "img:latest"),
						makeContainer("2", []string{"/app2"}, "RUNNING",
							map[string]string{"net.unraid.docker.webui": "http://localhost:8081"}, "img:latest"),
					},
				},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := &http.Client{}

	apps, err := queryUnraidContainersNoSSRF(client, server.URL+"/graphql", "valid-key")
	if err != nil {
		t.Errorf("expected no error for valid key, got: %v", err)
	}
	if len(apps) != 2 {
		t.Errorf("expected 2 containers, got %d", len(apps))
	}

	_, err = queryUnraidContainersNoSSRF(client, server.URL+"/graphql", "invalid-key")
	if err == nil {
		t.Error("expected error for invalid key")
	}
}

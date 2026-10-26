package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"dashgate/internal/auth"
	"dashgate/internal/models"
	"dashgate/internal/server"
)

func TestAdminDiscoveryScanStatus(t *testing.T) {
	app := server.New()
	cases := []struct {
		name    string
		manager *server.DiscoveryManager
		handler http.HandlerFunc
		field   string
	}{
		{"docker", app.DockerDiscovery, DockerDiscoveryHandler(app), "socketPath"},
		{"traefik", app.TraefikDiscovery, TraefikDiscoveryHandler(app), "hasPassword"},
		{"nginx", app.NginxDiscovery, NginxDiscoveryHandler(app), "configPath"},
		{"npm", app.NPMDiscovery, NPMDiscoveryHandler(app), "email"},
		{"caddy", app.CaddyDiscovery, CaddyDiscoveryHandler(app), "hasPassword"},
		{"unraid", app.UnraidDiscovery, UnraidDiscoveryHandler(app), "hasApiKey"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			get := func() map[string]any {
				w := httptest.NewRecorder()
				tc.handler(w, httptest.NewRequest(http.MethodGet, "/admin/discovery", nil))
				if w.Code != http.StatusOK {
					t.Fatalf("GET status %d", w.Code)
				}
				var body map[string]any
				if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				if _, ok := body[tc.field]; !ok {
					t.Fatalf("existing field %q missing: %v", tc.field, body)
				}
				if _, ok := body["appCount"]; !ok {
					t.Fatalf("existing appCount missing: %v", body)
				}
				return body
			}
			if scan := get()["scan"].(map[string]any); scan["state"] != "disabled" || scan["lastSuccessAt"] != nil {
				t.Fatalf("disabled = %v", scan)
			}
			tc.manager.EnableScan()
			if scan := get()["scan"].(map[string]any); scan["state"] != "waiting" {
				t.Fatalf("waiting = %v", scan)
			}
			tc.manager.RunScan(func() (server.DiscoveryScanResult, string) {
				return server.DiscoveryScanResult{Apps: []models.App{{Name: "one"}}}, ""
			})
			if scan := get()["scan"].(map[string]any); scan["state"] != "completed" || scan["lastSuccessCount"] != float64(1) || scan["lastSuccessAt"] == nil {
				t.Fatalf("completed = %v", scan)
			}
			tc.manager.RunScan(func() (server.DiscoveryScanResult, string) { return server.DiscoveryScanResult{}, "password=secret" })
			body := get()
			scan := body["scan"].(map[string]any)
			if scan["state"] != "failed" || scan["issueCode"] != "internal_error" || scan["lastSuccessCount"] != float64(1) {
				t.Fatalf("failed = %v", scan)
			}
			encoded, _ := json.Marshal(body)
			if strings.Contains(string(encoded), "secret") {
				t.Fatalf("secret leaked: %s", encoded)
			}
		})
	}
}

func TestAdminDiscoveryScanStatusRequiresAdmin(t *testing.T) {
	app := server.New()
	handler := auth.RequireAdmin(app, DockerDiscoveryHandler(app))
	w := httptest.NewRecorder()
	handler(w, httptest.NewRequest(http.MethodGet, "/api/admin/docker-discovery", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous status %d", w.Code)
	}
}

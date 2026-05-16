package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"dashgate/internal/config"
	"dashgate/internal/imports"
	"dashgate/internal/models"
	"dashgate/internal/server"
)

func setupTestApp(t *testing.T) *server.App {
	t.Helper()

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config", "config.yaml")
	os.MkdirAll(filepath.Dir(configPath), 0755)

	app := &server.App{
		Config: models.Config{
			Title: "Test DashGate",
			Categories: []models.Category{
				{Name: "Media", Apps: []models.App{}},
			},
		},
		ConfigPath: configPath,
	}

	if err := config.SaveConfig(app); err != nil {
		t.Fatalf("setup: failed to save initial config: %v", err)
	}

	return app
}

func setContextAdmin(r *http.Request) {
	r.Header.Set("X-Test-Admin", "true")
}

func TestImportPreviewHandler(t *testing.T) {
	app := setupTestApp(t)

	t.Run("valid homepage YAML", func(t *testing.T) {
		content := `- Media:
    - Plex:
        href: http://plex:32400
        description: Media server
    - Radarr:
        href: http://radarr:7878
        icon: https://example.com/radarr.png
- Admin:
    - Portainer:
        href: https://portainer.local
        description: Docker management
`
		body, _ := json.Marshal(imports.ImportRequest{
			Source:  imports.SourceHomepage,
			Content: content,
		})
		req := httptest.NewRequest(http.MethodPost, "/api/admin/import/preview", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		setContextAdmin(req)
		w := httptest.NewRecorder()

		ImportPreviewHandler(app).ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
		var result imports.ImportResult
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatalf("failed to unmarshal: %v", err)
		}
		if len(result.Apps) != 3 {
			t.Errorf("expected 3 apps, got %d", len(result.Apps))
		}
		if result.Apps[0].Name != "Plex" {
			t.Errorf("expected Plex, got '%s'", result.Apps[0].Name)
		}
		if result.Apps[0].Category != "Media" {
			t.Errorf("expected category Media, got '%s'", result.Apps[0].Category)
		}
	})

	t.Run("valid homarr JSON", func(t *testing.T) {
		content := `{
  "apps": [
    {"name": "Plex", "url": "http://plex:32400", "behaviour": {"externalUrl": ""}, "appearance": {"iconUrl": "https://icons/plex.png"}},
    {"name": "Sonarr", "url": "", "behaviour": {"externalUrl": "http://sonarr:8989"}, "appearance": {"iconUrl": ""}}
  ]
}`
		body, _ := json.Marshal(imports.ImportRequest{
			Source:  imports.SourceHomarr,
			Content: content,
		})
		req := httptest.NewRequest(http.MethodPost, "/api/admin/import/preview", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		setContextAdmin(req)
		w := httptest.NewRecorder()

		ImportPreviewHandler(app).ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
		var result imports.ImportResult
		json.Unmarshal(w.Body.Bytes(), &result)
		if len(result.Apps) != 2 {
			t.Errorf("expected 2 apps, got %d", len(result.Apps))
		}
		if result.Apps[1].URL != "http://sonarr:8989" {
			t.Errorf("expected externalUrl for Sonarr, got '%s'", result.Apps[1].URL)
		}
	})

	t.Run("valid heimdall JSON", func(t *testing.T) {
		content := `[
  {"title": "Plex", "url": "http://plex:32400", "icon": "https://icons/plex.png", "type": 0},
  {"title": "Movies", "url": "tag/movies", "type": 1},
  {"title": "Sonarr", "url": "http://sonarr:8989", "type": 0}
]`
		body, _ := json.Marshal(imports.ImportRequest{
			Source:  imports.SourceHeimdall,
			Content: content,
		})
		req := httptest.NewRequest(http.MethodPost, "/api/admin/import/preview", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		setContextAdmin(req)
		w := httptest.NewRecorder()

		ImportPreviewHandler(app).ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
		var result imports.ImportResult
		json.Unmarshal(w.Body.Bytes(), &result)
		if len(result.Apps) != 2 {
			t.Errorf("expected 2 apps (type=1 tag skipped), got %d", len(result.Apps))
		}
	})

	t.Run("empty content", func(t *testing.T) {
		body, _ := json.Marshal(imports.ImportRequest{
			Source:  imports.SourceHomepage,
			Content: "",
		})
		req := httptest.NewRequest(http.MethodPost, "/api/admin/import/preview", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		setContextAdmin(req)
		w := httptest.NewRecorder()

		ImportPreviewHandler(app).ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected 400 for empty content, got %d", w.Code)
		}
	})

	t.Run("malformed JSON body", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/admin/import/preview", bytes.NewReader([]byte(`{bad`)))
		req.Header.Set("Content-Type", "application/json")
		setContextAdmin(req)
		w := httptest.NewRecorder()

		ImportPreviewHandler(app).ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected 400 for bad JSON, got %d", w.Code)
		}
	})

	t.Run("unknown source", func(t *testing.T) {
		body, _ := json.Marshal(imports.ImportRequest{
			Source:  "nonexistent",
			Content: "test",
		})
		req := httptest.NewRequest(http.MethodPost, "/api/admin/import/preview", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		setContextAdmin(req)
		w := httptest.NewRecorder()

		ImportPreviewHandler(app).ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected 400 for unknown source, got %d", w.Code)
		}
	})

	t.Run("wrong HTTP method", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/admin/import/preview", nil)
		setContextAdmin(req)
		w := httptest.NewRecorder()

		ImportPreviewHandler(app).ServeHTTP(w, req)

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected 405 for GET, got %d", w.Code)
		}
	})

	t.Run("malformed YAML", func(t *testing.T) {
		body, _ := json.Marshal(imports.ImportRequest{
			Source:  imports.SourceHomepage,
			Content: "bad: : yaml: broken-",
		})
		req := httptest.NewRequest(http.MethodPost, "/api/admin/import/preview", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		setContextAdmin(req)
		w := httptest.NewRecorder()

		ImportPreviewHandler(app).ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected 400 for bad YAML, got %d", w.Code)
		}
	})
}

func TestImportApplyHandler(t *testing.T) {
	app := setupTestApp(t)

	t.Run("imports apps into existing category", func(t *testing.T) {
		body, _ := json.Marshal(map[string]interface{}{
			"source": "homepage",
			"apps": []imports.ImportedApp{
				{Name: "NewPlex", URL: "http://plex:32400", Icon: "plex.png", Category: "Media"},
			},
			"categories": map[string]string{},
		})
		req := httptest.NewRequest(http.MethodPut, "/api/admin/import/apply", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		setContextAdmin(req)
		w := httptest.NewRecorder()

		ImportApplyHandler(app).ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}

		var resp map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &resp)
		if resp["count"].(float64) != 1 {
			t.Errorf("expected count 1, got %v", resp["count"])
		}
		if len(app.Config.Categories[0].Apps) != 1 {
			t.Errorf("expected 1 app in Media category, got %d", len(app.Config.Categories[0].Apps))
		}
		if app.Config.Categories[0].Apps[0].Name != "NewPlex" {
			t.Errorf("expected NewPlex, got %s", app.Config.Categories[0].Apps[0].Name)
		}
	})

	t.Run("creates new category", func(t *testing.T) {
		body, _ := json.Marshal(map[string]interface{}{
			"source": "homarr",
			"apps": []imports.ImportedApp{
				{Name: "Grafana", URL: "http://grafana:3000", Category: "Monitoring"},
			},
			"categories": map[string]string{},
		})
		req := httptest.NewRequest(http.MethodPut, "/api/admin/import/apply", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		setContextAdmin(req)
		w := httptest.NewRecorder()

		ImportApplyHandler(app).ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}

		var found bool
		for _, cat := range app.Config.Categories {
			if cat.Name == "Monitoring" {
				found = true
				if len(cat.Apps) != 1 {
					t.Errorf("expected 1 app in Monitoring, got %d", len(cat.Apps))
				}
			}
		}
		if !found {
			t.Error("expected 'Monitoring' category to be created")
		}
	})

	t.Run("maps categories via overrides", func(t *testing.T) {
		body, _ := json.Marshal(map[string]interface{}{
			"source": "heimdall",
			"apps": []imports.ImportedApp{
				{Name: "Jellyfin", URL: "http://jellyfin:8096", Category: "Streaming"},
			},
			"categories": map[string]string{"Streaming": "Media"},
		})
		req := httptest.NewRequest(http.MethodPut, "/api/admin/import/apply", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		setContextAdmin(req)
		w := httptest.NewRecorder()

		ImportApplyHandler(app).ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}

		if len(app.Config.Categories[0].Apps) < 1 {
			t.Fatal("expected apps in Media category")
		}
		var found bool
		for _, a := range app.Config.Categories[0].Apps {
			if a.Name == "Jellyfin" {
				found = true
			}
		}
		if !found {
			t.Error("expected Jellyfin to be in Media category via mapping")
		}
	})

	t.Run("defaults to Imported category", func(t *testing.T) {
		body, _ := json.Marshal(map[string]interface{}{
			"source": "homepage",
			"apps": []imports.ImportedApp{
				{Name: "Unknown App", URL: "http://unknown:8080", Category: ""},
			},
			"categories": map[string]string{},
		})
		req := httptest.NewRequest(http.MethodPut, "/api/admin/import/apply", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		setContextAdmin(req)
		w := httptest.NewRecorder()

		ImportApplyHandler(app).ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
		if len(app.Config.Categories[0].Apps) < 1 {
			t.Fatal("expected at least 1 app")
		}
	})

	t.Run("skips apps with empty name", func(t *testing.T) {
		app2 := setupTestApp(t)

		body, _ := json.Marshal(map[string]interface{}{
			"source": "homepage",
			"apps": []imports.ImportedApp{
				{Name: "", URL: "http://something:8080", Category: "Test"},
				{Name: "Valid", URL: "http://valid:8080", Category: "Test"},
			},
			"categories": map[string]string{},
		})
		req := httptest.NewRequest(http.MethodPut, "/api/admin/import/apply", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		setContextAdmin(req)
		w := httptest.NewRecorder()

		ImportApplyHandler(app2).ServeHTTP(w, req)

		var resp map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &resp)
		if resp["count"].(float64) != 1 {
			t.Errorf("expected count 1 (empty name skipped), got %v", resp["count"])
		}
	})

	t.Run("skips apps with empty URL", func(t *testing.T) {
		app2 := setupTestApp(t)

		body, _ := json.Marshal(map[string]interface{}{
			"source": "homepage",
			"apps": []imports.ImportedApp{
				{Name: "NoURL", URL: "", Category: "Test"},
				{Name: "Valid", URL: "http://valid:8080", Category: "Test"},
			},
			"categories": map[string]string{},
		})
		req := httptest.NewRequest(http.MethodPut, "/api/admin/import/apply", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		setContextAdmin(req)
		w := httptest.NewRecorder()

		ImportApplyHandler(app2).ServeHTTP(w, req)

		var resp map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &resp)
		if resp["count"].(float64) != 1 {
			t.Errorf("expected count 1 (empty URL skipped), got %v", resp["count"])
		}
	})

	t.Run("empty apps array", func(t *testing.T) {
		body, _ := json.Marshal(map[string]interface{}{
			"source": "homepage",
			"apps":   []imports.ImportedApp{},
		})
		req := httptest.NewRequest(http.MethodPut, "/api/admin/import/apply", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		setContextAdmin(req)
		w := httptest.NewRecorder()

		ImportApplyHandler(app).ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected 400 for empty apps, got %d", w.Code)
		}
	})

	t.Run("wrong HTTP method", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/admin/import/apply", nil)
		setContextAdmin(req)
		w := httptest.NewRecorder()

		ImportApplyHandler(app).ServeHTTP(w, req)

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected 405 for GET, got %d", w.Code)
		}
	})
}

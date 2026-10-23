package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"dashgate/internal/models"
	"dashgate/internal/server"

	_ "github.com/mattn/go-sqlite3"
)

func ignoredTestApp(t *testing.T) *server.App {
	t.Helper()
	app := setupTestAppWithDB(t)
	app.DockerDiscovery = server.NewDiscoveryManager()
	app.TraefikDiscovery = server.NewDiscoveryManager()
	app.NginxDiscovery = server.NewDiscoveryManager()
	app.NPMDiscovery = server.NewDiscoveryManager()
	app.CaddyDiscovery = server.NewDiscoveryManager()
	app.UnraidDiscovery = server.NewDiscoveryManager()
	app.DiscoveredOverrides = map[string]*models.DiscoveredAppOverride{}
	return app
}

func ignoredAction(t *testing.T, app *server.App, action string, items ...map[string]string) int {
	t.Helper()
	w := httptest.NewRecorder()
	IgnoredDiscoveredAppsHandler(app)(w, newPost("/api/admin/discovered-apps/ignored", map[string]interface{}{"action": action, "items": items}))
	return w.Code
}

func ignoredRows(t *testing.T, app *server.App) []map[string]interface{} {
	t.Helper()
	w := httptest.NewRecorder()
	AdminDiscoveredAppsHandler(app)(w, newGet("/api/admin/discovered-apps"))
	if w.Code != http.StatusOK {
		t.Fatalf("GET status %d: %s", w.Code, w.Body.String())
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"active", "stale", "ignored"} {
		if _, ok := body[key]; !ok {
			t.Errorf("GET missing %s", key)
		}
	}
	var ignored []map[string]interface{}
	if err := json.Unmarshal(body["ignored"], &ignored); err != nil {
		t.Fatal(err)
	}
	return ignored
}

func TestIgnoredDiscovered_SourceURLIdentityAndRestore(t *testing.T) {
	app := ignoredTestApp(t)
	url := "https://shared.example"
	app.DockerDiscovery.Enabled, app.NginxDiscovery.Enabled = true, true
	app.DockerDiscovery.SetApps([]models.App{{Name: "Docker app", URL: url}})
	app.NginxDiscovery.SetApps([]models.App{{Name: "Nginx app", URL: url}})
	if got := ignoredAction(t, app, "dismiss", map[string]string{"source": "nginx", "url": url}); got != http.StatusOK {
		t.Fatalf("dismiss: %d", got)
	}
	rows := ignoredRows(t, app)
	if len(rows) != 1 || rows[0]["source"] != "nginx" || rows[0]["name"] != "Nginx app" {
		t.Fatalf("ignored rows: %+v", rows)
	}
	if got := ignoredAction(t, app, "restore", map[string]string{"source": "nginx", "url": url}); got != http.StatusOK {
		t.Fatalf("restore: %d", got)
	}
	if rows := ignoredRows(t, app); len(rows) != 0 {
		t.Fatalf("ignored after restore: %+v", rows)
	}
}

func TestIgnoredDiscovered_StaleRestoreAndPersistence(t *testing.T) {
	app := ignoredTestApp(t)
	app.NginxDiscovery.Enabled = true
	app.NginxDiscovery.SetApps([]models.App{{Name: "Webhook", URL: "https://example.test/hook"}})
	if got := ignoredAction(t, app, "dismiss", map[string]string{"source": "nginx", "url": "https://example.test/hook"}); got != http.StatusOK {
		t.Fatalf("dismiss: %d", got)
	}
	app.NginxDiscovery.ClearApps()
	if rows := ignoredRows(t, app); len(rows) != 1 {
		t.Fatalf("stale ignored rows: %+v", rows)
	}
	if got := ignoredAction(t, app, "restore", map[string]string{"source": "nginx", "url": "https://example.test/hook"}); got != http.StatusOK {
		t.Fatalf("stale restore: %d", got)
	}
	if got := ignoredAction(t, app, "restore", map[string]string{"source": "nginx", "url": "https://example.test/hook"}); got != http.StatusOK {
		t.Fatalf("repeat restore: %d", got)
	}
	path := filepath.Join(t.TempDir(), "persist.db")
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE ignored_discovered_apps (source TEXT NOT NULL, url TEXT NOT NULL, name TEXT NOT NULL DEFAULT '', created_at DATETIME DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(source,url));`)
	if err != nil {
		t.Fatal(err)
	}
	app.DB = db
	app.NginxDiscovery.SetApps([]models.App{{Name: "Persistent", URL: "https://persist.test"}})
	if got := ignoredAction(t, app, "dismiss", map[string]string{"source": "nginx", "url": "https://persist.test"}); got != http.StatusOK {
		t.Fatalf("file-backed dismiss: %d", got)
	}
	db.Close()
	reopened, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	app.DB = reopened
	if rows := ignoredRows(t, app); len(rows) != 1 || rows[0]["name"] != "Persistent" {
		t.Fatalf("reopened rows: %+v", rows)
	}
}

func TestIgnoredDiscovered_RejectPublishedAndAtomicBatch(t *testing.T) {
	app := ignoredTestApp(t)
	app.NginxDiscovery.Enabled = true
	app.NginxDiscovery.SetApps([]models.App{{Name: "Candidate", URL: "https://candidate.test"}, {Name: "Published", URL: "https://published.test"}})
	app.DiscoveredOverrides["https://published.test"] = &models.DiscoveredAppOverride{URL: "https://published.test", Source: "nginx", Hidden: false}
	good := map[string]string{"source": "nginx", "url": "https://candidate.test"}
	bad := map[string]string{"source": "nginx", "url": "https://published.test"}
	if got := ignoredAction(t, app, "dismiss", good, bad); got != http.StatusBadRequest {
		t.Fatalf("mixed batch status %d", got)
	}
	if rows := ignoredRows(t, app); len(rows) != 0 {
		t.Fatalf("partial write: %+v", rows)
	}
	if got := ignoredAction(t, app, "dismiss", bad); got != http.StatusBadRequest {
		t.Fatalf("published dismiss status %d", got)
	}
	if got := ignoredAction(t, app, "dismiss", good); got != http.StatusOK {
		t.Fatalf("valid dismiss status %d", got)
	}
	if app.DiscoveredOverrides["https://published.test"].Hidden {
		t.Fatal("published override changed")
	}
}

func TestIgnoredDiscovered_InvalidRequests(t *testing.T) {
	app := ignoredTestApp(t)
	for _, tc := range []struct {
		action string
		items  []map[string]string
	}{
		{"nope", []map[string]string{{"source": "nginx", "url": "https://x.test"}}},
		{"dismiss", nil},
		{"dismiss", []map[string]string{{"source": "", "url": "https://x.test"}}},
		{"dismiss", []map[string]string{{"source": "nginx", "url": "https://missing.test"}}},
	} {
		if got := ignoredAction(t, app, tc.action, tc.items...); got != http.StatusBadRequest {
			t.Errorf("%s %+v: %d", tc.action, tc.items, got)
		}
	}
	items := make([]map[string]string, 101)
	for i := range items {
		items[i] = map[string]string{"source": "nginx", "url": fmt.Sprintf("https://%d.test", i)}
	}
	if got := ignoredAction(t, app, "dismiss", items...); got != http.StatusBadRequest {
		t.Fatalf("oversize status %d", got)
	}
	w := httptest.NewRecorder()
	IgnoredDiscoveredAppsHandler(app)(w, httptest.NewRequest(http.MethodGet, "/api/admin/discovered-apps/ignored", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET status %d", w.Code)
	}
}

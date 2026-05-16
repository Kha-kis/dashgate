package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestSetupHandler_Get removed — requires template setup; covered by E2E tests

func TestSetupHandler_GetAlreadySetup(t *testing.T) {
	app := setupTestAppWithDB(t)
	seedUser(t, app, "admin", "letmein", "Big Admin", true)

	req := newGet("/setup")
	w := httptest.NewRecorder()
	SetupHandler(app).ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect, got %d", w.Code)
	}
}

func TestSetupHandler_PostCompleteSetup(t *testing.T) {
	app := setupTestAppWithDB(t)
	app.SystemConfig.SetupCompleted = false
	app.EncryptionKey = nil

	req := newPost("/setup", map[string]interface{}{
		"username":           "admin",
		"password":           "adminpass123",
		"email":              "admin@test.local",
		"displayName":        "Administrator",
		"localAuthEnabled":   true,
		"oidcAuthEnabled":    false,
		"oidcDisplayName":    "",
		"oidcIssuer":         "",
		"oidcClientID":       "",
		"oidcClientSecret":   "",
		"oidcRedirectURL":    "",
	})
	w := httptest.NewRecorder()
	SetupHandler(app).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	m := parseMap(w.Body.Bytes())
	if m["status"] != "ok" {
		t.Fatalf("expected status=ok, got %v", m)
	}

	var count int
	app.DB.QueryRow("SELECT COUNT(*) FROM users WHERE username = 'admin'").Scan(&count)
	if count != 1 {
		t.Fatal("admin user was not created")
	}
}

func TestSetupHandler_PostWithOIDC(t *testing.T) {
	app := setupTestAppWithDB(t)
	app.SystemConfig.SetupCompleted = false
	app.EncryptionKey = testEncryptionKey()

	req := newPost("/setup", map[string]interface{}{
		"username":           "admin",
		"password":           "adminpass123",
		"email":              "admin@test.local",
		"displayName":        "Administrator",
		"localAuthEnabled":   true,
		"oidcAuthEnabled":    true,
		"oidcDisplayName":    "B-Auth",
		"oidcIssuer":         "https://auth.example.com",
		"oidcClientID":       "client-123",
		"oidcClientSecret":   "secret-456",
		"oidcRedirectURL":    "https://dashgate.local/oidc/callback",
	})
	w := httptest.NewRecorder()
	SetupHandler(app).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	if app.SystemConfig.OIDCDisplayName != "B-Auth" {
		t.Errorf("expected OIDCDisplayName=B-Auth, got %s", app.SystemConfig.OIDCDisplayName)
	}
}

func TestSetupHandler_PostAlreadySetup(t *testing.T) {
	app := setupTestAppWithDB(t)
	seedUser(t, app, "admin", "letmein", "Big Admin", true)

	req := newPost("/setup", map[string]string{
		"username": "hacker",
		"password": "hackpass",
	})
	w := httptest.NewRecorder()
	SetupHandler(app).ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestSetupHandler_InvalidJSON(t *testing.T) {
	app := setupTestAppWithDB(t)
	app.SystemConfig.SetupCompleted = false
	app.EncryptionKey = nil

	req := httptest.NewRequest(http.MethodPost, "/setup", jsonBody("not-json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	SetupHandler(app).ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

var _ = json.Unmarshal

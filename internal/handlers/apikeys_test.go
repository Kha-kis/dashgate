package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"dashgate/internal/models"
)

func TestAPIKeysHandler_List(t *testing.T) {
	app := setupTestAppWithDB(t)
	userID := seedUser(t, app, "admin", "letmein", "Big Admin", true)
	sessionToken := "test-session-apikey-list"
	seedSession(t, app, userID, sessionToken)
	seedAPIKey(t, app, "my-key", "dgk_abc123", userID, `["admins"]`)

	req := newGet("/api/admin/api-keys")
	req.AddCookie(&http.Cookie{Name: "test_session", Value: sessionToken})
	w := httptest.NewRecorder()
	APIKeysHandler(app).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var keys []models.APIKey
	if err := json.Unmarshal(w.Body.Bytes(), &keys); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if keys[0].Name != "my-key" {
		t.Errorf("expected name=my-key, got %s", keys[0].Name)
	}
}

func TestAPIKeysHandler_ListEmpty(t *testing.T) {
	app := setupTestAppWithDB(t)
	userID := seedUser(t, app, "admin", "letmein", "Big Admin", true)
	sessionToken := "test-session-apikey-empty"
	seedSession(t, app, userID, sessionToken)

	req := newGet("/api/admin/api-keys")
	req.AddCookie(&http.Cookie{Name: "test_session", Value: sessionToken})
	w := httptest.NewRecorder()
	APIKeysHandler(app).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestAPIKeysHandler_Create(t *testing.T) {
	app := setupTestAppWithDB(t)
	userID := seedUser(t, app, "admin", "letmein", "Big Admin", true)
	sessionToken := "test-session-apikey-create"
	seedSession(t, app, userID, sessionToken)

	req := newPost("/api/admin/api-keys", map[string]interface{}{
		"name": "new-key",
	})
	req.AddCookie(&http.Cookie{Name: "test_session", Value: sessionToken})
	w := httptest.NewRecorder()
	APIKeysHandler(app).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAPIKeysHandler_CreateEmptyName(t *testing.T) {
	app := setupTestAppWithDB(t)
	userID := seedUser(t, app, "admin", "letmein", "Big Admin", true)
	sessionToken := "test-session-apikey-bad"
	seedSession(t, app, userID, sessionToken)

	req := newPost("/api/admin/api-keys", map[string]string{
		"name": "",
	})
	req.AddCookie(&http.Cookie{Name: "test_session", Value: sessionToken})
	w := httptest.NewRecorder()
	APIKeysHandler(app).ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAPIKeysHandler_Delete(t *testing.T) {
	app := setupTestAppWithDB(t)
	userID := seedUser(t, app, "admin", "letmein", "Big Admin", true)
	sessionToken := "test-session-apikey-delete"
	seedSession(t, app, userID, sessionToken)
	keyID := seedAPIKey(t, app, "to-delete", "dgk_del1", userID, `["admins"]`)

	req := newDelete("/api/admin/api-keys")
	req.AddCookie(&http.Cookie{Name: "test_session", Value: sessionToken})

	q := req.URL.Query()
	q.Set("id", strconv.Itoa(keyID))
	req.URL.RawQuery = q.Encode()

	w := httptest.NewRecorder()
	APIKeysHandler(app).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAPIKeysHandler_DeleteNotFound(t *testing.T) {
	app := setupTestAppWithDB(t)
	userID := seedUser(t, app, "admin", "letmein", "Big Admin", true)
	sessionToken := "test-session-apikey-delnotfound"
	seedSession(t, app, userID, sessionToken)

	req := newDelete("/api/admin/api-keys")
	req.AddCookie(&http.Cookie{Name: "test_session", Value: sessionToken})

	q := req.URL.Query()
	q.Set("id", "99999")
	req.URL.RawQuery = q.Encode()

	w := httptest.NewRecorder()
	APIKeysHandler(app).ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

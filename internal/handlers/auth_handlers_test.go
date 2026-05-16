package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLoginPost_ValidLocal(t *testing.T) {
	app := setupTestAppWithDB(t)
	seedUser(t, app, "admin", "letmein", "Big Admin", true)

	req := newPost("/api/auth/login", map[string]string{
		"username": "admin",
		"password": "letmein",
	})
	w := httptest.NewRecorder()
	LoginHandler(app).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	m := parseMap(w.Body.Bytes())
	if m["status"] != "ok" {
		t.Fatalf("expected status=ok, got %v", m)
	}

	cookies := w.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == "test_session" {
			found = true
			if c.Value == "" {
				t.Error("session cookie is empty")
			}
		}
	}
	if !found {
		t.Error("no session cookie set")
	}
}

func TestLoginPost_BadPassword(t *testing.T) {
	app := setupTestAppWithDB(t)
	seedUser(t, app, "admin", "letmein", "Big Admin", true)

	req := newPost("/api/auth/login", map[string]string{
		"username": "admin",
		"password": "WRONG",
	})
	w := httptest.NewRecorder()
	LoginHandler(app).ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestLoginPost_UnknownUser(t *testing.T) {
	app := setupTestAppWithDB(t)

	req := newPost("/api/auth/login", map[string]string{
		"username": "nobody",
		"password": "whatever",
	})
	w := httptest.NewRecorder()
	LoginHandler(app).ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestLoginPost_MissingFields(t *testing.T) {
	app := setupTestAppWithDB(t)

	req := newPost("/api/auth/login", map[string]string{
		"username": "",
		"password": "",
	})
	w := httptest.NewRecorder()
	LoginHandler(app).ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestLoginPost_EmptyBody(t *testing.T) {
	app := setupTestAppWithDB(t)

	req := newPost("/api/auth/login", map[string]string{})
	w := httptest.NewRecorder()
	LoginHandler(app).ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestLogoutPost(t *testing.T) {
	app := setupTestAppWithDB(t)
	userID := seedUser(t, app, "admin", "letmein", "Big Admin", true)
	sessionToken := "test-session-for-logout"
	seedSession(t, app, userID, sessionToken)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: "test_session", Value: sessionToken})
	w := httptest.NewRecorder()
	LogoutHandler(app).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	cookies := w.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == "test_session" {
			found = true
			if c.MaxAge != -1 {
				t.Errorf("expected MaxAge=-1 to clear cookie, got %d", c.MaxAge)
			}
		}
	}
	if !found {
		t.Error("no session clear-cookie set")
	}
}

func TestLogoutPost_NoSession(t *testing.T) {
	app := setupTestAppWithDB(t)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	w := httptest.NewRecorder()
	LogoutHandler(app).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestAuthMe_Authenticated(t *testing.T) {
	app := setupTestAppWithDB(t)
	userID := seedUser(t, app, "admin", "letmein", "Big Admin", true)
	sessionToken := "test-session-authme"
	seedSession(t, app, userID, sessionToken)

	req := newGet("/api/auth/me")
	req.AddCookie(&http.Cookie{Name: "test_session", Value: sessionToken})
	w := httptest.NewRecorder()
	AuthMeHandler(app).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAuthMe_Unauthenticated(t *testing.T) {
	app := setupTestAppWithDB(t)

	req := newGet("/api/auth/me")
	w := httptest.NewRecorder()
	AuthMeHandler(app).ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestAuthConfig(t *testing.T) {
	app := setupTestAppWithDB(t)

	req := newGet("/api/auth/config")
	w := httptest.NewRecorder()
	AuthConfigHandler(app).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	m := parseMap(w.Body.Bytes())
	if _, ok := m["localEnabled"]; !ok {
		t.Error("missing localEnabled")
	}
	if _, ok := m["oidcDisplayName"]; !ok {
		t.Error("missing oidcDisplayName")
	}
}

func TestAuthConfig_WrongMethod(t *testing.T) {
	app := setupTestAppWithDB(t)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/config", nil)
	w := httptest.NewRecorder()
	AuthConfigHandler(app).ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

var _ = strings.HasPrefix

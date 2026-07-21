package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"dashgate/internal/auth"
	"dashgate/internal/models"
)

func TestUserProfileHandler_Get(t *testing.T) {
	app := setupTestAppWithDB(t)
	userID := seedUser(t, app, "alice", "pass123", "Alice", false)
	sessionToken := "test-session-profile-get"
	seedSession(t, app, userID, sessionToken)

	req := newGet("/api/user/profile")
	req.AddCookie(&http.Cookie{Name: "test_session", Value: sessionToken})
	req = auth.WithUser(req, &models.AuthenticatedUser{
		Username: "alice", DisplayName: "Alice", Email: "alice@test.local", Source: "local", IsAdmin: false,
	})
	w := httptest.NewRecorder()
	UserProfileHandler(app).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if body["username"] != "alice" {
		t.Fatalf("expected username alice, got %v", body["username"])
	}
	if body["hasPassword"] != true {
		t.Fatal("expected hasPassword true for local user")
	}
}

func TestUserProfileHandler_UpdateDisplayName(t *testing.T) {
	app := setupTestAppWithDB(t)
	userID := seedUser(t, app, "bob", "pass123", "Bob", false)
	sessionToken := "test-session-profile-put"
	seedSession(t, app, userID, sessionToken)

	req := newPut("/api/user/profile", map[string]string{
		"displayName": "Robert",
		"email":       "bob@test.local",
	})
	req.AddCookie(&http.Cookie{Name: "test_session", Value: sessionToken})
	req = auth.WithUser(req, &models.AuthenticatedUser{
		Username: "bob", DisplayName: "Bob", Source: "local", IsAdmin: false,
	})
	w := httptest.NewRecorder()
	UserProfileHandler(app).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var displayName string
	app.DB.QueryRow("SELECT display_name FROM users WHERE username = 'bob'").Scan(&displayName)
	if displayName != "Robert" {
		t.Fatalf("expected display_name Robert, got %s", displayName)
	}
}

func TestUserProfileHandler_UpdateEmptyFields(t *testing.T) {
	app := setupTestAppWithDB(t)
	userID := seedUser(t, app, "carol", "pass123", "Carol", false)
	sessionToken := "test-session-profile-empty"
	seedSession(t, app, userID, sessionToken)

	req := newPut("/api/user/profile", map[string]string{
		"displayName": "",
		"email":       "",
	})
	req.AddCookie(&http.Cookie{Name: "test_session", Value: sessionToken})
	req = auth.WithUser(req, &models.AuthenticatedUser{
		Username: "carol", DisplayName: "Carol", Source: "local", IsAdmin: false,
	})
	w := httptest.NewRecorder()
	UserProfileHandler(app).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestUserProfileHandler_Unauthenticated(t *testing.T) {
	app := setupTestAppWithDB(t)

	req := newGet("/api/user/profile")
	w := httptest.NewRecorder()
	UserProfileHandler(app).ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestUserPasswordHandler_LocalUser(t *testing.T) {
	app := setupTestAppWithDB(t)
	userID := seedUser(t, app, "dave", "oldpass99", "Dave", false)
	sessionToken := "test-session-pw-change"
	seedSession(t, app, userID, sessionToken)

	req := newPost("/api/user/password", map[string]string{
		"currentPassword": "oldpass99",
		"newPassword":     "newpass123",
	})
	req.AddCookie(&http.Cookie{Name: "test_session", Value: sessionToken})
	req = auth.WithUser(req, &models.AuthenticatedUser{
		Username: "dave", Source: "local", IsAdmin: false,
	})
	w := httptest.NewRecorder()
	UserPasswordHandler(app).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestUserPasswordHandler_WrongCurrentPassword(t *testing.T) {
	app := setupTestAppWithDB(t)
	userID := seedUser(t, app, "eve", "correctpw", "Eve", false)
	sessionToken := "test-session-pw-wrong"
	seedSession(t, app, userID, sessionToken)

	req := newPost("/api/user/password", map[string]string{
		"currentPassword": "wrongpw99",
		"newPassword":     "newpass123",
	})
	req.AddCookie(&http.Cookie{Name: "test_session", Value: sessionToken})
	req = auth.WithUser(req, &models.AuthenticatedUser{
		Username: "eve", Source: "local", IsAdmin: false,
	})
	w := httptest.NewRecorder()
	UserPasswordHandler(app).ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestUserPasswordHandler_ShortPassword(t *testing.T) {
	app := setupTestAppWithDB(t)
	userID := seedUser(t, app, "frank", "pass", "Frank", false)
	sessionToken := "test-session-pw-short"
	seedSession(t, app, userID, sessionToken)

	req := newPost("/api/user/password", map[string]string{
		"currentPassword": "pass",
		"newPassword":     "short",
	})
	req.AddCookie(&http.Cookie{Name: "test_session", Value: sessionToken})
	req = auth.WithUser(req, &models.AuthenticatedUser{
		Username: "frank", Source: "local", IsAdmin: false,
	})
	w := httptest.NewRecorder()
	UserPasswordHandler(app).ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestUserPasswordHandler_NonLocalUser(t *testing.T) {
	app := setupTestAppWithDB(t)

	req := newPost("/api/user/password", map[string]string{
		"currentPassword": "whatever",
		"newPassword":     "newpass123",
	})
	req = auth.WithUser(req, &models.AuthenticatedUser{
		Username: "oidcuser", Source: "oidc", IsAdmin: false,
	})
	w := httptest.NewRecorder()
	UserPasswordHandler(app).ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 (non-local user), got %d: %s", w.Code, w.Body.String())
	}
}

package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"dashgate/internal/auth"
	"dashgate/internal/models"
)

func adminUser() *models.AuthenticatedUser {
	return &models.AuthenticatedUser{Username: "admin", IsAdmin: true}
}

func TestLocalUsersHandler_List(t *testing.T) {
	app := setupTestAppWithDB(t)
	adminID := seedUser(t, app, "admin", "letmein", "Big Admin", true)
	seedUser(t, app, "user1", "pass1", "User One", false)
	sessionToken := "test-session-user-list"
	seedSession(t, app, adminID, sessionToken)

	req := newGet("/api/admin/local-users")
	req.AddCookie(&http.Cookie{Name: "test_session", Value: sessionToken})
	w := httptest.NewRecorder()
	LocalUsersHandler(app).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var users []models.LocalUser
	if err := json.Unmarshal(w.Body.Bytes(), &users); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(users))
	}
}

func TestLocalUsersHandler_Create(t *testing.T) {
	app := setupTestAppWithDB(t)
	adminID := seedUser(t, app, "admin", "letmein", "Big Admin", true)
	sessionToken := "test-session-user-create"
	seedSession(t, app, adminID, sessionToken)

	req := newPost("/api/admin/local-users", map[string]string{
		"username":    "newuser",
		"password":    "secret123",
		"displayName": "New User",
		"email":       "new@test.local",
	})
	req.AddCookie(&http.Cookie{Name: "test_session", Value: sessionToken})
	w := httptest.NewRecorder()
	LocalUsersHandler(app).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var count int
	app.DB.QueryRow("SELECT COUNT(*) FROM users WHERE username = 'newuser'").Scan(&count)
	if count != 1 {
		t.Fatal("user was not created")
	}
}

func TestLocalUsersHandler_CreateDuplicate(t *testing.T) {
	app := setupTestAppWithDB(t)
	adminID := seedUser(t, app, "admin", "letmein", "Big Admin", true)
	seedUser(t, app, "existing", "pass", "Exists", false)
	sessionToken := "test-session-user-dup"
	seedSession(t, app, adminID, sessionToken)

	req := newPost("/api/admin/local-users", map[string]string{
		"username": "existing",
		"password": "whatever123",
	})
	req.AddCookie(&http.Cookie{Name: "test_session", Value: sessionToken})
	w := httptest.NewRecorder()
	LocalUsersHandler(app).ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", w.Code, w.Body.String())
	}
}

func TestLocalUserHandler_Update(t *testing.T) {
	app := setupTestAppWithDB(t)
	seedUser(t, app, "admin", "letmein", "Big Admin", true)
	userID := seedUser(t, app, "user1", "pass1", "User One", false)

	req := newPut("/api/admin/local-users/"+strconv.Itoa(userID), map[string]interface{}{
		"email":       "user1@test.local",
		"displayName": "Updated Name",
	})
	req = auth.WithUser(req, adminUser())
	w := httptest.NewRecorder()
	LocalUserHandler(app).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestLocalUserHandler_Delete(t *testing.T) {
	app := setupTestAppWithDB(t)
	seedUser(t, app, "admin", "letmein", "Big Admin", true)
	userID := seedUser(t, app, "victim", "pass123", "Victim", false)

	req := newDelete("/api/admin/local-users/" + strconv.Itoa(userID))
	req = auth.WithUser(req, adminUser())
	w := httptest.NewRecorder()
	LocalUserHandler(app).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var count int
	app.DB.QueryRow("SELECT COUNT(*) FROM users WHERE username = 'victim'").Scan(&count)
	if count != 0 {
		t.Fatal("user was not deleted")
	}
}

func TestLocalUserHandler_DeleteSelf(t *testing.T) {
	app := setupTestAppWithDB(t)
	adminID := seedUser(t, app, "admin", "letmein", "Big Admin", true)

	req := newDelete("/api/admin/local-users/" + strconv.Itoa(adminID))
	req = auth.WithUser(req, &models.AuthenticatedUser{Username: "admin", IsAdmin: true})
	w := httptest.NewRecorder()
	LocalUserHandler(app).ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 (cannot delete self), got %d: %s", w.Code, w.Body.String())
	}
}

func TestLocalUserHandler_PasswordReset(t *testing.T) {
	app := setupTestAppWithDB(t)
	seedUser(t, app, "admin", "letmein", "Big Admin", true)
	userID := seedUser(t, app, "user1", "oldpass", "User One", false)

	req := newPost("/api/admin/local-users/"+strconv.Itoa(userID)+"/password", map[string]string{
		"password": "newsecret1",
	})
	req = auth.WithUser(req, adminUser())
	w := httptest.NewRecorder()
	LocalUserHandler(app).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

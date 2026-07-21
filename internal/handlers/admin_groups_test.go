package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestManagedGroupsHandler_ListEmpty(t *testing.T) {
	app := setupTestAppWithDB(t)

	req := newGet("/api/admin/managed-groups")
	w := httptest.NewRecorder()
	AdminManagedGroupsHandler(app).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var groups []map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &groups); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if len(groups) != 0 {
		t.Fatalf("expected empty list, got %d items", len(groups))
	}
}

func TestManagedGroupsHandler_Create(t *testing.T) {
	app := setupTestAppWithDB(t)

	req := newPost("/api/admin/managed-groups", map[string]string{
		"name": "testgroup",
	})
	w := httptest.NewRecorder()
	AdminManagedGroupsHandler(app).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestManagedGroupsHandler_CreateDuplicate(t *testing.T) {
	app := setupTestAppWithDB(t)

	req := newPost("/api/admin/managed-groups", map[string]string{
		"name": "dupegroup",
	})
	w := httptest.NewRecorder()
	AdminManagedGroupsHandler(app).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on first create, got %d", w.Code)
	}

	req2 := newPost("/api/admin/managed-groups", map[string]string{
		"name": "dupegroup",
	})
	w2 := httptest.NewRecorder()
	AdminManagedGroupsHandler(app).ServeHTTP(w2, req2)

	if w2.Code != http.StatusConflict {
		t.Fatalf("expected 409 on duplicate, got %d: %s", w2.Code, w2.Body.String())
	}
}

func TestManagedGroupsHandler_CreateEmptyName(t *testing.T) {
	app := setupTestAppWithDB(t)

	req := newPost("/api/admin/managed-groups", map[string]string{
		"name": "",
	})
	w := httptest.NewRecorder()
	AdminManagedGroupsHandler(app).ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestManagedGroupHandler_Delete(t *testing.T) {
	app := setupTestAppWithDB(t)

	req := newPost("/api/admin/managed-groups", map[string]string{
		"name": "todelete",
	})
	w := httptest.NewRecorder()
	AdminManagedGroupsHandler(app).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("failed to create group: %d", w.Code)
	}

	delReq := newDelete("/api/admin/managed-groups/todelete")
	delW := httptest.NewRecorder()
	AdminManagedGroupHandler(app).ServeHTTP(delW, delReq)

	if delW.Code != http.StatusOK {
		t.Fatalf("expected 200 on delete, got %d: %s", delW.Code, delW.Body.String())
	}
}

func TestManagedGroupHandler_DeleteNonexistent(t *testing.T) {
	app := setupTestAppWithDB(t)

	req := newDelete("/api/admin/managed-groups/nonexistent")
	w := httptest.NewRecorder()
	AdminManagedGroupHandler(app).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (delete nonexistent is idempotent), got %d: %s", w.Code, w.Body.String())
	}
}

func TestManagedGroupHandler_ListAfterCreate(t *testing.T) {
	app := setupTestAppWithDB(t)

	req := newPost("/api/admin/managed-groups", map[string]string{
		"name": "alpha",
	})
	w := httptest.NewRecorder()
	AdminManagedGroupsHandler(app).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("failed to create group: %d", w.Code)
	}

	req = newPost("/api/admin/managed-groups", map[string]string{
		"name": "beta",
	})
	w = httptest.NewRecorder()
	AdminManagedGroupsHandler(app).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("failed to create group: %d", w.Code)
	}

	listReq := newGet("/api/admin/managed-groups")
	listW := httptest.NewRecorder()
	AdminManagedGroupsHandler(app).ServeHTTP(listW, listReq)

	if listW.Code != http.StatusOK {
		t.Fatalf("expected 200 on list, got %d", listW.Code)
	}

	var groups []map[string]interface{}
	if err := json.Unmarshal(listW.Body.Bytes(), &groups); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(groups))
	}
}

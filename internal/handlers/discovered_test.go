package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBulkDiscoveredAppsRequest_Validation(t *testing.T) {
	tests := []struct {
		name     string
		req      BulkDiscoveredAppsRequest
		wantURLs int
	}{
		{
			name:     "show action with single URL",
			req:      BulkDiscoveredAppsRequest{URLs: []string{"https://app1.local"}, Action: "show", Category: "Tools"},
			wantURLs: 1,
		},
		{
			name:     "show action with category and groups",
			req:      BulkDiscoveredAppsRequest{URLs: []string{"https://a.local", "https://b.local"}, Action: "show", Category: "Media", Groups: []string{"users"}},
			wantURLs: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.req.Action != "show" {
				t.Errorf("expected action show, got %s", tt.req.Action)
			}
			if len(tt.req.URLs) != tt.wantURLs {
				t.Errorf("expected %d URLs, got %d", tt.wantURLs, len(tt.req.URLs))
			}
		})
	}
}

func TestBulkDiscoveredAppsRequest_JSONParsing(t *testing.T) {
	jsonBody := `{"urls":["https://app1.local","https://app2.local"],"action":"show","category":"Media"}`

	var req BulkDiscoveredAppsRequest
	err := json.Unmarshal([]byte(jsonBody), &req)
	if err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if len(req.URLs) != 2 {
		t.Errorf("expected 2 URLs, got %d", len(req.URLs))
	}
	if req.Action != "show" {
		t.Errorf("expected action show, got %s", req.Action)
	}
}

func TestBulkDiscoveredAppsRequest_WithCategoryAndGroups(t *testing.T) {
	jsonBody := `{"urls":["https://app.local"],"action":"show","category":"Media","groups":["users","admins"]}`

	var req BulkDiscoveredAppsRequest
	err := json.Unmarshal([]byte(jsonBody), &req)
	if err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if req.Category != "Media" {
		t.Errorf("expected category Media, got %s", req.Category)
	}
	if len(req.Groups) != 2 {
		t.Errorf("expected 2 groups, got %d", len(req.Groups))
	}
}

func TestBulkDiscoveredAppsHandler_MethodNotAllowed(t *testing.T) {
	handler := BulkDiscoveredAppsHandler(nil)

	methods := []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/api/admin/discovered-apps/bulk", nil)
			w := httptest.NewRecorder()
			handler(w, req)

			if w.Code != http.StatusMethodNotAllowed {
				t.Errorf("expected 405, got %d", w.Code)
			}
		})
	}
}

func TestBulkDiscoveredAppsHandler_InvalidJSON(t *testing.T) {
	handler := BulkDiscoveredAppsHandler(nil)

	req := httptest.NewRequest(http.MethodPost, "/api/admin/discovered-apps/bulk", bytes.NewReader([]byte("invalid json")))
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestBulkDiscoveredAppsHandler_EmptyURLs(t *testing.T) {
	handler := BulkDiscoveredAppsHandler(nil)

	body, _ := json.Marshal(BulkDiscoveredAppsRequest{
		URLs:   []string{},
		Action: "show",
	})

	req := httptest.NewRequest(http.MethodPost, "/api/admin/discovered-apps/bulk", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestBulkDiscoveredAppsHandler_InvalidAction(t *testing.T) {
	handler := BulkDiscoveredAppsHandler(nil)

	body, _ := json.Marshal(BulkDiscoveredAppsRequest{
		URLs:   []string{"https://app.local"},
		Action: "invalid",
	})

	req := httptest.NewRequest(http.MethodPost, "/api/admin/discovered-apps/bulk", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestBulkDiscoveredAppsHandler_TooManyURLs(t *testing.T) {
	handler := BulkDiscoveredAppsHandler(nil)

	// Create 101 URLs to exceed the limit of 100
	urls := make([]string, 101)
	for i := range urls {
		urls[i] = fmt.Sprintf("https://app%d.local", i)
	}

	body, _ := json.Marshal(BulkDiscoveredAppsRequest{
		URLs:   urls,
		Action: "show",
	})

	req := httptest.NewRequest(http.MethodPost, "/api/admin/discovered-apps/bulk", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

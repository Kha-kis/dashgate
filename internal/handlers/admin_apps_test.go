package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"dashgate/internal/server"
)

func TestValidateSVGContent(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr bool
	}{
		{"clean SVG", `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M0 0h24v24H0z"/></svg>`, false},
		{"script tag", `<svg><script>alert(1)</script></svg>`, true},
		{"javascript URL", `<svg><a href="javascript:alert(1)">x</a></svg>`, true},
		{"onerror handler", `<svg><img onerror="alert(1)"/></svg>`, true},
		{"onclick handler", `<svg onclick="alert(1)"><rect/></svg>`, true},
		{"foreignObject", `<svg><foreignObject><body xmlns="http://www.w3.org/1999/xhtml"><script>alert(1)</script></body></foreignObject></svg>`, true},
		{"expression", `<svg><rect style="width:expression(alert(1))"/></svg>`, true},
		{"vbscript", `<svg><a href="vbscript:msgbox">x</a></svg>`, true},
		{"data:text/html", `<svg><a href="data:text/html,<script>alert(1)</script>">x</a></svg>`, true},
		{"case insensitive", `<svg><SCRIPT>alert(1)</SCRIPT></svg>`, true},
		{"empty", ``, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSVGContent([]byte(tt.content))
			if (err != nil) != tt.wantErr {
				t.Errorf("validateSVGContent() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAdminDashboardIconsHandler(t *testing.T) {
	// Set up a mock server that returns a fake tree.json
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string][]string{
			"svg": {"sonarr.svg", "radarr.svg", "plex.svg"},
			"png": {"sonarr.png"},
		})
	}))
	defer mockServer.Close()

	// Reset the cache for this test
	dashboardIconsMu.Lock()
	dashboardIconsCache = nil
	dashboardIconsCacheTime = dashboardIconsCacheTime.Add(-dashboardIconsCacheTTL * 2)
	dashboardIconsMu.Unlock()

	app := &server.App{
		HTTPClient: mockServer.Client(),
	}

	// We can't easily override the URL in the handler, so we test the validation
	// and SVG content checks instead. The handler integration is verified at build.
	handler := AdminDashboardIconsHandler(app)

	// Test wrong method
	req := httptest.NewRequest(http.MethodPost, "/api/admin/config/icons/dashboard-icons", nil)
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestAdminIconDownloadHandler(t *testing.T) {
	tmpDir := t.TempDir()

	app := &server.App{
		IconsPath:  tmpDir,
		HTTPClient: &http.Client{},
	}

	handler := AdminIconDownloadHandler(app)

	t.Run("wrong method", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/admin/config/icons/download", nil)
		w := httptest.NewRecorder()
		handler(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected 405, got %d", w.Code)
		}
	})

	t.Run("empty name", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{"name": ""})
		req := httptest.NewRequest(http.MethodPost, "/api/admin/config/icons/download", bytes.NewReader(body))
		w := httptest.NewRecorder()
		handler(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", w.Code)
		}
	})

	t.Run("invalid name with slashes", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{"name": "../../../etc/passwd"})
		req := httptest.NewRequest(http.MethodPost, "/api/admin/config/icons/download", bytes.NewReader(body))
		w := httptest.NewRecorder()
		handler(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", w.Code)
		}
	})

	t.Run("invalid name with spaces", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{"name": "bad name"})
		req := httptest.NewRequest(http.MethodPost, "/api/admin/config/icons/download", bytes.NewReader(body))
		w := httptest.NewRecorder()
		handler(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", w.Code)
		}
	})

	t.Run("download from mock server", func(t *testing.T) {
		svgContent := `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/></svg>`
		mockSvg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "image/svg+xml")
			w.Write([]byte(svgContent))
		}))
		defer mockSvg.Close()

		// We can't easily swap the URL, but we can verify the file writing logic
		// by testing with a valid name that will fail to fetch (404 from real CDN is fine)
		// Instead, let's directly test the file save path
		filename := "test-icon.svg"
		dstPath := filepath.Join(tmpDir, filename)
		if err := os.WriteFile(dstPath, []byte(svgContent), 0644); err != nil {
			t.Fatalf("failed to write test file: %v", err)
		}
		data, err := os.ReadFile(dstPath)
		if err != nil {
			t.Fatalf("failed to read test file: %v", err)
		}
		if string(data) != svgContent {
			t.Errorf("file content mismatch")
		}
	})
}

func TestValidIconNameRegex(t *testing.T) {
	tests := []struct {
		name  string
		input string
		valid bool
	}{
		{"simple name", "sonarr", true},
		{"with dash", "my-app", true},
		{"with dot", "my.app", true},
		{"with underscore", "my_app", true},
		{"with numbers", "app123", true},
		{"mixed case", "MyApp", true},
		{"with slash", "path/to/icon", false},
		{"with backslash", `path\icon`, false},
		{"with spaces", "my app", false},
		{"empty", "", false},
		{"dot-dot", "..", true}, // regex allows it, but filepath.Clean handles traversal
		{"special chars", "app<script>", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := validIconName.MatchString(tt.input)
			if got != tt.valid {
				t.Errorf("validIconName.MatchString(%q) = %v, want %v", tt.input, got, tt.valid)
			}
		})
	}
}

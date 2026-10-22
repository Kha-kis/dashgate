package handlers

import (
	"database/sql"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"dashgate/internal/database"
	"golang.org/x/crypto/bcrypt"
)

func TestAPIKeyCannotAccessUserPreferences(t *testing.T) {
	app := setupTestAppWithDB(t)
	app.SystemConfig.APIKeyEnabled = true
	handler := UserPreferencesHandler(app)

	seedUser(t, app, "testuser", "password123", "Test User", false)
	seedKey := func(name, key, username string) {
		t.Helper()
		hash, err := bcrypt.GenerateFromPassword([]byte(key), bcrypt.DefaultCost)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := app.DB.Exec(
			"INSERT INTO api_keys (name, key_hash, key_prefix, username, groups) VALUES (?, ?, ?, ?, ?)",
			name, hash, key[:8], username, `[]`,
		); err != nil {
			t.Fatal(err)
		}
	}
	const rowlessKey = "rowless1_full_key"
	seedKey("rowless", rowlessKey, "api-key")
	seedKey("matching-user", "matching_full_key", "testuser")

	for _, key := range []string{rowlessKey, "matching_full_key"} {
		for _, method := range []string{http.MethodGet, http.MethodPut} {
			r := httptest.NewRequest(method, "/api/user/preferences", strings.NewReader(`{"theme":"dark"}`))
			r.Header.Set("X-API-Key", key)
			w := httptest.NewRecorder()
			handler(w, r)
			if w.Code != http.StatusForbidden {
				t.Errorf("%s with key %q: status %d, body %s; want 403", method, key, w.Code, w.Body.String())
			}
		}
	}
	var preferenceRows int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM user_preferences").Scan(&preferenceRows); err != nil {
		t.Fatal(err)
	}
	if preferenceRows != 0 {
		t.Errorf("API-key requests created %d preference rows", preferenceRows)
	}
}

func TestProxyUserPreferencesPersistAndStaySeparate(t *testing.T) {
	app := setupTestAppWithDB(t)
	app.SystemConfig.ProxyAuthEnabled = true
	app.SystemConfig.TrustedProxies = "127.0.0.1"
	app.TrustedProxyIPs = []net.IP{net.ParseIP("127.0.0.1")}
	handler := UserPreferencesHandler(app)

	request := func(method, username, body string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, "/api/user/preferences", strings.NewReader(body))
		r.RemoteAddr = "127.0.0.1:12345"
		r.Header.Set("Remote-User", username)
		w := httptest.NewRecorder()
		handler(w, r)
		return w
	}

	for _, tc := range []struct{ username, body string }{
		{"proxy-alice", `{"settings":{"theme":"dark"}}`},
		{"proxy-bob", `{"settings":{"theme":"light"}}`},
	} {
		w := request(http.MethodPut, tc.username, tc.body)
		if w.Code != http.StatusOK {
			t.Fatalf("PUT for %s: status %d, body %s", tc.username, w.Code, w.Body.String())
		}
		id, err := database.GetUserIDByUsername(app, tc.username)
		if err != nil || id <= 0 {
			t.Fatalf("proxy user %s was not persisted: id=%d err=%v", tc.username, id, err)
		}
	}

	for _, tc := range []struct{ username, want string }{
		{"proxy-alice", `"theme":"dark"`},
		{"proxy-bob", `"theme":"light"`},
	} {
		w := request(http.MethodGet, tc.username, "")
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), tc.want) {
			t.Errorf("GET for %s: status %d, body %s; want %s", tc.username, w.Code, w.Body.String(), tc.want)
		}
	}

	if _, err := database.GetUserIDByUsername(app, "missing-user"); err != sql.ErrNoRows {
		t.Fatalf("unexpected row for missing user: %v", err)
	}

	untrusted := httptest.NewRequest(http.MethodPut, "/api/user/preferences", strings.NewReader(`{"settings":{}}`))
	untrusted.RemoteAddr = "192.0.2.1:12345"
	untrusted.Header.Set("Remote-User", "untrusted-user")
	w := httptest.NewRecorder()
	handler(w, untrusted)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("untrusted proxy request: status %d", w.Code)
	}
	if _, err := database.GetUserIDByUsername(app, "untrusted-user"); err != sql.ErrNoRows {
		t.Fatalf("untrusted proxy user was persisted: %v", err)
	}
}

func TestProxyUserCannotOverwriteAnotherAuthSource(t *testing.T) {
	app := setupTestAppWithDB(t)
	app.SystemConfig.ProxyAuthEnabled = true
	app.SystemConfig.TrustedProxies = "127.0.0.1"
	app.TrustedProxyIPs = []net.IP{net.ParseIP("127.0.0.1")}
	handler := UserPreferencesHandler(app)

	for _, source := range []string{"local", "LDAP_USER", "OIDC_USER"} {
		username := "collision-" + source
		id := seedUser(t, app, username, "password123", username, true)
		if source != "local" {
			if _, err := app.DB.Exec("UPDATE users SET password_hash = ? WHERE id = ?", source, id); err != nil {
				t.Fatal(err)
			}
		}

		r := httptest.NewRequest(http.MethodPut, "/api/user/preferences", strings.NewReader(`{"settings":{}}`))
		r.RemoteAddr = "127.0.0.1:12345"
		r.Header.Set("Remote-User", username)
		r.Header.Set("Remote-Groups", "users")
		r.Header.Set("Remote-Name", "Proxy Identity")
		r.Header.Set("Remote-Email", "proxy@example.test")
		w := httptest.NewRecorder()
		handler(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s collision: status %d, want 401", source, w.Code)
		}

		row, err := database.GetUserByUsername(app, username)
		if err != nil {
			t.Fatal(err)
		}
		if row.ID != id || row.GroupsJSON != `["admins"]` || row.DisplayName != username || row.Email != username+"@test.local" {
			t.Errorf("%s account changed: id=%d groups=%s display_name=%s email=%s", source, row.ID, row.GroupsJSON, row.DisplayName, row.Email)
		}
	}
}

func TestProxyUserUnchangedClaimsDoNotWrite(t *testing.T) {
	app := setupTestAppWithDB(t)
	app.SystemConfig.ProxyAuthEnabled = true
	app.SystemConfig.TrustedProxies = "127.0.0.1"
	app.TrustedProxyIPs = []net.IP{net.ParseIP("127.0.0.1")}
	handler := UserPreferencesHandler(app)

	request := func(groups string) {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "/api/user/preferences", nil)
		r.RemoteAddr = "127.0.0.1:12345"
		r.Header.Set("Remote-User", "stable-proxy")
		r.Header.Set("Remote-Groups", groups)
		w := httptest.NewRecorder()
		handler(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("proxy GET: status %d, body %s", w.Code, w.Body.String())
		}
	}

	request("users")
	if _, err := app.DB.Exec("UPDATE users SET updated_at = '2000-01-01' WHERE username = 'stable-proxy'"); err != nil {
		t.Fatal(err)
	}
	request("users")
	var updatedAt, groups string
	if err := app.DB.QueryRow("SELECT CAST(updated_at AS TEXT), groups FROM users WHERE username = 'stable-proxy'").Scan(&updatedAt, &groups); err != nil {
		t.Fatal(err)
	}
	if updatedAt != "2000-01-01" {
		t.Errorf("unchanged proxy claims wrote user row: updated_at=%s", updatedAt)
	}

	request("admins")
	if err := app.DB.QueryRow("SELECT CAST(updated_at AS TEXT), groups FROM users WHERE username = 'stable-proxy'").Scan(&updatedAt, &groups); err != nil {
		t.Fatal(err)
	}
	if updatedAt == "2000-01-01" || groups != `["admins"]` {
		t.Errorf("changed proxy claims not saved: updated_at=%s groups=%s", updatedAt, groups)
	}
}

func TestProxyUserWithDuplicateEmailCanSavePreferences(t *testing.T) {
	app := setupTestAppWithDB(t)
	app.SystemConfig.ProxyAuthEnabled = true
	app.SystemConfig.TrustedProxies = "127.0.0.1"
	app.TrustedProxyIPs = []net.IP{net.ParseIP("127.0.0.1")}
	seedUser(t, app, "local-owner", "password123", "Local Owner", false)
	handler := UserPreferencesHandler(app)

	request := func() *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodPut, "/api/user/preferences", strings.NewReader(`{"settings":{"theme":"dark"}}`))
		r.RemoteAddr = "127.0.0.1:12345"
		r.Header.Set("Remote-User", "proxy-other")
		r.Header.Set("Remote-Email", "local-owner@test.local")
		w := httptest.NewRecorder()
		handler(w, r)
		return w
	}

	if w := request(); w.Code != http.StatusOK {
		t.Fatalf("proxy user with duplicate email: status %d, body %s", w.Code, w.Body.String())
	}
	row, err := database.GetUserByUsername(app, "proxy-other")
	if err != nil {
		t.Fatal(err)
	}
	if row.Email != "" || row.PasswordHash != "PROXY_USER" {
		t.Errorf("proxy row has unexpected email or source: email=%q source=%q", row.Email, row.PasswordHash)
	}
	owner, err := database.GetUserByUsername(app, "local-owner")
	if err != nil {
		t.Fatal(err)
	}
	if owner.Email != "local-owner@test.local" {
		t.Errorf("existing account email changed: %q", owner.Email)
	}

	if _, err := app.DB.Exec("UPDATE users SET updated_at = '2000-01-01' WHERE username = 'proxy-other'"); err != nil {
		t.Fatal(err)
	}
	if w := request(); w.Code != http.StatusOK {
		t.Fatalf("repeat proxy request: status %d, body %s", w.Code, w.Body.String())
	}
	var updatedAt string
	if err := app.DB.QueryRow("SELECT CAST(updated_at AS TEXT) FROM users WHERE username = 'proxy-other'").Scan(&updatedAt); err != nil {
		t.Fatal(err)
	}
	if updatedAt != "2000-01-01" {
		t.Errorf("duplicate email caused redundant write: updated_at=%s", updatedAt)
	}
}

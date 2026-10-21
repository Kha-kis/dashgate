package handlers

import (
	"database/sql"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"dashgate/internal/database"
)

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

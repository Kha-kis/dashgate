package handlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"dashgate/internal/auth"
	"dashgate/internal/crypto"
	"dashgate/internal/models"
	"dashgate/internal/server"

	_ "github.com/mattn/go-sqlite3"
)

func testEncryptionKey() []byte {
	k := make([]byte, 32)
	return k
}

func setupTestAppWithDB(t testing.TB) *server.App {
	t.Helper()

	db, err := sql.Open("sqlite3", "file::memory:?cache=shared&_foreign_keys=on")
	if err != nil {
		t.Fatalf("failed to open in-memory DB: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })

	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		email TEXT UNIQUE,
		password_hash TEXT NOT NULL,
		display_name TEXT,
		groups TEXT DEFAULT '[]',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS sessions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		token TEXT UNIQUE NOT NULL,
		expires_at DATETIME NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);
	CREATE TABLE IF NOT EXISTS system_config (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS api_keys (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		key_hash TEXT NOT NULL,
		key_prefix TEXT NOT NULL,
		user_id INTEGER,
		username TEXT,
		groups TEXT DEFAULT '[]',
		permissions TEXT DEFAULT '["read"]',
		expires_at DATETIME,
		last_used_at DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
	);
	CREATE TABLE IF NOT EXISTS oidc_states (
		state TEXT PRIMARY KEY,
		redirect_url TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS user_preferences (
		user_id INTEGER PRIMARY KEY,
		username TEXT NOT NULL DEFAULT '',
		preferences TEXT NOT NULL DEFAULT '{}',
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);
	CREATE TABLE IF NOT EXISTS audit_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
		username TEXT,
		action TEXT,
		detail TEXT,
		ip TEXT
	);
	CREATE TABLE IF NOT EXISTS discovered_app_overrides (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		url TEXT UNIQUE NOT NULL,
		source TEXT NOT NULL DEFAULT '',
		name_override TEXT DEFAULT '',
		url_override TEXT DEFAULT '',
		icon_override TEXT DEFAULT '',
		description_override TEXT DEFAULT '',
		category TEXT DEFAULT '',
		groups TEXT DEFAULT '[]',
		hidden INTEGER DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
	CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
	`

	if _, err := db.Exec(schema); err != nil {
		t.Fatalf("failed to create schema: %v", err)
	}

	app := &server.App{
		DB: db,
		Config: models.Config{
			Title:      "Test DashGate",
			Categories: []models.Category{},
		},
		AuthConfig: models.AuthConfig{
			CookieName:      "test_session",
			SessionDuration: 7,
			CookieSecure:    false,
		},
		SystemConfig: models.SystemConfig{
			LocalAuthEnabled: true,
			OIDCAuthEnabled:  false,
			LDAPAuthEnabled:  false,
			ProxyAuthEnabled: false,
			SetupCompleted:   true,
			AdminGroup:       "admins",
		},
		EncryptionKey: testEncryptionKey(),
	}

	return app
}

func seedUser(t testing.TB, app *server.App, username, password, displayName string, admin bool) int {
	t.Helper()

	groupsJSON := `[]`
	if admin {
		groupsJSON = `["admins"]`
	}

	hash, err := crypto.HashPassword(password)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	result, err := app.DB.Exec(
		"INSERT INTO users (username, email, password_hash, display_name, groups) VALUES (?, ?, ?, ?, ?)",
		username, username+"@test.local", hash, displayName, groupsJSON,
	)
	if err != nil {
		t.Fatalf("failed to seed user: %v", err)
	}

	id, _ := result.LastInsertId()
	return int(id)
}

func seedSession(t testing.TB, app *server.App, userID int, token string) {
	t.Helper()
	_, err := app.DB.Exec(
		"INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, datetime('now', '+7 days'))",
		userID, token,
	)
	if err != nil {
		t.Fatalf("failed to seed session: %v", err)
	}
}

func seedAPIKey(t testing.TB, app *server.App, name, keyPrefix string, userID int, groupsJSON string) int {
	t.Helper()
	hash, err := crypto.HashPassword(keyPrefix + "_full_key")
	if err != nil {
		t.Fatalf("failed to hash API key: %v", err)
	}
	result, err := app.DB.Exec(
		"INSERT INTO api_keys (name, key_hash, key_prefix, user_id, username, groups) VALUES (?, ?, ?, ?, ?, ?)",
		name, hash, keyPrefix, userID, "testuser", groupsJSON,
	)
	if err != nil {
		t.Fatalf("failed to seed API key: %v", err)
	}
	id, _ := result.LastInsertId()
	return int(id)
}

func jsonBody(v interface{}) *bytes.Reader {
	data, _ := json.Marshal(v)
	return bytes.NewReader(data)
}

func newGet(path string) *http.Request {
	return httptest.NewRequest(http.MethodGet, path, nil)
}

func newPost(path string, body interface{}) *http.Request {
	req := httptest.NewRequest(http.MethodPost, path, jsonBody(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func newPut(path string, body interface{}) *http.Request {
	req := httptest.NewRequest(http.MethodPut, path, jsonBody(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func newDelete(path string) *http.Request {
	return httptest.NewRequest(http.MethodDelete, path, nil)
}

func mustJSON(v interface{}) []byte {
	data, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("mustJSON: %v", err))
	}
	return data
}

func parseMap(body []byte) map[string]interface{} {
	var m map[string]interface{}
	json.Unmarshal(body, &m)
	return m
}

var _ = auth.GenerateSessionToken

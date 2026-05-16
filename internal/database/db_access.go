package database

import (
	"database/sql"
	"encoding/json"
	"log"
	"time"

	"dashgate/internal/server"
)

type UserRow struct {
	ID           int
	Username     string
	Email        string
	DisplayName  string
	GroupsJSON   string
	PasswordHash string
	CreatedAt    string
}

type SessionUser struct {
	ID           int
	Username     string
	Email        string
	DisplayName  string
	GroupsJSON   string
	PasswordHash string
}

func GetUserByUsername(app *server.App, username string) (*UserRow, error) {
	var u UserRow
	err := app.DB.QueryRow(
		"SELECT id, username, COALESCE(email,''), COALESCE(display_name,''), groups, password_hash, COALESCE(created_at,'') FROM users WHERE username = ?",
		username,
	).Scan(&u.ID, &u.Username, &u.Email, &u.DisplayName, &u.GroupsJSON, &u.PasswordHash, &u.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func GetUserIDByUsername(app *server.App, username string) (int, error) {
	var id int
	err := app.DB.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&id)
	return id, err
}

func GetUsernameByID(app *server.App, id int) (string, error) {
	var username string
	err := app.DB.QueryRow("SELECT username FROM users WHERE id = ?", id).Scan(&username)
	return username, err
}

func GetUserBySession(app *server.App, token string) (*SessionUser, error) {
	var su SessionUser
	err := app.DB.QueryRow(
		"SELECT u.id, u.username, COALESCE(u.email,''), COALESCE(u.display_name,''), u.groups, u.password_hash FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.token = ? AND s.expires_at > datetime('now')",
		token,
	).Scan(&su.ID, &su.Username, &su.Email, &su.DisplayName, &su.GroupsJSON, &su.PasswordHash)
	if err != nil {
		return nil, err
	}
	return &su, nil
}

func CreateUser(app *server.App, username, email, passwordHash, displayName, groups string) (int64, error) {
	result, err := app.DB.Exec(
		"INSERT INTO users (username, email, password_hash, display_name, groups) VALUES (?, ?, ?, ?, ?)",
		username, email, passwordHash, displayName, groups,
	)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func CreateLDAPUser(app *server.App, username, email, displayName, groupsJSON string) (int64, error) {
	result, err := app.DB.Exec(
		"INSERT INTO users (username, email, password_hash, display_name, groups) VALUES (?, ?, 'LDAP_USER', ?, ?)",
		username, email, displayName, groupsJSON,
	)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func UpsertLDAPUser(app *server.App, username, email, displayName, groupsJSON string) error {
	_, err := app.DB.Exec(
		`INSERT INTO users (username, email, password_hash, display_name, groups)
		 VALUES (?, ?, 'LDAP_USER', ?, ?)
		 ON CONFLICT(username) DO UPDATE SET
		   email = excluded.email,
		   display_name = excluded.display_name,
		   groups = excluded.groups,
		   updated_at = ?`,
		username, email, displayName, groupsJSON, time.Now(),
	)
	if err != nil {
		log.Printf("Failed to upsert LDAP user: %v", err)
	}
	return err
}

func UpdateUser(app *server.App, id int, username, email, displayName, groups string) (int64, error) {
	result, err := app.DB.Exec(
		"UPDATE users SET username = ?, email = ?, display_name = ?, groups = ?, updated_at = ? WHERE id = ?",
		username, email, displayName, groups, time.Now(), id,
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func UpdateUserFields(app *server.App, id int, email, displayName, groups string) (int64, error) {
	result, err := app.DB.Exec(
		"UPDATE users SET email = ?, display_name = ?, groups = ?, updated_at = ? WHERE id = ?",
		email, displayName, groups, time.Now(), id,
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func DeleteUser(app *server.App, id int) (int64, error) {
	result, err := app.DB.Exec("DELETE FROM users WHERE id = ?", id)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func UpdateUserPassword(app *server.App, id int, passwordHash string) (int64, error) {
	result, err := app.DB.Exec(
		"UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?",
		passwordHash, time.Now(), id,
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func ListUsers(app *server.App) (*sql.Rows, error) {
	return app.DB.Query(
		"SELECT id, username, COALESCE(email, ''), COALESCE(display_name, ''), COALESCE(groups, '[]'), COALESCE(created_at, '') FROM users",
	)
}

func ListUsersAdmin(app *server.App) (*sql.Rows, error) {
	return app.DB.Query(
		"SELECT id, username, COALESCE(email,''), COALESCE(display_name,username), COALESCE(groups,'[]'), created_at, updated_at FROM users ORDER BY username",
	)
}

func UserCount(app *server.App) (int, error) {
	var count int
	err := app.DB.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	return count, err
}

func UpsertOIDCUser(app *server.App, username, email, displayName, groupsJSON string) error {
	_, err := app.DB.Exec(
		`INSERT INTO users (username, email, password_hash, display_name, groups)
		 VALUES (?, ?, 'OIDC_USER', ?, ?)
		 ON CONFLICT(username) DO UPDATE SET
		   email = excluded.email,
		   display_name = excluded.display_name,
		   groups = excluded.groups,
		   updated_at = ?`,
		username, email, displayName, groupsJSON, time.Now(),
	)
	if err != nil {
		log.Printf("Failed to upsert OIDC user: %v", err)
	}
	return err
}

func CreateSession(app *server.App, userID int, token string, expiresAt time.Time) error {
	_, err := app.DB.Exec(
		"INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, ?)",
		userID, token, expiresAt,
	)
	if err != nil {
		log.Printf("Error creating session: %v", err)
	}
	return err
}

func DeleteSession(app *server.App, token string) {
	if _, err := app.DB.Exec("DELETE FROM sessions WHERE token = ?", token); err != nil {
		log.Printf("Error deleting session: %v", err)
	}
}

type APIKeyRow struct {
	ID          int
	Name        string
	KeyHash     string
	KeyPrefix   string
	Username    string
	GroupsJSON  string
	Permissions string
	ExpiresAt   *time.Time
	LastUsedAt  *time.Time
	CreatedAt   string
}

func ListAPIKeys(app *server.App) (*sql.Rows, error) {
	return app.DB.Query(
		"SELECT id, name, key_prefix, username, COALESCE(groups, '[]'), COALESCE(permissions, '[]'), expires_at, last_used_at, COALESCE(created_at, '') FROM api_keys",
	)
}

func ListAPIKeysOrdered(app *server.App) (*sql.Rows, error) {
	return app.DB.Query(
		"SELECT id, name, key_prefix, username, groups, permissions, expires_at, last_used_at, created_at FROM api_keys ORDER BY created_at DESC",
	)
}

func CreateAPIKey(app *server.App, name, keyHash, keyPrefix, username, groups, permissions string, expiresAt *time.Time) (int64, error) {
	result, err := app.DB.Exec(
		"INSERT INTO api_keys (name, key_hash, key_prefix, username, groups, permissions, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		name, keyHash, keyPrefix, username, groups, permissions, expiresAt,
	)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func DeleteAPIKey(app *server.App, id int) (int64, error) {
	result, err := app.DB.Exec("DELETE FROM api_keys WHERE id = ?", id)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func GetAPIKeysByPrefix(app *server.App, prefix string) (*sql.Rows, error) {
	return app.DB.Query(
		"SELECT id, key_hash, username, groups, permissions, expires_at FROM api_keys WHERE key_prefix = ?",
		prefix,
	)
}

func UpdateAPIKeyLastUsed(app *server.App, id int) {
	if _, err := app.DB.Exec("UPDATE api_keys SET last_used_at = ? WHERE id = ?", time.Now(), id); err != nil {
		log.Printf("Error updating API key last_used_at: %v", err)
	}
}

func CreateOIDCState(app *server.App, state, redirectURL string) error {
	_, err := app.DB.Exec(
		"INSERT INTO oidc_states (state, redirect_url, created_at) VALUES (?, ?, ?)",
		state, redirectURL, time.Now(),
	)
	if err != nil {
		log.Printf("Failed to store OIDC state: %v", err)
	}
	return err
}

func GetOIDCState(app *server.App, state string) (string, error) {
	var redirectURL string
	err := app.DB.QueryRow("SELECT redirect_url FROM oidc_states WHERE state = ?", state).Scan(&redirectURL)
	return redirectURL, err
}

func DeleteOIDCState(app *server.App, state string) {
	if _, err := app.DB.Exec("DELETE FROM oidc_states WHERE state = ?", state); err != nil {
		log.Printf("Failed to delete OIDC state: %v", err)
	}
}

func CleanOldOIDCStates(app *server.App) {
	if _, err := app.DB.Exec("DELETE FROM oidc_states WHERE created_at < ?", time.Now().Add(-10*time.Minute)); err != nil {
		log.Printf("Failed to clean up old OIDC states: %v", err)
	}
}

func GetPreferences(app *server.App, userID int) (string, error) {
	var prefs string
	err := app.DB.QueryRow("SELECT preferences FROM user_preferences WHERE user_id = ?", userID).Scan(&prefs)
	return prefs, err
}

func GetPreferencesByUsername(app *server.App, username string) (string, error) {
	var prefs string
	err := app.DB.QueryRow("SELECT preferences FROM user_preferences WHERE username = ?", username).Scan(&prefs)
	return prefs, err
}

func SavePreferences(app *server.App, userID int, username string, prefsJSON string) error {
	_, err := app.DB.Exec(
		`INSERT OR REPLACE INTO user_preferences (user_id, username, preferences, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)`,
		userID, username, prefsJSON,
	)
	return err
}

func SavePreferencesByUserID(app *server.App, userID int, prefsJSON string) error {
	_, err := app.DB.Exec(
		`INSERT OR REPLACE INTO user_preferences (user_id, preferences, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)`,
		userID, prefsJSON,
	)
	return err
}

func SavePreferencesByUsername(app *server.App, username string, prefsJSON string) error {
	_, err := app.DB.Exec(
		`INSERT OR REPLACE INTO user_preferences (user_id, username, preferences, updated_at) VALUES (-1, ?, ?, CURRENT_TIMESTAMP)`,
		username, prefsJSON,
	)
	return err
}

func ListPreferences(app *server.App) (*sql.Rows, error) {
	return app.DB.Query("SELECT user_id, preferences FROM user_preferences")
}

func MarshalListJSON(items []string) string {
	if len(items) == 0 {
		return "[]"
	}
	data, _ := json.Marshal(items)
	return string(data)
}

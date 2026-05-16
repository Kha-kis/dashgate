package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"dashgate/internal/crypto"
	"dashgate/internal/models"
	"dashgate/internal/server"

	_ "github.com/mattn/go-sqlite3"
)

// InitAuthConfigDefaults sets sane defaults on app.AuthConfig from environment variables.
// These may be overwritten later by database-stored system config.
func InitAuthConfigDefaults(app *server.App) {
	app.SysConfigMu.Lock()
	defer app.SysConfigMu.Unlock()

	// Set defaults from env vars (will be overwritten by DB config if exists)
	app.AuthConfig.CookieName = "dashgate_session"
	app.AuthConfig.SessionDuration = 7
	app.AuthConfig.CookieSecure = true
	app.AuthConfig.Mode = models.AuthModeAuthelia

	// Override with env vars if present
	if mode := os.Getenv("AUTH_MODE"); mode != "" {
		switch mode {
		case "local":
			app.AuthConfig.Mode = models.AuthModeLocal
		case "hybrid":
			app.AuthConfig.Mode = models.AuthModeHybrid
		}
	}

	if days := os.Getenv("SESSION_DURATION_DAYS"); days != "" {
		if d, err := strconv.Atoi(days); err == nil && d > 0 {
			app.AuthConfig.SessionDuration = d
		}
	}

	if os.Getenv("COOKIE_SECURE") == "false" {
		app.AuthConfig.CookieSecure = false
	}
}

// InitDatabase opens the SQLite database, creates the schema, loads system config,
// applies it, loads discovered overrides, and starts the session cleanup goroutine.
func InitDatabase(app *server.App) error {
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "/config/dashgate.db"
	}

	// Ensure directory exists
	dbDir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dbDir, 0700); err != nil {
		return fmt.Errorf("failed to create database directory: %w", err)
	}

	var err error
	app.DB, err = sql.Open("sqlite3", dbPath+"?_foreign_keys=on")
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	app.DB.SetMaxOpenConns(1)
	app.DB.SetMaxIdleConns(1)
	app.DB.SetConnMaxLifetime(0)

	pragmas := []string{
		"PRAGMA journal_mode=WAL;",
		"PRAGMA busy_timeout=5000;",
		"PRAGMA synchronous=NORMAL;",
		"PRAGMA cache_size=-20000;",
	}
	for _, p := range pragmas {
		if _, err := app.DB.Exec(p); err != nil {
			return fmt.Errorf("failed to set %s: %w", p, err)
		}
	}

	// Set restrictive file permissions on the database file
	if err := os.Chmod(dbPath, 0600); err != nil {
		log.Printf("Warning: could not set database file permissions: %v", err)
	}

	// Create schema
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
	CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(key_prefix);
	CREATE INDEX IF NOT EXISTS idx_oidc_states_created ON oidc_states(created_at);
	CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
	CREATE UNIQUE INDEX IF NOT EXISTS idx_user_preferences_username ON user_preferences(username) WHERE username != '';
	`

	if _, err := app.DB.Exec(schema); err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}

	// Migrations: add columns for existing databases. ALTER TABLE returns an error
	// if the column already exists, which is expected and safe to ignore.
	if _, err := app.DB.Exec("ALTER TABLE discovered_app_overrides ADD COLUMN url_override TEXT DEFAULT ''"); err != nil {
		if !strings.Contains(err.Error(), "duplicate column") {
			log.Printf("Migration warning (url_override): %v", err)
		}
	}
	if _, err := app.DB.Exec("ALTER TABLE user_preferences ADD COLUMN username TEXT NOT NULL DEFAULT ''"); err != nil {
		if !strings.Contains(err.Error(), "duplicate column") {
			log.Printf("Migration warning (username): %v", err)
		}
	}
	app.DB.Exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_user_preferences_username ON user_preferences(username) WHERE username != ''")

	// Create audit log table
	if err := InitAuditTable(app); err != nil {
		return fmt.Errorf("failed to create audit_log table: %w", err)
	}

	log.Printf("Database initialized at %s", dbPath)

	// Initialize encryption key before loading config so sensitive values
	// can be decrypted on read and encrypted on write.
	InitEncryptionKey(app)

	// Load system config from database (overrides env defaults)
	if err := LoadSystemConfig(app); err != nil {
		log.Printf("No system config found, using defaults: %v", err)
	}

	// Apply system config to auth config
	ApplySystemConfig(app)

	// Migration: if proxy auth is enabled but no trusted proxies configured,
	// auto-set to private network ranges to avoid silently breaking proxy auth
	app.SysConfigMu.RLock()
	needsMigration := app.SystemConfig.SetupCompleted && app.SystemConfig.ProxyAuthEnabled && app.SystemConfig.TrustedProxies == ""
	app.SysConfigMu.RUnlock()

	if needsMigration {
		app.SysConfigMu.Lock()
		app.SystemConfig.TrustedProxies = "172.16.0.0/12, 10.0.0.0/8, 192.168.0.0/16"
		app.SysConfigMu.Unlock()
		if err := SaveSystemConfig(app); err != nil {
			log.Printf("Warning: failed to save migrated trusted proxies: %v", err)
		} else {
			log.Printf("MIGRATION: Proxy auth enabled without trusted proxies — auto-configured to private network ranges (172.16.0.0/12, 10.0.0.0/8, 192.168.0.0/16). Review this in Settings > Admin > Auth.")
		}
	}

	app.SysConfigMu.RLock()
	authMode := app.AuthConfig.Mode
	setupCompleted := app.SystemConfig.SetupCompleted
	app.SysConfigMu.RUnlock()
	log.Printf("Auth mode: %s (setup_completed: %v)", authMode, setupCompleted)

	// Load discovered app overrides cache
	if err := LoadDiscoveredOverrides(app); err != nil {
		log.Printf("Warning: failed to load discovered overrides: %v", err)
	}

	return nil
}

// StartSessionCleanupLoop starts a background goroutine that periodically
// cleans up expired sessions. The goroutine stops when the context is cancelled.
func StartSessionCleanupLoop(app *server.App, ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	go func() {
		defer ticker.Stop()
		defer func() {
			if r := recover(); r != nil {
				log.Printf("Session cleanup recovered from panic: %v", r)
			}
		}()
		for {
			select {
			case <-ctx.Done():
				log.Println("Session cleanup stopped")
				return
			case <-ticker.C:
				CleanupExpiredSessions(app)
			}
		}
	}()
}

// CleanupExpiredSessions deletes sessions that have passed their expiry time.
func CleanupExpiredSessions(app *server.App) {
	if app.DB == nil {
		return
	}
	result, err := app.DB.Exec("DELETE FROM sessions WHERE expires_at < ?", time.Now())
	if err != nil {
		log.Printf("Error cleaning up expired sessions: %v", err)
		return
	}
	if rows, _ := result.RowsAffected(); rows > 0 {
		log.Printf("Cleaned up %d expired sessions", rows)
	}
}

// NeedsSetup returns true if the application requires initial setup
// (no setup completed flag and no local users exist).
func NeedsSetup(app *server.App) bool {
	if app.DB == nil {
		return false
	}

	// Check if setup is completed
	app.SysConfigMu.RLock()
	completed := app.SystemConfig.SetupCompleted
	app.SysConfigMu.RUnlock()
	if completed {
		return false
	}

	// Check if any local users exist
	var count int
	err := app.DB.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	if err != nil {
		return true
	}

	return count == 0
}

// CreateAdminUser creates a new admin user with the given credentials.
func CreateAdminUser(app *server.App, username, password, email, displayName string) error {
	if app.DB == nil {
		return fmt.Errorf("database not initialized")
	}

	// Hash password using SHA-256 pre-hash to handle passwords longer than bcrypt's 72-byte limit
	hashedPassword, err := crypto.HashPassword(password)
	if err != nil {
		return err
	}

	// Admin user gets the configured admin groups
	app.SysConfigMu.RLock()
	adminGroupStr := app.SystemConfig.AdminGroup
	app.SysConfigMu.RUnlock()
	if adminGroupStr == "" {
		adminGroupStr = "admins"
	}
	// Build JSON array from comma-separated config
	groupNames := []string{}
	for _, g := range strings.Split(adminGroupStr, ",") {
		g = strings.TrimSpace(g)
		if g != "" {
			groupNames = append(groupNames, g)
		}
	}
	groupsJSON, _ := json.Marshal(groupNames)
	groups := string(groupsJSON)

	if email == "" {
		email = username + "@localhost"
	}
	if displayName == "" {
		displayName = "Administrator"
	}

	_, err = app.DB.Exec(
		"INSERT INTO users (username, email, password_hash, display_name, groups) VALUES (?, ?, ?, ?, ?)",
		username, email, hashedPassword, displayName, groups,
	)
	if err != nil {
		return err
	}

	log.Printf("Created admin user: %s", username)
	return nil
}

// InvalidateUserSessions deletes all sessions for a given user ID.
func InvalidateUserSessions(app *server.App, userID int) error {
	_, err := app.DB.Exec("DELETE FROM sessions WHERE user_id = ?", userID)
	if err != nil {
		log.Printf("Failed to invalidate sessions for user %d: %v", userID, err)
	}
	return err
}

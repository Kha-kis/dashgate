package auth

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"dashgate/internal/models"
	"dashgate/internal/server"

	"golang.org/x/crypto/bcrypt"
)

// GetAPIKeyUser authenticates a request via the Authorization header using
// an API key (Bearer or ApiKey scheme). It looks up matching keys by prefix,
// verifies via bcrypt, and returns the associated user.
func GetAPIKeyUser(app *server.App, r *http.Request) *models.AuthenticatedUser {
	app.SysConfigMu.RLock()
	apiKeyEnabled := app.SystemConfig.APIKeyEnabled
	app.SysConfigMu.RUnlock()

	if !apiKeyEnabled || app.DB == nil {
		return nil
	}

	// Check X-API-Key header first, then Authorization header
	apiKey := r.Header.Get("X-API-Key")
	if apiKey == "" {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			return nil
		}
		if strings.HasPrefix(authHeader, "Bearer ") {
			apiKey = strings.TrimPrefix(authHeader, "Bearer ")
		} else if strings.HasPrefix(authHeader, "ApiKey ") {
			apiKey = strings.TrimPrefix(authHeader, "ApiKey ")
		} else {
			return nil
		}
	}

	if len(apiKey) < 8 {
		return nil
	}

	keyPrefix := apiKey[:8]

	// Find matching key by prefix
	rows, err := app.DB.Query(
		"SELECT id, key_hash, username, groups, permissions, expires_at FROM api_keys WHERE key_prefix = ?",
		keyPrefix,
	)
	if err != nil {
		return nil
	}
	defer rows.Close()

	type matchedKey struct {
		id         int
		username   string
		groupsJSON string
	}
	var matched *matchedKey

	candidatesChecked := 0
	for rows.Next() {
		var id int
		var keyHash, username, groupsJSON, permsJSON string
		var expiresAt *time.Time

		if err := rows.Scan(&id, &keyHash, &username, &groupsJSON, &permsJSON, &expiresAt); err != nil {
			continue
		}

		// Check expiration
		if expiresAt != nil && time.Now().After(*expiresAt) {
			continue
		}

		// Limit bcrypt work to prevent abuse via prefix collisions
		candidatesChecked++
		if candidatesChecked > 3 {
			log.Printf("API key lookup exceeded max candidates for prefix %s", keyPrefix)
			return nil
		}

		// Verify key hash
		if err := bcrypt.CompareHashAndPassword([]byte(keyHash), []byte(apiKey)); err != nil {
			continue
		}

		matched = &matchedKey{id: id, username: username, groupsJSON: groupsJSON}
		break
	}
	rows.Close()

	if err := rows.Err(); err != nil {
		log.Printf("Error iterating API key rows: %v", err)
		return nil
	}

	if matched == nil {
		return nil
	}

	// Update last used outside of row iteration to avoid deadlock with SetMaxOpenConns(1)
	if _, err := app.DB.Exec("UPDATE api_keys SET last_used_at = ? WHERE id = ?", time.Now(), matched.id); err != nil {
		log.Printf("Error updating API key last_used_at: %v", err)
	}

	var groups []string
	if err := json.Unmarshal([]byte(matched.groupsJSON), &groups); err != nil {
		log.Printf("Error parsing groups JSON: %v", err)
		groups = []string{}
	}

	user := &models.AuthenticatedUser{
		Username:    matched.username,
		DisplayName: matched.username,
		Groups:      groups,
		Source:      "apikey",
	}
	user.IsAdmin = CheckIsAdmin(app, user.Groups)
	return user
}

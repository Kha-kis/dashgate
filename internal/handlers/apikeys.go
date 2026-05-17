package handlers

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"dashgate/internal/auth"
	"dashgate/internal/audit"
	"dashgate/internal/database"
	"dashgate/internal/models"
	"dashgate/internal/server"

	"golang.org/x/crypto/bcrypt"
)

// APIKeysHandler routes GET (list), POST (create), and DELETE operations for API keys.
func APIKeysHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			listAPIKeys(app, w, r)
		case http.MethodPost:
			createAPIKey(app, w, r)
		case http.MethodDelete:
			deleteAPIKey(app, w, r)
		default:
			respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	}
}

func listAPIKeys(app *server.App, w http.ResponseWriter, r *http.Request) {
	rows, err := database.ListAPIKeysOrdered(app)
	if err != nil {
		log.Printf("Error listing API keys: %v", err)
		respondError(w, http.StatusInternalServerError, "Internal server error")
		return
	}
	defer rows.Close()

	var keys []models.APIKey
	for rows.Next() {
		var k models.APIKey
		var groupsJSON, permsJSON string
		var expiresAt, lastUsedAt sql.NullTime

		if err := rows.Scan(&k.ID, &k.Name, &k.KeyPrefix, &k.Username, &groupsJSON, &permsJSON, &expiresAt, &lastUsedAt, &k.CreatedAt); err != nil {
			continue
		}

		json.Unmarshal([]byte(groupsJSON), &k.Groups)
		json.Unmarshal([]byte(permsJSON), &k.Permissions)
		if expiresAt.Valid {
			k.ExpiresAt = &expiresAt.Time
		}
		if lastUsedAt.Valid {
			k.LastUsedAt = &lastUsedAt.Time
		}
		keys = append(keys, k)
	}

	if err := rows.Err(); err != nil {
		log.Printf("Error iterating API keys rows: %v", err)
		respondError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	respondJSON(w, http.StatusOK, keys)
}

func createAPIKey(app *server.App, w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string   `json:"name"`
		Username    string   `json:"username"`
		Groups      []string `json:"groups"`
		Permissions []string `json:"permissions"`
		ExpiresIn   int      `json:"expiresIn"` // days, 0 = never
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Name == "" {
		respondError(w, http.StatusBadRequest, "Name is required")
		return
	}

	if req.Username == "" {
		req.Username = "api-key"
	}

	if len(req.Permissions) == 0 {
		req.Permissions = []string{"read"}
	}

	// Generate API key
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		log.Printf("Error generating random bytes for API key: %v", err)
		respondError(w, http.StatusInternalServerError, "Failed to generate key")
		return
	}
	apiKey := base64.URLEncoding.EncodeToString(keyBytes)
	keyPrefix := apiKey[:8]

	// Hash the key
	keyHash, err := bcrypt.GenerateFromPassword([]byte(apiKey), bcrypt.DefaultCost)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to generate key")
		return
	}

	groupsJSON, _ := json.Marshal(req.Groups)
	permsJSON, _ := json.Marshal(req.Permissions)

	var expiresAt *time.Time
	if req.ExpiresIn > 0 {
		t := time.Now().Add(time.Duration(req.ExpiresIn) * 24 * time.Hour)
		expiresAt = &t
	}

	id, err := database.CreateAPIKey(app, req.Name, string(keyHash), keyPrefix, req.Username, string(groupsJSON), string(permsJSON), expiresAt)
	if err != nil {
		log.Printf("Error creating API key: %v", err)
		respondError(w, http.StatusInternalServerError, "Failed to create key")
		return
	}

	adminUser := auth.GetUserFromContext(r)
	adminName := ""
	if adminUser != nil {
		adminName = adminUser.Username
	}
	audit.LogAudit(app, adminName, "api_key_created", fmt.Sprintf("Created API key %q (id=%d, prefix=%s)", req.Name, id, keyPrefix), r.RemoteAddr)

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"id":     id,
		"name":   req.Name,
		"key":    apiKey, // Only returned once!
		"prefix": keyPrefix,
	})
}

func deleteAPIKey(app *server.App, w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		respondError(w, http.StatusBadRequest, "ID required")
		return
	}

	id, err := strconv.Atoi(idStr)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid ID")
		return
	}

	rowsAffected, err := database.DeleteAPIKey(app, id)
	if err != nil {
		log.Printf("Error deleting API key: %v", err)
		respondError(w, http.StatusInternalServerError, "Failed to delete key")
		return
	}

	if rowsAffected == 0 {
		respondError(w, http.StatusNotFound, "Key not found")
		return
	}

	adminUser := auth.GetUserFromContext(r)
	adminName := ""
	if adminUser != nil {
		adminName = adminUser.Username
	}
	audit.LogAudit(app, adminName, "api_key_deleted", fmt.Sprintf("Deleted API key id=%d", id), r.RemoteAddr)

	respondJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

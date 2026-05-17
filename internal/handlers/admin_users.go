package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"dashgate/internal/auth"
	"dashgate/internal/audit"
	"dashgate/internal/database"
	"dashgate/internal/models"
	"dashgate/internal/server"
)

// LocalUsersHandler handles GET (list) and POST (create) for local users.
func LocalUsersHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if app.DB == nil {
			respondError(w, http.StatusServiceUnavailable, "Local auth not enabled")
			return
		}

		switch r.Method {
		case http.MethodGet:
			listLocalUsers(app, w, r)
		case http.MethodPost:
			createLocalUser(app, w, r)
		default:
			respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	}
}

// LocalUserHandler routes operations on a single local user by ID.
func LocalUserHandler(app *server.App) http.HandlerFunc {
	return 	func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())

		if app.DB == nil {
			respondError(w, http.StatusServiceUnavailable, "Local auth not enabled")
			return
		}

		// Extract user ID from path
		path := strings.TrimPrefix(r.URL.Path, "/api/admin/local-users/")
		parts := strings.Split(path, "/")
		if len(parts) == 0 || parts[0] == "" {
			respondError(w, http.StatusBadRequest, "User ID required")
			return
		}

		userID, err := strconv.Atoi(parts[0])
		if err != nil {
			respondError(w, http.StatusBadRequest, "Invalid user ID")
			return
		}

		// Check for password reset endpoint
		if len(parts) > 1 && parts[1] == "password" {
			resetUserPassword(app, w, r, userID)
			return
		}

		switch r.Method {
		case http.MethodPut:
			updateLocalUser(app, w, r, userID, user.Username)
		case http.MethodDelete:
			deleteLocalUser(app, w, r, userID, user.Username)
		default:
			respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	}
}

func listLocalUsers(app *server.App, w http.ResponseWriter, r *http.Request) {
	rows, err := database.ListUsersAdmin(app)
	if err != nil {
		log.Printf("Error listing users: %v", err)
		respondError(w, http.StatusInternalServerError, "Internal server error")
		return
	}
	defer rows.Close()

	var users []models.LocalUser
	for rows.Next() {
		var u models.LocalUser
		var groupsJSON string
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.DisplayName, &groupsJSON, &u.CreatedAt, &u.UpdatedAt); err != nil {
			log.Printf("Error scanning user: %v", err)
			continue
		}
		json.Unmarshal([]byte(groupsJSON), &u.Groups)
		users = append(users, u)
	}

	if err := rows.Err(); err != nil {
		log.Printf("Error iterating users rows: %v", err)
		respondError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	respondJSON(w, http.StatusOK, users)
}

func createLocalUser(app *server.App, w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username    string   `json:"username"`
		Email       string   `json:"email"`
		Password    string   `json:"password"`
		DisplayName string   `json:"displayName"`
		Groups      []string `json:"groups"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Username == "" || req.Password == "" {
		respondError(w, http.StatusBadRequest, "Username and password required")
		return
	}

	if len(req.Password) < 8 {
		respondError(w, http.StatusBadRequest, "Password must be at least 8 characters")
		return
	}

	// Hash password using SHA-256 pre-hash to handle passwords longer than bcrypt's 72-byte limit
	hashedPassword, err := auth.HashPassword(req.Password)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		respondError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	groupsJSON, _ := json.Marshal(req.Groups)
	if req.Groups == nil {
		groupsJSON = []byte("[]")
	}

	result, err := database.CreateUser(app, req.Username, req.Email, hashedPassword, req.DisplayName, string(groupsJSON))
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			respondError(w, http.StatusConflict, "Username or email already exists")
			return
		}
		log.Printf("Error creating user: %v", err)
		respondError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	id := result

	adminUser := auth.GetUserFromContext(r)
	adminName := ""
	if adminUser != nil {
		adminName = adminUser.Username
	}
	audit.LogAudit(app, adminName, "user_created", fmt.Sprintf("Created user %q (id=%d)", req.Username, id), r.RemoteAddr)

	respondJSON(w, http.StatusOK, map[string]interface{}{"status": "created", "id": id})
}

func updateLocalUser(app *server.App, w http.ResponseWriter, r *http.Request, userID int, currentUsername string) {
	var req struct {
		Email       string   `json:"email"`
		DisplayName string   `json:"displayName"`
		Groups      []string `json:"groups"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Prevent admin from removing their own admin role
	var targetUsername string
	targetUsername, _ = database.GetUsernameByID(app, userID)
	if targetUsername == currentUsername {
		if !auth.CheckIsAdmin(app, req.Groups) {
			respondError(w, http.StatusForbidden, "Cannot remove admin role from your own account")
			return
		}
	}

	groupsJSON, _ := json.Marshal(req.Groups)
	if req.Groups == nil {
		groupsJSON = []byte("[]")
	}

	rowsAffected, err := database.UpdateUserFields(app, userID, req.Email, req.DisplayName, string(groupsJSON))
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			respondError(w, http.StatusConflict, "Email already exists")
			return
		}
		log.Printf("Error updating user: %v", err)
		respondError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	if rowsAffected == 0 {
		respondError(w, http.StatusNotFound, "User not found")
		return
	}

	// Invalidate all sessions for this user since their privileges changed
	database.InvalidateUserSessions(app, userID)

	audit.LogAudit(app, currentUsername, "user_updated", fmt.Sprintf("Updated user id=%d", userID), r.RemoteAddr)

	respondJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func deleteLocalUser(app *server.App, w http.ResponseWriter, r *http.Request, userID int, currentUsername string) {
	var username string
	var err error
	username, err = database.GetUsernameByID(app, userID)
	if err == sql.ErrNoRows {
		respondError(w, http.StatusNotFound, "User not found")
		return
	}
	if err != nil {
		log.Printf("Error getting user: %v", err)
		respondError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	// Prevent self-deletion
	if username == currentUsername {
		respondError(w, http.StatusBadRequest, "Cannot delete yourself")
		return
	}

	// Invalidate all sessions for this user before deletion
	database.InvalidateUserSessions(app, userID)

	// Delete user (sessions would also cascade delete via foreign key)
	rowsAffected, err := database.DeleteUser(app, userID)
	if err != nil {
		log.Printf("Error deleting user: %v", err)
		respondError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	if rowsAffected == 0 {
		respondError(w, http.StatusNotFound, "User not found")
		return
	}

	audit.LogAudit(app, currentUsername, "user_deleted", fmt.Sprintf("Deleted user %q (id=%d)", username, userID), r.RemoteAddr)

	respondJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func resetUserPassword(app *server.App, w http.ResponseWriter, r *http.Request, userID int) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req struct {
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Password == "" {
		respondError(w, http.StatusBadRequest, "Password required")
		return
	}

	if len(req.Password) < 8 {
		respondError(w, http.StatusBadRequest, "Password must be at least 8 characters")
		return
	}

	// Hash new password using SHA-256 pre-hash to handle passwords longer than bcrypt's 72-byte limit
	hashedPassword, err := auth.HashPassword(req.Password)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		respondError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	// Update password and timestamp
	rowsAffected, err := database.UpdateUserPassword(app, userID, hashedPassword)
	if err != nil {
		log.Printf("Error updating password: %v", err)
		respondError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	if rowsAffected == 0 {
		respondError(w, http.StatusNotFound, "User not found")
		return
	}

	// Invalidate all user sessions after password reset
	database.InvalidateUserSessions(app, userID)

	adminUser := auth.GetUserFromContext(r)
	adminName := ""
	if adminUser != nil {
		adminName = adminUser.Username
	}
	audit.LogAudit(app, adminName, "password_reset", fmt.Sprintf("Reset password for user id=%d", userID), r.RemoteAddr)

	respondJSON(w, http.StatusOK, map[string]string{"status": "password_reset"})
}

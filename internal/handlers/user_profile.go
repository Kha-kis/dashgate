package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"dashgate/internal/auth"
	"dashgate/internal/database"
	"dashgate/internal/models"
	"dashgate/internal/server"
)

func UserProfileHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())
		if user == nil {
			respondError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}

		switch r.Method {
		case http.MethodGet:
			userProfileGet(app, w, r, user)
		case http.MethodPut:
			userProfileUpdate(app, w, r, user)
		default:
			respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	}
}

func UserPasswordHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())
		if user == nil {
			respondError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}

		if r.Method != http.MethodPost {
			respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}

		userPasswordChange(app, w, r, user)
	}
}

func userProfileGet(app *server.App, w http.ResponseWriter, r *http.Request, user *models.AuthenticatedUser) {
	hasPassword := false
	if user.Source == "local" {
		row, err := database.GetUserByUsername(app, user.Username)
		if err == nil {
			hasPassword = row.PasswordHash != "" && row.PasswordHash != "LDAP_USER" && row.PasswordHash != "OIDC_USER"
		}
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"username":    user.Username,
		"displayName": user.DisplayName,
		"email":       user.Email,
		"source":      user.Source,
		"hasPassword": hasPassword,
	})
}

func userProfileUpdate(app *server.App, w http.ResponseWriter, r *http.Request, user *models.AuthenticatedUser) {
	var req struct {
		DisplayName string `json:"displayName"`
		Email       string `json:"email"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	row, err := database.GetUserByUsername(app, user.Username)
	if err != nil {
		log.Printf("Error looking up user: %v", err)
		respondError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	email := req.Email
	if email == "" {
		email = row.Email
	}
	displayName := req.DisplayName
	if displayName == "" {
		displayName = row.DisplayName
	}

	_, err = database.UpdateUserFields(app, row.ID, email, displayName, row.GroupsJSON)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			respondError(w, http.StatusConflict, "Email already in use")
			return
		}
		log.Printf("Error updating profile: %v", err)
		respondError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func userPasswordChange(app *server.App, w http.ResponseWriter, r *http.Request, user *models.AuthenticatedUser) {
	if user.Source != "local" {
		respondError(w, http.StatusBadRequest, "Password change only available for local users")
		return
	}

	var req struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.CurrentPassword == "" || req.NewPassword == "" {
		respondError(w, http.StatusBadRequest, "Current and new password required")
		return
	}

	if len(req.NewPassword) < 8 {
		respondError(w, http.StatusBadRequest, "New password must be at least 8 characters")
		return
	}

	row, err := database.GetUserByUsername(app, user.Username)
	if err != nil {
		log.Printf("Error looking up user: %v", err)
		respondError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	if !auth.CheckPassword(req.CurrentPassword, row.PasswordHash) {
		respondError(w, http.StatusUnauthorized, "Current password is incorrect")
		return
	}

	hashedPassword, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		respondError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	_, err = database.UpdateUserPassword(app, row.ID, hashedPassword)
	if err != nil {
		log.Printf("Error updating password: %v", err)
		respondError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	database.InvalidateUserSessions(app, row.ID)

	respondJSON(w, http.StatusOK, map[string]string{"status": "password_changed"})
}

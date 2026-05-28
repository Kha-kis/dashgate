package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"dashgate/internal/database"
	"dashgate/internal/server"
)

func AdminManagedGroupsHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			listManagedGroups(app, w, r)
		case http.MethodPost:
			createManagedGroup(app, w, r)
		default:
			respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	}
}

func AdminManagedGroupHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/api/admin/managed-groups/")
		if name == "" {
			respondError(w, http.StatusBadRequest, "Group name required")
			return
		}

		switch r.Method {
		case http.MethodDelete:
			deleteManagedGroup(app, w, r, name)
		default:
			respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	}
}

func listManagedGroups(app *server.App, w http.ResponseWriter, r *http.Request) {
	groups, err := database.ListManagedGroups(app)
	if err != nil {
		log.Printf("Error listing managed groups: %v", err)
		respondError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	if groups == nil {
		groups = []database.ManagedGroup{}
	}

	respondJSON(w, http.StatusOK, groups)
}

func createManagedGroup(app *server.App, w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		DisplayName string `json:"displayName"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Name == "" {
		respondError(w, http.StatusBadRequest, "Group name required")
		return
	}

	if err := database.CreateManagedGroup(app, req.Name, req.DisplayName); err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			respondError(w, http.StatusConflict, "Group already exists")
			return
		}
		log.Printf("Error creating managed group: %v", err)
		respondError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"status": "created"})
}

func deleteManagedGroup(app *server.App, w http.ResponseWriter, r *http.Request, name string) {
	if err := database.DeleteManagedGroup(app, name); err != nil {
		log.Printf("Error deleting managed group: %v", err)
		respondError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

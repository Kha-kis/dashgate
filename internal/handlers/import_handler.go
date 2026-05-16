package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"dashgate/internal/auth"
	"dashgate/internal/config"
	"dashgate/internal/database"
	"dashgate/internal/imports"
	"dashgate/internal/models"
	"dashgate/internal/server"
)

func ImportPreviewHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}

		var req imports.ImportRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, "Invalid request body")
			return
		}

		if req.Content == "" {
			respondError(w, http.StatusBadRequest, "Content is required")
			return
		}

		result, err := imports.Parse(req.Source, req.Content)
		if err != nil {
			respondError(w, http.StatusBadRequest, fmt.Sprintf("Failed to parse config: %v", err))
			return
		}

		adminUser := auth.GetUserFromContext(r)
		adminName := ""
		if adminUser != nil {
			adminName = adminUser.Username
		}
		database.LogAudit(app, adminName, "import_previewed", fmt.Sprintf("Previewed %s import: %d apps found", req.Source, len(result.Apps)), r.RemoteAddr)

		respondJSON(w, http.StatusOK, result)
	}
}

func ImportApplyHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}

		var req struct {
			Source     imports.SourceType    `json:"source"`
			Apps       []imports.ImportedApp `json:"apps"`
			Categories map[string]string   `json:"categories"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, "Invalid request body")
			return
		}

		if len(req.Apps) == 0 {
			respondError(w, http.StatusBadRequest, "No apps to import")
			return
		}

		imported := 0

		func() {
			app.ConfigMu.Lock()
			defer app.ConfigMu.Unlock()

			categoryIndex := make(map[string]int)
			for i, cat := range app.Config.Categories {
				categoryIndex[strings.ToLower(cat.Name)] = i
			}

			for _, a := range req.Apps {
				if a.Name == "" || a.URL == "" {
					continue
				}

				catName := a.Category
				if mapped, ok := req.Categories[a.Category]; ok && mapped != "" {
					catName = mapped
				}
				if catName == "" {
					catName = "Imported"
				}

				idx, ok := categoryIndex[strings.ToLower(catName)]
				if !ok {
					app.Config.Categories = append(app.Config.Categories, models.Category{
						Name: catName,
						Apps: []models.App{},
					})
					idx = len(app.Config.Categories) - 1
					categoryIndex[strings.ToLower(catName)] = idx
				}

				newApp := models.App{
					Name:        a.Name,
					URL:         a.URL,
					Icon:        a.Icon,
					Description: a.Description,
				}
				app.Config.Categories[idx].Apps = append(app.Config.Categories[idx].Apps, newApp)
				imported++
			}
		}()

		if err := config.SaveConfig(app); err != nil {
			log.Printf("Error saving imported config: %v", err)
			respondError(w, http.StatusInternalServerError, "Failed to save config")
			return
		}

		adminUser := auth.GetUserFromContext(r)
		adminName := ""
		if adminUser != nil {
			adminName = adminUser.Username
		}
		database.LogAudit(app, adminName, "import_applied", fmt.Sprintf("Imported %d apps from %s", imported, req.Source), r.RemoteAddr)

		respondJSON(w, http.StatusOK, map[string]interface{}{
			"status":   "imported",
			"count":    imported,
		})
	}
}

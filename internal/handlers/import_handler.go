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
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req imports.ImportRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		if req.Content == "" {
			http.Error(w, "Content is required", http.StatusBadRequest)
			return
		}

		result, err := imports.Parse(req.Source, req.Content)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to parse config: %v", err), http.StatusBadRequest)
			return
		}

		adminUser := auth.GetUserFromContext(r)
		adminName := ""
		if adminUser != nil {
			adminName = adminUser.Username
		}
		database.LogAudit(app, adminName, "import_previewed", fmt.Sprintf("Previewed %s import: %d apps found", req.Source, len(result.Apps)), r.RemoteAddr)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}

func ImportApplyHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			Source     imports.SourceType    `json:"source"`
			Apps       []imports.ImportedApp `json:"apps"`
			Categories map[string]string   `json:"categories"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		if len(req.Apps) == 0 {
			http.Error(w, "No apps to import", http.StatusBadRequest)
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
			http.Error(w, "Failed to save config", http.StatusInternalServerError)
			return
		}

		adminUser := auth.GetUserFromContext(r)
		adminName := ""
		if adminUser != nil {
			adminName = adminUser.Username
		}
		database.LogAudit(app, adminName, "import_applied", fmt.Sprintf("Imported %d apps from %s", imported, req.Source), r.RemoteAddr)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":   "imported",
			"count":    imported,
		})
	}
}

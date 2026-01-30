package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"dashgate/internal/config"
	"dashgate/internal/health"
	"dashgate/internal/models"
	"dashgate/internal/server"
)

// AdminConfigAppsHandler handles CRUD operations for app entries in config.yaml.
func AdminConfigAppsHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			// Return full app config with all details
			type FullApp struct {
				Name        string   `json:"name"`
				URL         string   `json:"url"`
				Icon        string   `json:"icon"`
				Description string   `json:"description"`
				Groups      []string `json:"groups"`
				Category    string   `json:"category"`
			}

			app.ConfigMu.RLock()
			var apps []FullApp
			for _, cat := range app.Config.Categories {
				for _, a := range cat.Apps {
					apps = append(apps, FullApp{
						Name:        a.Name,
						URL:         a.URL,
						Icon:        a.Icon,
						Description: a.Description,
						Groups:      a.Groups,
						Category:    cat.Name,
					})
				}
			}
			app.ConfigMu.RUnlock()

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(apps)

		case http.MethodPost:
			// Create new app
			var req struct {
				Name        string   `json:"name"`
				URL         string   `json:"url"`
				Icon        string   `json:"icon"`
				Description string   `json:"description"`
				Groups      []string `json:"groups"`
				Category    string   `json:"category"`
			}

			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "Invalid request body", http.StatusBadRequest)
				return
			}

			if req.Name == "" || req.URL == "" || req.Category == "" {
				http.Error(w, "Name, URL, and Category are required", http.StatusBadRequest)
				return
			}

			// Validate URL scheme to prevent stored XSS via javascript: URLs
			if parsedURL, err := url.Parse(req.URL); err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
				http.Error(w, "URL must use http or https scheme", http.StatusBadRequest)
				return
			}

			app.ConfigMu.Lock()
			// Check if app URL already exists
			for _, cat := range app.Config.Categories {
				for _, a := range cat.Apps {
					if a.URL == req.URL {
						app.ConfigMu.Unlock()
						http.Error(w, "App with this URL already exists", http.StatusConflict)
						return
					}
				}
			}

			// Find or create category
			categoryFound := false
			for i, cat := range app.Config.Categories {
				if cat.Name == req.Category {
					app.Config.Categories[i].Apps = append(app.Config.Categories[i].Apps, models.App{
						Name:        req.Name,
						URL:         req.URL,
						Icon:        req.Icon,
						Description: req.Description,
						Groups:      req.Groups,
					})
					categoryFound = true
					break
				}
			}

			if !categoryFound {
				// Create new category
				app.Config.Categories = append(app.Config.Categories, models.Category{
					Name: req.Category,
					Apps: []models.App{{
						Name:        req.Name,
						URL:         req.URL,
						Icon:        req.Icon,
						Description: req.Description,
						Groups:      req.Groups,
					}},
				})
			}
			app.ConfigMu.Unlock()

			if err := config.SaveConfig(app); err != nil {
				log.Printf("Error saving config: %v", err)
				config.ReloadConfig(app)
				http.Error(w, "Failed to save config", http.StatusInternalServerError)
				return
			}

			// Trigger health check for new app
			go func() {
				status := health.CheckHealth(app, req.URL)
				app.HealthMu.Lock()
				app.HealthCache[req.URL] = status
				app.HealthMu.Unlock()
			}()

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "created"})

		case http.MethodPut:
			// Update existing app
			var req struct {
				OriginalURL string   `json:"originalUrl"`
				Name        string   `json:"name"`
				URL         string   `json:"url"`
				Icon        string   `json:"icon"`
				Description string   `json:"description"`
				Groups      []string `json:"groups"`
				Category    string   `json:"category"`
			}

			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "Invalid request body", http.StatusBadRequest)
				return
			}

			if req.OriginalURL == "" || req.Name == "" || req.URL == "" || req.Category == "" {
				http.Error(w, "OriginalURL, Name, URL, and Category are required", http.StatusBadRequest)
				return
			}

			// Validate URL scheme to prevent stored XSS via javascript: URLs
			if parsedURL, err := url.Parse(req.URL); err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
				http.Error(w, "URL must use http or https scheme", http.StatusBadRequest)
				return
			}

			app.ConfigMu.Lock()
			// Find and remove the app from its current category
			var foundApp *models.App
			var oldCategoryIdx int = -1
			var oldAppIdx int = -1

			for i, cat := range app.Config.Categories {
				for j, a := range cat.Apps {
					if a.URL == req.OriginalURL {
						foundApp = &app.Config.Categories[i].Apps[j]
						oldCategoryIdx = i
						oldAppIdx = j
						break
					}
				}
				if foundApp != nil {
					break
				}
			}

			if foundApp == nil {
				app.ConfigMu.Unlock()
				http.Error(w, "App not found", http.StatusNotFound)
				return
			}

			// Check if new URL conflicts with another app
			if req.URL != req.OriginalURL {
				for _, cat := range app.Config.Categories {
					for _, a := range cat.Apps {
						if a.URL == req.URL {
							app.ConfigMu.Unlock()
							http.Error(w, "Another app with this URL already exists", http.StatusConflict)
							return
						}
					}
				}
			}

			// Remove from old category
			app.Config.Categories[oldCategoryIdx].Apps = append(
				app.Config.Categories[oldCategoryIdx].Apps[:oldAppIdx],
				app.Config.Categories[oldCategoryIdx].Apps[oldAppIdx+1:]...,
			)

			// Remove empty category
			if len(app.Config.Categories[oldCategoryIdx].Apps) == 0 {
				app.Config.Categories = append(
					app.Config.Categories[:oldCategoryIdx],
					app.Config.Categories[oldCategoryIdx+1:]...,
				)
			}

			// Add to new/existing category
			newApp := models.App{
				Name:        req.Name,
				URL:         req.URL,
				Icon:        req.Icon,
				Description: req.Description,
				Groups:      req.Groups,
			}

			categoryFound := false
			for i, cat := range app.Config.Categories {
				if cat.Name == req.Category {
					app.Config.Categories[i].Apps = append(app.Config.Categories[i].Apps, newApp)
					categoryFound = true
					break
				}
			}

			if !categoryFound {
				app.Config.Categories = append(app.Config.Categories, models.Category{
					Name: req.Category,
					Apps: []models.App{newApp},
				})
			}

			// Update app mappings if URL changed
			urlChanged := req.URL != req.OriginalURL
			if urlChanged {
				app.MappingsMu.Lock()
				if groups, ok := app.AppMappings[req.OriginalURL]; ok {
					delete(app.AppMappings, req.OriginalURL)
					app.AppMappings[req.URL] = groups
				}
				app.MappingsMu.Unlock()
			}
			app.ConfigMu.Unlock()

			if urlChanged {
				config.SaveAppMappings(app)
			}

			if err := config.SaveConfig(app); err != nil {
				log.Printf("Error saving config: %v", err)
				config.ReloadConfig(app)
				http.Error(w, "Failed to save config", http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "updated"})

		case http.MethodDelete:
			// Delete app
			appURL := r.URL.Query().Get("url")
			if appURL == "" {
				http.Error(w, "URL parameter required", http.StatusBadRequest)
				return
			}

			app.ConfigMu.Lock()
			found := false
			for i, cat := range app.Config.Categories {
				for j, a := range cat.Apps {
					if a.URL == appURL {
						// Remove app
						app.Config.Categories[i].Apps = append(
							app.Config.Categories[i].Apps[:j],
							app.Config.Categories[i].Apps[j+1:]...,
						)
						found = true

						// Remove empty category
						if len(app.Config.Categories[i].Apps) == 0 {
							app.Config.Categories = append(
								app.Config.Categories[:i],
								app.Config.Categories[i+1:]...,
							)
						}
						break
					}
				}
				if found {
					break
				}
			}
			app.ConfigMu.Unlock()

			if !found {
				http.Error(w, "App not found", http.StatusNotFound)
				return
			}

			// Remove from app mappings
			app.MappingsMu.Lock()
			delete(app.AppMappings, appURL)
			app.MappingsMu.Unlock()
			config.SaveAppMappings(app)

			if err := config.SaveConfig(app); err != nil {
				log.Printf("Error saving config: %v", err)
				config.ReloadConfig(app)
				http.Error(w, "Failed to save config", http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})

		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

// AdminCategoriesHandler handles CRUD operations for categories.
func AdminCategoriesHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			app.ConfigMu.RLock()
			categories := make([]map[string]interface{}, len(app.Config.Categories))
			for i, cat := range app.Config.Categories {
				categories[i] = map[string]interface{}{
					"name":     cat.Name,
					"appCount": len(cat.Apps),
				}
			}
			app.ConfigMu.RUnlock()

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(categories)

		case http.MethodPost:
			var req struct {
				Name string `json:"name"`
			}

			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "Invalid request body", http.StatusBadRequest)
				return
			}

			if req.Name == "" {
				http.Error(w, "Category name required", http.StatusBadRequest)
				return
			}

			app.ConfigMu.Lock()
			// Check if category exists
			for _, cat := range app.Config.Categories {
				if cat.Name == req.Name {
					app.ConfigMu.Unlock()
					http.Error(w, "Category already exists", http.StatusConflict)
					return
				}
			}

			app.Config.Categories = append(app.Config.Categories, models.Category{
				Name: req.Name,
				Apps: []models.App{},
			})
			app.ConfigMu.Unlock()

			if err := config.SaveConfig(app); err != nil {
				log.Printf("Error saving config: %v", err)
				config.ReloadConfig(app)
				http.Error(w, "Failed to save config", http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "created"})

		case http.MethodPut:
			var req struct {
				OldName string `json:"oldName"`
				NewName string `json:"newName"`
			}

			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "Invalid request body", http.StatusBadRequest)
				return
			}

			if req.OldName == "" || req.NewName == "" {
				http.Error(w, "Old and new category names required", http.StatusBadRequest)
				return
			}

			app.ConfigMu.Lock()
			found := false
			for i, cat := range app.Config.Categories {
				if cat.Name == req.OldName {
					app.Config.Categories[i].Name = req.NewName
					found = true
					break
				}
			}
			app.ConfigMu.Unlock()

			if !found {
				http.Error(w, "Category not found", http.StatusNotFound)
				return
			}

			if err := config.SaveConfig(app); err != nil {
				log.Printf("Error saving config: %v", err)
				config.ReloadConfig(app)
				http.Error(w, "Failed to save config", http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "updated"})

		case http.MethodDelete:
			name := r.URL.Query().Get("name")
			if name == "" {
				http.Error(w, "Category name required", http.StatusBadRequest)
				return
			}

			app.ConfigMu.Lock()
			found := false
			for i, cat := range app.Config.Categories {
				if cat.Name == name {
					if len(cat.Apps) > 0 {
						app.ConfigMu.Unlock()
						http.Error(w, "Cannot delete category with apps", http.StatusBadRequest)
						return
					}
					app.Config.Categories = append(app.Config.Categories[:i], app.Config.Categories[i+1:]...)
					found = true
					break
				}
			}
			app.ConfigMu.Unlock()

			if !found {
				http.Error(w, "Category not found", http.StatusNotFound)
				return
			}

			if err := config.SaveConfig(app); err != nil {
				log.Printf("Error saving config: %v", err)
				config.ReloadConfig(app)
				http.Error(w, "Failed to save config", http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})

		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

// AdminIconsHandler lists available icon files.
func AdminIconsHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		entries, err := os.ReadDir(app.IconsPath)
		if err != nil {
			log.Printf("Error reading icons directory: %v", err)
			http.Error(w, "Failed to list icons", http.StatusInternalServerError)
			return
		}

		var icons []string
		for _, entry := range entries {
			if !entry.IsDir() {
				name := entry.Name()
				// Only include image files
				if strings.HasSuffix(name, ".svg") ||
					strings.HasSuffix(name, ".png") ||
					strings.HasSuffix(name, ".jpg") ||
					strings.HasSuffix(name, ".jpeg") ||
					strings.HasSuffix(name, ".webp") ||
					strings.HasSuffix(name, ".ico") {
					icons = append(icons, name)
				}
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(icons)
	}
}

// validateSVGContent checks SVG content for dangerous XSS patterns.
func validateSVGContent(content []byte) error {
	contentStr := strings.ToLower(string(content))
	dangerousPatterns := []string{
		"<script", "javascript:", "vbscript:", "data:text/html", "data:image/svg+xml",
		"onerror", "onload", "onclick", "onmouseover", "onmouseout",
		"onfocus", "onblur", "oninput", "onchange", "onsubmit",
		"onkeydown", "onkeyup", "onkeypress", "onmousedown", "onmouseup",
		"ondblclick", "oncontextmenu", "ondrag", "ondragend", "ondragenter",
		"ondragleave", "ondragover", "ondragstart", "ondrop", "onscroll",
		"onwheel", "oncopy", "oncut", "onpaste", "onanimationend",
		"onanimationstart", "ontransitionend", "onresize", "ontoggle",
		"onbegin", "onend", "onrepeat",
		"<foreignobject", "<iframe", "<embed", "<object", "<handler",
		"expression(",
	}
	for _, pattern := range dangerousPatterns {
		if strings.Contains(contentStr, pattern) {
			return fmt.Errorf("SVG contains potentially unsafe content: %s", pattern)
		}
	}
	return nil
}

// AdminIconUploadHandler handles icon file uploads.
func AdminIconUploadHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Parse multipart form (max 5MB)
		if err := r.ParseMultipartForm(5 << 20); err != nil {
			http.Error(w, "File too large or invalid form", http.StatusBadRequest)
			return
		}

		file, header, err := r.FormFile("icon")
		if err != nil {
			http.Error(w, "No file uploaded", http.StatusBadRequest)
			return
		}
		defer file.Close()

		// Validate file extension
		ext := strings.ToLower(filepath.Ext(header.Filename))
		validExts := map[string]bool{".svg": true, ".png": true, ".jpg": true, ".jpeg": true, ".webp": true, ".ico": true}
		if !validExts[ext] {
			http.Error(w, "Invalid file type. Allowed: svg, png, jpg, jpeg, webp, ico", http.StatusBadRequest)
			return
		}

		// Sanitize filename
		filename := strings.ToLower(header.Filename)
		filename = strings.ReplaceAll(filename, " ", "-")
		filename = filepath.Base(filename)

		// SVG XSS validation
		if ext == ".svg" {
			content, err := io.ReadAll(file)
			if err != nil {
				http.Error(w, "Failed to read file", http.StatusInternalServerError)
				return
			}
			if err := validateSVGContent(content); err != nil {
				http.Error(w, "SVG contains potentially unsafe content", http.StatusBadRequest)
				return
			}
			dstPath := filepath.Join(app.IconsPath, filename)
			cleanDst := filepath.Clean(dstPath)
			cleanBase := filepath.Clean(app.IconsPath)
			if !strings.HasPrefix(cleanDst, cleanBase) {
				http.Error(w, "Invalid filename", http.StatusBadRequest)
				return
			}
			if err := os.WriteFile(dstPath, content, 0644); err != nil {
				log.Printf("Error writing SVG icon file: %v", err)
				http.Error(w, "Failed to save icon", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"filename": filename, "status": "uploaded"})
			return
		}

		// Create destination file with path traversal check
		dstPath := filepath.Join(app.IconsPath, filename)
		cleanDst := filepath.Clean(dstPath)
		cleanBase := filepath.Clean(app.IconsPath)
		if !strings.HasPrefix(cleanDst, cleanBase) {
			http.Error(w, "Invalid filename", http.StatusBadRequest)
			return
		}
		dst, err := os.Create(dstPath)
		if err != nil {
			log.Printf("Error creating icon file: %v", err)
			http.Error(w, "Failed to save icon", http.StatusInternalServerError)
			return
		}
		defer dst.Close()

		// Copy file
		if _, err := io.Copy(dst, file); err != nil {
			log.Printf("Error writing icon file: %v", err)
			http.Error(w, "Failed to save icon", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"filename": filename, "status": "uploaded"})
	}
}

// Dashboard icons cache
var (
	dashboardIconsCache     []string
	dashboardIconsCacheTime time.Time
	dashboardIconsMu        sync.Mutex
	dashboardIconsCacheTTL  = 24 * time.Hour
	validIconName           = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
)

// AdminDashboardIconsHandler returns the list of available icons from dashboard-icons.
func AdminDashboardIconsHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		dashboardIconsMu.Lock()
		if dashboardIconsCache != nil && time.Since(dashboardIconsCacheTime) < dashboardIconsCacheTTL {
			cached := dashboardIconsCache
			dashboardIconsMu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(cached)
			return
		}
		dashboardIconsMu.Unlock()

		resp, err := app.HTTPClient.Get("https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/tree.json")
		if err != nil {
			log.Printf("Error fetching dashboard icons index: %v", err)
			http.Error(w, "Failed to fetch icon index", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			http.Error(w, "Failed to fetch icon index", http.StatusBadGateway)
			return
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
		if err != nil {
			http.Error(w, "Failed to read icon index", http.StatusBadGateway)
			return
		}

		var tree map[string][]string
		if err := json.Unmarshal(body, &tree); err != nil {
			http.Error(w, "Failed to parse icon index", http.StatusBadGateway)
			return
		}

		svgList := tree["svg"]
		names := make([]string, 0, len(svgList))
		for _, entry := range svgList {
			name := strings.TrimSuffix(entry, ".svg")
			if name != "" {
				names = append(names, name)
			}
		}

		dashboardIconsMu.Lock()
		dashboardIconsCache = names
		dashboardIconsCacheTime = time.Now()
		dashboardIconsMu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(names)
	}
}

// AdminIconDownloadHandler downloads an icon from dashboard-icons and saves it locally.
func AdminIconDownloadHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		if req.Name == "" || !validIconName.MatchString(req.Name) {
			http.Error(w, "Invalid icon name", http.StatusBadRequest)
			return
		}

		iconURL := "https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/svg/" + req.Name + ".svg"
		resp, err := app.HTTPClient.Get(iconURL)
		if err != nil {
			log.Printf("Error downloading dashboard icon %s: %v", req.Name, err)
			http.Error(w, "Failed to download icon", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			http.Error(w, "Icon not found", http.StatusNotFound)
			return
		}

		content, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			http.Error(w, "Failed to read icon", http.StatusBadGateway)
			return
		}

		ct := resp.Header.Get("Content-Type")
		if !strings.Contains(ct, "svg") && !strings.Contains(ct, "xml") && !strings.Contains(ct, "octet-stream") {
			http.Error(w, "Unexpected content type", http.StatusBadRequest)
			return
		}

		if err := validateSVGContent(content); err != nil {
			log.Printf("Dashboard icon %s failed SVG validation: %v", req.Name, err)
			http.Error(w, "Icon failed safety validation", http.StatusBadRequest)
			return
		}

		filename := req.Name + ".svg"
		dstPath := filepath.Join(app.IconsPath, filename)
		cleanDst := filepath.Clean(dstPath)
		cleanBase := filepath.Clean(app.IconsPath)
		if !strings.HasPrefix(cleanDst, cleanBase) {
			http.Error(w, "Invalid icon name", http.StatusBadRequest)
			return
		}

		if err := os.WriteFile(dstPath, content, 0644); err != nil {
			log.Printf("Error saving dashboard icon %s: %v", req.Name, err)
			http.Error(w, "Failed to save icon", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"filename": filename, "status": "downloaded"})
	}
}

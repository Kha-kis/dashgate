package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"dashgate/internal/database"
	"dashgate/internal/discovery"
	"dashgate/internal/models"
	"dashgate/internal/server"
	"dashgate/internal/urlvalidation"
)

// DockerDiscoveryHandler manages Docker container discovery settings.
func DockerDiscoveryHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			app.DiscoveryMu.Lock()
			enabled := app.DockerDiscovery.Enabled
			app.DiscoveryMu.Unlock()

			app.SysConfigMu.RLock()
			socketPath := app.SystemConfig.DockerSocketPath
			app.SysConfigMu.RUnlock()

			status := map[string]interface{}{
				"enabled":     enabled,
				"socketPath":  socketPath,
				"appCount":    len(app.DockerDiscovery.GetApps()),
				"envOverride": app.DockerDiscoveryEnvOverride,
			}
			respondJSON(w, http.StatusOK, status)

		case http.MethodPost:
			// Trigger manual refresh
			go discovery.DiscoverDockerApps(app)
			respondJSON(w, http.StatusOK, map[string]string{"status": "refresh triggered"})

		case http.MethodPut:
			// Update settings (only works if not controlled by env var)
			if app.DockerDiscoveryEnvOverride {
				respondError(w, http.StatusConflict, "Docker discovery is controlled by environment variables")
				return
			}

			var req struct {
				Enabled    bool   `json:"enabled"`
				SocketPath string `json:"socketPath"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				respondError(w, http.StatusBadRequest, "Invalid JSON")
				return
			}

			// Update system config
			app.SysConfigMu.Lock()
			app.SystemConfig.DockerDiscoveryEnabled = req.Enabled
			if req.SocketPath != "" {
				app.SystemConfig.DockerSocketPath = req.SocketPath
			}
			app.SysConfigMu.Unlock()

			// Save to database
			if err := database.SaveSystemConfig(app); err != nil {
				log.Printf("Failed to save discovery config: %v", err)
				respondError(w, http.StatusInternalServerError, "Failed to save configuration")
				return
			}

			// Start or stop discovery loop
			if req.Enabled {
				discovery.StartDockerDiscoveryLoop(app)
			} else {
				discovery.StopDockerDiscoveryLoop(app)
			}

			app.DiscoveryMu.Lock()
			enabled := app.DockerDiscovery.Enabled
			app.DiscoveryMu.Unlock()

			respondJSON(w, http.StatusOK, map[string]interface{}{
				"status":  "updated",
				"enabled": enabled,
			})

		default:
			respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	}
}

// TraefikDiscoveryHandler manages Traefik router discovery settings.
func TraefikDiscoveryHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			app.DiscoveryMu.Lock()
			enabled := app.TraefikDiscovery.Enabled
			app.DiscoveryMu.Unlock()

			app.SysConfigMu.RLock()
			traefikURL := app.SystemConfig.TraefikURL
			traefikUsername := app.SystemConfig.TraefikUsername
			hasPassword := app.SystemConfig.TraefikPassword != ""
			app.SysConfigMu.RUnlock()

			status := map[string]interface{}{
				"enabled":     enabled,
				"url":         traefikURL,
				"username":    traefikUsername,
				"hasPassword": hasPassword,
				"appCount":    len(app.TraefikDiscovery.GetApps()),
				"envOverride": app.TraefikDiscoveryEnvOverride,
			}
			respondJSON(w, http.StatusOK, status)

		case http.MethodPost:
			// Trigger manual refresh
			go discovery.DiscoverTraefikApps(app)
			respondJSON(w, http.StatusOK, map[string]string{"status": "refresh triggered"})

		case http.MethodPut:
			if app.TraefikDiscoveryEnvOverride {
				respondError(w, http.StatusConflict, "Traefik discovery is controlled by environment variables")
				return
			}

			var req struct {
				Enabled  bool   `json:"enabled"`
				URL      string `json:"url"`
				Username string `json:"username"`
				Password string `json:"password"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				respondError(w, http.StatusBadRequest, "Invalid JSON")
				return
			}

			if req.URL != "" {
				if err := urlvalidation.ValidateDiscoveryURL(req.URL); err != nil {
					respondError(w, http.StatusBadRequest, "Invalid URL: "+err.Error())
					return
				}
			}

			// Update system config
			app.SysConfigMu.Lock()
			app.SystemConfig.TraefikDiscoveryEnabled = req.Enabled
			app.SystemConfig.TraefikURL = req.URL
			app.SystemConfig.TraefikUsername = req.Username
			if req.Password != "" {
				app.SystemConfig.TraefikPassword = req.Password
			}
			app.SysConfigMu.Unlock()

			// Save to database
			if err := database.SaveSystemConfig(app); err != nil {
				log.Printf("Failed to save discovery config: %v", err)
				respondError(w, http.StatusInternalServerError, "Failed to save configuration")
				return
			}

			// Start or stop discovery loop
			if req.Enabled && req.URL != "" {
				discovery.StartTraefikDiscoveryLoop(app)
			} else {
				discovery.StopTraefikDiscoveryLoop(app)
			}

			app.DiscoveryMu.Lock()
			enabled := app.TraefikDiscovery.Enabled
			app.DiscoveryMu.Unlock()

			respondJSON(w, http.StatusOK, map[string]interface{}{
				"status":  "updated",
				"enabled": enabled,
			})

		default:
			respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	}
}

// NginxDiscoveryHandler manages Nginx config discovery settings.
func NginxDiscoveryHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			app.DiscoveryMu.Lock()
			enabled := app.NginxDiscovery.Enabled
			app.DiscoveryMu.Unlock()

			app.SysConfigMu.RLock()
			configPath := app.SystemConfig.NginxConfigPath
			app.SysConfigMu.RUnlock()

			status := map[string]interface{}{
				"enabled":     enabled,
				"configPath":  configPath,
				"appCount":    len(app.NginxDiscovery.GetApps()),
				"envOverride": app.NginxDiscoveryEnvOverride,
			}
			respondJSON(w, http.StatusOK, status)

		case http.MethodPost:
			go discovery.DiscoverNginxApps(app)
			respondJSON(w, http.StatusOK, map[string]string{"status": "refresh triggered"})

		case http.MethodPut:
			if app.NginxDiscoveryEnvOverride {
				respondError(w, http.StatusConflict, "Nginx discovery is controlled by environment variables")
				return
			}

			var req struct {
				Enabled    bool   `json:"enabled"`
				ConfigPath string `json:"configPath"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				respondError(w, http.StatusBadRequest, "Invalid JSON")
				return
			}

			if req.ConfigPath != "" {
				if err := urlvalidation.ValidateNginxConfigPath(req.ConfigPath); err != nil {
					respondError(w, http.StatusBadRequest, "Invalid config path: "+err.Error())
					return
				}
			}

			app.SysConfigMu.Lock()
			app.SystemConfig.NginxDiscoveryEnabled = req.Enabled
			if req.ConfigPath != "" {
				app.SystemConfig.NginxConfigPath = req.ConfigPath
			}
			app.SysConfigMu.Unlock()

			if err := database.SaveSystemConfig(app); err != nil {
				log.Printf("Failed to save discovery config: %v", err)
				respondError(w, http.StatusInternalServerError, "Failed to save configuration")
				return
			}

			if req.Enabled {
				discovery.StartNginxDiscoveryLoop(app)
			} else {
				discovery.StopNginxDiscoveryLoop(app)
			}

			app.DiscoveryMu.Lock()
			enabled := app.NginxDiscovery.Enabled
			app.DiscoveryMu.Unlock()

			respondJSON(w, http.StatusOK, map[string]interface{}{
				"status":  "updated",
				"enabled": enabled,
			})

		default:
			respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	}
}

// NPMDiscoveryHandler manages Nginx Proxy Manager discovery settings.
func NPMDiscoveryHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			app.DiscoveryMu.Lock()
			enabled := app.NPMDiscovery.Enabled
			app.DiscoveryMu.Unlock()

			app.SysConfigMu.RLock()
			npmURL := app.SystemConfig.NPMUrl
			npmEmail := app.SystemConfig.NPMEmail
			app.SysConfigMu.RUnlock()

			status := map[string]interface{}{
				"enabled":     enabled,
				"url":         npmURL,
				"email":       npmEmail,
				"appCount":    len(app.NPMDiscovery.GetApps()),
				"envOverride": app.NPMDiscoveryEnvOverride,
			}
			respondJSON(w, http.StatusOK, status)

		case http.MethodPost:
			go discovery.DiscoverNPMApps(app)
			respondJSON(w, http.StatusOK, map[string]string{"status": "refresh triggered"})

		case http.MethodPut:
			if app.NPMDiscoveryEnvOverride {
				respondError(w, http.StatusConflict, "NPM discovery is controlled by environment variables")
				return
			}

			var req struct {
				Enabled  bool   `json:"enabled"`
				URL      string `json:"url"`
				Email    string `json:"email"`
				Password string `json:"password"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				respondError(w, http.StatusBadRequest, "Invalid JSON")
				return
			}

			if req.URL != "" {
				if err := urlvalidation.ValidateDiscoveryURL(req.URL); err != nil {
					respondError(w, http.StatusBadRequest, "Invalid URL: "+err.Error())
					return
				}
			}

			app.SysConfigMu.Lock()
			app.SystemConfig.NPMDiscoveryEnabled = req.Enabled
			app.SystemConfig.NPMUrl = req.URL
			app.SystemConfig.NPMEmail = req.Email
			if req.Password != "" {
				app.SystemConfig.NPMPassword = req.Password
			}
			npmPassword := app.SystemConfig.NPMPassword
			app.SysConfigMu.Unlock()

			if err := database.SaveSystemConfig(app); err != nil {
				log.Printf("Failed to save discovery config: %v", err)
				respondError(w, http.StatusInternalServerError, "Failed to save configuration")
				return
			}

			if req.Enabled && req.URL != "" && req.Email != "" && (req.Password != "" || npmPassword != "") {
				discovery.StartNPMDiscoveryLoop(app)
			} else {
				discovery.StopNPMDiscoveryLoop(app)
			}

			app.DiscoveryMu.Lock()
			enabled := app.NPMDiscovery.Enabled
			app.DiscoveryMu.Unlock()

			respondJSON(w, http.StatusOK, map[string]interface{}{
				"status":  "updated",
				"enabled": enabled,
			})

		default:
			respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	}
}

// CaddyDiscoveryHandler manages Caddy server discovery settings.
func CaddyDiscoveryHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			app.DiscoveryMu.Lock()
			enabled := app.CaddyDiscovery.Enabled
			app.DiscoveryMu.Unlock()

			app.SysConfigMu.RLock()
			caddyURL := app.SystemConfig.CaddyAdminURL
			caddyUsername := app.SystemConfig.CaddyUsername
			hasPassword := app.SystemConfig.CaddyPassword != ""
			app.SysConfigMu.RUnlock()

			status := map[string]interface{}{
				"enabled":     enabled,
				"url":         caddyURL,
				"username":    caddyUsername,
				"hasPassword": hasPassword,
				"appCount":    len(app.CaddyDiscovery.GetApps()),
				"envOverride": app.CaddyDiscoveryEnvOverride,
			}
			respondJSON(w, http.StatusOK, status)

		case http.MethodPost:
			go discovery.DiscoverCaddyApps(app)
			respondJSON(w, http.StatusOK, map[string]string{"status": "refresh triggered"})

		case http.MethodPut:
			if app.CaddyDiscoveryEnvOverride {
				respondError(w, http.StatusConflict, "Caddy discovery is controlled by environment variables")
				return
			}

			var req struct {
				Enabled  bool   `json:"enabled"`
				URL      string `json:"url"`
				Username string `json:"username"`
				Password string `json:"password"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				respondError(w, http.StatusBadRequest, "Invalid JSON")
				return
			}

			if req.URL != "" {
				if err := urlvalidation.ValidateDiscoveryURL(req.URL); err != nil {
					respondError(w, http.StatusBadRequest, "Invalid URL: "+err.Error())
					return
				}
			}

			app.SysConfigMu.Lock()
			app.SystemConfig.CaddyDiscoveryEnabled = req.Enabled
			app.SystemConfig.CaddyAdminURL = req.URL
			app.SystemConfig.CaddyUsername = req.Username
			if req.Password != "" {
				app.SystemConfig.CaddyPassword = req.Password
			}
			app.SysConfigMu.Unlock()

			if err := database.SaveSystemConfig(app); err != nil {
				log.Printf("Failed to save discovery config: %v", err)
				respondError(w, http.StatusInternalServerError, "Failed to save configuration")
				return
			}

			if req.Enabled && req.URL != "" {
				discovery.StartCaddyDiscoveryLoop(app)
			} else {
				discovery.StopCaddyDiscoveryLoop(app)
			}

			app.DiscoveryMu.Lock()
			enabled := app.CaddyDiscovery.Enabled
			app.DiscoveryMu.Unlock()

			respondJSON(w, http.StatusOK, map[string]interface{}{
				"status":  "updated",
				"enabled": enabled,
			})

		default:
			respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	}
}

// TraefikTestHandler tests connectivity to a Traefik API endpoint.
func TraefikTestHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}

		var req struct {
			URL      string `json:"url"`
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, "Invalid JSON")
			return
		}

		if req.URL == "" {
			respondError(w, http.StatusBadRequest, "URL is required")
			return
		}

		if err := urlvalidation.ValidateDiscoveryURL(req.URL); err != nil {
			respondError(w, http.StatusBadRequest, "Invalid URL: "+err.Error())
			return
		}

		// Test the connection by fetching the routers endpoint
		httpReq, err := http.NewRequest("GET", req.URL+"/api/http/routers", nil)
		if err != nil {
			respondJSON(w, http.StatusInternalServerError, map[string]interface{}{
				"success": false,
				"error":   fmt.Sprintf("Failed to create request: %v", err),
			})
			return
		}

		// Add basic auth if provided
		if req.Username != "" && req.Password != "" {
			httpReq.SetBasicAuth(req.Username, req.Password)
		}

		resp, err := app.HTTPClient.Do(httpReq)
		if err != nil {
			respondJSON(w, http.StatusBadGateway, map[string]interface{}{
				"success": false,
				"error":   fmt.Sprintf("Connection failed: %v", err),
			})
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusUnauthorized {
			respondJSON(w, http.StatusUnauthorized, map[string]interface{}{
				"success": false,
				"error":   "Authentication required or invalid credentials",
			})
			return
		}

		if resp.StatusCode != http.StatusOK {
			respondJSON(w, http.StatusBadGateway, map[string]interface{}{
				"success": false,
				"error":   fmt.Sprintf("Traefik API returned status %d", resp.StatusCode),
			})
			return
		}

		// Try to decode the response to validate it's a valid Traefik API
		var routers []models.TraefikRouter
		if err := json.NewDecoder(resp.Body).Decode(&routers); err != nil {
			respondJSON(w, http.StatusBadGateway, map[string]interface{}{
				"success": false,
				"error":   "Invalid response from Traefik API",
			})
			return
		}

		respondJSON(w, http.StatusOK, map[string]interface{}{
			"success":     true,
			"message":     fmt.Sprintf("Connection successful! Found %d routers", len(routers)),
			"routerCount": len(routers),
		})
	}
}

// NPMTestHandler tests connectivity to a Nginx Proxy Manager API endpoint.
func NPMTestHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}

		var req struct {
			URL      string `json:"url"`
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, "Invalid JSON")
			return
		}

		if req.URL == "" || req.Email == "" || req.Password == "" {
			respondError(w, http.StatusBadRequest, "URL, email, and password are required")
			return
		}

		if err := urlvalidation.ValidateDiscoveryURL(req.URL); err != nil {
			respondError(w, http.StatusBadRequest, "Invalid URL: "+err.Error())
			return
		}

		// Test the connection by requesting a token
		payload := map[string]string{
			"identity": req.Email,
			"secret":   req.Password,
		}
		body, err := json.Marshal(payload)
		if err != nil {
			respondJSON(w, http.StatusInternalServerError, map[string]interface{}{
				"success": false,
				"error":   "Failed to create request",
			})
			return
		}

		resp, err := app.HTTPClient.Post(req.URL+"/api/tokens", "application/json", bytes.NewReader(body))
		if err != nil {
			respondJSON(w, http.StatusBadGateway, map[string]interface{}{
				"success": false,
				"error":   fmt.Sprintf("Connection failed: %v", err),
			})
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			respondJSON(w, http.StatusUnauthorized, map[string]interface{}{
				"success": false,
				"error":   "Invalid credentials",
			})
			return
		}

		if resp.StatusCode != http.StatusOK {
			respondJSON(w, http.StatusBadGateway, map[string]interface{}{
				"success": false,
				"error":   fmt.Sprintf("NPM API returned status %d", resp.StatusCode),
			})
			return
		}

		var tokenResp struct {
			Token string `json:"token"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil || tokenResp.Token == "" {
			respondJSON(w, http.StatusBadGateway, map[string]interface{}{
				"success": false,
				"error":   "Invalid response from NPM API",
			})
			return
		}

		respondJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "Connection successful! Authentication verified",
		})
	}
}

// CaddyTestHandler tests connectivity to a Caddy Admin API endpoint.
func CaddyTestHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}

		var req struct {
			URL      string `json:"url"`
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, "Invalid JSON")
			return
		}

		if req.URL == "" {
			respondError(w, http.StatusBadRequest, "URL is required")
			return
		}

		if err := urlvalidation.ValidateDiscoveryURL(req.URL); err != nil {
			respondError(w, http.StatusBadRequest, "Invalid URL: "+err.Error())
			return
		}

		// Test the connection by fetching the config endpoint
		httpReq, err := http.NewRequest("GET", req.URL+"/config/", nil)
		if err != nil {
			respondJSON(w, http.StatusInternalServerError, map[string]interface{}{
				"success": false,
				"error":   fmt.Sprintf("Failed to create request: %v", err),
			})
			return
		}

		// Add basic auth if provided
		if req.Username != "" && req.Password != "" {
			httpReq.SetBasicAuth(req.Username, req.Password)
		}

		resp, err := app.HTTPClient.Do(httpReq)
		if err != nil {
			respondJSON(w, http.StatusBadGateway, map[string]interface{}{
				"success": false,
				"error":   fmt.Sprintf("Connection failed: %v", err),
			})
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusUnauthorized {
			respondJSON(w, http.StatusUnauthorized, map[string]interface{}{
				"success": false,
				"error":   "Authentication required or invalid credentials",
			})
			return
		}

		if resp.StatusCode != http.StatusOK {
			respondJSON(w, http.StatusBadGateway, map[string]interface{}{
				"success": false,
				"error":   fmt.Sprintf("Caddy Admin API returned status %d", resp.StatusCode),
			})
			return
		}

		respondJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "Connection successful! Caddy Admin API is accessible",
		})
	}
}

// UnraidDiscoveryHandler manages Unraid Docker discovery settings.
func UnraidDiscoveryHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			app.DiscoveryMu.Lock()
			enabled := app.UnraidDiscovery.Enabled
			app.DiscoveryMu.Unlock()

			app.SysConfigMu.RLock()
			unraidURL := app.SystemConfig.UnraidURL
			hasAPIKey := app.SystemConfig.UnraidAPIKey != ""
			app.SysConfigMu.RUnlock()

			status := map[string]interface{}{
				"enabled":     enabled,
				"url":         unraidURL,
				"hasApiKey":   hasAPIKey,
				"appCount":    len(app.UnraidDiscovery.GetApps()),
				"envOverride": app.UnraidDiscoveryEnvOverride,
			}
			respondJSON(w, http.StatusOK, status)

		case http.MethodPost:
			go discovery.DiscoverUnraidApps(app)
			respondJSON(w, http.StatusOK, map[string]string{"status": "refresh triggered"})

		case http.MethodPut:
			if app.UnraidDiscoveryEnvOverride {
				respondError(w, http.StatusConflict, "Unraid discovery is controlled by environment variables")
				return
			}

			var req struct {
				Enabled bool   `json:"enabled"`
				URL     string `json:"url"`
				APIKey  string `json:"apiKey"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				respondError(w, http.StatusBadRequest, "Invalid JSON")
				return
			}

			if req.URL != "" {
				if err := urlvalidation.ValidateDiscoveryURL(req.URL); err != nil {
					respondError(w, http.StatusBadRequest, "Invalid URL: "+err.Error())
					return
				}
			}

			app.SysConfigMu.Lock()
			app.SystemConfig.UnraidDiscoveryEnabled = req.Enabled
			app.SystemConfig.UnraidURL = req.URL
			if req.APIKey != "" {
				app.SystemConfig.UnraidAPIKey = req.APIKey
			}
			unraidAPIKey := app.SystemConfig.UnraidAPIKey
			app.SysConfigMu.Unlock()

			if err := database.SaveSystemConfig(app); err != nil {
				log.Printf("Failed to save discovery config: %v", err)
				respondError(w, http.StatusInternalServerError, "Failed to save configuration")
				return
			}

			if req.Enabled && req.URL != "" && (req.APIKey != "" || unraidAPIKey != "") {
				discovery.StartUnraidDiscoveryLoop(app)
			} else {
				discovery.StopUnraidDiscoveryLoop(app)
			}

			app.DiscoveryMu.Lock()
			enabled := app.UnraidDiscovery.Enabled
			app.DiscoveryMu.Unlock()

			respondJSON(w, http.StatusOK, map[string]interface{}{
				"status":  "updated",
				"enabled": enabled,
			})

		default:
			respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	}
}

// UnraidTestHandler tests connectivity to an Unraid GraphQL API endpoint.
func UnraidTestHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}

		var req struct {
			URL    string `json:"url"`
			APIKey string `json:"apiKey"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, "Invalid JSON")
			return
		}

		if req.URL == "" || req.APIKey == "" {
			respondError(w, http.StatusBadRequest, "URL and API key are required")
			return
		}

		if err := urlvalidation.ValidateDiscoveryURL(req.URL); err != nil {
			respondError(w, http.StatusBadRequest, "Invalid URL: "+err.Error())
			return
		}

		containerCount, err := discovery.TestUnraidConnection(app.HTTPClient, req.URL, req.APIKey)
		if err != nil {
			status := http.StatusBadGateway
			errStr := err.Error()
			switch {
			case strings.Contains(errStr, "authentication failed"):
				status = http.StatusUnauthorized
			case strings.Contains(errStr, "SSRF protection") || strings.Contains(errStr, "Invalid URL"):
				status = http.StatusBadRequest
			}
			respondJSON(w, status, map[string]interface{}{
				"success": false,
				"error":   errStr,
			})
			return
		}

		respondJSON(w, http.StatusOK, map[string]interface{}{
			"success":        true,
			"message":        fmt.Sprintf("Connection successful! Found %d container(s) with WebUI", containerCount),
			"containerCount": containerCount,
		})
	}
}

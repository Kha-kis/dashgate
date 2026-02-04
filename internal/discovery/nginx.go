package discovery

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"sort"
	"strings"
	"time"

	"dashgate/internal/models"
	"dashgate/internal/server"
	"dashgate/internal/urlvalidation"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// Package-level compiled regexes (compiled once, safe for concurrent use).
var (
	includeRe    = regexp.MustCompile(`(?m)^\s*include\s+([^;]+);`)
	serverNameRe = regexp.MustCompile(`server_name\s+([^;]+);`)
	proxyPassRe  = regexp.MustCompile(`proxy_pass\s+([^;]+);`)
	listenRe     = regexp.MustCompile(`listen\s+(\d+)(\s+ssl)?`)
	locationRe   = regexp.MustCompile(`location\s+(?:[=~^]*\s*)?(/[^\s{]*)\s*\{`)
	commentRe    = regexp.MustCompile(`(?m)#.*$`)
	titleCaser   = cases.Title(language.English)
)

// maxIncludeFileSize is the maximum size of a file that can be included (1 MB).
const maxIncludeFileSize = 1 << 20

// InitNginxDiscovery checks environment variables and system config,
// then starts the Nginx discovery loop if enabled.
func InitNginxDiscovery(app *server.App) {
	if cp := os.Getenv("NGINX_CONFIG_PATH"); cp != "" {
		app.SysConfigMu.Lock()
		app.SystemConfig.NginxConfigPath = cp
		app.SysConfigMu.Unlock()
	}

	if os.Getenv("NGINX_DISCOVERY") == "true" {
		app.NginxDiscoveryEnvOverride = true
		StartNginxDiscoveryLoop(app)
		app.SysConfigMu.RLock()
		log.Printf("Nginx discovery enabled (via environment variable, config path: %s)", app.SystemConfig.NginxConfigPath)
		app.SysConfigMu.RUnlock()
	} else if app.SystemConfig.NginxDiscoveryEnabled {
		StartNginxDiscoveryLoop(app)
		app.SysConfigMu.RLock()
		log.Printf("Nginx discovery enabled (via database config, config path: %s)", app.SystemConfig.NginxConfigPath)
		app.SysConfigMu.RUnlock()
	}
}

// StartNginxDiscoveryLoop starts the background goroutine that periodically
// parses Nginx configuration files. It is safe to call if already running.
func StartNginxDiscoveryLoop(app *server.App) {
	app.DiscoveryMu.Lock()
	defer app.DiscoveryMu.Unlock()

	if app.NginxDiscovery.Stop != nil {
		return // Already running
	}

	app.NginxDiscovery.Enabled = true
	app.NginxDiscovery.Stop = make(chan struct{})

	app.NginxDiscovery.Wg.Add(1)
	go func() {
		defer app.NginxDiscovery.Wg.Done()
		defer func() {
			if r := recover(); r != nil {
				log.Printf("Nginx discovery goroutine panicked: %v\n%s", r, debug.Stack())
			}
		}()
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		DiscoverNginxApps(app) // Initial discovery
		for {
			select {
			case <-app.NginxDiscovery.Stop:
				return
			case <-ticker.C:
				DiscoverNginxApps(app)
			}
		}
	}()
}

// StopNginxDiscoveryLoop stops the Nginx discovery background loop
// and clears all discovered apps.
func StopNginxDiscoveryLoop(app *server.App) {
	app.DiscoveryMu.Lock()
	if app.NginxDiscovery.Stop != nil {
		close(app.NginxDiscovery.Stop)
		app.NginxDiscovery.Stop = nil
	}
	app.DiscoveryMu.Unlock()

	app.NginxDiscovery.Wg.Wait()

	app.DiscoveryMu.Lock()
	app.NginxDiscovery.Enabled = false
	app.NginxDiscovery.ClearApps()
	app.DiscoveryMu.Unlock()
}

// skipExtensions contains file extensions to ignore when scanning config directories.
var skipExtensions = map[string]bool{
	".bak":      true,
	".dpkg-old": true,
	".dpkg-new": true,
	".dpkg-dist": true,
	".swp":      true,
	".swo":      true,
	".tmp":      true,
	".orig":     true,
}

// skipLocationPaths contains exact location paths that are not real apps.
var skipLocationPaths = map[string]bool{
	"/":              true,
	"/.well-known":   true,
	"/api":           true,
	"/static":        true,
	"/assets":        true,
	"/public":        true,
	"/media":         true,
	"/uploads":       true,
	"/favicon.ico":   true,
	"/robots.txt":    true,
	"/health":        true,
	"/healthz":       true,
	"/metrics":       true,
	"/stub_status":   true,
	"/nginx_status":  true,
	"/server-status": true,
}

// skipLocationPatterns contains substrings that indicate non-app paths.
// These match anywhere in the path (case-insensitive).
var skipLocationPatterns = []string{
	// Auth/security middleware (these are internal, not user-facing apps)
	"/authelia/",
	"/authentik/",
	"/api/authz",  // More specific to avoid matching /authz-app/
	"/.oauth/",
	"/oauth2/",
	// WebSocket/realtime endpoints (features of other apps)
	"/socket.io/",
	"/sockjs/",
	"/websocket/",
	// Common sub-features (not standalone apps)
	"/api/",       // API namespaces
	"/control/",   // Admin control panels
	"/download/",  // Download endpoints
	"/downloads/",
}

// skipLocationSuffixes contains path suffixes to skip.
// These only match at the end of the path.
var skipLocationSuffixes = []string{
	// API and data endpoints
	"/api",
	"/ws",
	"/wss",
	// Feed endpoints (XML content, not apps)
	"/feed",
	"/rss",
	"/atom",
	// Auth endpoints (almost never standalone apps)
	"/auth",
	"/login",
	"/logout",
	"/callback",
	"/signin",
	"/signout",
	// Protocol endpoints (features of parent apps like audiobookshelf)
	"/opds",
	"/kobo",
}

// hasRegexMetachars returns true if the path contains nginx regex location chars.
func hasRegexMetachars(path string) bool {
	return strings.ContainsAny(path, "()[]{}*+?^$|\\")
}

// shouldSkipLocation returns true if the location path should be filtered out.
func shouldSkipLocation(locPath string) bool {
	// Skip regex locations
	if hasRegexMetachars(locPath) {
		return true
	}

	cleanPath := strings.TrimRight(locPath, "/")
	if cleanPath == "" {
		cleanPath = "/"
	}

	// Skip exact matches
	if skipLocationPaths[cleanPath] {
		return true
	}

	// Skip pattern matches (case-insensitive)
	lowerPath := strings.ToLower(locPath)
	for _, pattern := range skipLocationPatterns {
		if strings.Contains(lowerPath, pattern) {
			return true
		}
	}

	// Skip suffix matches
	for _, suffix := range skipLocationSuffixes {
		if strings.HasSuffix(cleanPath, suffix) {
			return true
		}
	}

	return false
}

// dedupeAppsByBasePath removes sub-path duplicates, keeping only the shortest path per host.
// For example, if we have /lidarr and /lidarr/api, only /lidarr is kept.
func dedupeAppsByBasePath(apps []models.App) []models.App {
	if len(apps) == 0 {
		return apps
	}

	// Group apps by host
	byHost := make(map[string][]models.App)
	for _, app := range apps {
		// Extract host from URL
		host := app.URL
		if idx := strings.Index(app.URL, "://"); idx != -1 {
			host = app.URL[idx+3:]
		}
		if idx := strings.Index(host, "/"); idx != -1 {
			host = host[:idx]
		}
		byHost[host] = append(byHost[host], app)
	}

	var result []models.App
	for _, hostApps := range byHost {
		// Sort by URL length (shortest first) for consistent ordering
		sort.Slice(hostApps, func(i, j int) bool {
			return len(hostApps[i].URL) < len(hostApps[j].URL)
		})

		// Keep only apps that aren't sub-paths of earlier (shorter) apps
		var kept []string
		for _, app := range hostApps {
			normalizedURL := strings.TrimRight(app.URL, "/")
			isSubPath := false
			for _, keptURL := range kept {
				// Check if this app's URL starts with a kept URL (plus /)
				if strings.HasPrefix(normalizedURL, keptURL+"/") {
					isSubPath = true
					break
				}
			}
			if !isSubPath {
				kept = append(kept, normalizedURL)
				result = append(result, app)
			}
		}
	}

	return result
}

// resolveIncludes reads file content and inlines any include directives,
// replacing them with the contents of the included files. Depth-limited
// to prevent infinite recursion.
func resolveIncludes(content string, depth int) string {
	if depth > 3 {
		return content
	}

	return includeRe.ReplaceAllStringFunc(content, func(match string) string {
		sub := includeRe.FindStringSubmatch(match)
		if len(sub) < 2 {
			return match
		}
		includePath := strings.TrimSpace(sub[1])

		// Validate the path is safe
		if err := urlvalidation.ValidateNginxConfigPath(includePath); err != nil {
			return "# include skipped (validation failed)"
		}

		// Expand glob patterns
		matches, err := filepath.Glob(includePath)
		if err != nil || len(matches) == 0 {
			return "# include not found"
		}

		var result strings.Builder
		for _, m := range matches {
			// Resolve symlinks
			resolved, err := filepath.EvalSymlinks(m)
			if err != nil {
				log.Printf("Nginx include: cannot resolve symlinks for %s, skipping", m)
				continue
			}

			// Re-validate resolved path
			if err := urlvalidation.ValidateNginxConfigPath(resolved); err != nil {
				log.Printf("Nginx include: resolved path %s failed validation, skipping", resolved)
				continue
			}

			// Check file size before reading
			fi, err := os.Stat(resolved)
			if err != nil {
				log.Printf("Nginx include: cannot stat %s: %v", resolved, err)
				continue
			}
			if fi.Size() > maxIncludeFileSize {
				log.Printf("Nginx include: %s exceeds %d byte limit, skipping", resolved, maxIncludeFileSize)
				continue
			}

			data, err := os.ReadFile(resolved)
			if err != nil {
				log.Printf("Nginx include: cannot read %s: %v", resolved, err)
				continue
			}

			// Recursively resolve includes in the included content
			result.WriteString(resolveIncludes(string(data), depth+1))
			result.WriteString("\n")
		}
		return result.String()
	})
}

// extractBlock extracts the content between braces starting from the given
// position in the string. Comments (# to end-of-line) are ignored during
// brace counting. Returns the block content and the index after the closing
// brace, or -1 if no complete block is found.
func extractBlock(s string) (string, int) {
	braceCount := 1
	inComment := false
	for i, char := range s {
		if char == '\n' {
			inComment = false
			continue
		}
		if inComment {
			continue
		}
		if char == '#' {
			inComment = true
			continue
		}
		if char == '{' {
			braceCount++
		} else if char == '}' {
			braceCount--
			if braceCount == 0 {
				return s[:i], i
			}
		}
	}
	return s, -1
}

// isNginxConfigFile returns true if the file name looks like an Nginx config file.
func isNginxConfigFile(name string) bool {
	// Skip hidden files
	if strings.HasPrefix(name, ".") {
		return false
	}
	// Check for backup/swap file extensions
	ext := filepath.Ext(name)
	if ext != "" && skipExtensions[ext] {
		return false
	}
	// Also check full suffixes for multi-part extensions like .dpkg-old
	for suffix := range skipExtensions {
		if strings.HasSuffix(name, suffix) {
			return false
		}
	}
	return true
}

// DiscoverNginxApps parses Nginx configuration files in the configured directory
// to discover proxied applications and updates the NginxDiscovery manager.
func DiscoverNginxApps(app *server.App) {
	app.DiscoveryMu.RLock()
	enabled := app.NginxDiscovery.Enabled
	app.DiscoveryMu.RUnlock()
	if !enabled {
		return
	}

	app.SysConfigMu.RLock()
	nginxConfigPath := app.SystemConfig.NginxConfigPath
	app.SysConfigMu.RUnlock()

	if nginxConfigPath == "" {
		nginxConfigPath = "/etc/nginx/conf.d"
	}

	// Check if config directory exists
	info, err := os.Stat(nginxConfigPath)
	if err != nil {
		log.Printf("Nginx config path error: %v", err)
		return
	}
	if !info.IsDir() {
		log.Printf("Nginx config path is not a directory: %s", nginxConfigPath)
		return
	}

	var apps []models.App
	seenURLs := make(map[string]bool)

	// Process a config file: read content, resolve includes, parse server and location blocks
	processConfigFile := func(filePath string) {
		data, err := os.ReadFile(filePath)
		if err != nil {
			log.Printf("Error reading nginx config file %s: %v", filePath, err)
			return
		}

		// Inline all include directives
		configContent := resolveIncludes(string(data), 0)

		// Strip comments to prevent false matches on braces or keywords in comments
		configContent = commentRe.ReplaceAllString(configContent, "")

		// Find server blocks
		blocks := strings.Split(configContent, "server {")
		for i, block := range blocks {
			if i == 0 {
				continue // Skip content before first server block
			}

			serverBlock, _ := extractBlock(block)

			// Extract server_name
			serverNameMatch := serverNameRe.FindStringSubmatch(serverBlock)
			if serverNameMatch == nil {
				continue
			}

			serverNames := strings.Fields(serverNameMatch[1])
			if len(serverNames) == 0 {
				continue
			}

			// Skip catch-all, localhost, default
			validHost := ""
			for _, name := range serverNames {
				name = strings.TrimSpace(name)
				if name == "_" || name == "localhost" || name == "default_server" || name == "" {
					continue
				}
				validHost = name
				break
			}
			if validHost == "" {
				continue
			}

			// Determine protocol based on listen directive
			protocol := "http"
			listenMatches := listenRe.FindAllStringSubmatch(serverBlock, -1)
			for _, match := range listenMatches {
				port := match[1]
				hasSSL := len(match) > 2 && match[2] != ""
				if port == "443" || hasSSL {
					protocol = "https"
					break
				}
			}

			// Parse location blocks within this server block
			locationMatches := locationRe.FindAllStringSubmatchIndex(serverBlock, -1)
			foundLocationApps := false

			for _, locMatch := range locationMatches {
				// Extract the location path
				locPath := serverBlock[locMatch[2]:locMatch[3]]

				// Use unified skip check
				if shouldSkipLocation(locPath) {
					continue
				}

				// Extract the block content after the opening brace
				afterBrace := serverBlock[locMatch[1]:]
				locBlock, _ := extractBlock(afterBrace)

				// Check for proxy_pass within this location block
				locProxyMatch := proxyPassRe.FindStringSubmatch(locBlock)
				if locProxyMatch == nil {
					continue
				}
				upstream := strings.TrimSpace(locProxyMatch[1])

				// Build the full app URL
				appURL := fmt.Sprintf("%s://%s%s", protocol, validHost, locPath)

				// Skip duplicates
				if seenURLs[appURL] {
					continue
				}
				seenURLs[appURL] = true

				// Derive app name from the location path
				pathName := strings.TrimLeft(locPath, "/")
				pathName = strings.TrimRight(pathName, "/")
				// Take only the first path segment for the name
				if idx := strings.Index(pathName, "/"); idx > 0 {
					pathName = pathName[:idx]
				}
				appName := titleCaser.String(strings.ReplaceAll(pathName, "-", " "))
				if appName == "" {
					continue
				}

				apps = append(apps, models.App{
					Name:        appName,
					URL:         appURL,
					Description: fmt.Sprintf("Discovered via Nginx (proxied to %s)", upstream),
					Status:      "online",
				})
				foundLocationApps = true
			}

			// Fallback: if no location blocks found, use server-level proxy_pass
			if !foundLocationApps {
				proxyPassMatch := proxyPassRe.FindStringSubmatch(serverBlock)
				if proxyPassMatch == nil {
					continue
				}
				upstream := strings.TrimSpace(proxyPassMatch[1])

				appURL := fmt.Sprintf("%s://%s", protocol, validHost)
				if seenURLs[appURL] {
					continue
				}
				seenURLs[appURL] = true

				// Create app name from hostname
				name := validHost
				parts := strings.Split(validHost, ".")
				if len(parts) > 0 {
					name = titleCaser.String(strings.ReplaceAll(parts[0], "-", " "))
				}

				apps = append(apps, models.App{
					Name:        name,
					URL:         appURL,
					Description: fmt.Sprintf("Discovered via Nginx (proxied to %s)", upstream),
					Status:      "online",
				})
			}
		}
	}

	// Read all config files in the directory (not just .conf)
	entries, err := os.ReadDir(nginxConfigPath)
	if err != nil {
		log.Printf("Error reading nginx config directory: %v", err)
		return
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if isNginxConfigFile(entry.Name()) {
			processConfigFile(filepath.Join(nginxConfigPath, entry.Name()))
		}
	}

	// Deduplicate: remove sub-paths (e.g., keep /lidarr, remove /lidarr/api)
	apps = dedupeAppsByBasePath(apps)

	app.NginxDiscovery.SetApps(apps)

	log.Printf("Nginx discovery found %d apps", len(apps))
}

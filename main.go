package main

import (
	"context"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"dashgate/internal/auth"
	"dashgate/internal/config"
	"dashgate/internal/database"
	"dashgate/internal/discovery"
	"dashgate/internal/handlers"
	"dashgate/internal/health"
	"dashgate/internal/lldap"
	"dashgate/internal/middleware"
	"dashgate/internal/server"
)

// Version is set at build time via -ldflags "-X main.Version=...".
// Falls back to "dev" for local development.
var Version = "1.0.5"

// neuteredFileSystem wraps http.FileSystem to disable directory listings.
// Requests for directories without an index.html will return 404.
type neuteredFileSystem struct {
	fs http.FileSystem
}

func (nfs neuteredFileSystem) Open(path string) (http.File, error) {
	f, err := nfs.fs.Open(path)
	if err != nil {
		return nil, err
	}
	s, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if s.IsDir() {
		// Check if index.html exists in this directory
		index := strings.TrimSuffix(path, "/") + "/index.html"
		indexFile, err := nfs.fs.Open(index)
		if err != nil {
			f.Close()
			return nil, os.ErrNotExist
		}
		indexFile.Close()
	}
	return f, nil
}

func main() {
	app := server.New()
	app.Version = Version

	// Configuration paths
	app.ConfigPath = os.Getenv("CONFIG_PATH")
	if app.ConfigPath == "" {
		app.ConfigPath = "/config/config.yaml"
	}

	app.MappingsPath = strings.TrimSuffix(app.ConfigPath, ".yaml") + "-mappings.yaml"
	if mp := os.Getenv("MAPPINGS_PATH"); mp != "" {
		app.MappingsPath = mp
	}

	app.IconsPath = os.Getenv("ICONS_PATH")
	if app.IconsPath == "" {
		app.IconsPath = "/config/icons"
	}
	if err := os.MkdirAll(app.IconsPath, 0755); err != nil {
		log.Printf("Warning: could not create icons directory %s: %v", app.IconsPath, err)
	}

	// Load configuration
	if err := config.LoadConfig(app, app.ConfigPath); err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	app.ConfigMu.RLock()
	log.Printf("Loaded config with %d categories", len(app.Config.Categories))
	app.ConfigMu.RUnlock()

	config.LoadAppMappings(app)

	// Initialize auth and database
	database.InitAuthConfigDefaults(app)
	if err := database.InitDatabase(app); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	// Template directory (default: /app/templates for Docker, override with TEMPLATES_PATH)
	app.TemplateDir = "/app/templates"
	if dir := os.Getenv("TEMPLATES_PATH"); dir != "" {
		app.TemplateDir = dir
	}

	// Dev mode: reload templates from disk on every request
	app.DevMode = os.Getenv("DEV_MODE") == "true"
	if app.DevMode {
		log.Printf("Dev mode enabled — templates will reload from %s on every request", app.TemplateDir)
	}

	app.TemplateFuncMap = template.FuncMap{
		"multiply": func(a, b int) int { return a * b },
		"mod":      func(a, b int) int { return a % b },
	}

	var err error
	app.Templates, err = template.New("").Funcs(app.TemplateFuncMap).ParseGlob(filepath.Join(app.TemplateDir, "*.html"))
	if err != nil {
		log.Fatalf("Failed to load templates: %v", err)
	}

	// Background service context — cancelled during shutdown to stop all goroutines
	bgCtx, bgCancel := context.WithCancel(context.Background())
	defer bgCancel()

	// Start background services
	health.StartHealthChecker(app, bgCtx)
	database.StartSessionCleanupLoop(app, bgCtx)
	lldap.InitLLDAP(app)
	discovery.InitDockerDiscovery(app)
	discovery.InitTraefikDiscovery(app)
	discovery.InitNginxDiscovery(app)
	discovery.InitNPMDiscovery(app)
	discovery.InitCaddyDiscovery(app)

	// Security middleware
	loginRateLimit := 5
	if envLimit := os.Getenv("LOGIN_RATE_LIMIT"); envLimit != "" {
		if n, err := strconv.Atoi(envLimit); err == nil && n > 0 {
			loginRateLimit = n
		}
	}
	loginLimiter := middleware.NewRateLimiter(loginRateLimit, 15*time.Minute, bgCtx)

	// Build the handler chain: security headers → CSRF → rate limiting → mux
	mux := http.NewServeMux()

	// Page routes
	mux.HandleFunc("/", handlers.DashboardHandler(app))
	mux.HandleFunc("/login", handlers.LoginHandler(app))
	mux.HandleFunc("/setup", handlers.SetupHandler(app))
	mux.HandleFunc("/offline.html", handlers.OfflineHandler(app))
	mux.HandleFunc("/health", handlers.HealthHandler(app))
	mux.HandleFunc("/api/health", handlers.APIHealthHandler(app))
	mux.HandleFunc("/manifest.json", handlers.ManifestHandler(app))
	mux.HandleFunc("/sw.js", handlers.ServiceWorkerHandler(app))

	// Static files (default: /app/static for Docker, override with STATIC_PATH)
	staticDir := "/app/static"
	if dir := os.Getenv("STATIC_PATH"); dir != "" {
		staticDir = dir
	}

	// Seed bundled icons into persistent icons directory on first run.
	// This copies default app icons from the container image to the persistent
	// volume so they survive rebuilds alongside user-uploaded icons.
	if _, err := os.Stat(app.IconsPath); err == nil {
		bundledIconsDir := filepath.Join(staticDir, "icons")
		if entries, err := os.ReadDir(bundledIconsDir); err == nil {
			for _, entry := range entries {
				if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
					continue
				}
				dst := filepath.Join(app.IconsPath, entry.Name())
				if _, err := os.Stat(dst); err == nil {
					continue // already exists, don't overwrite user customizations
				}
				src := filepath.Join(bundledIconsDir, entry.Name())
				data, err := os.ReadFile(src)
				if err != nil {
					log.Printf("Warning: could not read bundled icon %s: %v", entry.Name(), err)
					continue
				}
				if err := os.WriteFile(dst, data, 0644); err != nil {
					log.Printf("Warning: could not seed icon %s: %v", entry.Name(), err)
				}
			}
		}
	} else {
		log.Printf("Warning: icons directory %s does not exist, skipping icon seeding", app.IconsPath)
	}

	// Serve icons with cascading lookup: persistent ICONS_PATH first, then bundled fallback.
	// This ensures user overrides in /config/icons/ take priority, while bundled icons
	// from /app/static/icons/ remain available as a fallback.
	bundledIconsFS := http.Dir(filepath.Join(staticDir, "icons"))
	persistentIconsFS := http.Dir(app.IconsPath)
	persistentIconServer := http.FileServer(neuteredFileSystem{persistentIconsFS})
	bundledIconServer := http.FileServer(neuteredFileSystem{bundledIconsFS})
	mux.Handle("/static/icons/", http.StripPrefix("/static/icons/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Try persistent path first
		f, err := persistentIconsFS.Open(r.URL.Path)
		if err == nil {
			f.Close()
			persistentIconServer.ServeHTTP(w, r)
			return
		}
		// Fall back to bundled icons
		bundledIconServer.ServeHTTP(w, r)
	})))
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(neuteredFileSystem{http.Dir(staticDir)})))

	// Auth API routes
	mux.HandleFunc("/api/auth/login", handlers.LoginHandler(app))
	mux.HandleFunc("/api/auth/logout", handlers.LogoutHandler(app))
	mux.HandleFunc("/api/auth/me", handlers.AuthMeHandler(app))
	mux.HandleFunc("/api/auth/config", handlers.AuthConfigHandler(app))

	// User preferences
	mux.HandleFunc("/api/user/preferences", handlers.UserPreferencesHandler(app))

	// OIDC routes
	mux.HandleFunc("/auth/oidc", auth.OIDCAuthHandler(app))
	mux.HandleFunc("/auth/oidc/callback", auth.OIDCCallbackHandler(app))

	// API key management
	mux.HandleFunc("/api/admin/api-keys", auth.RequireAdmin(app, handlers.APIKeysHandler(app)))

	// System config
	mux.HandleFunc("/api/admin/system-config", auth.RequireAdmin(app, handlers.SystemConfigHandler(app)))

	// Audit log
	mux.HandleFunc("/api/admin/audit-log", auth.RequireAdmin(app, handlers.AuditLogHandler(app)))

	// Admin API routes
	mux.HandleFunc("/api/admin/check", auth.RequireAdmin(app, handlers.AdminCheckHandler(app)))
	mux.HandleFunc("/api/admin/users", auth.RequireAdmin(app, handlers.AdminLLDAPUsersHandler(app)))
	mux.HandleFunc("/api/admin/groups", auth.RequireAdmin(app, handlers.AdminLLDAPGroupsHandler(app)))
	mux.HandleFunc("/api/admin/apps", auth.RequireAdmin(app, handlers.AdminAppsHandler(app)))
	mux.HandleFunc("/api/admin/apps/mapping", auth.RequireAdmin(app, handlers.AdminAppMappingHandler(app)))

	// Local user management
	mux.HandleFunc("/api/admin/local-users", auth.RequireAdmin(app, handlers.LocalUsersHandler(app)))
	mux.HandleFunc("/api/admin/local-users/", auth.RequireAdmin(app, handlers.LocalUserHandler(app)))

	// App configuration CRUD
	mux.HandleFunc("/api/admin/config/apps", auth.RequireAdmin(app, handlers.AdminConfigAppsHandler(app)))
	mux.HandleFunc("/api/admin/config/categories", auth.RequireAdmin(app, handlers.AdminCategoriesHandler(app)))
	mux.HandleFunc("/api/admin/config/icons", auth.RequireAdmin(app, handlers.AdminIconsHandler(app)))
	mux.HandleFunc("/api/admin/config/icons/upload", auth.RequireAdmin(app, handlers.AdminIconUploadHandler(app)))
	mux.HandleFunc("/api/admin/config/icons/dashboard-icons", auth.RequireAdmin(app, handlers.AdminDashboardIconsHandler(app)))
	mux.HandleFunc("/api/admin/config/icons/download", auth.RequireAdmin(app, handlers.AdminIconDownloadHandler(app)))

	// Dependencies API
	mux.HandleFunc("/api/dependencies", handlers.DependenciesHandler(app))

	// Discovered apps
	mux.HandleFunc("/api/discovered-apps", handlers.DiscoveredAppsHandler(app))
	mux.HandleFunc("/api/admin/discovered-apps", auth.RequireAdmin(app, handlers.AdminDiscoveredAppsHandler(app)))
	mux.HandleFunc("/api/admin/discovered-apps/bulk", auth.RequireAdmin(app, handlers.BulkDiscoveredAppsHandler(app)))

	// Discovery management
	mux.HandleFunc("/api/admin/docker-discovery", auth.RequireAdmin(app, handlers.DockerDiscoveryHandler(app)))
	mux.HandleFunc("/api/admin/traefik-discovery", auth.RequireAdmin(app, handlers.TraefikDiscoveryHandler(app)))
	mux.HandleFunc("/api/admin/nginx-discovery", auth.RequireAdmin(app, handlers.NginxDiscoveryHandler(app)))
	mux.HandleFunc("/api/admin/npm-discovery", auth.RequireAdmin(app, handlers.NPMDiscoveryHandler(app)))
	mux.HandleFunc("/api/admin/caddy-discovery", auth.RequireAdmin(app, handlers.CaddyDiscoveryHandler(app)))

	// Discovery test endpoints
	mux.HandleFunc("/api/admin/traefik-discovery/test", auth.RequireAdmin(app, handlers.TraefikTestHandler(app)))
	mux.HandleFunc("/api/admin/npm-discovery/test", auth.RequireAdmin(app, handlers.NPMTestHandler(app)))
	mux.HandleFunc("/api/admin/caddy-discovery/test", auth.RequireAdmin(app, handlers.CaddyTestHandler(app)))

	// Backup/Restore
	mux.HandleFunc("/api/admin/backup", auth.RequireAdmin(app, handlers.BackupHandler(app)))
	mux.HandleFunc("/api/admin/restore", auth.RequireAdmin(app, handlers.RestoreHandler(app)))

	// Apply middleware chain: body size limit → rate limiting → CSRF → security headers
	bodySizeLimited := middleware.MaxBodySize(1<<20, mux) // 1 MB max request body
	rateLimited := loginLimiter.LimitPath([]string{"/api/auth/login", "/login"}, bodySizeLimited)
	csrfProtected := middleware.CSRFProtection(rateLimited)
	handler := middleware.SecurityHeaders(csrfProtected)

	port := os.Getenv("PORT")
	if port == "" {
		port = "1738"
	}

	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	log.Printf("Starting DashGate v%s on :%s", Version, port)
	<-ctx.Done()
	log.Println("Shutting down server...")

	// Stop all background goroutines (health checker, session cleanup, rate limiter)
	bgCancel()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("Server shutdown error: %v", err)
	}
	app.DB.Close()
	log.Println("Server stopped")
}

package server

import (
	"crypto/tls"
	"database/sql"
	"html/template"
	"net"
	"net/http"
	"sync"
	"time"

	"dashgate/internal/models"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// App is the central state holder for the entire application, replacing all global variables.
type App struct {
	// Database
	DB   *sql.DB
	DBMu sync.RWMutex

	// YAML config (categories + apps)
	Config   models.Config
	ConfigMu sync.RWMutex
	ConfigPath string

	// System config (stored in DB, configurable via UI)
	SystemConfig    models.SystemConfig
	SysConfigMu     sync.RWMutex
	TrustedProxyNets []*net.IPNet
	TrustedProxyIPs  []net.IP

	// Auth
	AuthConfig   models.AuthConfig
	LDAPAuth     *models.LDAPAuthConfig
	OIDCProvider *oidc.Provider
	OAuth2Config *oauth2.Config

	// Health
	HealthCache map[string]string
	HealthMu    sync.RWMutex

	// App mappings (URL -> groups)
	AppMappings  map[string][]string
	MappingsMu   sync.RWMutex
	MappingsPath string

	// LLDAP client config
	LLDAPConfig *LLDAPConfigRef

	// Discovery managers
	DockerDiscovery  *DiscoveryManager
	TraefikDiscovery *DiscoveryManager
	NginxDiscovery   *DiscoveryManager
	NPMDiscovery     *DiscoveryManager
	CaddyDiscovery   *DiscoveryManager
	UnraidDiscovery  *DiscoveryManager
	DiscoveryMu      sync.RWMutex

	// Discovery env override flags
	DockerDiscoveryEnvOverride  bool
	TraefikDiscoveryEnvOverride bool
	NginxDiscoveryEnvOverride   bool
	NPMDiscoveryEnvOverride     bool
	CaddyDiscoveryEnvOverride   bool
	UnraidDiscoveryEnvOverride  bool

	// Discovered app overrides cache
	DiscoveredOverrides   map[string]*models.DiscoveredAppOverride
	DiscoveredOverridesMu sync.RWMutex

	// HTTP clients
	HTTPClient     *http.Client // Standard TLS verification
	InsecureClient *http.Client // For health checks only (skip TLS verify)

	// Templates
	Templates   *template.Template
	TemplateDir string
	DevMode     bool

	// Paths
	IconsPath string

	// Template functions
	TemplateFuncMap template.FuncMap

	// NPM token management
	NPMToken       string
	NPMTokenMu     sync.RWMutex
	NPMTokenExpiry time.Time

	// Encryption key for sensitive config values (AES-256, 32 bytes)
	EncryptionKey []byte

	// Version string set at startup
	Version string
}

// LLDAPConfigRef holds LLDAP connection details.
type LLDAPConfigRef struct {
	URL      string
	Username string
	Password string
	Token    string
	TokenMu  sync.RWMutex
	Expiry   time.Time
}

// DiscoveryManager tracks a single discovery source.
type DiscoveryManager struct {
	Enabled bool
	Apps    []models.App
	AppsMu  sync.RWMutex
	Stop    chan struct{}
	Wg      sync.WaitGroup
}

// NewDiscoveryManager creates a new discovery manager.
func NewDiscoveryManager() *DiscoveryManager {
	return &DiscoveryManager{
		Apps: []models.App{},
	}
}

// GetApps returns a copy of the discovered apps.
func (dm *DiscoveryManager) GetApps() []models.App {
	dm.AppsMu.RLock()
	defer dm.AppsMu.RUnlock()
	return append([]models.App{}, dm.Apps...)
}

// SetApps replaces the discovered apps.
func (dm *DiscoveryManager) SetApps(apps []models.App) {
	dm.AppsMu.Lock()
	dm.Apps = apps
	dm.AppsMu.Unlock()
}

// ClearApps removes all discovered apps.
func (dm *DiscoveryManager) ClearApps() {
	dm.AppsMu.Lock()
	dm.Apps = nil
	dm.AppsMu.Unlock()
}

// New creates and initializes a new App instance.
func New() *App {
	return &App{
		HealthCache:       make(map[string]string),
		AppMappings:       make(map[string][]string),
		DiscoveredOverrides: make(map[string]*models.DiscoveredAppOverride),
		DockerDiscovery:   NewDiscoveryManager(),
		TraefikDiscovery:  NewDiscoveryManager(),
		NginxDiscovery:    NewDiscoveryManager(),
		NPMDiscovery:      NewDiscoveryManager(),
		CaddyDiscovery:    NewDiscoveryManager(),
		UnraidDiscovery:   NewDiscoveryManager(),
		HTTPClient: &http.Client{
			Timeout: 5 * time.Second,
		},
		InsecureClient: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
		TemplateFuncMap: template.FuncMap{
			"multiply": func(a, b int) int { return a * b },
			"mod":      func(a, b int) int { return a % b },
		},
	}
}

// GetTemplates returns templates, reloading from disk in dev mode.
func (a *App) GetTemplates() *template.Template {
	if a.DevMode {
		t, err := template.New("").Funcs(a.TemplateFuncMap).ParseGlob(a.TemplateDir + "/*.html")
		if err != nil {
			return a.Templates
		}
		return t
	}
	return a.Templates
}

package models

import (
	"time"
)

// App represents a DashGate application entry.
type App struct {
	Name        string   `yaml:"name" json:"name"`
	URL         string   `yaml:"url" json:"url"`
	Icon        string   `yaml:"icon" json:"icon"`
	Groups      []string `yaml:"groups" json:"groups"`
	Description string   `yaml:"description" json:"description"`
	DependsOn   []string `yaml:"depends_on,omitempty" json:"depends_on,omitempty"`
	Status      string   `json:"status"`
}

// Category groups apps in DashGate.
type Category struct {
	Name string `yaml:"name" json:"name"`
	Apps []App  `yaml:"apps" json:"apps"`
}

// Config is the top-level YAML configuration.
type Config struct {
	Title      string     `yaml:"title"`
	Categories []Category `yaml:"categories"`
}

// TemplateData is passed to the main DashGate template.
type TemplateData struct {
	Title      string
	User       string
	Categories []Category
	Version    string
}

// LLDAPUser represents a user from the LLDAP directory (read-only).
type LLDAPUser struct {
	ID          string   `json:"id"`
	Email       string   `json:"email"`
	DisplayName string   `json:"displayName"`
	Groups      []string `json:"groups,omitempty"`
}

// LLDAPGroup represents a group from the LLDAP directory (read-only).
type LLDAPGroup struct {
	ID          int      `json:"id"`
	DisplayName string   `json:"displayName"`
	Users       []string `json:"users,omitempty"`
}

// DiscoveredAppOverride stores opt-in overrides for discovered apps.
type DiscoveredAppOverride struct {
	ID                  int      `json:"id"`
	URL                 string   `json:"url"`
	Source              string   `json:"source"`
	NameOverride        string   `json:"nameOverride"`
	URLOverride         string   `json:"urlOverride"`
	IconOverride        string   `json:"iconOverride"`
	DescriptionOverride string   `json:"descriptionOverride"`
	Category            string   `json:"category"`
	Groups              []string `json:"groups"`
	Hidden              bool     `json:"hidden"`
}

// DiscoveredAppWithOverride combines a raw discovered app with its override info.
type DiscoveredAppWithOverride struct {
	Name        string                 `json:"name"`
	URL         string                 `json:"url"`
	Icon        string                 `json:"icon"`
	Description string                 `json:"description"`
	Source      string                 `json:"source"`
	Override    *DiscoveredAppOverride `json:"override"`
}

// AppMapping maps an app URL to allowed groups.
type AppMapping struct {
	AppURL string   `json:"appUrl" yaml:"app_url"`
	Groups []string `json:"groups" yaml:"groups"`
}

// AppMappingsConfig is the YAML structure for app-to-group mappings.
type AppMappingsConfig struct {
	Mappings []AppMapping `json:"mappings" yaml:"mappings"`
}

// AuthMode determines the authentication strategy.
type AuthMode string

const (
	AuthModeAuthelia AuthMode = "authelia"
	AuthModeLocal    AuthMode = "local"
	AuthModeHybrid   AuthMode = "hybrid"
)

// AuthConfig holds runtime authentication settings.
type AuthConfig struct {
	Mode            AuthMode
	SessionDuration int    // days, default 7
	CookieName      string // default "dashgate_session"
	CookieSecure    bool   // default true
}

// LocalUser represents a user stored in the local SQLite database.
type LocalUser struct {
	ID           int       `json:"id"`
	Username     string    `json:"username"`
	Email        string    `json:"email,omitempty"`
	PasswordHash string    `json:"-"`
	DisplayName  string    `json:"displayName"`
	Groups       []string  `json:"groups"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

// AuthenticatedUser is the unified user struct used throughout the app.
type AuthenticatedUser struct {
	Username    string   `json:"username"`
	DisplayName string   `json:"displayName"`
	Email       string   `json:"email,omitempty"`
	Groups      []string `json:"groups"`
	Source      string   `json:"source"` // "proxy", "local", "ldap", "oidc", "apikey"
	IsAdmin     bool     `json:"isAdmin"`
}

// SystemConfig holds all configuration stored in the database, configurable via UI.
type SystemConfig struct {
	// General settings
	SessionDays    int    `json:"sessionDays"`
	CookieSecure   bool   `json:"cookieSecure"`
	SetupCompleted bool   `json:"setupCompleted"`
	AdminGroup     string `json:"adminGroup"`
	TrustedProxies string `json:"trustedProxies"`

	// Auth providers enabled
	ProxyAuthEnabled bool `json:"proxyAuthEnabled"`
	LocalAuthEnabled bool `json:"localAuthEnabled"`
	LDAPAuthEnabled  bool `json:"ldapAuthEnabled"`
	OIDCAuthEnabled  bool `json:"oidcAuthEnabled"`
	APIKeyEnabled    bool `json:"apiKeyEnabled"`

	// LDAP settings
	LDAPServer       string `json:"ldapServer"`
	LDAPBindDN       string `json:"ldapBindDN"`
	LDAPBindPassword string `json:"-"`
	LDAPBaseDN       string `json:"ldapBaseDN"`
	LDAPUserFilter   string `json:"ldapUserFilter"`
	LDAPGroupFilter  string `json:"ldapGroupFilter"`
	LDAPUserAttr     string `json:"ldapUserAttr"`
	LDAPEmailAttr    string `json:"ldapEmailAttr"`
	LDAPDisplayAttr  string `json:"ldapDisplayAttr"`
	LDAPGroupAttr    string `json:"ldapGroupAttr"`
	LDAPStartTLS     bool   `json:"ldapStartTLS"`
	LDAPSkipVerify   bool   `json:"ldapSkipVerify"`

	// OIDC settings
	OIDCIssuer       string `json:"oidcIssuer"`
	OIDCClientID     string `json:"oidcClientID"`
	OIDCClientSecret string `json:"-"`
	OIDCRedirectURL  string `json:"oidcRedirectURL"`
	OIDCScopes       string `json:"oidcScopes"`
	OIDCGroupsClaim  string `json:"oidcGroupsClaim"`

	// Discovery settings
	DockerDiscoveryEnabled  bool   `json:"dockerDiscoveryEnabled"`
	DockerSocketPath        string `json:"dockerSocketPath"`
	TraefikDiscoveryEnabled bool   `json:"traefikDiscoveryEnabled"`
	TraefikURL              string `json:"traefikUrl"`
	TraefikUsername         string `json:"traefikUsername"`
	TraefikPassword         string `json:"-"`
	NginxDiscoveryEnabled   bool   `json:"nginxDiscoveryEnabled"`
	NginxConfigPath         string `json:"nginxConfigPath"`
	NPMDiscoveryEnabled     bool   `json:"npmDiscoveryEnabled"`
	NPMUrl                  string `json:"npmUrl"`
	NPMEmail                string `json:"npmEmail"`
	NPMPassword             string `json:"-"`
	CaddyDiscoveryEnabled   bool   `json:"caddyDiscoveryEnabled"`
	CaddyAdminURL           string `json:"caddyAdminUrl"`
	CaddyUsername           string `json:"caddyUsername"`
	CaddyPassword           string `json:"-"`
	UnraidDiscoveryEnabled  bool   `json:"unraidDiscoveryEnabled"`
	UnraidURL               string `json:"unraidUrl"`
	UnraidAPIKey            string `json:"-"`
}

// LDAPAuthConfig holds runtime LDAP authentication configuration.
type LDAPAuthConfig struct {
	Server       string
	BindDN       string
	BindPassword string
	BaseDN       string
	UserFilter   string
	GroupFilter  string
	UserAttr     string
	EmailAttr    string
	DisplayAttr  string
	GroupAttr    string
	StartTLS     bool
	SkipVerify   bool
}

// OIDCAuthConfig holds runtime OIDC authentication configuration.
type OIDCAuthConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	GroupsClaim  string
}

// APIKey represents an API key stored in the database.
type APIKey struct {
	ID          int        `json:"id"`
	Name        string     `json:"name"`
	KeyHash     string     `json:"-"`
	KeyPrefix   string     `json:"keyPrefix"`
	UserID      int        `json:"userId,omitempty"`
	Username    string     `json:"username,omitempty"`
	Groups      []string   `json:"groups"`
	Permissions []string   `json:"permissions"`
	ExpiresAt   *time.Time `json:"expiresAt,omitempty"`
	LastUsedAt  *time.Time `json:"lastUsedAt,omitempty"`
	CreatedAt   time.Time  `json:"createdAt"`
}

// DockerContainer represents a Docker container from the API.
type DockerContainer struct {
	ID     string            `json:"Id"`
	Names  []string          `json:"Names"`
	State  string            `json:"State"`
	Labels map[string]string `json:"Labels"`
}

// TraefikRouter represents a Traefik HTTP router.
type TraefikRouter struct {
	Name        string   `json:"name"`
	Provider    string   `json:"provider"`
	Status      string   `json:"status"`
	EntryPoints []string `json:"entryPoints"`
	Rule        string   `json:"rule"`
	Service     string   `json:"service"`
}

// UnraidGraphQLResponse is the response from the Unraid GraphQL API.
type UnraidGraphQLResponse struct {
	Data struct {
		Docker struct {
			Containers []UnraidContainer `json:"containers"`
		} `json:"docker"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors,omitempty"`
}

// UnraidContainer represents a Docker container from the Unraid GraphQL API.
type UnraidContainer struct {
	ID        string            `json:"id"`
	Names     []string          `json:"names"`
	State     string            `json:"state"` // RUNNING, PAUSED, EXITED
	Labels    map[string]string `json:"labels"`
	Image     string            `json:"image"`
	AutoStart bool              `json:"autoStart"`
}

package database

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"dashgate/internal/models"
	"dashgate/internal/server"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// LoadSystemConfig reads all key-value pairs from the system_config table
// and populates app.SystemConfig.
func LoadSystemConfig(app *server.App) error {
	rows, err := app.DB.Query("SELECT key, value FROM system_config")
	if err != nil {
		return err
	}
	defer rows.Close()

	app.SysConfigMu.Lock()
	defer app.SysConfigMu.Unlock()

	found := false
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			continue
		}
		found = true

		// Decrypt sensitive values before use
		if IsSensitiveKey(key) {
			decrypted, err := DecryptValue(app.EncryptionKey, value)
			if err != nil {
				log.Printf("WARNING: failed to decrypt config key %q, using raw value: %v", key, err)
			} else {
				value = decrypted
			}
		}

		switch key {
		// General settings
		case "session_days":
			if d, err := strconv.Atoi(value); err == nil {
				app.SystemConfig.SessionDays = d
			}
		case "cookie_secure":
			app.SystemConfig.CookieSecure = value == "true"
		case "setup_completed":
			app.SystemConfig.SetupCompleted = value == "true"
		case "admin_group":
			app.SystemConfig.AdminGroup = value
		case "trusted_proxies":
			app.SystemConfig.TrustedProxies = value

		// Auth providers enabled
		case "proxy_auth_enabled":
			app.SystemConfig.ProxyAuthEnabled = value == "true"
		case "local_auth_enabled":
			app.SystemConfig.LocalAuthEnabled = value == "true"
		case "ldap_auth_enabled":
			app.SystemConfig.LDAPAuthEnabled = value == "true"
		case "oidc_auth_enabled":
			app.SystemConfig.OIDCAuthEnabled = value == "true"
		case "api_key_enabled":
			app.SystemConfig.APIKeyEnabled = value == "true"

		// LDAP settings
		case "ldap_server":
			app.SystemConfig.LDAPServer = value
		case "ldap_bind_dn":
			app.SystemConfig.LDAPBindDN = value
		case "ldap_bind_password":
			app.SystemConfig.LDAPBindPassword = value
		case "ldap_base_dn":
			app.SystemConfig.LDAPBaseDN = value
		case "ldap_user_filter":
			app.SystemConfig.LDAPUserFilter = value
		case "ldap_group_filter":
			app.SystemConfig.LDAPGroupFilter = value
		case "ldap_user_attr":
			app.SystemConfig.LDAPUserAttr = value
		case "ldap_email_attr":
			app.SystemConfig.LDAPEmailAttr = value
		case "ldap_display_attr":
			app.SystemConfig.LDAPDisplayAttr = value
		case "ldap_group_attr":
			app.SystemConfig.LDAPGroupAttr = value
		case "ldap_start_tls":
			app.SystemConfig.LDAPStartTLS = value == "true"
		case "ldap_skip_verify":
			app.SystemConfig.LDAPSkipVerify = value == "true"

		// OIDC settings
		case "oidc_issuer":
			app.SystemConfig.OIDCIssuer = value
		case "oidc_client_id":
			app.SystemConfig.OIDCClientID = value
		case "oidc_client_secret":
			app.SystemConfig.OIDCClientSecret = value
		case "oidc_redirect_url":
			app.SystemConfig.OIDCRedirectURL = value
		case "oidc_scopes":
			app.SystemConfig.OIDCScopes = value
		case "oidc_groups_claim":
			app.SystemConfig.OIDCGroupsClaim = value

		// Discovery settings
		case "docker_discovery_enabled":
			app.SystemConfig.DockerDiscoveryEnabled = value == "true"
		case "docker_socket_path":
			app.SystemConfig.DockerSocketPath = value
		case "traefik_discovery_enabled":
			app.SystemConfig.TraefikDiscoveryEnabled = value == "true"
		case "traefik_url":
			app.SystemConfig.TraefikURL = value
		case "traefik_username":
			app.SystemConfig.TraefikUsername = value
		case "traefik_password":
			app.SystemConfig.TraefikPassword = value
		case "nginx_discovery_enabled":
			app.SystemConfig.NginxDiscoveryEnabled = value == "true"
		case "nginx_config_path":
			app.SystemConfig.NginxConfigPath = value
		case "npm_discovery_enabled":
			app.SystemConfig.NPMDiscoveryEnabled = value == "true"
		case "npm_url":
			app.SystemConfig.NPMUrl = value
		case "npm_email":
			app.SystemConfig.NPMEmail = value
		case "npm_password":
			app.SystemConfig.NPMPassword = value
		case "caddy_discovery_enabled":
			app.SystemConfig.CaddyDiscoveryEnabled = value == "true"
		case "caddy_admin_url":
			app.SystemConfig.CaddyAdminURL = value
		case "caddy_username":
			app.SystemConfig.CaddyUsername = value
		case "caddy_password":
			app.SystemConfig.CaddyPassword = value
		case "unraid_discovery_enabled":
			app.SystemConfig.UnraidDiscoveryEnabled = value == "true"
		case "unraid_url":
			app.SystemConfig.UnraidURL = value
		case "unraid_api_key":
			app.SystemConfig.UnraidAPIKey = value
		}
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("error iterating system config rows: %w", err)
	}

	if !found {
		return fmt.Errorf("no config found")
	}
	return nil
}

// SaveSystemConfig persists all fields of app.SystemConfig to the database
// and then calls ApplySystemConfig to update runtime state.
func SaveSystemConfig(app *server.App) error {
	if app.DB == nil {
		return fmt.Errorf("database not initialized")
	}

	app.SysConfigMu.RLock()
	configs := map[string]string{
		// General settings
		"session_days":    strconv.Itoa(app.SystemConfig.SessionDays),
		"cookie_secure":   strconv.FormatBool(app.SystemConfig.CookieSecure),
		"setup_completed": strconv.FormatBool(app.SystemConfig.SetupCompleted),
		"admin_group":     app.SystemConfig.AdminGroup,
		"trusted_proxies": app.SystemConfig.TrustedProxies,

		// Auth providers enabled
		"proxy_auth_enabled": strconv.FormatBool(app.SystemConfig.ProxyAuthEnabled),
		"local_auth_enabled": strconv.FormatBool(app.SystemConfig.LocalAuthEnabled),
		"ldap_auth_enabled":  strconv.FormatBool(app.SystemConfig.LDAPAuthEnabled),
		"oidc_auth_enabled":  strconv.FormatBool(app.SystemConfig.OIDCAuthEnabled),
		"api_key_enabled":    strconv.FormatBool(app.SystemConfig.APIKeyEnabled),

		// LDAP settings
		"ldap_server":        app.SystemConfig.LDAPServer,
		"ldap_bind_dn":       app.SystemConfig.LDAPBindDN,
		"ldap_bind_password": app.SystemConfig.LDAPBindPassword,
		"ldap_base_dn":       app.SystemConfig.LDAPBaseDN,
		"ldap_user_filter":   app.SystemConfig.LDAPUserFilter,
		"ldap_group_filter":  app.SystemConfig.LDAPGroupFilter,
		"ldap_user_attr":     app.SystemConfig.LDAPUserAttr,
		"ldap_email_attr":    app.SystemConfig.LDAPEmailAttr,
		"ldap_display_attr":  app.SystemConfig.LDAPDisplayAttr,
		"ldap_group_attr":    app.SystemConfig.LDAPGroupAttr,
		"ldap_start_tls":     strconv.FormatBool(app.SystemConfig.LDAPStartTLS),
		"ldap_skip_verify":   strconv.FormatBool(app.SystemConfig.LDAPSkipVerify),

		// OIDC settings
		"oidc_issuer":        app.SystemConfig.OIDCIssuer,
		"oidc_client_id":     app.SystemConfig.OIDCClientID,
		"oidc_client_secret": app.SystemConfig.OIDCClientSecret,
		"oidc_redirect_url":  app.SystemConfig.OIDCRedirectURL,
		"oidc_scopes":        app.SystemConfig.OIDCScopes,
		"oidc_groups_claim":  app.SystemConfig.OIDCGroupsClaim,

		// Discovery settings
		"docker_discovery_enabled":  strconv.FormatBool(app.SystemConfig.DockerDiscoveryEnabled),
		"docker_socket_path":        app.SystemConfig.DockerSocketPath,
		"traefik_discovery_enabled": strconv.FormatBool(app.SystemConfig.TraefikDiscoveryEnabled),
		"traefik_url":               app.SystemConfig.TraefikURL,
		"traefik_username":          app.SystemConfig.TraefikUsername,
		"traefik_password":          app.SystemConfig.TraefikPassword,
		"nginx_discovery_enabled":   strconv.FormatBool(app.SystemConfig.NginxDiscoveryEnabled),
		"nginx_config_path":         app.SystemConfig.NginxConfigPath,
		"npm_discovery_enabled":     strconv.FormatBool(app.SystemConfig.NPMDiscoveryEnabled),
		"npm_url":                   app.SystemConfig.NPMUrl,
		"npm_email":                 app.SystemConfig.NPMEmail,
		"npm_password":              app.SystemConfig.NPMPassword,
		"caddy_discovery_enabled":   strconv.FormatBool(app.SystemConfig.CaddyDiscoveryEnabled),
		"caddy_admin_url":           app.SystemConfig.CaddyAdminURL,
		"caddy_username":            app.SystemConfig.CaddyUsername,
		"caddy_password":            app.SystemConfig.CaddyPassword,
		"unraid_discovery_enabled":  strconv.FormatBool(app.SystemConfig.UnraidDiscoveryEnabled),
		"unraid_url":                app.SystemConfig.UnraidURL,
		"unraid_api_key":            app.SystemConfig.UnraidAPIKey,
	}
	app.SysConfigMu.RUnlock()

	// Encrypt sensitive values before persisting
	for key, value := range configs {
		if IsSensitiveKey(key) && value != "" {
			encrypted, err := EncryptValue(app.EncryptionKey, value)
			if err != nil {
				log.Printf("WARNING: failed to encrypt config key %q, storing in plaintext: %v", key, err)
			} else {
				configs[key] = encrypted
			}
		}
	}

	tx, err := app.DB.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	for key, value := range configs {
		_, err := tx.Exec(
			"INSERT OR REPLACE INTO system_config (key, value, updated_at) VALUES (?, ?, ?)",
			key, value, time.Now(),
		)
		if err != nil {
			tx.Rollback()
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Apply to runtime config
	ApplySystemConfig(app)

	return nil
}

// ApplySystemConfig takes the current app.SystemConfig values and applies them
// to the runtime auth configuration, LDAP config, and OIDC provider.
func ApplySystemConfig(app *server.App) {
	app.SysConfigMu.Lock()
	// NOTE: Do NOT defer Unlock here. The OIDC branch manually unlocks
	// before performing network I/O to avoid blocking all config reads.

	// Apply session settings
	if app.SystemConfig.SessionDays > 0 {
		app.AuthConfig.SessionDuration = app.SystemConfig.SessionDays
	}
	app.AuthConfig.CookieSecure = app.SystemConfig.CookieSecure

	// Allow COOKIE_SECURE env var to override DB config
	if os.Getenv("COOKIE_SECURE") == "false" {
		app.AuthConfig.CookieSecure = false
	}

	// Determine auth mode from enabled providers (for backward compatibility)
	if app.SystemConfig.ProxyAuthEnabled && app.SystemConfig.LocalAuthEnabled {
		app.AuthConfig.Mode = models.AuthModeHybrid
	} else if app.SystemConfig.LocalAuthEnabled {
		app.AuthConfig.Mode = models.AuthModeLocal
	} else {
		app.AuthConfig.Mode = models.AuthModeAuthelia
	}

	// Parse and cache trusted proxy CIDRs/IPs
	app.TrustedProxyNets = nil
	app.TrustedProxyIPs = nil
	if tp := app.SystemConfig.TrustedProxies; tp != "" {
		for _, entry := range strings.Split(tp, ",") {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}
			if strings.Contains(entry, "/") {
				_, cidr, err := net.ParseCIDR(entry)
				if err == nil {
					app.TrustedProxyNets = append(app.TrustedProxyNets, cidr)
				}
			} else {
				if ip := net.ParseIP(entry); ip != nil {
					app.TrustedProxyIPs = append(app.TrustedProxyIPs, ip)
				}
			}
		}
	}

	// Initialize LDAP if enabled
	if app.SystemConfig.LDAPAuthEnabled && app.SystemConfig.LDAPServer != "" {
		app.LDAPAuth = &models.LDAPAuthConfig{
			Server:       app.SystemConfig.LDAPServer,
			BindDN:       app.SystemConfig.LDAPBindDN,
			BindPassword: app.SystemConfig.LDAPBindPassword,
			BaseDN:       app.SystemConfig.LDAPBaseDN,
			UserFilter:   app.SystemConfig.LDAPUserFilter,
			GroupFilter:  app.SystemConfig.LDAPGroupFilter,
			UserAttr:     app.SystemConfig.LDAPUserAttr,
			EmailAttr:    app.SystemConfig.LDAPEmailAttr,
			DisplayAttr:  app.SystemConfig.LDAPDisplayAttr,
			GroupAttr:    app.SystemConfig.LDAPGroupAttr,
			StartTLS:     app.SystemConfig.LDAPStartTLS,
			SkipVerify:   app.SystemConfig.LDAPSkipVerify,
		}
		// Set defaults if not specified
		if app.LDAPAuth.UserFilter == "" {
			app.LDAPAuth.UserFilter = "(uid=%s)"
		}
		if app.LDAPAuth.UserAttr == "" {
			app.LDAPAuth.UserAttr = "uid"
		}
		if app.LDAPAuth.EmailAttr == "" {
			app.LDAPAuth.EmailAttr = "mail"
		}
		if app.LDAPAuth.DisplayAttr == "" {
			app.LDAPAuth.DisplayAttr = "displayName"
		}
		if app.LDAPAuth.GroupAttr == "" {
			app.LDAPAuth.GroupAttr = "memberOf"
		}
		log.Printf("LDAP auth configured: %s", app.LDAPAuth.Server)
	} else {
		app.LDAPAuth = nil
	}

	// Initialize OIDC if enabled - copy values and release lock before network I/O
	oidcEnabled := app.SystemConfig.OIDCAuthEnabled
	oidcIssuer := app.SystemConfig.OIDCIssuer
	oidcClientID := app.SystemConfig.OIDCClientID
	oidcClientSecret := app.SystemConfig.OIDCClientSecret
	oidcRedirectURL := app.SystemConfig.OIDCRedirectURL
	oidcScopes := app.SystemConfig.OIDCScopes
	oidcGroupsClaim := app.SystemConfig.OIDCGroupsClaim

	if oidcEnabled && oidcIssuer != "" && oidcClientID != "" {
		// Release lock before network call to avoid blocking all config reads
		app.SysConfigMu.Unlock()
		InitOIDCProvider(app, oidcIssuer, oidcClientID, oidcClientSecret, oidcRedirectURL, oidcScopes, oidcGroupsClaim)
	} else {
		app.OIDCProvider = nil
		app.OAuth2Config = nil
		app.SysConfigMu.Unlock()
	}
}

// InitOIDCProvider initializes the OIDC provider and OAuth2 config.
// This function performs network I/O and must NOT be called while holding SysConfigMu.
func InitOIDCProvider(app *server.App, issuer, clientID, clientSecret, redirectURL, scopes, groupsClaim string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		log.Printf("Failed to initialize OIDC provider: %v", err)
		return
	}

	scopeList := []string{oidc.ScopeOpenID, "profile", "email"}
	if scopes != "" {
		scopeList = strings.Split(scopes, " ")
	}

	oauthConfig := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       scopeList,
	}

	if groupsClaim == "" {
		groupsClaim = "groups"
	}

	// Store results under the lock
	app.SysConfigMu.Lock()
	app.OIDCProvider = provider
	app.OAuth2Config = oauthConfig
	app.SystemConfig.OIDCGroupsClaim = groupsClaim
	app.SysConfigMu.Unlock()

	log.Printf("OIDC auth configured: %s", issuer)
}

package auth

import (
	"log"
	"net"
	"net/http"
	"strings"

	"dashgate/internal/database"
	"dashgate/internal/models"
	"dashgate/internal/server"
)

// IsRequestFromTrustedProxy checks whether the request originates from a
// configured trusted proxy IP or CIDR range.
func IsRequestFromTrustedProxy(app *server.App, r *http.Request) bool {
	app.SysConfigMu.RLock()
	nets := app.TrustedProxyNets
	ips := app.TrustedProxyIPs
	hasTrusted := app.SystemConfig.TrustedProxies != ""
	app.SysConfigMu.RUnlock()

	if !hasTrusted {
		log.Printf("Proxy auth headers rejected: no trusted proxies configured")
		return false
	}

	remoteIP := r.RemoteAddr
	if host, _, err := net.SplitHostPort(remoteIP); err == nil {
		remoteIP = host
	}
	parsedRemoteIP := net.ParseIP(remoteIP)
	if parsedRemoteIP == nil {
		log.Printf("Warning: could not parse remote IP: %s", remoteIP)
		return false
	}

	for _, cidr := range nets {
		if cidr.Contains(parsedRemoteIP) {
			return true
		}
	}

	for _, ip := range ips {
		if ip.Equal(parsedRemoteIP) {
			return true
		}
	}

	log.Printf("Proxy auth headers rejected from untrusted IP: %s", remoteIP)
	return false
}

// GetAutheliaUser extracts user information from proxy authentication headers
// (Remote-User, Remote-Groups, Remote-Name, Remote-Email) after verifying the
// request comes from a trusted proxy.
func GetAutheliaUser(app *server.App, r *http.Request) *models.AuthenticatedUser {
	username := r.Header.Get("Remote-User")
	if username == "" {
		return nil
	}

	// Verify request comes from a trusted proxy
	if !IsRequestFromTrustedProxy(app, r) {
		return nil
	}

	groupsHeader := r.Header.Get("Remote-Groups")
	var groups []string
	if groupsHeader != "" {
		groups = strings.Split(groupsHeader, ",")
		for i := range groups {
			groups[i] = strings.TrimSpace(groups[i])
		}
	}

	displayName := r.Header.Get("Remote-Name")
	if displayName == "" {
		displayName = username
	}

	email := r.Header.Get("Remote-Email")
	if err := database.UpsertProxyUser(app, username, email, displayName, database.MarshalListJSON(groups)); err != nil {
		return nil
	}

	user := &models.AuthenticatedUser{
		Username:    username,
		DisplayName: displayName,
		Email:       email,
		Groups:      groups,
		Source:      "authelia",
	}
	user.IsAdmin = CheckIsAdmin(app, user.Groups)
	return user
}

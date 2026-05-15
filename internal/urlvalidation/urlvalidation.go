package urlvalidation

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ValidateDiscoveryURL checks that a URL is safe for server-side requests.
// It blocks loopback, link-local, and cloud metadata endpoints.
// NOTE: RFC 1918 private addresses (10.x, 172.16-31.x, 192.168.x)
// are intentionally allowed for self-hosted/Unraid setups.
// For deployment contexts where this is undesirable, add additional
// caller-side restrictions before passing URLs here.
func ValidateDiscoveryURL(rawURL string) error {
	if rawURL == "" {
		return fmt.Errorf("URL is empty")
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %v", err)
	}

	// Only allow http and https schemes
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("URL scheme must be http or https")
	}

	hostname := parsed.Hostname()

	// Block cloud metadata endpoints
	metadataHosts := []string{
		"169.254.169.254",
		"metadata.google.internal",
		"metadata.google.com",
	}
	for _, h := range metadataHosts {
		if strings.EqualFold(hostname, h) {
			return fmt.Errorf("URL points to cloud metadata endpoint")
		}
	}

	// Resolve hostname and check IP
	ips, err := net.LookupHost(hostname)
	if err != nil {
		return fmt.Errorf("cannot resolve hostname %q: %v", hostname, err)
	}

	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return fmt.Errorf("URL resolves to disallowed address: %s", ipStr)
		}
		// RFC 1918 private ranges are intentionally allowed (not blocked).
		// Many self-hosted deployments use private IPs for Unraid servers.
	}

	return nil
}

// ValidateNginxConfigPath checks that a path looks like a valid Nginx config directory.
func ValidateNginxConfigPath(path string) error {
	if path == "" {
		return fmt.Errorf("path is empty")
	}
	// Block obvious dangerous paths (use trailing slash to avoid blocking e.g. /processor)
	dangerousPrefixes := []string{"/proc/", "/sys/", "/dev/", "/boot/", "/root/", "/etc/shadow", "/etc/passwd"}
	dangerousExact := []string{"/proc", "/sys", "/dev", "/boot", "/root"}
	for _, prefix := range dangerousPrefixes {
		if strings.HasPrefix(path, prefix) {
			return fmt.Errorf("path %s is not allowed", prefix)
		}
	}
	for _, exact := range dangerousExact {
		if path == exact {
			return fmt.Errorf("path %s is not allowed", exact)
		}
	}
	// Must be an absolute path
	if !strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "C:") && !strings.HasPrefix(path, "\\") {
		return fmt.Errorf("path must be absolute")
	}
	// Block path traversal
	if strings.Contains(path, "..") {
		return fmt.Errorf("path must not contain '..'")
	}
	return nil
}

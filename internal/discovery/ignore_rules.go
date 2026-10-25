package discovery

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"dashgate/internal/models"
)

var ignoreRuleSources = map[string]bool{
	"docker": true, "traefik": true, "nginx": true,
	"npm": true, "caddy": true, "unraid": true,
}

// NormalizeIgnoreRule validates a source-scoped origin and non-root path.
func NormalizeIgnoreRule(source, origin, pathPrefix string) (models.DiscoveryIgnoreRule, error) {
	if !ignoreRuleSources[source] {
		return models.DiscoveryIgnoreRule{}, fmt.Errorf("invalid discovery source")
	}
	if len(origin) > 512 || len(pathPrefix) > 2048 {
		return models.DiscoveryIgnoreRule{}, fmt.Errorf("rule is too long")
	}
	u, err := url.Parse(origin)
	if err != nil || u == nil || u.Opaque != "" || u.User != nil || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return models.DiscoveryIgnoreRule{}, fmt.Errorf("origin must be an HTTP(S) scheme and host without path or query")
	}
	normalizedOrigin, err := ignoreRuleOrigin(u)
	if err != nil {
		return models.DiscoveryIgnoreRule{}, err
	}
	if !strings.HasPrefix(pathPrefix, "/") || strings.ContainsAny(pathPrefix, "?#%") || strings.Contains(pathPrefix, "//") {
		return models.DiscoveryIgnoreRule{}, fmt.Errorf("path prefix must be an absolute plain path")
	}
	pathPrefix = strings.TrimRight(pathPrefix, "/")
	if pathPrefix == "" || pathPrefix == "/" {
		return models.DiscoveryIgnoreRule{}, fmt.Errorf("root path cannot be ignored")
	}
	for _, segment := range strings.Split(strings.TrimPrefix(pathPrefix, "/"), "/") {
		if segment == "." || segment == ".." {
			return models.DiscoveryIgnoreRule{}, fmt.Errorf("dot segments are not allowed")
		}
	}
	return models.DiscoveryIgnoreRule{Source: source, Origin: normalizedOrigin, PathPrefix: pathPrefix}, nil
}

func ignoreRuleOrigin(u *url.URL) (string, error) {
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("origin must use HTTP or HTTPS")
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || strings.ContainsAny(host, " /?#@") {
		return "", fmt.Errorf("origin host is required")
	}
	port := u.Port()
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", fmt.Errorf("invalid origin port")
		}
		if (scheme == "http" && n == 80) || (scheme == "https" && n == 443) {
			port = ""
		} else {
			port = strconv.Itoa(n)
		}
	}
	if port != "" {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return scheme + "://" + host, nil
}

// MatchesIgnoreRule uses the same predicate for previews and saved rules.
func MatchesIgnoreRule(rule models.DiscoveryIgnoreRule, app models.DiscoveredAppWithOverride) bool {
	if rule.Source != app.Source || (app.Override != nil && !app.Override.Hidden) {
		return false
	}
	u, err := url.Parse(app.URL)
	if err != nil || u == nil || u.User != nil {
		return false
	}
	origin, err := ignoreRuleOrigin(u)
	if err != nil || origin != rule.Origin {
		return false
	}
	path := u.EscapedPath()
	return path == rule.PathPrefix || strings.HasPrefix(path, rule.PathPrefix+"/")
}

// MatchIgnoreRules returns each actionable route once, using the lowest
// matching rule ID for a stable explanation when rules overlap.
func MatchIgnoreRules(rules []models.DiscoveryIgnoreRule, apps []models.DiscoveredAppWithOverride) []models.DiscoveryRuleMatch {
	matches := make([]models.DiscoveryRuleMatch, 0)
	seen := make(map[string]bool)
	for _, app := range apps {
		var lowest int64
		for _, rule := range rules {
			if !rule.Enabled || !MatchesIgnoreRule(rule, app) {
				continue
			}
			if lowest == 0 || rule.ID < lowest {
				lowest = rule.ID
			}
		}
		key := app.Source + "\x00" + app.URL
		if lowest != 0 && !seen[key] {
			matches = append(matches, models.DiscoveryRuleMatch{Source: app.Source, URL: app.URL, RuleID: lowest})
			seen[key] = true
		}
	}
	return matches
}

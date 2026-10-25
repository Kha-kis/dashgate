package discovery

import (
	"strings"
	"testing"

	"dashgate/internal/models"
)

func TestIgnoreRuleMatchesWholePathSegmentsAndSource(t *testing.T) {
	rule, err := NormalizeIgnoreRule("nginx", "HTTPS://Example.TEST:443", "/health/")
	if err != nil {
		t.Fatal(err)
	}
	if rule.Origin != "https://example.test" || rule.PathPrefix != "/health" {
		t.Fatalf("normalized rule: %+v", rule)
	}
	tests := []struct {
		name, source, url string
		override          *models.DiscoveredAppOverride
		want              bool
	}{
		{"exact", "nginx", "https://example.test/health", nil, true},
		{"child", "nginx", "https://EXAMPLE.test:443/health/live?probe=1#fragment", nil, true},
		{"sibling", "nginx", "https://example.test/healthz", nil, false},
		{"encoded slash", "nginx", "https://example.test/health%2Flive", nil, false},
		{"other source", "docker", "https://example.test/health", nil, false},
		{"other scheme", "nginx", "http://example.test/health", nil, false},
		{"other port", "nginx", "https://example.test:8443/health", nil, false},
		{"path case", "nginx", "https://example.test/Health", nil, false},
		{"malformed", "nginx", "https://example.test/%zz", nil, false},
		{"visible configured", "nginx", "https://example.test/health", &models.DiscoveredAppOverride{Hidden: false}, false},
		{"hidden configured", "nginx", "https://example.test/health", &models.DiscoveredAppOverride{Hidden: true}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := MatchesIgnoreRule(rule, models.DiscoveredAppWithOverride{Source: tc.source, URL: tc.url, Override: tc.override})
			if got != tc.want {
				t.Fatalf("match %q: got %v, want %v", tc.url, got, tc.want)
			}
		})
	}
	if !MatchesIgnoreRule(rule, models.DiscoveredAppWithOverride{Source: "nginx", URL: "https://example.test/health/new-after-rule"}) {
		t.Fatal("future discovered route should match existing rule")
	}
}

func TestIgnoreRuleRejectsBroadAndInvalidInputs(t *testing.T) {
	tests := []struct{ source, origin, prefix string }{
		{"all", "https://example.test", "/health"},
		{"nginx", "https://example.test", "/"},
		{"nginx", "https://example.test/path", "/health"},
		{"nginx", "https://user@example.test", "/health"},
		{"nginx", "https://example.test?q=1", "/health"},
		{"nginx", "ftp://example.test", "/health"},
		{"nginx", "https://example.test", "health"},
		{"nginx", "https://example.test", "/health?x=1"},
		{"nginx", "https://example.test", "/health#x"},
		{"nginx", "https://" + strings.Repeat("a", 520) + ".test", "/health"},
		{"nginx", "https://example.test", "/" + strings.Repeat("a", 2049)},
	}
	for _, tc := range tests {
		if _, err := NormalizeIgnoreRule(tc.source, tc.origin, tc.prefix); err == nil {
			t.Errorf("accepted source=%q origin=%q prefix=%q", tc.source, tc.origin, tc.prefix)
		}
	}
}

func TestIgnoreRuleOverlapsUseStableLowestID(t *testing.T) {
	rules := []models.DiscoveryIgnoreRule{
		{ID: 8, Source: "nginx", Origin: "https://example.test", PathPrefix: "/health", Enabled: true},
		{ID: 3, Source: "nginx", Origin: "https://example.test", PathPrefix: "/health/live", Enabled: true},
		{ID: 2, Source: "nginx", Origin: "https://example.test", PathPrefix: "/health", Enabled: false},
	}
	apps := []models.DiscoveredAppWithOverride{{Source: "nginx", URL: "https://example.test/health/live"}}
	matches := MatchIgnoreRules(rules, apps)
	if len(matches) != 1 || matches[0].RuleID != 3 || matches[0].Source != "nginx" || matches[0].URL != apps[0].URL {
		t.Fatalf("matches: %+v", matches)
	}
}

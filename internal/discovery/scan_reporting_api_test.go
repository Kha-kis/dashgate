package discovery

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"dashgate/internal/server"
)

func TestNPMScanReporting(t *testing.T) {
	app := server.New()
	app.NPMDiscovery.Enabled = true
	app.NPMDiscovery.EnableScan()
	DiscoverNPMApps(app)
	if got := app.NPMDiscovery.GetScanSnapshot(); got.State != server.ScanFailed || got.IssueCode != "missing_config" {
		t.Fatalf("missing config: %+v", got)
	}
	app.SystemConfig.NPMUrl = "http://192.168.1.7"
	app.SystemConfig.NPMEmail, app.SystemConfig.NPMPassword = "user", "password"
	app.HTTPClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		body := `[{"domain_names":["one.example"],"ssl_forced":true,"enabled":true,"meta":{"nginx_online":true}}]`
		if strings.Contains(req.URL.Path, "/tokens") {
			body = `{"token":"token","expires":"2099-01-01T00:00:00Z"}`
		}
		return apiResponse(200, body), nil
	})}
	DiscoverNPMApps(app)
	if got := app.NPMDiscovery.GetScanSnapshot(); got.State != server.ScanCompleted || got.LastSuccessCount != 1 {
		t.Fatalf("success: %+v", got)
	}
	app.NPMTokenMu.Lock()
	app.NPMToken = ""
	app.NPMTokenMu.Unlock()
	app.HTTPClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return apiResponse(401, `{"error":"password=secret"}`), nil
	})}
	DiscoverNPMApps(app)
	assertSafeFailure(t, app.NPMDiscovery.GetScanSnapshot(), "upstream_auth")
	for _, tc := range []struct{ name string; status int; body, code string }{
		{"server error", 500, `{"error":"secret"}`, "bad_response"},
		{"malformed token", 200, `{`, "decode_failed"},
		{"empty token", 200, `{"token":""}`, "bad_response"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app.NPMTokenMu.Lock()
			app.NPMToken = ""
			app.NPMTokenMu.Unlock()
			app.HTTPClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return apiResponse(tc.status, tc.body), nil
			})}
			DiscoverNPMApps(app)
			assertSafeFailure(t, app.NPMDiscovery.GetScanSnapshot(), tc.code)
		})
	}
}

func TestCaddyScanReporting(t *testing.T) {
	app := server.New()
	app.CaddyDiscovery.Enabled = true
	app.CaddyDiscovery.EnableScan()
	DiscoverCaddyApps(app)
	if got := app.CaddyDiscovery.GetScanSnapshot(); got.State != server.ScanFailed || got.IssueCode != "missing_config" {
		t.Fatalf("missing config: %+v", got)
	}
	app.SystemConfig.CaddyAdminURL = "http://192.168.1.7"
	app.HTTPClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return apiResponse(200, `{"srv":{"listen":[":443"],"routes":[{"match":[{"host":["one.example"]}]}]}}`), nil
	})}
	DiscoverCaddyApps(app)
	if got := app.CaddyDiscovery.GetScanSnapshot(); got.State != server.ScanCompleted || got.LastSuccessCount != 1 {
		t.Fatalf("success: %+v", got)
	}
	app.HTTPClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) { return apiResponse(403, "secret"), nil })}
	DiscoverCaddyApps(app)
	assertSafeFailure(t, app.CaddyDiscovery.GetScanSnapshot(), "upstream_auth")
}

func TestUnraidScanReporting(t *testing.T) {
	app := server.New()
	app.UnraidDiscovery.Enabled = true
	app.UnraidDiscovery.EnableScan()
	DiscoverUnraidApps(app)
	if got := app.UnraidDiscovery.GetScanSnapshot(); got.State != server.ScanFailed || got.IssueCode != "missing_config" {
		t.Fatalf("missing config: %+v", got)
	}
	app.SystemConfig.UnraidURL = "http://192.168.1.7"
	app.SystemConfig.UnraidAPIKey = "top-secret-key"
	app.HTTPClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return apiResponse(200, `{"data":{"docker":{"containers":[{"names":["/one"],"state":"RUNNING","labels":{"net.unraid.docker.webui":"http://[IP]:8080"}}]}}}`), nil
	})}
	DiscoverUnraidApps(app)
	if got := app.UnraidDiscovery.GetScanSnapshot(); got.State != server.ScanCompleted || got.LastSuccessCount != 1 {
		t.Fatalf("success: %+v", got)
	}
	app.HTTPClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return apiResponse(200, `{"errors":[{"message":"top-secret-key"}]}`), nil
	})}
	DiscoverUnraidApps(app)
	assertSafeFailure(t, app.UnraidDiscovery.GetScanSnapshot(), "bad_response")
}

func apiResponse(code int, body string) *http.Response {
	return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}
}

func assertSafeFailure(t *testing.T, scan server.DiscoveryScanSnapshot, code string) {
	t.Helper()
	data, _ := json.Marshal(scan)
	if scan.State != server.ScanFailed || scan.IssueCode != code || strings.Contains(string(data), "secret") || strings.Contains(string(data), "password") {
		t.Fatalf("unsafe failure: %s", data)
	}
}

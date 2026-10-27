package discovery

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"dashgate/internal/server"
)

func testDockerSocket(t *testing.T, status int, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "docker.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	})}
	go srv.Serve(listener)
	t.Cleanup(func() { srv.Close(); listener.Close() })
	return path
}

func TestDockerScanReporting(t *testing.T) {
	app := server.New()
	app.DockerDiscovery.Enabled = true
	app.DockerDiscovery.EnableScan()
	app.SystemConfig.DockerSocketPath = filepath.Join(t.TempDir(), "missing.sock")
	DiscoverDockerApps(app)
	if got := app.DockerDiscovery.GetScanSnapshot(); got.State != server.ScanFailed || got.IssueCode != "missing_config" {
		t.Fatalf("missing socket: %+v", got)
	}
	for _, tc := range []struct {
		status            int
		body, state, code string
		count             int
	}{
		{503, "down", "failed", "bad_response", 0},
		{200, "bad", "failed", "decode_failed", 0},
		{200, `[]`, "completed", "", 0},
		{200, `[{"Names":["/one"],"State":"running","Labels":{"dashgate.enable":"true","dashgate.url":"https://one.example"}}]`, "completed", "", 1},
		{200, `[{"Names":["/one"],"State":"running","Labels":{"homepage.name":"One","homepage.href":"https://one.example"}}]`, "completed", "", 1},
		{200, `[{"Names":["/one"],"State":"running","Labels":{"homarr.name":"One","homarr.href":"https://one.example","homarr.description":"External labels"}}]`, "completed", "", 1},
	} {
		app.SystemConfig.DockerSocketPath = testDockerSocket(t, tc.status, tc.body)
		DiscoverDockerApps(app)
		got := app.DockerDiscovery.GetScanSnapshot()
		if string(got.State) != tc.state || got.IssueCode != tc.code || got.LastSuccessCount != tc.count {
			t.Fatalf("docker case %+v: %+v", tc, got)
		}
	}
}

func TestTraefikScanReporting(t *testing.T) {
	app := server.New()
	app.TraefikDiscovery.Enabled = true
	app.TraefikDiscovery.EnableScan()
	DiscoverTraefikApps(app)
	if got := app.TraefikDiscovery.GetScanSnapshot(); got.State != server.ScanFailed || got.IssueCode != "missing_config" {
		t.Fatalf("missing URL: %+v", got)
	}
	app.SystemConfig.TraefikURL = "http://192.168.1.7"
	for _, tc := range []struct {
		status            int
		body, state, code string
		count             int
	}{
		{401, "denied", "failed", "upstream_auth", 0},
		{503, "down", "failed", "bad_response", 0},
		{200, "bad", "failed", "decode_failed", 0},
		{200, `[]`, "completed", "", 0},
		{200, "[{\"name\":\"one@docker\",\"service\":\"one\",\"rule\":\"Host(`one.example`)\",\"status\":\"enabled\"}]", "completed", "", 1},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tc.status); fmt.Fprint(w, tc.body) }))
		app.HTTPClient = &http.Client{Transport: &redirectTransport{target: srv.URL}}
		DiscoverTraefikApps(app)
		srv.Close()
		got := app.TraefikDiscovery.GetScanSnapshot()
		if string(got.State) != tc.state || got.IssueCode != tc.code || got.LastSuccessCount != tc.count {
			t.Fatalf("traefik case %+v: %+v", tc, got)
		}
	}
	app.SystemConfig.TraefikURL = "http://127.0.0.1"
	DiscoverTraefikApps(app)
	if got := app.TraefikDiscovery.GetScanSnapshot(); got.State != server.ScanFailed || got.IssueCode != "invalid_config" {
		t.Fatalf("invalid URL: %+v", got)
	}
}

func TestDiscoveryRefreshOverlap(t *testing.T) {
	app := server.New()
	app.TraefikDiscovery.Enabled = true
	app.TraefikDiscovery.EnableScan()
	app.SystemConfig.TraefikURL = "http://192.168.1.7"
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	app.HTTPClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		close(entered)
		<-release
		return &http.Response{StatusCode: 200, Body: http.NoBody, Header: make(http.Header)}, nil
	})}
	go func() { DiscoverTraefikApps(app); close(done) }()
	<-entered
	DiscoverTraefikApps(app)
	if got := app.TraefikDiscovery.GetScanSnapshot().State; got != server.ScanScanning {
		t.Fatalf("overlap state = %q", got)
	}
	app.TraefikDiscovery.DisableScan()
	app.TraefikDiscovery.EnableScan()
	close(release)
	<-done
	if got := app.TraefikDiscovery.GetScanSnapshot(); got.State != server.ScanWaiting || got.LastSuccessCount != 0 {
		t.Fatalf("old refresh republished: %+v", got)
	}
}

func TestDiscoveryConcurrentStop(t *testing.T) {
	app := server.New()
	app.DockerDiscovery.Enabled = true
	app.DockerDiscovery.EnableScan()
	stop := make(chan struct{})
	app.DockerDiscovery.Stop = stop
	app.DockerDiscovery.Wg.Add(1)
	firstDone := make(chan struct{})
	go func() { StopDockerDiscoveryLoop(app); close(firstDone) }()
	<-stop
	secondDone := make(chan any, 1)
	go func() {
		defer func() {
			panicValue := recover()
			if panicValue != nil {
				app.DiscoveryMu.Unlock()
			}
			secondDone <- panicValue
		}()
		StopDockerDiscoveryLoop(app)
	}()
	time.Sleep(20 * time.Millisecond)
	app.DockerDiscovery.Wg.Done()
	<-firstDone
	if panicValue := <-secondDone; panicValue != nil {
		t.Fatalf("concurrent stop panicked: %v", panicValue)
	}
	if got := app.DockerDiscovery.GetScanSnapshot().State; got != server.ScanDisabled {
		t.Fatalf("stopped state = %q", got)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type redirectTransport struct{ target string }

func (r *redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	target, _ := http.NewRequest(req.Method, r.target+req.URL.Path, nil)
	return http.DefaultTransport.RoundTrip(target)
}

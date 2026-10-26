package health

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"dashgate/internal/models"
	"dashgate/internal/server"
)

func TestHealthChecksOnlyConfiguredDiscoveredApps(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	app := server.New()
	app.DockerDiscovery.Enabled = true
	app.DockerDiscovery.SetApps([]models.App{{Name: "unreviewed", URL: srv.URL}})
	RunHealthChecks(app)
	if got := requests.Load(); got != 0 {
		t.Fatalf("unreviewed discovery caused %d health requests", got)
	}

	app.DiscoveredOverrides[srv.URL] = &models.DiscoveredAppOverride{URL: srv.URL, Source: "docker"}
	RunHealthChecks(app)
	if got := requests.Load(); got != 1 {
		t.Fatalf("configured discovery caused %d health requests, want 1", got)
	}
}

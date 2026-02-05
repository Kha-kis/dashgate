package health

import (
	"context"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"dashgate/internal/discovery"
	"dashgate/internal/server"
)

// isHealthy returns true if the HTTP status code indicates the service is running.
// 2xx/3xx are healthy, and 401/403 count as online (service is up but requires auth).
func isHealthy(statusCode int) bool {
	if statusCode >= 200 && statusCode < 400 {
		return true
	}
	return statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden
}

// CheckHealth performs a HEAD request against the given URL and returns "online" or "offline".
// Some apps (e.g. File Browser) don't handle HEAD requests properly, so if HEAD returns a
// non-success status we fall back to GET before declaring the service offline.
// This is the ONLY place where InsecureClient (TLS skip verify) is used, because health
// checks need to reach services with self-signed certificates.
func CheckHealth(app *server.App, url string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "HEAD", url, nil)
	if err != nil {
		return "offline"
	}

	resp, err := app.InsecureClient.Do(req)
	if err != nil {
		return "offline"
	}
	resp.Body.Close()

	if isHealthy(resp.StatusCode) {
		return "online"
	}

	// HEAD failed with a non-success status — retry with GET as a fallback.
	// Use a fresh timeout so the GET attempt gets its own full window.
	getCtx, getCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer getCancel()

	req, err = http.NewRequestWithContext(getCtx, "GET", url, nil)
	if err != nil {
		return "offline"
	}

	resp, err = app.InsecureClient.Do(req)
	if err != nil {
		return "offline"
	}
	// Drain a small amount to allow connection reuse, then close.
	io.CopyN(io.Discard, resp.Body, 4096)
	resp.Body.Close()

	if isHealthy(resp.StatusCode) {
		return "online"
	}
	return "offline"
}

// StartHealthChecker starts a background goroutine that runs health checks every 30 seconds.
// The goroutine stops when the provided context is cancelled.
func StartHealthChecker(app *server.App, ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	go func() {
		defer ticker.Stop()
		defer func() {
			if r := recover(); r != nil {
				log.Printf("Health checker recovered from panic: %v", r)
			}
		}()
		RunHealthChecks(app)
		for {
			select {
			case <-ctx.Done():
				log.Println("Health checker stopped")
				return
			case <-ticker.C:
				RunHealthChecks(app)
			}
		}
	}()
}

// RunHealthChecks concurrently checks the health of all configured app URLs
// and updates the app.HealthCache.
func RunHealthChecks(app *server.App) {
	var wg sync.WaitGroup
	results := make(chan struct {
		url    string
		status string
	}, 100)

	app.ConfigMu.RLock()
	urls := make(map[string]bool)
	for _, cat := range app.Config.Categories {
		for _, a := range cat.Apps {
			urls[a.URL] = true
		}
	}
	app.ConfigMu.RUnlock()

	// Include discovered apps in health checks
	for _, dApp := range discovery.GetAllRawDiscoveredApps(app) {
		// Use URLOverride if set, otherwise use discovered URL
		url := dApp.URL
		if dApp.Override != nil && dApp.Override.URLOverride != "" {
			url = dApp.Override.URLOverride
		}
		urls[url] = true
	}

	sem := make(chan struct{}, 20)

	for url := range urls {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			status := CheckHealth(app, u)
			results <- struct {
				url    string
				status string
			}{u, status}
		}(url)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	newCache := make(map[string]string)
	for result := range results {
		newCache[result.url] = result.status
	}

	app.HealthMu.Lock()
	app.HealthCache = newCache
	app.HealthMu.Unlock()

	log.Printf("Health check complete: %d services checked", len(newCache))
}

// GetHealthStatus returns the cached health status for the given URL.
// Returns "unknown" if no status has been recorded yet.
func GetHealthStatus(app *server.App, url string) string {
	app.HealthMu.RLock()
	defer app.HealthMu.RUnlock()
	if status, ok := app.HealthCache[url]; ok {
		return status
	}
	return "unknown"
}

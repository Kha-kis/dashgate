package discovery

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"dashgate/internal/server"
)

func TestNginxScanReporting(t *testing.T) {
	app := server.New()
	app.NginxDiscovery.Enabled = true
	app.NginxDiscovery.EnableScan()
	app.SystemConfig.NginxConfigPath = filepath.Join(t.TempDir(), "missing")
	DiscoverNginxApps(app)
	if got := app.NginxDiscovery.GetScanSnapshot(); got.State != server.ScanFailed || got.IssueCode != "missing_config" {
		t.Fatalf("missing root: %+v", got)
	}
	dir := t.TempDir()
	app.SystemConfig.NginxConfigPath = dir
	DiscoverNginxApps(app)
	if got := app.NginxDiscovery.GetScanSnapshot(); got.State != server.ScanCompleted || got.LastSuccessCount != 0 {
		t.Fatalf("empty root: %+v", got)
	}
	good := filepath.Join(dir, "good.conf")
	bad := filepath.Join(dir, "unreadable.conf")
	content := "server { listen 443 ssl; server_name one.example; location /app { proxy_pass http://upstream; } location /health { proxy_pass http://upstream; } }"
	if err := os.WriteFile(good, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bad, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	app.NginxDiscovery.RunScan(func() (server.DiscoveryScanResult, string) {
		return scanNginxApps(app, func(path string) ([]byte, error) {
			if path == bad {
				return nil, &os.PathError{Op: "open", Path: path, Err: fs.ErrPermission}
			}
			return os.ReadFile(path)
		})
	})
	if got := app.NginxDiscovery.GetScanSnapshot(); got.State != server.ScanWarning || got.WarningCount != 1 || got.IssueCode != "partial_read" || got.LastSuccessCount != 1 {
		t.Fatalf("partial result: %+v", got)
	}
	app.NginxDiscovery.RunScan(func() (server.DiscoveryScanResult, string) { return scanNginxApps(app, os.ReadFile) })
	if got := app.NginxDiscovery.GetScanSnapshot(); got.State != server.ScanCompleted || got.WarningCount != 0 || got.LastSuccessCount != 1 {
		t.Fatalf("normal result: %+v", got)
	}
}

func TestNginxScanIncludeWarning(t *testing.T) {
	dir := t.TempDir()
	includeDir := filepath.Join(dir, "includes")
	if err := os.Mkdir(includeDir, 0700); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(includeDir, "child.conf")
	if err := os.WriteFile(child, []byte("location /app { proxy_pass http://upstream; }"), 0600); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(dir, "root.conf")
	if err := os.WriteFile(root, []byte("server { server_name one.example;\ninclude "+child+";\n}"), 0600); err != nil {
		t.Fatal(err)
	}
	app := server.New()
	app.SystemConfig.NginxConfigPath = dir
	app.NginxDiscovery.EnableScan()
	app.NginxDiscovery.RunScan(func() (server.DiscoveryScanResult, string) {
		return scanNginxApps(app, func(path string) ([]byte, error) {
			if strings.HasSuffix(path, "child.conf") {
				return nil, fs.ErrPermission
			}
			return os.ReadFile(path)
		})
	})
	if got := app.NginxDiscovery.GetScanSnapshot(); got.State != server.ScanWarning || got.WarningCount != 1 {
		t.Fatalf("include warning: %+v", got)
	}
}

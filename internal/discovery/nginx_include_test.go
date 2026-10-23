package discovery

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestResolveIncludesLimitsRepeatedPermissionWarnings(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret.conf")
	public := filepath.Join(dir, "public.conf")
	if err := os.WriteFile(secret, []byte("server_name secret.example;"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(public, []byte("server_name public.example;"), 0600); err != nil {
		t.Fatal(err)
	}

	current := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	var warnings []string
	resolver := includeResolver{
		readFile: func(path string) ([]byte, error) {
			if path == secret {
				return nil, &os.PathError{Op: "open", Path: path, Err: fs.ErrPermission}
			}
			return os.ReadFile(path)
		},
		logf: func(format string, args ...any) {
			warnings = append(warnings, fmt.Sprintf(format, args...))
		},
		warnings: &includeWarningLimiter{},
		now:      func() time.Time { return current },
	}
	input := fmt.Sprintf("include %s;\ninclude %s;", secret, public)
	for range 3 {
		resolved := resolver.resolve(input, 0)
		if !strings.Contains(resolved, "server_name public.example;") || strings.Contains(resolved, "secret.example") {
			t.Fatalf("resolved includes = %q", resolved)
		}
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "permission denied") {
		t.Fatalf("warnings = %v, want one permission warning", warnings)
	}

	current = current.Add(time.Hour)
	resolver.resolve(input, 0)
	if len(warnings) != 2 {
		t.Fatalf("warnings after one hour = %d, want 2", len(warnings))
	}
}

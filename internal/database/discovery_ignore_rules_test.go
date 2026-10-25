package database

import (
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"dashgate/internal/models"
	"dashgate/internal/server"
)

func TestDiscoveryIgnoreRulePersistsCRUDAndStartsEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dashgate.db")
	t.Setenv("DB_PATH", path)
	app := &server.App{}
	if err := InitDatabase(app); err != nil {
		t.Fatal(err)
	}
	defer app.DB.Close()
	if rows, err := ListDiscoveryIgnoreRules(app); err != nil || len(rows) != 0 {
		t.Fatalf("initial rules: %+v, %v", rows, err)
	}
	rule, err := CreateDiscoveryIgnoreRule(app, models.DiscoveryIgnoreRule{
		Source: "nginx", Origin: "https://example.test", PathPrefix: "/health", Enabled: true,
	})
	if err != nil || rule.ID <= 0 {
		t.Fatalf("create: %+v, %v", rule, err)
	}
	rule.Enabled = false
	if err := UpdateDiscoveryIgnoreRule(app, rule); err != nil {
		t.Fatal(err)
	}
	if err := app.DB.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := &server.App{}
	if err := InitDatabase(reopened); err != nil {
		t.Fatal(err)
	}
	defer reopened.DB.Close()
	rows, err := ListDiscoveryIgnoreRules(reopened)
	if err != nil || len(rows) != 1 || rows[0].ID != rule.ID || rows[0].Enabled ||
		rows[0].CreatedAt == "" || rows[0].UpdatedAt == "" {
		t.Fatalf("reopened rules: %+v, %v", rows, err)
	}
	if err := DeleteDiscoveryIgnoreRule(reopened, rule.ID); err != nil {
		t.Fatal(err)
	}
	if rows, err := ListDiscoveryIgnoreRules(reopened); err != nil || len(rows) != 0 {
		t.Fatalf("deleted rules: %+v, %v", rows, err)
	}
	if err := DeleteDiscoveryIgnoreRule(reopened, rule.ID); !errors.Is(err, ErrDiscoveryIgnoreRuleNotFound) {
		t.Fatalf("missing delete error: %v", err)
	}
}

func TestDiscoveryIgnoreRuleRejectsDuplicateAndLimit(t *testing.T) {
	t.Setenv("DB_PATH", filepath.Join(t.TempDir(), "dashgate.db"))
	app := &server.App{}
	if err := InitDatabase(app); err != nil {
		t.Fatal(err)
	}
	defer app.DB.Close()
	base := models.DiscoveryIgnoreRule{Source: "nginx", Origin: "https://example.test", PathPrefix: "/health", Enabled: true}
	if _, err := CreateDiscoveryIgnoreRule(app, base); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateDiscoveryIgnoreRule(app, base); !errors.Is(err, ErrDiscoveryIgnoreRuleDuplicate) {
		t.Fatalf("duplicate error: %v", err)
	}
	for i := 1; i < 100; i++ {
		next := base
		next.PathPrefix = fmt.Sprintf("/health%d", i)
		if _, err := CreateDiscoveryIgnoreRule(app, next); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
	}
	extra := base
	extra.PathPrefix = "/over-limit"
	if _, err := CreateDiscoveryIgnoreRule(app, extra); !errors.Is(err, ErrDiscoveryIgnoreRuleLimit) {
		t.Fatalf("limit error: %v", err)
	}
	if rows, err := ListDiscoveryIgnoreRules(app); err != nil || len(rows) != 100 {
		t.Fatalf("rule count: %d, %v", len(rows), err)
	}
}

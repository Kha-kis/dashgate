package database

import (
	"fmt"

	"dashgate/internal/models"
	"dashgate/internal/server"
)

// ListIgnoredDiscoveredApps returns saved inbox dismissals, including stale ones.
func ListIgnoredDiscoveredApps(app *server.App) ([]models.IgnoredDiscoveredApp, error) {
	rows, err := app.DB.Query(`SELECT source, url, name, created_at FROM ignored_discovered_apps ORDER BY created_at DESC, source, url`)
	if err != nil {
		return nil, fmt.Errorf("list ignored discovered apps: %w", err)
	}
	defer rows.Close()
	items := []models.IgnoredDiscoveredApp{}
	for rows.Next() {
		var item models.IgnoredDiscoveredApp
		if err := rows.Scan(&item.Source, &item.URL, &item.Name, &item.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan ignored discovered app: %w", err)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// DismissDiscoveredApps saves a validated batch atomically.
func DismissDiscoveredApps(app *server.App, items []models.IgnoredDiscoveredApp) error {
	tx, err := app.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, item := range items {
		if _, err := tx.Exec(`INSERT INTO ignored_discovered_apps(source,url,name) VALUES(?,?,?) ON CONFLICT(source,url) DO UPDATE SET name=excluded.name`, item.Source, item.URL, item.Name); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// RestoreIgnoredDiscoveredApps removes a batch atomically, including stale entries.
func RestoreIgnoredDiscoveredApps(app *server.App, items []models.IgnoredDiscoveredApp) error {
	tx, err := app.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, item := range items {
		if _, err := tx.Exec(`DELETE FROM ignored_discovered_apps WHERE source=? AND url=?`, item.Source, item.URL); err != nil {
			return err
		}
	}
	return tx.Commit()
}

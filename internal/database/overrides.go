package database

import (
	"encoding/json"
	"fmt"
	"log"

	"dashgate/internal/models"
	"dashgate/internal/server"
)

// LoadDiscoveredOverrides reads all discovered app overrides from the database
// and populates app.DiscoveredOverrides.
func LoadDiscoveredOverrides(app *server.App) error {
	rows, err := app.DB.Query("SELECT id, url, source, name_override, url_override, icon_override, description_override, category, groups, hidden FROM discovered_app_overrides")
	if err != nil {
		return err
	}
	defer rows.Close()

	overrides := make(map[string]*models.DiscoveredAppOverride)
	for rows.Next() {
		var o models.DiscoveredAppOverride
		var groupsJSON string
		var hiddenInt int
		if err := rows.Scan(&o.ID, &o.URL, &o.Source, &o.NameOverride, &o.URLOverride, &o.IconOverride, &o.DescriptionOverride, &o.Category, &groupsJSON, &hiddenInt); err != nil {
			log.Printf("Error scanning discovered override: %v", err)
			continue
		}
		o.Hidden = hiddenInt == 1
		if err := json.Unmarshal([]byte(groupsJSON), &o.Groups); err != nil {
			o.Groups = []string{}
		}
		overrides[o.URL] = &o
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("error iterating discovered overrides rows: %w", err)
	}

	app.DiscoveredOverridesMu.Lock()
	app.DiscoveredOverrides = overrides
	app.DiscoveredOverridesMu.Unlock()

	log.Printf("Loaded %d discovered app overrides", len(overrides))
	return nil
}

// SaveDiscoveredOverride inserts or updates a discovered app override in the database
// and updates the in-memory cache.
func SaveDiscoveredOverride(app *server.App, o *models.DiscoveredAppOverride) error {
	groupsJSON, err := json.Marshal(o.Groups)
	if err != nil {
		return fmt.Errorf("failed to marshal groups: %w", err)
	}

	hiddenInt := 0
	if o.Hidden {
		hiddenInt = 1
	}

	_, err = app.DB.Exec(`INSERT INTO discovered_app_overrides (url, source, name_override, url_override, icon_override, description_override, category, groups, hidden, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(url) DO UPDATE SET
			source=excluded.source,
			name_override=excluded.name_override,
			url_override=excluded.url_override,
			icon_override=excluded.icon_override,
			description_override=excluded.description_override,
			category=excluded.category,
			groups=excluded.groups,
			hidden=excluded.hidden,
			updated_at=CURRENT_TIMESTAMP`,
		o.URL, o.Source, o.NameOverride, o.URLOverride, o.IconOverride, o.DescriptionOverride, o.Category, string(groupsJSON), hiddenInt)
	if err != nil {
		return fmt.Errorf("failed to save discovered override: %w", err)
	}

	// Update cache
	app.DiscoveredOverridesMu.Lock()
	app.DiscoveredOverrides[o.URL] = o
	app.DiscoveredOverridesMu.Unlock()

	return nil
}

// SaveDiscoveredOverridesBatch saves multiple overrides in a single transaction.
func SaveDiscoveredOverridesBatch(app *server.App, overrides []*models.DiscoveredAppOverride) error {
	tx, err := app.DB.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`INSERT INTO discovered_app_overrides (url, source, name_override, url_override, icon_override, description_override, category, groups, hidden, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(url) DO UPDATE SET
			source=excluded.source,
			name_override=excluded.name_override,
			url_override=excluded.url_override,
			icon_override=excluded.icon_override,
			description_override=excluded.description_override,
			category=excluded.category,
			groups=excluded.groups,
			hidden=excluded.hidden,
			updated_at=CURRENT_TIMESTAMP`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, o := range overrides {
		groupsJSON, err := json.Marshal(o.Groups)
		if err != nil {
			return fmt.Errorf("failed to marshal groups: %w", err)
		}

		hiddenInt := 0
		if o.Hidden {
			hiddenInt = 1
		}

		_, err = stmt.Exec(o.URL, o.Source, o.NameOverride, o.URLOverride, o.IconOverride, o.DescriptionOverride, o.Category, string(groupsJSON), hiddenInt)
		if err != nil {
			return fmt.Errorf("failed to save override for %s: %w", o.URL, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Update cache
	app.DiscoveredOverridesMu.Lock()
	for _, o := range overrides {
		app.DiscoveredOverrides[o.URL] = o
	}
	app.DiscoveredOverridesMu.Unlock()

	return nil
}

// DeleteDiscoveredOverride removes a discovered app override by URL from both
// the database and the in-memory cache.
func DeleteDiscoveredOverride(app *server.App, url string) error {
	_, err := app.DB.Exec("DELETE FROM discovered_app_overrides WHERE url = ?", url)
	if err != nil {
		return fmt.Errorf("failed to delete discovered override: %w", err)
	}

	app.DiscoveredOverridesMu.Lock()
	delete(app.DiscoveredOverrides, url)
	app.DiscoveredOverridesMu.Unlock()

	return nil
}

// GetDiscoveredOverride returns a copy of the override for the given URL,
// or nil if none exists.
func GetDiscoveredOverride(app *server.App, url string) *models.DiscoveredAppOverride {
	app.DiscoveredOverridesMu.RLock()
	defer app.DiscoveredOverridesMu.RUnlock()
	if o, ok := app.DiscoveredOverrides[url]; ok {
		// Return a copy
		cp := *o
		cp.Groups = append([]string{}, o.Groups...)
		return &cp
	}
	return nil
}

// GetAllDiscoveredOverrides returns a deep copy of all discovered app overrides.
func GetAllDiscoveredOverrides(app *server.App) map[string]*models.DiscoveredAppOverride {
	app.DiscoveredOverridesMu.RLock()
	defer app.DiscoveredOverridesMu.RUnlock()
	result := make(map[string]*models.DiscoveredAppOverride, len(app.DiscoveredOverrides))
	for k, v := range app.DiscoveredOverrides {
		cp := *v
		cp.Groups = append([]string{}, v.Groups...)
		result[k] = &cp
	}
	return result
}

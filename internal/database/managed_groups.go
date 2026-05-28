package database

import (
	"dashgate/internal/server"
)

type ManagedGroup struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	UserCount   int    `json:"userCount"`
}

func ListManagedGroups(app *server.App) ([]ManagedGroup, error) {
	rows, err := app.DB.Query(`
		SELECT mg.name, COALESCE(mg.display_name, mg.name),
		       COALESCE((SELECT COUNT(*) FROM users WHERE groups LIKE '%"' || mg.name || '"%'), 0)
		FROM managed_groups mg ORDER BY mg.name
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []ManagedGroup
	for rows.Next() {
		var g ManagedGroup
		if err := rows.Scan(&g.Name, &g.DisplayName, &g.UserCount); err != nil {
			return nil, err
		}
		groups = append(groups, g)
	}
	return groups, rows.Err()
}

func CreateManagedGroup(app *server.App, name, displayName string) error {
	if displayName == "" {
		displayName = name
	}
	_, err := app.DB.Exec(
		"INSERT INTO managed_groups (name, display_name) VALUES (?, ?)",
		name, displayName,
	)
	return err
}

func DeleteManagedGroup(app *server.App, name string) error {
	_, err := app.DB.Exec("DELETE FROM managed_groups WHERE name = ?", name)
	return err
}

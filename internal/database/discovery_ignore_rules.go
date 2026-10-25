package database

import (
	"errors"
	"fmt"

	"dashgate/internal/models"
	"dashgate/internal/server"

	sqlite3 "github.com/mattn/go-sqlite3"
)

var (
	ErrDiscoveryIgnoreRuleDuplicate = errors.New("discovery ignore rule already exists")
	ErrDiscoveryIgnoreRuleLimit     = errors.New("discovery ignore rule limit reached")
	ErrDiscoveryIgnoreRuleNotFound  = errors.New("discovery ignore rule not found")
)

func ListDiscoveryIgnoreRules(app *server.App) ([]models.DiscoveryIgnoreRule, error) {
	rows, err := app.DB.Query(`SELECT id, source, origin, path_prefix, enabled, created_at, updated_at
		FROM discovery_ignore_rules ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list discovery ignore rules: %w", err)
	}
	defer rows.Close()
	rules := make([]models.DiscoveryIgnoreRule, 0)
	for rows.Next() {
		var rule models.DiscoveryIgnoreRule
		if err := rows.Scan(&rule.ID, &rule.Source, &rule.Origin, &rule.PathPrefix,
			&rule.Enabled, &rule.CreatedAt, &rule.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan discovery ignore rule: %w", err)
		}
		rules = append(rules, rule)
	}
	return rules, rows.Err()
}

func CreateDiscoveryIgnoreRule(app *server.App, rule models.DiscoveryIgnoreRule) (models.DiscoveryIgnoreRule, error) {
	tx, err := app.DB.Begin()
	if err != nil {
		return models.DiscoveryIgnoreRule{}, err
	}
	defer tx.Rollback()
	var count int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM discovery_ignore_rules`).Scan(&count); err != nil {
		return models.DiscoveryIgnoreRule{}, err
	}
	if count >= 100 {
		return models.DiscoveryIgnoreRule{}, ErrDiscoveryIgnoreRuleLimit
	}
	result, err := tx.Exec(`INSERT INTO discovery_ignore_rules(source, origin, path_prefix, enabled)
		VALUES(?,?,?,?)`, rule.Source, rule.Origin, rule.PathPrefix, rule.Enabled)
	if err != nil {
		return models.DiscoveryIgnoreRule{}, classifyIgnoreRuleError(err)
	}
	rule.ID, err = result.LastInsertId()
	if err != nil {
		return models.DiscoveryIgnoreRule{}, err
	}
	if err := tx.QueryRow(`SELECT created_at, updated_at FROM discovery_ignore_rules WHERE id=?`,
		rule.ID).Scan(&rule.CreatedAt, &rule.UpdatedAt); err != nil {
		return models.DiscoveryIgnoreRule{}, err
	}
	if err := tx.Commit(); err != nil {
		return models.DiscoveryIgnoreRule{}, err
	}
	return rule, nil
}

func UpdateDiscoveryIgnoreRule(app *server.App, rule models.DiscoveryIgnoreRule) error {
	result, err := app.DB.Exec(`UPDATE discovery_ignore_rules
		SET source=?, origin=?, path_prefix=?, enabled=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		rule.Source, rule.Origin, rule.PathPrefix, rule.Enabled, rule.ID)
	if err != nil {
		return classifyIgnoreRuleError(err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrDiscoveryIgnoreRuleNotFound
	}
	return nil
}

func DeleteDiscoveryIgnoreRule(app *server.App, id int64) error {
	result, err := app.DB.Exec(`DELETE FROM discovery_ignore_rules WHERE id=?`, id)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrDiscoveryIgnoreRuleNotFound
	}
	return nil
}

func classifyIgnoreRuleError(err error) error {
	var sqliteErr sqlite3.Error
	if errors.As(err, &sqliteErr) && sqliteErr.ExtendedCode == sqlite3.ErrConstraintUnique {
		return ErrDiscoveryIgnoreRuleDuplicate
	}
	return err
}

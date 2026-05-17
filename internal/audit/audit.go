package audit

import (
	"log"
	"time"

	"dashgate/internal/server"
)

type AuditEntry struct {
	ID        int    `json:"id"`
	Timestamp string `json:"timestamp"`
	Username  string `json:"username"`
	Action    string `json:"action"`
	Detail    string `json:"detail"`
	IP        string `json:"ip"`
}

func InitAuditTable(app *server.App) error {
	_, err := app.DB.Exec(`
		CREATE TABLE IF NOT EXISTS audit_log (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
			username TEXT,
			action TEXT,
			detail TEXT,
			ip TEXT
		);
		CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);
		CREATE INDEX IF NOT EXISTS idx_audit_log_username ON audit_log(username);
	`)
	return err
}

func LogAudit(app *server.App, username, action, detail, ip string) {
	if app.DB == nil {
		return
	}
	_, err := app.DB.Exec(
		"INSERT INTO audit_log (timestamp, username, action, detail, ip) VALUES (?, ?, ?, ?, ?)",
		time.Now().UTC().Format(time.RFC3339), username, action, detail, ip,
	)
	if err != nil {
		log.Printf("Failed to write audit log: %v", err)
	}
}

func GetAuditLogs(app *server.App, limit int) ([]AuditEntry, error) {
	if limit <= 0 {
		limit = 100
	}

	rows, err := app.DB.Query(
		"SELECT id, timestamp, COALESCE(username, ''), COALESCE(action, ''), COALESCE(detail, ''), COALESCE(ip, '') FROM audit_log ORDER BY id DESC LIMIT ?",
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.Username, &e.Action, &e.Detail, &e.IP); err != nil {
			log.Printf("Error scanning audit log row: %v", err)
			continue
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return entries, nil
}

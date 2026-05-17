package database

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"log"
	"os"

	"dashgate/internal/server"
)

const encryptionKeyDBKey = "system_encryption_key"

// InitEncryptionKey sets up the AES-256 encryption key on the App struct.
//
// Key resolution order:
//  1. ENCRYPTION_KEY environment variable (hex-encoded, 32 bytes / 64 hex chars)
//  2. Previously stored key in the encryption_keys database table
//  3. Freshly generated random 32-byte key, persisted to the database
//
// If key initialisation fails entirely the application continues without
// encryption and a warning is logged. Sensitive values will be stored in
// plaintext until the issue is resolved.
func InitEncryptionKey(app *server.App) {
	_, err := app.DB.Exec(`
		CREATE TABLE IF NOT EXISTS encryption_keys (
			key_name TEXT PRIMARY KEY,
			key_value TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		log.Printf("WARNING: failed to create encryption_keys table: %v — sensitive values will be stored in plaintext", err)
		return
	}

	if envKey := os.Getenv("ENCRYPTION_KEY"); envKey != "" {
		decoded, err := hex.DecodeString(envKey)
		if err != nil || len(decoded) != 32 {
			log.Printf("WARNING: ENCRYPTION_KEY env var is invalid (must be 64 hex chars / 32 bytes) — ignoring")
		} else {
			app.EncryptionKey = decoded
			log.Println("Encryption key loaded from ENCRYPTION_KEY environment variable")
			return
		}
	}

	var storedHex string
	err = app.DB.QueryRow("SELECT key_value FROM encryption_keys WHERE key_name = ?", encryptionKeyDBKey).Scan(&storedHex)
	if err == nil {
		decoded, err := hex.DecodeString(storedHex)
		if err == nil && len(decoded) == 32 {
			app.EncryptionKey = decoded
			log.Println("Encryption key loaded from database")
			return
		}
		log.Printf("WARNING: stored encryption key is invalid, generating a new one")
	}

	newKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, newKey); err != nil {
		log.Printf("WARNING: failed to generate encryption key: %v — sensitive values will be stored in plaintext", err)
		return
	}

	hexKey := hex.EncodeToString(newKey)
	_, err = app.DB.Exec(
		"INSERT OR REPLACE INTO encryption_keys (key_name, key_value) VALUES (?, ?)",
		encryptionKeyDBKey, hexKey,
	)
	if err != nil {
		log.Printf("WARNING: failed to persist encryption key to database: %v — key will be lost on restart", err)
	} else {
		log.Println("Generated and stored new encryption key in database")
	}

	app.EncryptionKey = newKey
}

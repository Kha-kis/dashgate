package database

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"dashgate/internal/server"
)

const (
	// encPrefix is prepended to encrypted values so we can distinguish them
	// from legacy plaintext values stored before encryption was enabled.
	encPrefix = "enc:"

	// encryptionKeyDBKey is the key used to store the auto-generated
	// encryption key in the encryption_keys table.
	encryptionKeyDBKey = "system_encryption_key"
)

// sensitiveKeys lists the system_config keys whose values must be encrypted at rest.
var sensitiveKeys = map[string]bool{
	"ldap_bind_password": true,
	"oidc_client_secret": true,
	"npm_password":       true,
	"traefik_password":   true,
	"caddy_password":     true,
	"unraid_api_key":     true,
}

// IsSensitiveKey returns true if the given system_config key holds a secret
// that should be encrypted at rest.
func IsSensitiveKey(key string) bool {
	return sensitiveKeys[key]
}

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
	// Ensure the encryption_keys table exists.
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

	// 1. Try ENCRYPTION_KEY env var
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

	// 2. Try loading from DB
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

	// 3. Generate a new key and store it
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

// EncryptValue encrypts plaintext using AES-256-GCM and returns a string
// with the "enc:" prefix followed by base64-encoded (nonce + ciphertext).
//
// If the key is nil or empty the plaintext is returned unchanged (graceful
// degradation when encryption is not configured).
func EncryptValue(key []byte, plaintext string) (string, error) {
	if len(key) == 0 {
		return plaintext, nil
	}

	// Don't encrypt empty strings
	if plaintext == "" {
		return plaintext, nil
	}

	// Already encrypted — return as-is
	if strings.HasPrefix(plaintext, encPrefix) {
		return plaintext, nil
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	encoded := base64.StdEncoding.EncodeToString(ciphertext)

	return encPrefix + encoded, nil
}

// DecryptValue decrypts a value that was encrypted by EncryptValue.
//
// If the value does not carry the "enc:" prefix it is assumed to be a legacy
// plaintext value and returned unchanged (backwards compatibility).
//
// If the key is nil or empty the value is returned unchanged.
func DecryptValue(key []byte, ciphertext string) (string, error) {
	if len(key) == 0 {
		return ciphertext, nil
	}

	// Not encrypted — return plaintext as-is (backward compatibility)
	if !strings.HasPrefix(ciphertext, encPrefix) {
		return ciphertext, nil
	}

	// Empty after prefix should not happen, but handle gracefully
	encoded := strings.TrimPrefix(ciphertext, encPrefix)
	if encoded == "" {
		return "", nil
	}

	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("failed to base64 decode: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, sealed := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, sealed, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	return string(plaintext), nil
}

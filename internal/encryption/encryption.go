package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
)

const encPrefix = "enc:"

var sensitiveKeys = map[string]bool{
	"ldap_bind_password": true,
	"oidc_client_secret": true,
	"npm_password":       true,
	"traefik_password":   true,
	"caddy_password":     true,
	"unraid_api_key":     true,
}

func IsSensitiveKey(key string) bool {
	return sensitiveKeys[key]
}

func EncryptValue(key []byte, plaintext string) (string, error) {
	if len(key) == 0 {
		return plaintext, nil
	}

	if plaintext == "" {
		return plaintext, nil
	}

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

func DecryptValue(key []byte, ciphertext string) (string, error) {
	if len(key) == 0 {
		return ciphertext, nil
	}

	if !strings.HasPrefix(ciphertext, encPrefix) {
		return ciphertext, nil
	}

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

package encryption

import (
	"crypto/rand"
	"io"
	"strings"
	"testing"
)

func generateTestKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	return key
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := generateTestKey(t)
	plaintext := "my-secret-password-123!"

	encrypted, err := EncryptValue(key, plaintext)
	if err != nil {
		t.Fatalf("EncryptValue failed: %v", err)
	}

	if !strings.HasPrefix(encrypted, encPrefix) {
		t.Errorf("encrypted value should have %q prefix, got %q", encPrefix, encrypted)
	}

	if encrypted == plaintext {
		t.Error("encrypted value should differ from plaintext")
	}

	decrypted, err := DecryptValue(key, encrypted)
	if err != nil {
		t.Fatalf("DecryptValue failed: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("decrypted value %q does not match original %q", decrypted, plaintext)
	}
}

func TestDecryptPlaintextPassthrough(t *testing.T) {
	key := generateTestKey(t)
	plaintext := "legacy-plaintext-value"

	result, err := DecryptValue(key, plaintext)
	if err != nil {
		t.Fatalf("DecryptValue failed: %v", err)
	}
	if result != plaintext {
		t.Errorf("expected %q, got %q", plaintext, result)
	}
}

func TestEncryptEmptyString(t *testing.T) {
	key := generateTestKey(t)

	encrypted, err := EncryptValue(key, "")
	if err != nil {
		t.Fatalf("EncryptValue failed: %v", err)
	}
	if encrypted != "" {
		t.Errorf("empty string should remain empty, got %q", encrypted)
	}
}

func TestEncryptNilKey(t *testing.T) {
	plaintext := "some-value"

	encrypted, err := EncryptValue(nil, plaintext)
	if err != nil {
		t.Fatalf("EncryptValue failed: %v", err)
	}
	if encrypted != plaintext {
		t.Errorf("expected %q, got %q", plaintext, encrypted)
	}
}

func TestDecryptNilKey(t *testing.T) {
	ciphertext := "enc:somethingencrypted"

	result, err := DecryptValue(nil, ciphertext)
	if err != nil {
		t.Fatalf("DecryptValue failed: %v", err)
	}
	if result != ciphertext {
		t.Errorf("expected %q, got %q", ciphertext, result)
	}
}

func TestEncryptAlreadyEncrypted(t *testing.T) {
	key := generateTestKey(t)
	plaintext := "test-password"

	encrypted, err := EncryptValue(key, plaintext)
	if err != nil {
		t.Fatalf("first EncryptValue failed: %v", err)
	}

	doubleEncrypted, err := EncryptValue(key, encrypted)
	if err != nil {
		t.Fatalf("second EncryptValue failed: %v", err)
	}

	if doubleEncrypted != encrypted {
		t.Error("double encryption should be a no-op")
	}
}

func TestDecryptWrongKey(t *testing.T) {
	key1 := generateTestKey(t)
	key2 := generateTestKey(t)

	plaintext := "secret-data"

	encrypted, err := EncryptValue(key1, plaintext)
	if err != nil {
		t.Fatalf("EncryptValue failed: %v", err)
	}

	_, err = DecryptValue(key2, encrypted)
	if err == nil {
		t.Error("decrypting with wrong key should fail")
	}
}

func TestDecryptCorruptedData(t *testing.T) {
	key := generateTestKey(t)

	_, err := DecryptValue(key, "enc:notvalidbase64!!!")
	if err == nil {
		t.Error("decrypting corrupted data should fail")
	}
}

func TestEncryptDifferentNonces(t *testing.T) {
	key := generateTestKey(t)
	plaintext := "same-plaintext"

	encrypted1, _ := EncryptValue(key, plaintext)
	encrypted2, _ := EncryptValue(key, plaintext)

	if encrypted1 == encrypted2 {
		t.Error("encrypting the same value twice should produce different ciphertexts")
	}

	decrypted1, _ := DecryptValue(key, encrypted1)
	decrypted2, _ := DecryptValue(key, encrypted2)
	if decrypted1 != plaintext || decrypted2 != plaintext {
		t.Error("both ciphertexts should decrypt to the original plaintext")
	}
}

func TestIsSensitiveKey(t *testing.T) {
	sensitiveTests := []struct {
		key      string
		expected bool
	}{
		{"ldap_bind_password", true},
		{"oidc_client_secret", true},
		{"npm_password", true},
		{"traefik_password", true},
		{"caddy_password", true},
		{"ldap_server", false},
		{"session_days", false},
		{"oidc_issuer", false},
		{"npm_url", false},
		{"", false},
	}

	for _, tt := range sensitiveTests {
		if got := IsSensitiveKey(tt.key); got != tt.expected {
			t.Errorf("IsSensitiveKey(%q) = %v, want %v", tt.key, got, tt.expected)
		}
	}
}

func TestDecryptEmptyAfterPrefix(t *testing.T) {
	key := generateTestKey(t)

	result, err := DecryptValue(key, "enc:")
	if err != nil {
		t.Fatalf("DecryptValue failed: %v", err)
	}
	if result != "" {
		t.Errorf("expected empty string, got %q", result)
	}
}

package crypto

import (
	"crypto/sha256"
	"encoding/hex"

	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	sha := sha256.Sum256([]byte(password))
	preHashed := hex.EncodeToString(sha[:])
	hash, err := bcrypt.GenerateFromPassword([]byte(preHashed), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func CheckPassword(password, hash string) bool {
	sha := sha256.Sum256([]byte(password))
	preHashed := hex.EncodeToString(sha[:])
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(preHashed)) == nil {
		return true
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

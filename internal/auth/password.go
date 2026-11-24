// Password hashing and verification using Go's standard library crypto/pbkdf2.

package auth

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	// DefaultPBKDF2Iterations follows OWASP guidance for PBKDF2-HMAC-SHA256.
	DefaultPBKDF2Iterations = 600_000
	pbkdf2SaltLen           = 16
	pbkdf2KeyLen            = 32
	pbkdf2Scheme            = "pbkdf2-sha256"
	minPBKDF2Iterations     = 1000
)

// dummySalt and dummyKey are used to spend equal PBKDF2 time when a username
// does not exist or has no password set yet, preventing timing enumeration.
var (
	dummySalt = []byte("nuqs-dummy-salt!")
	dummyKey  = make([]byte, pbkdf2KeyLen)
)

// HashPassword derives a salted PBKDF2-HMAC-SHA256 hash using Go's stdlib
// crypto/pbkdf2 and returns a versioned string safe for storage.
func HashPassword(password string, iterations int) (string, error) {
	if iterations <= 0 {
		iterations = DefaultPBKDF2Iterations
	}
	salt := make([]byte, pbkdf2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	dk, err := pbkdf2.Key(sha256.New, password, salt, iterations, pbkdf2KeyLen)
	if err != nil {
		return "", fmt.Errorf("derive password key: %w", err)
	}
	return fmt.Sprintf("%s$%d$%s$%s",
		pbkdf2Scheme,
		iterations,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(dk),
	), nil
}

// VerifyPassword reports whether password matches encodedHash using
// constant-time comparison. Empty or malformed hashes always return false.
func VerifyPassword(password, encodedHash string) bool {
	scheme, iter, salt, want, err := parsePasswordHash(encodedHash)
	if err != nil || scheme != pbkdf2Scheme || iter < minPBKDF2Iterations {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, iter, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

// dummyVerify performs one PBKDF2 derivation so missing accounts take the same
// time as valid accounts during login.
func dummyVerify(password string, iterations int) {
	if iterations <= 0 {
		iterations = DefaultPBKDF2Iterations
	}
	got, err := pbkdf2.Key(sha256.New, password, dummySalt, iterations, pbkdf2KeyLen)
	if err == nil {
		_ = subtle.ConstantTimeCompare(got, dummyKey)
	}
}

func parsePasswordHash(encoded string) (string, int, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 {
		return "", 0, nil, nil, errors.New("malformed password hash")
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter <= 0 {
		return "", 0, nil, nil, errors.New("invalid iteration count")
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil || len(salt) == 0 {
		return "", 0, nil, nil, errors.New("invalid salt")
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil || len(key) == 0 {
		return "", 0, nil, nil, errors.New("invalid hash")
	}
	return parts[0], iter, salt, key, nil
}

// Cryptographic one-time setup/reset codes and session token helpers.

package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

const (
	oneTimeCodeBytes = 15 // 120 bits -> 24 symmetric base32 chars (6 groups of 4)
	sessionBytes     = 32 // 256 bits of entropy
)

var codeEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateCode creates a cryptographically random 120-bit one-time code
// formatted into six readable 4-character hyphenated groups.
func GenerateCode() (string, error) {
	buf := make([]byte, oneTimeCodeBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate one-time code: %w", err)
	}
	raw := codeEncoding.EncodeToString(buf) // 24 uppercase base32 chars
	return formatCodeGroups(raw, 4), nil
}

// NormalizeCode strips spaces and hyphens and uppercases a user-entered code
// before hashing so spacing or case differences don't reject valid codes.
func NormalizeCode(code string) string {
	var b strings.Builder
	b.Grow(len(code))
	for _, r := range code {
		if r == '-' || r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			continue
		}
		if r >= 'a' && r <= 'z' {
			r -= 'a' - 'A'
		}
		b.WriteRune(r)
	}
	return b.String()
}

// HashCode returns the SHA-256 hex digest of a normalized one-time code.
func HashCode(code string) string {
	return HashSecret(NormalizeCode(code))
}

// GenerateSessionToken creates a 256-bit random URL-safe session token.
func GenerateSessionToken() (string, error) {
	buf := make([]byte, sessionBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate session token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// HashSecret returns the SHA-256 hex digest of secret for storage at rest.
func HashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

func formatCodeGroups(s string, size int) string {
	var parts []string
	for len(s) > size {
		parts = append(parts, s[:size])
		s = s[size:]
	}
	if len(s) > 0 {
		parts = append(parts, s)
	}
	return strings.Join(parts, "-")
}

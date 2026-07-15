// Package hash provides the content-addressing primitive for continuum.
//
// A blob's identity is the hex SHA-256 of its canonical bytes (the git /
// Merkle-DAG object model). Identical content => identical id => stored once
// (dedup), and any tampering flips the id (integrity). SHA-256 is chosen for
// ubiquity + stdlib availability with zero external dependencies.
package hash

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Sum returns the lowercase hex SHA-256 of b. This is the content id.
func Sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// Valid reports whether s looks like a content id this package produces
// (64 lowercase hex chars). Used by the store + verify to reject malformed ids
// before touching the filesystem (§11.4.201 — assert the real condition).
func Valid(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// Short returns the first n chars of an id for display (never for lookup).
func Short(id string, n int) string {
	if n <= 0 || n >= len(id) {
		return id
	}
	return strings.ToLower(id[:n])
}

// Package idgen produces opaque, globally unique identifiers.
//
// Every table in the platform uses a TEXT primary key. Identifiers are
// prefixed with a short resource tag so a log line or an audit record is
// self-describing: "proj_9f2...", "task_1ab...", "aud_7c0...".
package idgen

import (
	"crypto/rand"
	"encoding/hex"
	"strings"

	"github.com/google/uuid"
)

// New returns "<prefix>_<uuid-v4>" (prefix is sanitised, never empty).
func New(prefix string) string {
	p := sanitize(prefix)
	if p == "" {
		return uuid.NewString()
	}
	return p + "_" + uuid.NewString()
}

// Token returns a cryptographically random 32-byte hex string. Used for
// worker bearer tokens and other secrets.
func Token() string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand.Read never fails on a supported platform; fall back to
		// two UUIDv4s so we never return an empty secret.
		return strings.ReplaceAll(uuid.NewString()+uuid.NewString(), "-", "")
	}
	return hex.EncodeToString(buf)
}

// UUID returns a bare UUID v4.
func UUID() string { return uuid.NewString() }

func sanitize(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '_' || r == '-':
			b.WriteRune(r)
		}
	}
	return b.String()
}

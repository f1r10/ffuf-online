// Package auth implements password hashing, JWT issuing/parsing and RBAC.
package auth

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// ErrPasswordMismatch is returned when a password does not match its hash.
var ErrPasswordMismatch = errors.New("auth: password does not match")

// MinPasswordLength is the shortest password the API will accept.
const MinPasswordLength = 8

// HashPassword returns a bcrypt hash of pw using the default cost.
func HashPassword(pw string) (string, error) {
	if len(pw) < MinPasswordLength {
		return "", fmt.Errorf("auth: password must be at least %d characters", MinPasswordLength)
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("auth: hash password: %w", err)
	}
	return string(h), nil
}

// VerifyPassword reports whether pw matches hash. It is constant-time with
// respect to the hash contents (bcrypt.CompareHashAndPassword).
func VerifyPassword(hash, pw string) error {
	if hash == "" {
		return ErrPasswordMismatch
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)); err != nil {
		return ErrPasswordMismatch
	}
	return nil
}

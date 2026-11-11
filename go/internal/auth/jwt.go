package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ErrInvalidToken is returned for any malformed, expired or mis-signed token.
var ErrInvalidToken = errors.New("auth: invalid token")

// Claims is the JWT payload issued for a user session.
type Claims struct {
	// TenantID is the tenant the session is scoped to.
	TenantID string `json:"tenant_id"`
	// Role is the tenant role of the user.
	Role string `json:"role"`
	// SuperAdmin marks a platform super administrator.
	SuperAdmin bool `json:"super_admin,omitempty"`
	jwt.RegisteredClaims
}

// JWTManager issues and verifies HS256 session tokens.
type JWTManager struct {
	secret []byte
	ttl    time.Duration
}

// NewJWTManager returns a manager signing with secret and issuing tokens that
// live for ttl.
func NewJWTManager(secret string, ttl time.Duration) *JWTManager {
	return &JWTManager{secret: []byte(secret), ttl: ttl}
}

// TTL returns the configured session lifetime.
func (m *JWTManager) TTL() time.Duration { return m.ttl }

// Issue mints a token for the given subject.
func (m *JWTManager) Issue(userID, tenantID, role string, superAdmin bool, now time.Time) (string, time.Time, error) {
	exp := now.Add(m.ttl)
	claims := Claims{
		TenantID:   tenantID,
		Role:       role,
		SuperAdmin: superAdmin,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString(m.secret)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("auth: sign jwt: %w", err)
	}
	return signed, exp, nil
}

// Parse verifies a token's signature, algorithm and expiry.
func (m *JWTManager) Parse(token string) (*Claims, error) {
	claims := &Claims{}
	parsed, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("auth: unexpected signing method %v", t.Header["alg"])
		}
		return m.secret, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	if !parsed.Valid {
		return nil, ErrInvalidToken
	}
	if claims.Subject == "" {
		return nil, fmt.Errorf("%w: missing subject", ErrInvalidToken)
	}
	return claims, nil
}

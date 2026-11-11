// Package tenant carries the authenticated identity through a request context.
//
// This is the ONLY source of truth for a request's tenant id. Handlers must
// never read tenant_id from a request body, query string or header: the value
// in the context is derived from a verified JWT, a worker bearer token or an
// internal service token.
package tenant

import "context"

// Kind describes what kind of principal made the request.
type Kind string

const (
	// KindUser is a human authenticated with a JWT.
	KindUser Kind = "user"
	// KindWorker is a worker agent authenticated with a worker token.
	KindWorker Kind = "worker"
	// KindService is an internal service (e.g. the Python intelligence engine)
	// authenticated with the service token, or with no credentials in
	// development mode.
	KindService Kind = "service"
)

// Identity is the authenticated principal of a request.
type Identity struct {
	// UserID is set for KindUser.
	UserID string
	// WorkerID is set for KindWorker.
	WorkerID string
	// TenantID scopes every store call. Empty for a platform worker pool
	// member or an unauthenticated service call.
	TenantID string
	// Role is the tenant role for KindUser; empty otherwise.
	Role string
	// Email is the user's email for KindUser.
	Email string
	// IsSuperAdmin marks a platform super administrator (orthogonal to Role).
	IsSuperAdmin bool
	// Kind is the principal kind.
	Kind Kind
}

type ctxKey struct{}

// With returns a copy of ctx carrying the identity.
func With(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// FromContext returns the identity stored in ctx, or the zero Identity when the
// request is unauthenticated.
func FromContext(ctx context.Context) Identity {
	id, _ := ctx.Value(ctxKey{}).(Identity)
	return id
}

// IsAuthenticated reports whether ctx carries a usable principal.
func IsAuthenticated(ctx context.Context) bool {
	id, ok := ctx.Value(ctxKey{}).(Identity)
	return ok && id.Kind != ""
}

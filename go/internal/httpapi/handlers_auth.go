package httpapi

import (
	"net/http"

	"github.com/ffuf-online/platform/internal/audit"
	"github.com/ffuf-online/platform/internal/auth"
	"github.com/ffuf-online/platform/internal/tenant"
)

type loginRequest struct {
	Email      string `json:"email"`
	Password   string `json:"password"`
	TenantID   string `json:"tenant_id"`
	TenantSlug string `json:"tenant_slug"`
}

type loginResponse struct {
	Token     string `json:"token"`
	TokenType string `json:"token_type"`
	ExpiresAt string `json:"expires_at"`
	TenantID  string `json:"tenant_id"`
	Role      string `json:"role"`
	UserID    string `json:"user_id"`
}

// handleLogin authenticates a user against bcrypt credentials and mints an
// HS256 session token scoped to one tenant. It is the only unauthenticated
// endpoint that touches credentials.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if !s.readJSON(w, r, &req) {
		return
	}
	if req.Email == "" || req.Password == "" {
		failValidation(w, "email and password are required", nil)
		return
	}

	user, err := s.store.GetUserByEmail(r.Context(), req.Email)
	if err != nil {
		writeError(w, http.StatusUnauthorized, CodeUnauthorized, "invalid credentials", nil)
		return
	}
	if auth.VerifyPassword(user.PasswordHash, req.Password) != nil {
		writeError(w, http.StatusUnauthorized, CodeUnauthorized, "invalid credentials", nil)
		return
	}

	tenantID := req.TenantID
	if tenantID == "" && req.TenantSlug != "" {
		t, err := s.store.GetTenantBySlug(r.Context(), req.TenantSlug)
		if err != nil {
			writeError(w, http.StatusUnauthorized, CodeUnauthorized, "invalid credentials", nil)
			return
		}
		tenantID = t.ID
	}

	role := ""
	if tenantID != "" {
		if m, err := s.store.GetMembership(r.Context(), tenantID, user.ID); err == nil {
			role = m.Role
		}
	}
	if !user.IsSuperAdmin && (tenantID == "" || role == "") {
		writeError(w, http.StatusForbidden, CodeForbidden, "user is not a member of the requested tenant", nil)
		return
	}
	if tenantID == "" && user.IsSuperAdmin {
		// Platform administrators may hold a tenant-less session.
		role = ""
	}

	token, exp, err := s.jwt.Issue(user.ID, tenantID, role, user.IsSuperAdmin, s.now())
	if err != nil {
		writeError(w, http.StatusInternalServerError, CodeInternal, "could not issue token", nil)
		return
	}

	if _, err := s.audit.Record(r.Context(), audit.Entry{
		TenantID:     tenantID,
		ActorUserID:  user.ID,
		ActorKind:    "user",
		Action:       "auth.login",
		ResourceType: "user",
		ResourceID:   user.ID,
		Result:       "success",
	}); err != nil {
		s.log.Error("audit login failed", "error", err)
	}

	writeJSON(w, http.StatusOK, loginResponse{
		Token:     token,
		TokenType: "Bearer",
		ExpiresAt: exp.UTC().Format("2006-01-02T15:04:05Z07:00"),
		TenantID:  tenantID,
		Role:      role,
		UserID:    user.ID,
	})
}

// handleMe returns the resolved principal. It never trusts a body or header
// for the tenant id.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	id := tenant.FromContext(r.Context())
	if id.Kind == "" {
		writeError(w, http.StatusUnauthorized, CodeUnauthorized, "authentication required", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"kind":           string(id.Kind),
		"user_id":        id.UserID,
		"worker_id":      id.WorkerID,
		"tenant_id":      id.TenantID,
		"role":           id.Role,
		"is_super_admin": id.IsSuperAdmin,
	})
}

package httpapi

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/ffuf-online/platform/internal/auth"
	"github.com/ffuf-online/platform/internal/domain"
)

type createMemberRequest struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
}

type updateMemberRequest struct {
	Role string `json:"role"`
}

func (s *Server) requireUserTenant(w http.ResponseWriter, r *http.Request) (string, bool) {
	tenantID, ok := identityTenant(r)
	if !ok || tenantID == "" {
		writeError(w, http.StatusForbidden, CodeForbidden, "session is not scoped to a tenant", nil)
		return "", false
	}
	return tenantID, true
}

// handleListMembers lists the memberships of the caller's tenant.
func (s *Server) handleListMembers(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := s.requireUserTenant(w, r)
	if !ok {
		return
	}
	limit, offset, err := pagination(r)
	if err != nil {
		failValidation(w, err.Error(), nil)
		return
	}
	items, total, err := s.store.ListMemberships(r.Context(), tenantID, limit, offset)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, newList(items, total, limit, offset))
}

// handleCreateMember adds a user to the caller's tenant by id or email.
func (s *Server) handleCreateMember(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := s.requireUserTenant(w, r)
	if !ok {
		return
	}
	var req createMemberRequest
	if !s.readJSON(w, r, &req) {
		return
	}
	userID := strings.TrimSpace(req.UserID)
	if userID == "" && req.Email != "" {
		u, err := s.store.GetUserByEmail(r.Context(), req.Email)
		if err != nil {
			writeError(w, http.StatusNotFound, CodeNotFound, "user not found", nil)
			return
		}
		userID = u.ID
	}
	if userID == "" {
		failValidation(w, "user_id or email is required", nil)
		return
	}
	role := strings.ToLower(strings.TrimSpace(req.Role))
	if !auth.ValidTenantRole(role) {
		failValidation(w, "role must be one of the tenant roles", map[string]any{"roles": auth.TenantRoles})
		return
	}
	// A membership can never carry the platform role.
	if role == string(auth.RolePlatform) {
		failValidation(w, "the platform role cannot be granted through membership", nil)
		return
	}
	m := domain.Membership{
		ID:        newID("member"),
		TenantID:  tenantID,
		UserID:    userID,
		Role:      role,
		CreatedAt: s.now(),
	}
	if err := s.store.CreateMembership(r.Context(), m); err != nil {
		s.writeStoreError(w, err)
		return
	}
	s.recordAudit(r, s.auditFor(r, tenantID, "", "member.create", "membership", userID))
	writeJSON(w, http.StatusCreated, m)
}

// handleUpdateMember changes a member's role within the caller's tenant.
func (s *Server) handleUpdateMember(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := s.requireUserTenant(w, r)
	if !ok {
		return
	}
	userID := chi.URLParam(r, "userID")
	var req updateMemberRequest
	if !s.readJSON(w, r, &req) {
		return
	}
	role := strings.ToLower(strings.TrimSpace(req.Role))
	if !auth.ValidTenantRole(role) {
		failValidation(w, "role must be one of the tenant roles", map[string]any{"roles": auth.TenantRoles})
		return
	}
	if err := s.store.UpdateMembershipRole(r.Context(), tenantID, userID, role); err != nil {
		s.writeStoreError(w, err)
		return
	}
	m, err := s.store.GetMembership(r.Context(), tenantID, userID)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	s.recordAudit(r, s.auditFor(r, tenantID, "", "member.update", "membership", userID))
	writeJSON(w, http.StatusOK, m)
}

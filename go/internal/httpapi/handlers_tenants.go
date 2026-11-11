package httpapi

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/ffuf-online/platform/internal/auth"
	"github.com/ffuf-online/platform/internal/domain"
	"github.com/ffuf-online/platform/internal/store"
	"github.com/ffuf-online/platform/internal/tenant"
)

type createTenantRequest struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
}

// handleCreateTenant is the tenant self-service signup: any authenticated user
// may create a tenant and becomes its org_owner. It grants no platform access.
func (s *Server) handleCreateTenant(w http.ResponseWriter, r *http.Request) {
	id := tenant.FromContext(r.Context())
	if id.Kind != tenant.KindUser || id.UserID == "" {
		writeError(w, http.StatusUnauthorized, CodeUnauthorized, "authentication required", nil)
		return
	}
	var req createTenantRequest
	if !s.readJSON(w, r, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Slug = strings.ToLower(strings.TrimSpace(req.Slug))
	if req.Name == "" || req.Slug == "" {
		failValidation(w, "name and slug are required", nil)
		return
	}

	t := domain.Tenant{
		ID:        newID("tenant"),
		Name:      req.Name,
		Slug:      req.Slug,
		Status:    "active",
		CreatedAt: s.now(),
	}
	if err := s.store.CreateTenant(r.Context(), t); err != nil {
		s.writeStoreError(w, err)
		return
	}
	m := domain.Membership{
		ID:        newID("member"),
		TenantID:  t.ID,
		UserID:    id.UserID,
		Role:      string(auth.RoleOrgOwner),
		CreatedAt: s.now(),
	}
	if err := s.store.CreateMembership(r.Context(), m); err != nil {
		s.writeStoreError(w, err)
		return
	}
	s.recordAudit(r, s.auditFor(r, t.ID, "", "tenant.create", "tenant", t.ID))
	writeJSON(w, http.StatusCreated, t)
}

// handleListTenants is the platform administrator surface (platform role only).
func (s *Server) handleListTenants(w http.ResponseWriter, r *http.Request) {
	limit, offset, err := pagination(r)
	if err != nil {
		failValidation(w, err.Error(), nil)
		return
	}
	items, total, err := s.store.ListTenants(r.Context(), limit, offset)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, newList(items, total, limit, offset))
}

// handleGetCurrentTenant returns the tenant named by the session token.
func (s *Server) handleGetCurrentTenant(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := identityTenant(r)
	if !ok || tenantID == "" {
		writeError(w, http.StatusForbidden, CodeForbidden, "session is not scoped to a tenant", nil)
		return
	}
	t, err := s.store.GetTenant(r.Context(), tenantID)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, t)
}

// handleGetTenant returns a tenant when the caller is a member of it or holds
// the platform role.
func (s *Server) handleGetTenant(w http.ResponseWriter, r *http.Request) {
	tenantID := chi.URLParam(r, "tenantID")
	id := tenant.FromContext(r.Context())
	if !s.mayAccessTenant(r, id, tenantID) {
		writeError(w, http.StatusNotFound, CodeNotFound, "resource not found", nil)
		return
	}
	t, err := s.store.GetTenant(r.Context(), tenantID)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, t)
}

// mayAccessTenant reports whether the principal may read tenantID: the session
// tenant matches, the principal is a member, or it holds the platform role.
func (s *Server) mayAccessTenant(r *http.Request, id tenant.Identity, tenantID string) bool {
	if tenantID == "" {
		return false
	}
	if id.Kind == tenant.KindUser && (id.IsSuperAdmin || id.Role == string(auth.RolePlatform)) {
		return true
	}
	if id.TenantID == tenantID && id.Kind != "" {
		return true
	}
	if id.Kind == tenant.KindUser && id.UserID != "" {
		if _, err := s.store.GetMembership(r.Context(), tenantID, id.UserID); err == nil {
			return true
		}
	}
	return false
}

// ensureProjectAccess verifies the caller's tenant owns projectID.
func (s *Server) ensureProjectAccess(w http.ResponseWriter, r *http.Request, tenantID, projectID string) bool {
	if _, err := s.store.GetProject(r.Context(), tenantID, projectID); err != nil {
		if err == store.ErrNotFound || err == store.ErrCrossTenant {
			writeError(w, http.StatusNotFound, CodeNotFound, "resource not found", nil)
			return false
		}
		s.writeStoreError(w, err)
		return false
	}
	return true
}

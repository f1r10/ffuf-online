package httpapi

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/ffuf-online/platform/internal/domain"
	"github.com/ffuf-online/platform/internal/scopesdk"
	"github.com/ffuf-online/platform/internal/tenant"
)

// targetKinds is the exact `target.kind` enumeration accepted by the Rust
// scope engine.
var targetKinds = []string{"domain", "wildcard_domain", "hostname", "ip", "cidr", "url", "url_prefix"}

type scopeRuleRequest struct {
	Kind   string `json:"kind"`
	Value  string `json:"value"`
	Action string `json:"action"`
	Note   string `json:"note"`
}

type createScopeRequest struct {
	PolicyProfile  string             `json:"policy_profile"`
	PolicyVersion  int                `json:"policy_version"`
	MaxRPS         int                `json:"max_rps"`
	MaxConcurrency int                `json:"max_concurrency"`
	WindowStartUTC string             `json:"window_start_utc"`
	WindowEndUTC   string             `json:"window_end_utc"`
	ExpiresAt      *time.Time         `json:"expires_at"`
	Rules          []scopeRuleRequest `json:"rules"`
}

type authorizeScopeRequest struct {
	Version int `json:"version"`
}

type scopeTargetRequest struct {
	Kind   string  `json:"kind"`
	Value  string  `json:"value"`
	Scheme *string `json:"scheme"`
	Host   *string `json:"host"`
	Port   *int    `json:"port"`
	Path   *string `json:"path"`
}

// decideRequest is the body of the scope decision proxy. It deliberately has
// NO scope_rules field: the rules always come from the stored scope version.
type decideRequest struct {
	Target        scopeTargetRequest `json:"target"`
	PolicyProfile string             `json:"policy_profile"`
	ScopeVersion  *int               `json:"scope_version"`
	ResolvedIPs   []string           `json:"resolved_ips"`
	RedirectChain []string           `json:"redirect_chain"`
	DestIP        *string            `json:"dest_ip"`
}

func (s *Server) handleGetScope(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := s.requireUserTenant(w, r)
	if !ok {
		return
	}
	projectID := chi.URLParam(r, "projectID")
	if !s.ensureProjectAccess(w, r, tenantID, projectID) {
		return
	}
	sv, rules, err := s.store.GetCurrentScope(r.Context(), tenantID, projectID)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"scope_version": sv, "rules": rules})
}

// handleCreateScope appends a new immutable scope version. The rules become
// effective for decisions, but a version only authorizes testing once it is
// explicitly approved (handleAuthorizeScope).
func (s *Server) handleCreateScope(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := s.requireUserTenant(w, r)
	if !ok {
		return
	}
	projectID := chi.URLParam(r, "projectID")
	if !s.ensureProjectAccess(w, r, tenantID, projectID) {
		return
	}
	var req createScopeRequest
	if !s.readJSON(w, r, &req) {
		return
	}
	profile := req.PolicyProfile
	if profile == "" {
		profile = "passive"
	}
	if !domain.Contains(domain.PolicyProfiles, profile) {
		failValidation(w, "invalid policy_profile", map[string]any{"profiles": domain.PolicyProfiles})
		return
	}
	rules := make([]domain.ScopeRule, 0, len(req.Rules))
	for i, in := range req.Rules {
		in.Kind = strings.TrimSpace(in.Kind)
		in.Value = strings.TrimSpace(in.Value)
		in.Action = strings.ToLower(strings.TrimSpace(in.Action))
		if !domain.Contains(domain.ScopeRuleKinds, in.Kind) {
			failValidation(w, "invalid rule kind", map[string]any{"index": i, "kinds": domain.ScopeRuleKinds})
			return
		}
		if in.Value == "" {
			failValidation(w, "rule value is required", map[string]any{"index": i})
			return
		}
		if in.Action != "include" && in.Action != "exclude" {
			failValidation(w, "rule action must be include or exclude", map[string]any{"index": i})
			return
		}
		rules = append(rules, domain.ScopeRule{
			Kind:   in.Kind,
			Value:  in.Value,
			Action: in.Action,
			Note:   in.Note,
		})
	}
	sv := domain.ScopeVersion{
		ID:             newID("scope"),
		TenantID:       tenantID,
		ProjectID:      projectID,
		PolicyVersion:  req.PolicyVersion,
		PolicyProfile:  profile,
		MaxRPS:         req.MaxRPS,
		MaxConcurrency: req.MaxConcurrency,
		WindowStartUTC: req.WindowStartUTC,
		WindowEndUTC:   req.WindowEndUTC,
		ExpiresAt:      req.ExpiresAt,
		CreatedAt:      s.now(),
	}
	created, err := s.store.CreateScopeVersion(r.Context(), sv, rules)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	stored, storedRules, err := s.store.GetScopeVersion(r.Context(), tenantID, projectID, created.Version)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	s.recordAudit(r, s.auditFor(r, tenantID, projectID, "scope.create", "scope_version", created.ID))
	writeJSON(w, http.StatusCreated, map[string]any{"scope_version": stored, "rules": storedRules})
}

// handleAuthorizeScope marks a scope version as authorized for active testing.
// Only org_owner (scope:authorize) may do this.
func (s *Server) handleAuthorizeScope(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := s.requireUserTenant(w, r)
	if !ok {
		return
	}
	projectID := chi.URLParam(r, "projectID")
	if !s.ensureProjectAccess(w, r, tenantID, projectID) {
		return
	}
	var req authorizeScopeRequest
	if !readOptionalJSON(w, r, &req) {
		return
	}
	version := req.Version
	if version == 0 {
		cur, _, err := s.store.GetCurrentScope(r.Context(), tenantID, projectID)
		if err != nil {
			s.writeStoreError(w, err)
			return
		}
		version = cur.Version
	}
	id := tenant.FromContext(r.Context())
	sv, err := s.store.AuthorizeScope(r.Context(), tenantID, projectID, version, id.UserID, s.now())
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	s.recordAudit(r, s.auditFor(r, tenantID, projectID, "scope.authorize", "scope_version", sv.ID))
	writeJSON(w, http.StatusOK, sv)
}

// handleScopeDecide is the ONLY place the control plane asks about scope. It
// loads the stored rules and forwards the question to the Rust engine. A
// client-supplied scope_rules field is ignored by construction.
func (s *Server) handleScopeDecide(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := s.requireUserTenant(w, r)
	if !ok {
		return
	}
	projectID := chi.URLParam(r, "projectID")
	if !s.ensureProjectAccess(w, r, tenantID, projectID) {
		return
	}
	var req decideRequest
	if !s.readJSON(w, r, &req) {
		return
	}
	req.Target.Kind = strings.TrimSpace(req.Target.Kind)
	req.Target.Value = strings.TrimSpace(req.Target.Value)
	if req.Target.Kind == "" || req.Target.Value == "" {
		failValidation(w, "target.kind and target.value are required", nil)
		return
	}
	if !domain.Contains(targetKinds, req.Target.Kind) {
		failValidation(w, "invalid target.kind", map[string]any{"kinds": targetKinds})
		return
	}

	// Load stored scope only.
	profile := req.PolicyProfile
	var (
		scopeVersion int
		rules        []scopesdk.Rule
		expiresAt    *time.Time
		authorized   bool
	)
	sv, storedRules, err := s.loadScope(r.Context(), tenantID, projectID, req.ScopeVersion)
	if err == nil {
		scopeVersion = sv.Version
		authorized = sv.Authorized
		expiresAt = sv.ExpiresAt
		if profile == "" {
			profile = sv.PolicyProfile
		}
		for _, rule := range storedRules {
			rules = append(rules, scopesdk.Rule{ID: rule.ID, Kind: rule.Kind, Value: rule.Value, Action: rule.Action})
		}
	}
	if profile == "" {
		profile = "passive"
	}
	if !domain.Contains(domain.PolicyProfiles, profile) {
		failValidation(w, "invalid policy_profile", map[string]any{"profiles": domain.PolicyProfiles})
		return
	}

	scopeReq := scopesdk.Request{
		RequestID:     newID("req"),
		TenantID:      tenantID,
		ProjectID:     projectID,
		PolicyProfile: profile,
		Target: scopesdk.Target{
			Kind:   req.Target.Kind,
			Value:  req.Target.Value,
			Scheme: req.Target.Scheme,
			Host:   req.Target.Host,
			Port:   req.Target.Port,
			Path:   req.Target.Path,
		},
		ResolvedIPs:   req.ResolvedIPs,
		RedirectChain: req.RedirectChain,
		DestIP:        req.DestIP,
		ScopeRules:    rules,
		Authorization: &scopesdk.Authorization{Authorized: authorized, ExpiresAt: expiresAt},
	}
	if scopeVersion > 0 {
		scopeReq.ScopeVersion = &scopeVersion
	}

	decision, err := s.scope.Decide(r.Context(), scopeReq)
	if err != nil {
		s.log.Error("scope engine unreachable", "error", err, "tenant", tenantID, "project", projectID)
		writeError(w, http.StatusBadGateway, CodeUnavailable, "scope engine unavailable", map[string]any{"reason": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, decision)
}

func (s *Server) loadScope(rctx context.Context, tenantID, projectID string, version *int) (domain.ScopeVersion, []domain.ScopeRule, error) {
	if version != nil {
		return s.store.GetScopeVersion(rctx, tenantID, projectID, *version)
	}
	return s.store.GetCurrentScope(rctx, tenantID, projectID)
}

package httpapi

import (
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/ffuf-online/platform/internal/domain"
	"github.com/ffuf-online/platform/internal/tenant"
)

type createProjectRequest struct {
	Name string `json:"name"`
}

type createProgramRequest struct {
	Name   string `json:"name"`
	Source string `json:"source"`
}

type createAuthorizationRequest struct {
	Kind      string     `json:"kind"`
	Reference string     `json:"reference"`
	SHA256    string     `json:"sha256"`
	ExpiresAt *time.Time `json:"expires_at"`
}

type createScanRequest struct {
	ToolID           string         `json:"tool_id"`
	Input            map[string]any `json:"input"`
	ExecutionProfile string         `json:"execution_profile"`
	Priority         int            `json:"priority"`
	MaxDepth         int            `json:"max_depth"`
}

func (s *Server) handleCreateProject(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := s.requireUserTenant(w, r)
	if !ok {
		return
	}
	var req createProjectRequest
	if !s.readJSON(w, r, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		failValidation(w, "name is required", nil)
		return
	}
	id := tenant.FromContext(r.Context())
	p := domain.Project{
		ID:        newID("project"),
		TenantID:  tenantID,
		Name:      req.Name,
		CreatedBy: id.UserID,
		CreatedAt: s.now(),
	}
	if err := s.store.CreateProject(r.Context(), p); err != nil {
		s.writeStoreError(w, err)
		return
	}
	s.recordAudit(r, s.auditFor(r, tenantID, p.ID, "project.create", "project", p.ID))
	writeJSON(w, http.StatusCreated, p)
}

func (s *Server) handleListProjects(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := s.requireUserTenant(w, r)
	if !ok {
		return
	}
	limit, offset, err := pagination(r)
	if err != nil {
		failValidation(w, err.Error(), nil)
		return
	}
	items, total, err := s.store.ListProjects(r.Context(), tenantID, limit, offset)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, newList(items, total, limit, offset))
}

func (s *Server) handleGetProject(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := s.requireUserTenant(w, r)
	if !ok {
		return
	}
	p, err := s.store.GetProject(r.Context(), tenantID, chi.URLParam(r, "projectID"))
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) handleCreateProgram(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := s.requireUserTenant(w, r)
	if !ok {
		return
	}
	projectID := chi.URLParam(r, "projectID")
	if !s.ensureProjectAccess(w, r, tenantID, projectID) {
		return
	}
	var req createProgramRequest
	if !s.readJSON(w, r, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		failValidation(w, "name is required", nil)
		return
	}
	if req.Source == "" {
		req.Source = "manual"
	}
	p := domain.Program{
		ID:        newID("program"),
		TenantID:  tenantID,
		ProjectID: projectID,
		Name:      req.Name,
		Source:    req.Source,
		CreatedAt: s.now(),
	}
	if err := s.store.CreateProgram(r.Context(), p); err != nil {
		s.writeStoreError(w, err)
		return
	}
	s.recordAudit(r, s.auditFor(r, tenantID, projectID, "program.create", "program", p.ID))
	writeJSON(w, http.StatusCreated, p)
}

func (s *Server) handleListPrograms(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := s.requireUserTenant(w, r)
	if !ok {
		return
	}
	projectID := chi.URLParam(r, "projectID")
	if !s.ensureProjectAccess(w, r, tenantID, projectID) {
		return
	}
	limit, offset, err := pagination(r)
	if err != nil {
		failValidation(w, err.Error(), nil)
		return
	}
	items, total, err := s.store.ListPrograms(r.Context(), tenantID, projectID, limit, offset)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, newList(items, total, limit, offset))
}

func (s *Server) handleCreateAuthorization(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := s.requireUserTenant(w, r)
	if !ok {
		return
	}
	projectID := chi.URLParam(r, "projectID")
	if !s.ensureProjectAccess(w, r, tenantID, projectID) {
		return
	}
	var req createAuthorizationRequest
	if !s.readJSON(w, r, &req) {
		return
	}
	req.Kind = strings.TrimSpace(req.Kind)
	req.Reference = strings.TrimSpace(req.Reference)
	if req.Kind == "" || req.Reference == "" {
		failValidation(w, "kind and reference are required", nil)
		return
	}
	id := tenant.FromContext(r.Context())
	e := domain.AuthorizationEvidence{
		ID:         newID("authz"),
		TenantID:   tenantID,
		ProjectID:  projectID,
		Kind:       req.Kind,
		Reference:  req.Reference,
		SHA256:     req.SHA256,
		RecordedBy: id.UserID,
		ExpiresAt:  req.ExpiresAt,
		CreatedAt:  s.now(),
	}
	if err := s.store.CreateAuthorizationEvidence(r.Context(), e); err != nil {
		s.writeStoreError(w, err)
		return
	}
	s.recordAudit(r, s.auditFor(r, tenantID, projectID, "authorization.create", "authorization_evidence", e.ID))
	writeJSON(w, http.StatusCreated, e)
}

func (s *Server) handleListAuthorization(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := s.requireUserTenant(w, r)
	if !ok {
		return
	}
	projectID := chi.URLParam(r, "projectID")
	if !s.ensureProjectAccess(w, r, tenantID, projectID) {
		return
	}
	limit, offset, err := pagination(r)
	if err != nil {
		failValidation(w, err.Error(), nil)
		return
	}
	items, total, err := s.store.ListAuthorizationEvidence(r.Context(), tenantID, projectID, limit, offset)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, newList(items, total, limit, offset))
}

// handleCreateScan starts a scan: it opens a workflow and enqueues the first
// task. Downstream tasks are produced by the Python intelligence engine from
// the resulting events, never hardcoded here.
func (s *Server) handleCreateScan(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := s.requireUserTenant(w, r)
	if !ok {
		return
	}
	projectID := chi.URLParam(r, "projectID")
	if !s.ensureProjectAccess(w, r, tenantID, projectID) {
		return
	}
	var req createScanRequest
	if !s.readJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.ToolID) == "" {
		failValidation(w, "tool_id is required", nil)
		return
	}
	if _, known := s.toolIndex[req.ToolID]; !known {
		failValidation(w, "unknown tool_id", map[string]any{"tool_id": req.ToolID})
		return
	}
	profile := req.ExecutionProfile
	if profile == "" {
		profile = "passive"
	}
	if !domain.Contains(domain.PolicyProfiles, profile) {
		failValidation(w, "invalid execution_profile", map[string]any{"profiles": domain.PolicyProfiles})
		return
	}
	maxDepth := req.MaxDepth
	if maxDepth <= 0 {
		maxDepth = 5
	}
	wf := domain.Workflow{
		ID:        newID("wf"),
		TenantID:  tenantID,
		ProjectID: projectID,
		Status:    "running",
		MaxDepth:  maxDepth,
		CreatedAt: s.now(),
	}
	if err := s.store.CreateWorkflow(r.Context(), wf); err != nil {
		s.writeStoreError(w, err)
		return
	}
	input := req.Input
	if input == nil {
		input = map[string]any{}
	}
	task, _, err := s.store.CreateTask(r.Context(), s.buildTask(tenantID, projectID, req.ToolID, input, profile, req.Priority, 0, wf.ID, "", "", "scan requested"))
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	s.recordAudit(r, s.auditFor(r, tenantID, projectID, "scan.create", "workflow", wf.ID))
	writeJSON(w, http.StatusCreated, map[string]any{"workflow": wf, "task": task})
}

func (s *Server) handleListScans(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := s.requireUserTenant(w, r)
	if !ok {
		return
	}
	projectID := chi.URLParam(r, "projectID")
	if !s.ensureProjectAccess(w, r, tenantID, projectID) {
		return
	}
	limit, offset, err := pagination(r)
	if err != nil {
		failValidation(w, err.Error(), nil)
		return
	}
	items, total, err := s.store.ListWorkflows(r.Context(), tenantID, projectID, limit, offset)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, newList(items, total, limit, offset))
}

func (s *Server) handleGetWorkflow(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := s.requireUserTenant(w, r)
	if !ok {
		return
	}
	workflowID := chi.URLParam(r, "workflowID")
	wf, err := s.store.GetWorkflow(r.Context(), tenantID, workflowID)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	nodes, err := s.store.ListWorkflowNodes(r.Context(), tenantID, workflowID)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"workflow": wf, "nodes": nodes})
}

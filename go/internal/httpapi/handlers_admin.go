package httpapi

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/ffuf-online/platform/internal/auth"
	"github.com/ffuf-online/platform/internal/domain"
	"github.com/ffuf-online/platform/internal/jobs"
)

type workflowNodeBody struct {
	ID           string `json:"id"`
	ToolID       string `json:"tool_id"`
	TriggerEvent string `json:"trigger_event"`
	Depth        int    `json:"depth"`
	Status       string `json:"status"`
	Reason       string `json:"reason"`
}

type workflowBody struct {
	TenantID   string             `json:"tenant_id"`
	ProjectID  string             `json:"project_id"`
	WorkflowID string             `json:"workflow_id"`
	Status     string             `json:"status"`
	MaxDepth   int                `json:"max_depth"`
	Nodes      []workflowNodeBody `json:"nodes"`
}

type executionBody struct {
	domain.ToolExecution
}

func (s *Server) handleListTools(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"items": s.tools, "total": len(s.tools)})
}

func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := s.requireUserTenant(w, r)
	if !ok {
		return
	}
	limit, offset, err := pagination(r)
	if err != nil {
		failValidation(w, err.Error(), nil)
		return
	}
	items, total, err := s.audit.List(r.Context(), tenantID, limit, offset)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, newList(items, total, limit, offset))
}

func (s *Server) handleVerifyAudit(w http.ResponseWriter, r *http.Request) {
	if err := s.audit.VerifyChain(r.Context()); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleListUsage(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := s.requireUserTenant(w, r)
	if !ok {
		return
	}
	limit, offset, err := pagination(r)
	if err != nil {
		failValidation(w, err.Error(), nil)
		return
	}
	items, total, err := s.store.ListUsage(r.Context(), tenantID, limit, offset)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, newList(items, total, limit, offset))
}

func (s *Server) handleIngestUsage(w http.ResponseWriter, r *http.Request) {
	var body domain.UsageRecord
	if !s.readJSON(w, r, &body) {
		return
	}
	tenantID, ok := s.ingestionTenant(r, body.TenantID)
	if !ok {
		writeError(w, http.StatusBadRequest, CodeValidation, "tenant could not be resolved", nil)
		return
	}
	body.TenantID = tenantID
	if err := s.store.AddUsage(r.Context(), body); err != nil {
		s.writeStoreError(w, err)
		return
	}
	s.recordAudit(r, s.auditFor(r, tenantID, body.ProjectID, "usage.record", "usage", body.ID))
	writeJSON(w, http.StatusAccepted, body)
}

func (s *Server) handleIngestWorkflow(w http.ResponseWriter, r *http.Request) {
	var body workflowBody
	if !s.readJSON(w, r, &body) {
		return
	}
	tenantID, ok := s.ingestionTenant(r, body.TenantID)
	if !ok {
		writeError(w, http.StatusBadRequest, CodeValidation, "tenant could not be resolved", nil)
		return
	}
	projectID := strings.TrimSpace(body.ProjectID)
	if projectID == "" {
		failValidation(w, "project_id is required", nil)
		return
	}
	if !s.ensureProjectAccess(w, r, tenantID, projectID) {
		return
	}
	wfID := strings.TrimSpace(body.WorkflowID)
	if wfID == "" {
		wfID = newID("wf")
	}
	wf := domain.Workflow{
		ID:        wfID,
		TenantID:  tenantID,
		ProjectID: projectID,
		Status:    body.Status,
		MaxDepth:  body.MaxDepth,
		CreatedAt: s.now(),
	}
	if err := s.store.CreateWorkflow(r.Context(), wf); err != nil {
		s.writeStoreError(w, err)
		return
	}
	nodes := make([]domain.WorkflowNode, 0, len(body.Nodes))
	for _, n := range body.Nodes {
		node := domain.WorkflowNode{
			ID:           n.ID,
			TenantID:     tenantID,
			WorkflowID:   wfID,
			ToolID:       n.ToolID,
			TriggerEvent: n.TriggerEvent,
			Depth:        n.Depth,
			Status:       n.Status,
			Reason:       n.Reason,
			CreatedAt:    s.now(),
		}
		if err := s.store.UpsertWorkflowNode(r.Context(), node); err != nil {
			s.writeStoreError(w, err)
			return
		}
		nodes = append(nodes, node)
	}
	s.recordAudit(r, s.auditFor(r, tenantID, projectID, "workflow.create", "workflow", wfID))
	writeJSON(w, http.StatusCreated, map[string]any{"workflow": wf, "nodes": nodes})
}

// handleIngestExecution records (or updates) a tool execution reported by a
// worker.
func (s *Server) handleIngestExecution(w http.ResponseWriter, r *http.Request) {
	var body executionBody
	if !s.readJSON(w, r, &body) {
		return
	}
	exec := body.ToolExecution
	tenantID, ok := s.ingestionTenant(r, exec.TenantID)
	if !ok {
		writeError(w, http.StatusBadRequest, CodeValidation, "tenant could not be resolved", nil)
		return
	}
	exec.TenantID = tenantID
	if exec.ProjectID == "" {
		failValidation(w, "project_id is required", nil)
		return
	}
	if !s.ensureProjectAccess(w, r, tenantID, exec.ProjectID) {
		return
	}
	if workerID := chi.URLParam(r, "workerID"); workerID != "" {
		exec.WorkerID = workerID
	}
	if exec.ID == "" {
		if err := s.store.CreateExecution(r.Context(), exec); err != nil {
			s.writeStoreError(w, err)
			return
		}
	} else if err := s.store.UpdateExecution(r.Context(), exec); err != nil {
		s.writeStoreError(w, err)
		return
	}
	s.recordAudit(r, s.auditFor(r, tenantID, exec.ProjectID, "execution.record", "execution", exec.ID))
	writeJSON(w, http.StatusAccepted, exec)
}

// handleVerifyJob lets a worker or an operator validate a job signature.
func (s *Server) handleVerifyJob(w http.ResponseWriter, r *http.Request) {
	var job domain.Job
	if !s.readJSON(w, r, &job) {
		return
	}
	if err := jobs.Verify(job, s.cfg.JobSigningSecret); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"valid": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"valid": true})
}

// handleAdminRoles exposes the documented role/action matrix (platform only).
func (s *Server) handleAdminRoles(w http.ResponseWriter, r *http.Request) {
	ranks := make(map[string]int, len(auth.TenantRoles)+1)
	for _, role := range auth.TenantRoles {
		ranks[string(role)] = role.Rank()
	}
	ranks[string(auth.RolePlatform)] = auth.RolePlatform.Rank()

	matrix := make(map[string]string, len(auth.AllActions()))
	for _, action := range auth.AllActions() {
		min := ""
		if action.IsPlatform() {
			min = string(auth.RolePlatform)
		} else {
			for _, role := range auth.TenantRoles {
				if auth.Can(role, action) {
					min = string(role)
					break
				}
			}
		}
		matrix[string(action)] = min
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"roles":       auth.TenantRoles,
		"role_ranks":  ranks,
		"actions":     auth.AllActions(),
		"min_roles":   matrix,
		"platform_role": auth.RolePlatform,
	})
}

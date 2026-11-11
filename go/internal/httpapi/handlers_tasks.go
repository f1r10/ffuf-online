package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/ffuf-online/platform/internal/domain"
	"github.com/ffuf-online/platform/internal/jobs"
	"github.com/ffuf-online/platform/internal/tenant"
	"github.com/ffuf-online/platform/internal/worker"
)

var taskStatuses = []string{
	domain.TaskPending, domain.TaskRunning, domain.TaskCompleted,
	domain.TaskFailed, domain.TaskCancelled, domain.TaskBlocked,
}

type taskBody struct {
	TenantID         string         `json:"tenant_id"`
	ProjectID        string         `json:"project_id"`
	WorkflowID       string         `json:"workflow_id"`
	NodeID           string         `json:"node_id"`
	ToolID           string         `json:"tool_id"`
	ToolVersion      string         `json:"tool_version"`
	Input            map[string]any `json:"input"`
	ExecutionProfile string         `json:"execution_profile"`
	Priority         int            `json:"priority"`
	Depth            int            `json:"depth"`
	IdempotencyKey   string         `json:"idempotency_key"`
	Reason           string         `json:"reason"`
	Status           string         `json:"status"`
}

type taskStatusBody struct {
	TenantID string `json:"tenant_id"`
	Status   string `json:"status"`
	Reason   string `json:"reason"`
}

func (s *Server) handleCreateTask(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := s.requireUserTenant(w, r)
	if !ok {
		return
	}
	projectID := chi.URLParam(r, "projectID")
	if !s.ensureProjectAccess(w, r, tenantID, projectID) {
		return
	}
	var body taskBody
	if !s.readJSON(w, r, &body) {
		return
	}
	s.createTask(w, r, tenantID, projectID, body)
}

// handleIngestTask is how the Python planner submits planned work. The tenant
// is taken from the caller's identity for a user/worker and from the body only
// for a trusted service principal.
func (s *Server) handleIngestTask(w http.ResponseWriter, r *http.Request) {
	var body taskBody
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
	s.createTask(w, r, tenantID, projectID, body)
}

func (s *Server) createTask(w http.ResponseWriter, r *http.Request, tenantID, projectID string, body taskBody) {
	body.ToolID = strings.TrimSpace(body.ToolID)
	if body.ToolID == "" {
		failValidation(w, "tool_id is required", nil)
		return
	}
	if _, known := s.toolIndex[body.ToolID]; !known {
		failValidation(w, "unknown tool_id", map[string]any{"tool_id": body.ToolID})
		return
	}
	profile := body.ExecutionProfile
	if profile == "" {
		profile = "passive"
	}
	if !domain.Contains(domain.PolicyProfiles, profile) {
		failValidation(w, "invalid execution_profile", map[string]any{"profiles": domain.PolicyProfiles})
		return
	}
	if body.WorkflowID != "" {
		if _, err := s.store.GetWorkflow(r.Context(), tenantID, body.WorkflowID); err != nil {
			s.writeStoreError(w, err)
			return
		}
	}
	task := s.buildTask(tenantID, projectID, body.ToolID, body.Input, profile, body.Priority, body.Depth,
		body.WorkflowID, body.NodeID, body.IdempotencyKey, body.Reason)
	if body.ToolVersion != "" {
		task.ToolVersion = body.ToolVersion
	}
	stored, duplicate, err := s.store.CreateTask(r.Context(), task)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	if !duplicate {
		s.recordAudit(r, s.auditFor(r, tenantID, projectID, "task.create", "task", stored.ID))
	}
	status := http.StatusCreated
	if duplicate {
		status = http.StatusOK
	}
	writeJSON(w, status, map[string]any{"task": stored, "duplicate": duplicate})
}

func (s *Server) handleListTasks(w http.ResponseWriter, r *http.Request) {
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
	status := r.URL.Query().Get("status")
	items, total, err := s.store.ListTasks(r.Context(), tenantID, projectID, status, limit, offset)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, newList(items, total, limit, offset))
}

func (s *Server) handleGetTask(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := s.requireUserTenant(w, r)
	if !ok {
		return
	}
	t, err := s.store.GetTask(r.Context(), tenantID, chi.URLParam(r, "taskID"))
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, t)
}

// handleTaskStatus is reported by workers (or an operator cancelling work).
func (s *Server) handleTaskStatus(w http.ResponseWriter, r *http.Request) {
	var body taskStatusBody
	if !s.readJSON(w, r, &body) {
		return
	}
	body.Status = strings.ToLower(strings.TrimSpace(body.Status))
	if !domain.Contains(taskStatuses, body.Status) {
		failValidation(w, "unknown task status", map[string]any{"statuses": taskStatuses})
		return
	}
	tenantID := s.machineTenant(r, body.TenantID)
	if tenantID == "" {
		writeError(w, http.StatusBadRequest, CodeValidation, "tenant could not be resolved", nil)
		return
	}
	t, err := s.store.UpdateTaskStatus(r.Context(), tenantID, chi.URLParam(r, "taskID"), body.Status, body.Reason)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	s.recordAudit(r, s.auditFor(r, tenantID, t.ProjectID, "task.status", "task", t.ID))
	writeJSON(w, http.StatusOK, t)
}

// handleDispatchTask selects an eligible worker, builds a signed Job and
// records the attempt.
func (s *Server) handleDispatchTask(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := s.requireUserTenant(w, r)
	if !ok {
		return
	}
	t, err := s.store.GetTask(r.Context(), tenantID, chi.URLParam(r, "taskID"))
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	workers, err := s.store.ListAllWorkers(r.Context())
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	chosen, err := worker.Select(workers, worker.Request{
		TenantID:         tenantID,
		ToolID:           t.ToolID,
		Now:              s.now(),
		HeartbeatTimeout: s.cfg.WorkerHeartbeatTimeout,
	})
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, CodeUnavailable, "no eligible worker available", nil)
		return
	}

	scopeVersion, policyVersion := 0, 0
	limits := domain.JobLimits{CPU: "1.0", Memory: "1g", TimeoutSeconds: 900}
	if sv, _, err := s.store.GetCurrentScope(r.Context(), tenantID, t.ProjectID); err == nil {
		scopeVersion = sv.Version
		policyVersion = sv.PolicyVersion
		if sv.MaxRPS > 0 {
			limits.MaxRPS = intPtr(sv.MaxRPS)
		}
	}
	taskID := t.ID
	job := domain.Job{
		JobID:            newID("job"),
		TenantID:         tenantID,
		ProjectID:        t.ProjectID,
		ScopeVersion:     scopeVersion,
		PolicyVersion:    policyVersion,
		ToolID:           t.ToolID,
		ToolVersion:      t.ToolVersion,
		ExecutionProfile: t.ExecutionProfile,
		Input:            t.Input,
		Limits:           limits,
		TaskID:           &taskID,
		CreatedAt:        s.now(),
		ExpiresAt:        s.now().Add(s.cfg.JobTTL),
		IdempotencyKey:   t.IdempotencyKey,
	}
	signed, err := jobs.Signed(job, s.cfg.JobSigningSecret)
	if err != nil {
		writeError(w, http.StatusInternalServerError, CodeInternal, "could not sign job", nil)
		return
	}
	if err := s.store.CreateTaskAttempt(r.Context(), domain.TaskAttempt{
		ID:        newID("attempt"),
		TenantID:  tenantID,
		TaskID:    t.ID,
		WorkerID:  chosen.ID,
		Status:    "dispatched",
		StartedAt: s.now(),
	}); err != nil {
		s.writeStoreError(w, err)
		return
	}
	s.recordAudit(r, s.auditFor(r, tenantID, t.ProjectID, "task.dispatch", "task", t.ID))
	writeJSON(w, http.StatusOK, map[string]any{"job": signed, "worker_id": chosen.ID})
}

// buildTask assembles a task with a deterministic idempotency key when the
// caller did not supply one, so a replayed plan never duplicates work.
func (s *Server) buildTask(tenantID, projectID, toolID string, input map[string]any, profile string, priority, depth int,
	workflowID, nodeID, idemKey, reason string) domain.Task {
	if input == nil {
		input = map[string]any{}
	}
	if strings.TrimSpace(idemKey) == "" {
		idemKey = taskIdempotencyKey(tenantID, projectID, toolID, depth, input)
	}
	return domain.Task{
		ID:               newID("task"),
		TenantID:         tenantID,
		ProjectID:        projectID,
		WorkflowID:       workflowID,
		NodeID:           nodeID,
		ToolID:           toolID,
		Input:            input,
		ExecutionProfile: profile,
		Priority:         priority,
		Depth:            depth,
		Status:           domain.TaskPending,
		IdempotencyKey:   idemKey,
		Reason:           reason,
		CreatedAt:        s.now(),
	}
}

func taskIdempotencyKey(tenantID, projectID, toolID string, depth int, input map[string]any) string {
	canonical, err := jobs.CanonicalJSON(map[string]any{
		"input":     input,
		"project":   projectID,
		"tenant":    tenantID,
		"tool":      toolID,
		"depth":     depth,
	})
	if err != nil {
		canonical = []byte(tenantID + "|" + projectID + "|" + toolID)
	}
	sum := sha256.Sum256(canonical)
	return "idem_" + hex.EncodeToString(sum[:])
}

// machineTenant resolves the tenant for a machine-reported operation: the
// identity wins for a user, a tenant-less machine principal may name it in the
// body.
func (s *Server) machineTenant(r *http.Request, bodyTenantID string) string {
	id := tenant.FromContext(r.Context())
	if id.Kind == tenant.KindUser {
		return id.TenantID
	}
	if id.TenantID != "" {
		return id.TenantID
	}
	if id.Kind == tenant.KindService || id.Kind == tenant.KindWorker {
		return strings.TrimSpace(bodyTenantID)
	}
	return ""
}

func intPtr(n int) *int { return &n }

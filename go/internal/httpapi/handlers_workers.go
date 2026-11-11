package httpapi

import (
	"net/http"
	"strings"

	"github.com/ffuf-online/platform/internal/auth"
	"github.com/ffuf-online/platform/internal/domain"
	"github.com/ffuf-online/platform/internal/idgen"
	"github.com/ffuf-online/platform/internal/tenant"
)

type createWorkerRequest struct {
	Name    string   `json:"name"`
	Kind    string   `json:"kind"`
	ToolIDs []string `json:"tool_ids"`
}

type heartbeatRequest struct {
	TenantID    string  `json:"tenant_id"`
	WorkerID    string  `json:"worker_id"`
	RunningJobs int     `json:"running_jobs"`
	CPULoad     float64 `json:"cpu_load"`
}

// handleCreateWorker registers a worker and returns its bearer token once. The
// token is only ever stored as a SHA-256 hash.
func (s *Server) handleCreateWorker(w http.ResponseWriter, r *http.Request) {
	id := tenant.FromContext(r.Context())
	tenantID := id.TenantID
	var req createWorkerRequest
	if !s.readJSON(w, r, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		failValidation(w, "name is required", nil)
		return
	}
	kind := strings.ToLower(strings.TrimSpace(req.Kind))
	if kind == "" {
		kind = "tenant"
	}
	switch kind {
	case "tenant":
		if tenantID == "" {
			writeError(w, http.StatusForbidden, CodeForbidden, "a tenant worker requires a tenant-scoped session", nil)
			return
		}
	case "platform":
		if !(id.IsSuperAdmin || id.Role == string(auth.RolePlatform)) {
			writeError(w, http.StatusForbidden, CodeForbidden, "platform workers require the platform role", nil)
			return
		}
		tenantID = ""
	default:
		failValidation(w, "kind must be tenant or platform", nil)
		return
	}
	token := idgen.Token()
	wk := domain.Worker{
		ID:        newID("worker"),
		TenantID:  tenantID,
		Name:      req.Name,
		Kind:      kind,
		Status:    "offline",
		ToolIDs:   req.ToolIDs,
		CreatedAt: s.now(),
		TokenHash: HashToken(token),
	}
	if err := s.store.CreateWorker(r.Context(), wk); err != nil {
		s.writeStoreError(w, err)
		return
	}
	s.recordAudit(r, s.auditFor(r, tenantID, "", "worker.create", "worker", wk.ID))
	writeJSON(w, http.StatusCreated, map[string]any{"worker": wk, "token": token})
}

func (s *Server) handleListWorkers(w http.ResponseWriter, r *http.Request) {
	id := tenant.FromContext(r.Context())
	tenantID := id.TenantID
	if id.IsSuperAdmin || id.Role == string(auth.RolePlatform) {
		tenantID = ""
	}
	limit, offset, err := pagination(r)
	if err != nil {
		failValidation(w, err.Error(), nil)
		return
	}
	items, total, err := s.store.ListWorkers(r.Context(), tenantID, limit, offset)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, newList(items, total, limit, offset))
}

// handleHeartbeat records a worker's liveness sample. A worker token may only
// beat for itself; an operator may beat for a named worker.
func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	var req heartbeatRequest
	if !s.readJSON(w, r, &req) {
		return
	}
	id := tenant.FromContext(r.Context())
	workerID := strings.TrimSpace(req.WorkerID)
	if id.Kind == tenant.KindWorker && id.WorkerID != "" {
		workerID = id.WorkerID
	}
	if workerID == "" {
		failValidation(w, "worker_id is required", nil)
		return
	}
	if err := s.store.UpdateWorkerHeartbeat(r.Context(), workerID, req.RunningJobs, req.CPULoad, s.now()); err != nil {
		s.writeStoreError(w, err)
		return
	}
	wk, err := s.store.GetWorker(r.Context(), workerID)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, wk)
}

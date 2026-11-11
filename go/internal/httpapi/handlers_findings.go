package httpapi

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/ffuf-online/platform/internal/auth"
	"github.com/ffuf-online/platform/internal/domain"
	"github.com/ffuf-online/platform/internal/tenant"
)

var findingSeverities = []string{"unknown", "info", "low", "medium", "high", "critical"}

// createFindingStatuses are the only statuses a finding may be created with.
// Anything at or beyond `validated` must go through the explicit transition
// endpoint so it carries an approver.
var createFindingStatuses = []string{"discovered", "candidate", "needs_validation"}

// findingTransitions is the allowed lifecycle state machine.
var findingTransitions = map[string][]string{
	"discovered":       {"candidate"},
	"candidate":        {"needs_validation", "rejected"},
	"needs_validation": {"validated", "rejected"},
	"validated":        {"confirmed_impact", "rejected"},
	"confirmed_impact": {"report_ready"},
	"report_ready":     {"submitted"},
	"submitted":        {"accepted", "duplicate", "informative", "rejected"},
}

// validationStatuses require finding:validate and an explicit approver.
var validationStatuses = map[string]bool{
	"validated":        true,
	"confirmed_impact": true,
	"report_ready":     true,
	"submitted":        true,
	"accepted":         true,
	"duplicate":        true,
	"informative":      true,
	"rejected":         true,
}

type findingBody struct {
	TenantID          string   `json:"tenant_id"`
	ProjectID         string   `json:"project_id"`
	AssetID           *string  `json:"asset_id"`
	Endpoint          *string  `json:"endpoint"`
	HTTPMethod        *string  `json:"http_method"`
	Parameter         *string  `json:"parameter"`
	FindingType       string   `json:"finding_type"`
	Title             string   `json:"title"`
	Severity          string   `json:"severity"`
	Confidence        float64  `json:"confidence"`
	Status            string   `json:"status"`
	SourceTools       []string `json:"source_tools"`
	EvidenceIDs       []string `json:"evidence_ids"`
	RelatedFindingIDs []string `json:"related_finding_ids"`
	ScopeVersion      int      `json:"scope_version"`
}

type transitionBody struct {
	Status     string `json:"status"`
	Reason     string `json:"reason"`
	ApprovedBy string `json:"approved_by"`
}

func (s *Server) handleCreateFinding(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := s.requireUserTenant(w, r)
	if !ok {
		return
	}
	projectID := chi.URLParam(r, "projectID")
	if !s.ensureProjectAccess(w, r, tenantID, projectID) {
		return
	}
	var body findingBody
	if !s.readJSON(w, r, &body) {
		return
	}
	s.createFinding(w, r, tenantID, projectID, body)
}

func (s *Server) handleIngestFinding(w http.ResponseWriter, r *http.Request) {
	var body findingBody
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
	s.createFinding(w, r, tenantID, projectID, body)
}

func (s *Server) createFinding(w http.ResponseWriter, r *http.Request, tenantID, projectID string, body findingBody) {
	body.FindingType = strings.TrimSpace(body.FindingType)
	body.Title = strings.TrimSpace(body.Title)
	if body.FindingType == "" || body.Title == "" {
		failValidation(w, "finding_type and title are required", nil)
		return
	}
	if body.Severity == "" {
		body.Severity = "unknown"
	}
	if !domain.Contains(findingSeverities, body.Severity) {
		failValidation(w, "invalid severity", map[string]any{"severities": findingSeverities})
		return
	}
	if body.Confidence < 0 || body.Confidence > 1 {
		failValidation(w, "confidence must be between 0 and 1", nil)
		return
	}
	if body.Status == "" {
		body.Status = "discovered"
	}
	if !domain.Contains(createFindingStatuses, body.Status) {
		failValidation(w, "findings may only be created as discovered, candidate or needs_validation", map[string]any{"statuses": createFindingStatuses})
		return
	}
	f := domain.Finding{
		ID:                newID("finding"),
		TenantID:          tenantID,
		ProjectID:         projectID,
		AssetID:           body.AssetID,
		Endpoint:          body.Endpoint,
		HTTPMethod:        body.HTTPMethod,
		Parameter:         body.Parameter,
		FindingType:       body.FindingType,
		Title:             body.Title,
		Severity:          body.Severity,
		Confidence:        body.Confidence,
		Status:            body.Status,
		SourceTools:       body.SourceTools,
		EvidenceIDs:       body.EvidenceIDs,
		RelatedFindingIDs: body.RelatedFindingIDs,
		ScopeVersion:      body.ScopeVersion,
		CreatedAt:         s.now(),
		UpdatedAt:         s.now(),
	}
	stored, created, err := s.store.CreateFinding(r.Context(), f)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	if created {
		s.recordAudit(r, s.auditFor(r, tenantID, projectID, "finding.create", "finding", stored.ID))
	}
	status := http.StatusCreated
	if !created {
		status = http.StatusOK
	}
	writeJSON(w, status, map[string]any{"finding": stored, "created": created})
}

func (s *Server) handleListFindings(w http.ResponseWriter, r *http.Request) {
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
	items, total, err := s.store.ListFindings(r.Context(), tenantID, projectID, status, limit, offset)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, newList(items, total, limit, offset))
}

func (s *Server) handleGetFinding(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := s.requireUserTenant(w, r)
	if !ok {
		return
	}
	f, err := s.store.GetFinding(r.Context(), tenantID, chi.URLParam(r, "findingID"))
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, f)
}

// handleTransitionFinding applies a validated lifecycle transition. Reaching
// `validated` (or any later state, including `rejected`) additionally requires
// the finding:validate permission and an explicit approver.
func (s *Server) handleTransitionFinding(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := s.requireUserTenant(w, r)
	if !ok {
		return
	}
	var body transitionBody
	if !s.readJSON(w, r, &body) {
		return
	}
	body.Status = strings.ToLower(strings.TrimSpace(body.Status))
	if !domain.Contains(domain.FindingStatuses, body.Status) {
		failValidation(w, "unknown status", map[string]any{"statuses": domain.FindingStatuses})
		return
	}
	f, err := s.store.GetFinding(r.Context(), tenantID, chi.URLParam(r, "findingID"))
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	allowed := false
	for _, next := range findingTransitions[f.Status] {
		if next == body.Status {
			allowed = true
			break
		}
	}
	if !allowed {
		writeError(w, http.StatusConflict, CodeConflict, "illegal finding transition",
			map[string]any{"from": f.Status, "to": body.Status, "allowed": findingTransitions[f.Status]})
		return
	}

	id := tenant.FromContext(r.Context())
	role := auth.Role(id.Role)
	if validationStatuses[body.Status] {
		if !auth.Can(role, auth.ActionFindingValidate) {
			writeError(w, http.StatusForbidden, CodeForbidden, "validation requires the finding:validate permission",
				map[string]any{"action": string(auth.ActionFindingValidate)})
			return
		}
		if strings.TrimSpace(body.ApprovedBy) == "" {
			failValidation(w, "approved_by is required for validated findings", nil)
			return
		}
		f.ApprovedBy = strings.TrimSpace(body.ApprovedBy)
	}

	f.Status = body.Status
	if err := s.store.UpdateFinding(r.Context(), f); err != nil {
		s.writeStoreError(w, err)
		return
	}
	entry := s.auditFor(r, tenantID, f.ProjectID, "finding.transition", "finding", f.ID)
	entry.Result = "success"
	s.recordAudit(r, entry)
	writeJSON(w, http.StatusOK, f)
}

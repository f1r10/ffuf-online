package httpapi

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/ffuf-online/platform/internal/domain"
)

type assetsBody struct {
	TenantID  string         `json:"tenant_id"`
	ProjectID string         `json:"project_id"`
	Assets    []domain.Asset `json:"assets"`
}

type endpointBody struct {
	TenantID    string `json:"tenant_id"`
	ProjectID   string `json:"project_id"`
	AssetID     string `json:"asset_id"`
	URL         string `json:"url"`
	Method      string `json:"method"`
	StatusCode  *int   `json:"status_code"`
	ContentType string `json:"content_type"`
}

// handleCreateAssets upserts assets into the caller's project. The tenant and
// project come from the identity and the path; any body tenant_id is ignored.
func (s *Server) handleCreateAssets(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := s.requireUserTenant(w, r)
	if !ok {
		return
	}
	projectID := chi.URLParam(r, "projectID")
	if !s.ensureProjectAccess(w, r, tenantID, projectID) {
		return
	}
	var body assetsBody
	if !s.readJSON(w, r, &body) {
		return
	}
	s.upsertAssets(w, r, tenantID, projectID, body.Assets)
}

// handleIngestAssets is the machine ingestion path (Python adapters/engine).
func (s *Server) handleIngestAssets(w http.ResponseWriter, r *http.Request) {
	var body assetsBody
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
	s.upsertAssets(w, r, tenantID, projectID, body.Assets)
}

func (s *Server) upsertAssets(w http.ResponseWriter, r *http.Request, tenantID, projectID string, assets []domain.Asset) {
	if len(assets) == 0 {
		failValidation(w, "assets must not be empty", nil)
		return
	}
	for i := range assets {
		assets[i].TenantID = tenantID
		assets[i].ProjectID = projectID
		if assets[i].AssetType == "" || assets[i].Value == "" {
			failValidation(w, "each asset requires asset_type and value", map[string]any{"index": i})
			return
		}
		if !domain.Contains(domain.AssetTypes, assets[i].AssetType) {
			failValidation(w, "invalid asset_type", map[string]any{"index": i, "types": domain.AssetTypes})
			return
		}
	}
	res, err := s.store.UpsertAssets(r.Context(), tenantID, projectID, assets)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	s.recordAudit(r, s.auditFor(r, tenantID, projectID, "asset.upsert", "asset", projectID))
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleListAssets(w http.ResponseWriter, r *http.Request) {
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
	items, total, err := s.store.ListAssets(r.Context(), tenantID, projectID, limit, offset)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, newList(items, total, limit, offset))
}

func (s *Server) handleGetAsset(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := s.requireUserTenant(w, r)
	if !ok {
		return
	}
	a, err := s.store.GetAsset(r.Context(), tenantID, chi.URLParam(r, "assetID"))
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, a)
}

func (s *Server) handleCreateEndpoint(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := s.requireUserTenant(w, r)
	if !ok {
		return
	}
	projectID := chi.URLParam(r, "projectID")
	if !s.ensureProjectAccess(w, r, tenantID, projectID) {
		return
	}
	var body endpointBody
	if !s.readJSON(w, r, &body) {
		return
	}
	s.createEndpoint(w, r, tenantID, projectID, body)
}

func (s *Server) handleIngestEndpoint(w http.ResponseWriter, r *http.Request) {
	var body endpointBody
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
	s.createEndpoint(w, r, tenantID, projectID, body)
}

func (s *Server) createEndpoint(w http.ResponseWriter, r *http.Request, tenantID, projectID string, body endpointBody) {
	body.URL = strings.TrimSpace(body.URL)
	if body.URL == "" {
		failValidation(w, "url is required", nil)
		return
	}
	if body.Method == "" {
		body.Method = http.MethodGet
	}
	e := domain.Endpoint{
		ID:          newID("ep"),
		TenantID:    tenantID,
		ProjectID:   projectID,
		AssetID:     body.AssetID,
		URL:         body.URL,
		Method:      strings.ToUpper(body.Method),
		StatusCode:  body.StatusCode,
		ContentType: body.ContentType,
		FirstSeenAt: s.now(),
	}
	if err := s.store.CreateEndpoint(r.Context(), e); err != nil {
		s.writeStoreError(w, err)
		return
	}
	s.recordAudit(r, s.auditFor(r, tenantID, projectID, "endpoint.create", "endpoint", e.ID))
	writeJSON(w, http.StatusCreated, e)
}

func (s *Server) handleListEndpoints(w http.ResponseWriter, r *http.Request) {
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
	items, total, err := s.store.ListEndpoints(r.Context(), tenantID, projectID, limit, offset)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, newList(items, total, limit, offset))
}

func (s *Server) handleListExecutions(w http.ResponseWriter, r *http.Request) {
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
	items, total, err := s.store.ListExecutions(r.Context(), tenantID, projectID, limit, offset)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, newList(items, total, limit, offset))
}

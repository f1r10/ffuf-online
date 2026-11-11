package httpapi

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/ffuf-online/platform/internal/domain"
	"github.com/ffuf-online/platform/internal/eventbus"
)

// handleIngestEvent accepts a DomainEvent from the intelligence engine or an
// adapter, persists it, fans it out on the bus and forwards it to the Python
// intelligence engine. Forwarding is best-effort and never fails the request.
func (s *Server) handleIngestEvent(w http.ResponseWriter, r *http.Request) {
	var ev domain.DomainEvent
	if !s.readJSON(w, r, &ev) {
		return
	}
	tenantID, ok := s.ingestionTenant(r, ev.TenantID)
	if !ok {
		writeError(w, http.StatusBadRequest, CodeValidation, "tenant could not be resolved", nil)
		return
	}
	ev.TenantID = tenantID
	ev.ProjectID = strings.TrimSpace(ev.ProjectID)
	if ev.ProjectID == "" {
		failValidation(w, "project_id is required", nil)
		return
	}
	ev.EventType = strings.TrimSpace(ev.EventType)
	if ev.EventType == "" {
		failValidation(w, "event_type is required", nil)
		return
	}
	if !domain.Contains(domain.EventTypes, ev.EventType) {
		failValidation(w, "unknown event_type", map[string]any{"event_types": domain.EventTypes})
		return
	}
	if !s.ensureProjectAccess(w, r, tenantID, ev.ProjectID) {
		return
	}
	if ev.EventID == "" {
		ev.EventID = newID("evt")
	}
	if ev.SchemaVersion == "" {
		ev.SchemaVersion = "1.0.0"
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = s.now()
	}
	if ev.Payload == nil {
		ev.Payload = map[string]any{}
	}
	if ev.ScopeVersion == 0 {
		ev.ScopeVersion = 1
	}

	stored, created, err := s.store.CreateEvent(r.Context(), ev)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}

	forwarded := false
	if created {
		if err := s.bus.Publish(r.Context(), eventbus.SubjectEvents, stored); err != nil {
			s.log.Warn("event bus publish failed", "event_id", stored.EventID, "error", err)
		}
		if s.forwarder != nil && s.forwarder.Enabled() {
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			if ferr := s.forwarder.Forward(ctx, stored); ferr != nil {
				s.log.Warn("intel forward failed", "event_id", stored.EventID, "error", ferr)
			} else {
				forwarded = true
			}
			cancel()
		}
		s.recordAudit(r, s.auditFor(r, tenantID, stored.ProjectID, "event.ingest", "event", stored.EventID))
	}

	writeJSON(w, http.StatusAccepted, map[string]any{
		"event":     stored,
		"duplicate": !created,
		"forwarded": forwarded,
	})
}

func (s *Server) handleListEvents(w http.ResponseWriter, r *http.Request) {
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
	items, total, err := s.store.ListEvents(r.Context(), tenantID, projectID, limit, offset)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, newList(items, total, limit, offset))
}

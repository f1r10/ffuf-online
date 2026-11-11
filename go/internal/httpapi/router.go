// Package httpapi is the HTTP control plane of FFUF Online.
//
// It hosts the /api/v1 surface: authentication, tenant-scoped CRUD, the scope
// decision proxy to the Rust engine, ingestion from the Python intelligence
// engine, worker management and the append-only audit surface.
//
// Two invariants are enforced here and tested in httpapi_test.go:
//
//  1. A request's tenant is derived exclusively from the authenticated identity
//     (see middleware.go). No handler ever reads a tenant id from a body, the
//     query string or a header.
//  2. Scope is never decided by Go. Every decision is delegated to the Rust
//     scope engine through internal/scopesdk.
package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/ffuf-online/platform/internal/audit"
	"github.com/ffuf-online/platform/internal/auth"
	"github.com/ffuf-online/platform/internal/config"
	"github.com/ffuf-online/platform/internal/domain"
	"github.com/ffuf-online/platform/internal/eventbus"
	"github.com/ffuf-online/platform/internal/scopesdk"
	"github.com/ffuf-online/platform/internal/store"
)

// Version is the reported control-plane version.
const Version = "1.0.0"

// Options configures a Server. Only Config, Store and JWT are mandatory; the
// remaining collaborators are constructed with sensible defaults when nil.
type Options struct {
	Config    config.Config
	Store     store.Store
	JWT       *auth.JWTManager
	Logger    *slog.Logger
	Audit     *audit.Recorder
	Scope     *scopesdk.Client
	Bus       eventbus.Bus
	Forwarder *eventbus.Forwarder
	Tools     []domain.Tool
}

// Server holds every dependency of the HTTP surface.
type Server struct {
	cfg       config.Config
	store     store.Store
	jwt       *auth.JWTManager
	log       *slog.Logger
	audit     *audit.Recorder
	scope     *scopesdk.Client
	bus       eventbus.Bus
	forwarder *eventbus.Forwarder
	tools     []domain.Tool
	toolIndex map[string]domain.Tool
	now       func() time.Time
}

// New builds a Server from opts.
func New(opts Options) (*Server, error) {
	if opts.Store == nil {
		return nil, errors.New("httpapi: Store is required")
	}
	if opts.JWT == nil {
		return nil, errors.New("httpapi: JWT is required")
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	s := &Server{
		cfg:   opts.Config,
		store: opts.Store,
		jwt:   opts.JWT,
		log:   logger,
		scope: opts.Scope,
		bus:   opts.Bus,
		now:   func() time.Time { return time.Now().UTC() },
	}
	if s.scope == nil {
		s.scope = scopesdk.New(opts.Config.ScopeEngineURL)
	}
	if opts.Audit != nil {
		s.audit = opts.Audit
	} else {
		s.audit = audit.NewRecorder(opts.Store)
	}
	if opts.Bus != nil {
		s.bus = opts.Bus
	} else {
		s.bus = eventbus.Nop{}
	}
	if opts.Forwarder != nil {
		s.forwarder = opts.Forwarder
	} else {
		s.forwarder = eventbus.NewForwarder(opts.Config.IntelURL, 5*time.Second, logger)
	}
	if opts.Tools != nil {
		s.tools = opts.Tools
	} else {
		loaded, _, _ := domain.LoadToolRegistry(opts.Config.ToolRegistryPath)
		s.tools = loaded
	}
	s.toolIndex = domain.ToolIndex(s.tools)
	return s, nil
}

// Now overrides the clock (test hook).
func (s *Server) Now(fn func() time.Time) { s.now = fn }

// Router mounts the whole HTTP surface.
func (s *Server) Router() http.Handler {
	r := chi.NewRouter()
	r.Use(chimw.RealIP)
	r.Use(chimw.RequestID)
	r.Use(s.recoverer)
	r.Use(s.authenticate)

	r.NotFound(s.handleNotFound)
	r.MethodNotAllowed(s.handleMethodNotAllowed)

	r.Get("/healthz", s.handleHealth)
	r.Get("/api/v1/healthz", s.handleHealth)
	r.Get("/api/v1/meta", s.handleMeta)

	// ---- auth ----
	r.Post("/api/v1/auth/login", s.handleLogin)
	r.Get("/api/v1/auth/me", s.handleMe)

	// ---- tenants ----
	r.With(s.require(auth.ActionPlatformTenantManage)).Get("/api/v1/tenants", s.handleListTenants)
	r.Post("/api/v1/tenants", s.handleCreateTenant)
	r.Get("/api/v1/tenants/current", s.handleGetCurrentTenant)
	r.Get("/api/v1/tenants/{tenantID}", s.handleGetTenant)

	// ---- members ----
	r.With(s.require(auth.ActionMemberManage)).Get("/api/v1/members", s.handleListMembers)
	r.With(s.require(auth.ActionMemberManage)).Post("/api/v1/members", s.handleCreateMember)
	r.With(s.require(auth.ActionMemberManage)).Patch("/api/v1/members/{userID}", s.handleUpdateMember)

	// ---- projects ----
	r.With(s.require(auth.ActionProjectRead)).Get("/api/v1/projects", s.handleListProjects)
	r.With(s.require(auth.ActionProjectWrite)).Post("/api/v1/projects", s.handleCreateProject)
	r.With(s.require(auth.ActionProjectRead)).Get("/api/v1/projects/{projectID}", s.handleGetProject)

	// ---- programs ----
	r.With(s.require(auth.ActionProjectRead)).Get("/api/v1/projects/{projectID}/programs", s.handleListPrograms)
	r.With(s.require(auth.ActionProjectWrite)).Post("/api/v1/projects/{projectID}/programs", s.handleCreateProgram)

	// ---- authorization evidence ----
	r.With(s.require(auth.ActionProjectRead)).Get("/api/v1/projects/{projectID}/authorization", s.handleListAuthorization)
	r.With(s.require(auth.ActionScopeAuthorize)).Post("/api/v1/projects/{projectID}/authorization", s.handleCreateAuthorization)

	// ---- scope ----
	r.With(s.require(auth.ActionProjectRead)).Get("/api/v1/projects/{projectID}/scope", s.handleGetScope)
	r.With(s.require(auth.ActionScopeWrite)).Post("/api/v1/projects/{projectID}/scope", s.handleCreateScope)
	r.With(s.require(auth.ActionScopeAuthorize)).Post("/api/v1/projects/{projectID}/scope/authorize", s.handleAuthorizeScope)
	r.With(s.require(auth.ActionProjectRead)).Post("/api/v1/projects/{projectID}/scope/decide", s.handleScopeDecide)

	// ---- scans (workflow + first task) ----
	r.With(s.require(auth.ActionProjectRead)).Get("/api/v1/projects/{projectID}/scans", s.handleListScans)
	r.With(s.require(auth.ActionProjectWrite)).Post("/api/v1/projects/{projectID}/scans", s.handleCreateScan)
	r.With(s.require(auth.ActionProjectRead)).Get("/api/v1/projects/{projectID}/workflows/{workflowID}", s.handleGetWorkflow)

	// ---- assets & endpoints ----
	r.With(s.require(auth.ActionAssetRead)).Get("/api/v1/projects/{projectID}/assets", s.handleListAssets)
	r.With(s.require(auth.ActionAssetWrite)).Post("/api/v1/projects/{projectID}/assets", s.handleCreateAssets)
	r.With(s.require(auth.ActionAssetRead)).Get("/api/v1/assets/{assetID}", s.handleGetAsset)
	r.With(s.require(auth.ActionAssetRead)).Get("/api/v1/projects/{projectID}/endpoints", s.handleListEndpoints)
	r.With(s.require(auth.ActionAssetWrite)).Post("/api/v1/projects/{projectID}/endpoints", s.handleCreateEndpoint)

	// ---- findings ----
	r.With(s.require(auth.ActionFindingRead)).Get("/api/v1/projects/{projectID}/findings", s.handleListFindings)
	r.With(s.require(auth.ActionFindingWrite)).Post("/api/v1/projects/{projectID}/findings", s.handleCreateFinding)
	r.With(s.require(auth.ActionFindingRead)).Get("/api/v1/findings/{findingID}", s.handleGetFinding)
	r.With(s.require(auth.ActionFindingRead)).Post("/api/v1/findings/{findingID}/transition", s.handleTransitionFinding)

	// ---- tasks ----
	r.With(s.require(auth.ActionTaskRead)).Get("/api/v1/projects/{projectID}/tasks", s.handleListTasks)
	r.With(s.require(auth.ActionProjectWrite)).Post("/api/v1/projects/{projectID}/tasks", s.handleCreateTask)
	r.With(s.require(auth.ActionTaskRead)).Get("/api/v1/tasks/{taskID}", s.handleGetTask)
	r.With(s.workerOr(auth.ActionProjectWrite)).Post("/api/v1/tasks/{taskID}/status", s.handleTaskStatus)
	r.With(s.require(auth.ActionProjectWrite)).Post("/api/v1/tasks/{taskID}/dispatch", s.handleDispatchTask)

	// ---- executions ----
	r.With(s.require(auth.ActionProjectRead)).Get("/api/v1/projects/{projectID}/executions", s.handleListExecutions)

	// ---- events ----
	r.With(s.require(auth.ActionProjectRead)).Get("/api/v1/projects/{projectID}/events", s.handleListEvents)

	// ---- workers ----
	r.With(s.require(auth.ActionWorkerManage)).Get("/api/v1/workers", s.handleListWorkers)
	r.With(s.require(auth.ActionWorkerManage)).Post("/api/v1/workers", s.handleCreateWorker)
	r.With(s.workerOr(auth.ActionWorkerManage)).Post("/api/v1/workers/heartbeat", s.handleHeartbeat)

	// ---- tools ----
	r.With(s.require(auth.ActionProjectRead)).Get("/api/v1/tools", s.handleListTools)

	// ---- audit ----
	r.With(s.require(auth.ActionAuditRead)).Get("/api/v1/audit", s.handleListAudit)
	r.With(s.require(auth.ActionAuditRead)).Get("/api/v1/audit/verify", s.handleVerifyAudit)

	// ---- usage ----
	r.With(s.require(auth.ActionUsageRead)).Get("/api/v1/usage", s.handleListUsage)

	// ---- platform admin ----
	r.With(s.require(auth.ActionPlatformAdmin)).Get("/api/v1/admin/roles", s.handleAdminRoles)

	// ---- ingestion (machine-to-machine) ----
	r.With(s.allowIngest(auth.ActionAssetWrite)).Post("/api/v1/events", s.handleIngestEvent)
	r.With(s.allowIngest(auth.ActionAssetWrite)).Post("/api/v1/assets", s.handleIngestAssets)
	r.With(s.allowIngest(auth.ActionAssetWrite)).Post("/api/v1/endpoints", s.handleIngestEndpoint)
	r.With(s.allowIngest(auth.ActionFindingWrite)).Post("/api/v1/findings", s.handleIngestFinding)
	r.With(s.allowIngest(auth.ActionTaskRead)).Post("/api/v1/tasks", s.handleIngestTask)
	r.With(s.allowIngest(auth.ActionAssetWrite)).Post("/api/v1/workflows", s.handleIngestWorkflow)
	r.With(s.allowIngest(auth.ActionAssetWrite)).Post("/api/v1/executions", s.handleIngestExecution)
	r.With(s.allowIngest(auth.ActionUsageRead)).Post("/api/v1/usage", s.handleIngestUsage)
	r.With(s.allowIngest(auth.ActionTaskRead)).Post("/api/v1/jobs/verify", s.handleVerifyJob)
	r.With(s.allowIngest(auth.ActionAssetWrite)).Post("/api/v1/workers/{workerID}/executions", s.handleIngestExecution)

	return r
}

// recoverer converts a panic into the canonical error envelope.
func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.log.Error("panic recovered", "error", rec, "path", r.URL.Path, "stack", string(debug.Stack()))
				writeError(w, http.StatusInternalServerError, CodeInternal, "internal error", nil)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleNotFound(w http.ResponseWriter, _ *http.Request) {
	writeError(w, http.StatusNotFound, CodeNotFound, "resource not found", nil)
}

func (s *Server) handleMethodNotAllowed(w http.ResponseWriter, _ *http.Request) {
	writeError(w, http.StatusMethodNotAllowed, CodeBadRequest, "method not allowed", nil)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	status := "ok"
	code := http.StatusOK
	dbErr := ""
	if err := s.store.Ping(r.Context()); err != nil {
		status = "degraded"
		code = http.StatusServiceUnavailable
		dbErr = err.Error()
	}
	resp := map[string]any{
		"status":  status,
		"version": Version,
		"storage": s.cfg.Storage,
	}
	if dbErr != "" {
		resp["error"] = dbErr
	}
	writeJSON(w, code, resp)
}

func (s *Server) handleMeta(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"version":       Version,
		"event_types":   domain.EventTypes,
		"asset_types":   domain.AssetTypes,
		"finding_statuses": domain.FindingStatuses,
		"policy_profiles":  domain.PolicyProfiles,
		"roles":         auth.TenantRoles,
		"actions":       auth.AllActions(),
	})
}

// readJSON decodes the body into dst, writing a 400 response on failure.
func (s *Server) readJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	if err := decodeJSON(r, dst); err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid JSON body", map[string]any{"reason": err.Error()})
		return false
	}
	return true
}

// failValidation writes the canonical validation error.
func failValidation(w http.ResponseWriter, message string, details any) {
	writeError(w, http.StatusBadRequest, CodeValidation, message, details)
}

// readOptionalJSON decodes the body when one is present; an absent or empty
// body is not an error.
func readOptionalJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	if r.Body == nil || r.ContentLength == 0 {
		return true
	}
	if err := decodeJSON(r, dst); err != nil {
		if errors.Is(err, io.EOF) {
			return true
		}
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid JSON body", map[string]any{"reason": err.Error()})
		return false
	}
	return true
}

// mustJSON marshals v for audit details; a failure yields nil.
func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
}

package httpapi

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/ffuf-online/platform/internal/audit"
	"github.com/ffuf-online/platform/internal/auth"
	"github.com/ffuf-online/platform/internal/idgen"
	"github.com/ffuf-online/platform/internal/tenant"
)

const (
	defaultLimit = 50
	maxLimit     = 200
	maxBodyBytes = 1 << 20 // 1 MiB
)

// HashToken returns the hex SHA-256 of a bearer token. Worker tokens are stored
// and looked up only as hashes; the plaintext is never persisted.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// authenticate resolves the request principal once and stores it in the
// context. It is the ONLY place a tenant id enters a request.
func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := s.resolveIdentity(r)
		next.ServeHTTP(w, r.WithContext(tenant.With(r.Context(), id)))
	})
}

func (s *Server) resolveIdentity(r *http.Request) tenant.Identity {
	// 1. Internal service token.
	if provided := r.Header.Get("X-Service-Token"); provided != "" && s.cfg.ServiceToken != "" {
		if subtle.ConstantTimeCompare([]byte(provided), []byte(s.cfg.ServiceToken)) == 1 {
			return tenant.Identity{Kind: tenant.KindService}
		}
	}
	// 2. Bearer credentials: a user JWT or a worker token.
	if bearer := bearerToken(r); bearer != "" {
		if claims, err := s.jwt.Parse(bearer); err == nil {
			role := claims.Role
			if claims.SuperAdmin {
				role = string(auth.RolePlatform)
			}
			return tenant.Identity{
				Kind:         tenant.KindUser,
				UserID:       claims.Subject,
				TenantID:     claims.TenantID,
				Role:         role,
				IsSuperAdmin: claims.SuperAdmin,
			}
		}
		if w, err := s.store.GetWorkerByTokenHash(r.Context(), HashToken(bearer)); err == nil {
			return tenant.Identity{Kind: tenant.KindWorker, WorkerID: w.ID, TenantID: w.TenantID}
		}
	}
	return tenant.Identity{}
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

// require enforces that the caller is an authenticated user holding action.
func (s *Server) require(action auth.Action) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := tenant.FromContext(r.Context())
			if id.Kind != tenant.KindUser {
				writeError(w, http.StatusUnauthorized, CodeUnauthorized, "authentication required", nil)
				return
			}
			if !auth.Can(auth.Role(id.Role), action) {
				writeError(w, http.StatusForbidden, CodeForbidden, "permission denied", map[string]any{"action": string(action)})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// workerActions is the fixed set of actions a worker token may perform.
var workerActions = map[auth.Action]bool{
	auth.ActionAssetWrite:   true,
	auth.ActionAssetRead:    true,
	auth.ActionFindingWrite: true,
	auth.ActionFindingRead:  true,
	auth.ActionTaskRead:     true,
	auth.ActionUsageRead:    true,
}

// allowIngest guards a machine-to-machine ingestion endpoint.
//
// When SERVICE_TOKEN is configured the caller MUST present it; when it is empty
// (development) an anonymous request is accepted and treated as an internal
// service principal. A valid worker token is also accepted.
func (s *Server) allowIngest(action auth.Action) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := tenant.FromContext(r.Context())
			if s.cfg.ServiceToken != "" {
				if id.Kind != tenant.KindService {
					writeError(w, http.StatusUnauthorized, CodeUnauthorized, "service token required", nil)
					return
				}
			} else if id.Kind == "" {
				id = tenant.Identity{Kind: tenant.KindService}
				r = r.WithContext(tenant.With(r.Context(), id))
			}
			if !machineAllowed(id, action) {
				writeError(w, http.StatusForbidden, CodeForbidden, "permission denied", map[string]any{"action": string(action)})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func machineAllowed(id tenant.Identity, action auth.Action) bool {
	switch id.Kind {
	case tenant.KindService:
		return !action.IsPlatform()
	case tenant.KindWorker:
		return workerActions[action]
	case tenant.KindUser:
		return auth.Can(auth.Role(id.Role), action)
	default:
		return false
	}
}

// workerOr guards an endpoint that may be driven either by a machine principal
// (a worker agent or an internal service) or by a human holding action.
//
// It is deliberately distinct from allowIngest: it does NOT consult the worker
// action allowlist, so it is only used where an unauthenticated caller must
// never be accepted and where a worker legitimately performs the operation
// (task status reports, heartbeats).
func (s *Server) workerOr(action auth.Action) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := tenant.FromContext(r.Context())
			ok := false
			switch id.Kind {
			case tenant.KindService:
				ok = !action.IsPlatform()
			case tenant.KindWorker:
				ok = true
			case tenant.KindUser:
				ok = auth.Can(auth.Role(id.Role), action)
			}
			if !ok {
				writeError(w, http.StatusForbidden, CodeForbidden, "permission denied", map[string]any{"action": string(action)})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// identityTenant returns the caller's tenant for user/worker principals.
func identityTenant(r *http.Request) (string, bool) {
	id := tenant.FromContext(r.Context())
	if id.Kind == tenant.KindUser || id.Kind == tenant.KindWorker {
		return id.TenantID, true
	}
	return "", false
}

// ingestionTenant resolves the tenant of an ingestion request.
//
// This is the single, explicit exception to "tenant comes from identity": a
// trusted internal service principal (authenticated with SERVICE_TOKEN) may
// address any tenant and therefore supplies it in the body. A user or worker
// principal NEVER does: its tenant strictly wins and any body tenant_id is
// ignored.
func (s *Server) ingestionTenant(r *http.Request, bodyTenantID string) (string, bool) {
	id := tenant.FromContext(r.Context())
	switch id.Kind {
	case tenant.KindUser, tenant.KindWorker:
		if id.TenantID == "" {
			return "", false
		}
		return id.TenantID, true
	case tenant.KindService:
		if bodyTenantID == "" {
			return "", false
		}
		return bodyTenantID, true
	default:
		return "", false
	}
}

// decodeJSON decodes at most maxBodyBytes of the request body into dst.
func decodeJSON(r *http.Request, dst any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes))
	return dec.Decode(dst)
}

// pagination parses ?limit=&offset= and applies the documented defaults.
func pagination(r *http.Request) (limit, offset int, err error) {
	limit, offset = defaultLimit, 0
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, convErr := strconv.Atoi(raw)
		if convErr != nil || n < 0 {
			return 0, 0, errBadParam("limit must be a non-negative integer")
		}
		if n == 0 {
			n = defaultLimit
		}
		limit = n
	}
	if limit > maxLimit {
		limit = maxLimit
	}
	if raw := r.URL.Query().Get("offset"); raw != "" {
		n, convErr := strconv.Atoi(raw)
		if convErr != nil || n < 0 {
			return 0, 0, errBadParam("offset must be a non-negative integer")
		}
		offset = n
	}
	return limit, offset, nil
}

type badParamError struct{ msg string }

func (e badParamError) Error() string { return e.msg }

func errBadParam(msg string) error { return badParamError{msg: msg} }

// auditFor builds an audit entry attributed to the current principal in the
// given tenant. Every mutating handler calls Record with one of these.
func (s *Server) auditFor(r *http.Request, tenantID, projectID, action, resourceType, resourceID string) audit.Entry {
	id := tenant.FromContext(r.Context())
	e := audit.Entry{
		TenantID:     tenantID,
		ProjectID:    projectID,
		ActorUserID:  id.UserID,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Result:       "success",
	}
	switch id.Kind {
	case tenant.KindUser:
		e.ActorKind = "user"
	case tenant.KindWorker:
		e.ActorKind = "worker"
	default:
		e.ActorKind = "system"
	}
	return e
}

// recordAudit appends an audit entry; a failure to audit is logged but never
// fails the request (the operation already happened).
func (s *Server) recordAudit(r *http.Request, e audit.Entry) {
	if _, err := s.audit.Record(r.Context(), e); err != nil {
		s.log.Error("audit record failed", "action", e.Action, "error", err)
	}
}

// newID is a small indirection so handlers stay readable.
func newID(prefix string) string { return idgen.New(prefix) }

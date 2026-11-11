// Package store defines the persistence contract of the control plane.
//
// Every method takes the tenant id explicitly as its second argument. There is
// no ambient tenant: a store can never leak another tenant's row, and a lookup
// for a resource owned by another tenant returns ErrNotFound even when the row
// exists.
package store

import (
	"context"
	"errors"
	"time"

	"github.com/ffuf-online/platform/internal/audit"
	"github.com/ffuf-online/platform/internal/domain"
)

// Sentinel errors returned by every Store implementation.
var (
	// ErrNotFound is returned when a resource does not exist in the tenant.
	ErrNotFound = errors.New("store: not found")
	// ErrConflict is returned on a unique-constraint violation.
	ErrConflict = errors.New("store: conflict")
	// ErrCrossTenant is returned when a write would attach a resource to a
	// project owned by a different tenant.
	ErrCrossTenant = errors.New("store: cross-tenant write refused")
)

// AssetUpsertResult summarises a bulk asset upsert.
type AssetUpsertResult struct {
	// Upserted is the number of assets written (created + merged).
	Upserted int `json:"upserted"`
	// Created is the number of assets that did not exist before.
	Created int `json:"created"`
	// Items are the resulting assets in request order.
	Items []domain.Asset `json:"items"`
}

// AuditBackend is implemented by the store so the audit package can own the
// hash chain while the store owns persistence.
type AuditBackend interface {
	LastAuditHash(ctx context.Context) (string, error)
	PutAudit(ctx context.Context, e audit.Entry) (audit.Entry, error)
	ListAudit(ctx context.Context, tenantID string, limit, offset int) ([]audit.Entry, int, error)
	AllAudit(ctx context.Context) ([]audit.Entry, error)
}

// Store is the full persistence contract.
type Store interface {
	AuditBackend

	// Ping verifies the backend is reachable.
	Ping(ctx context.Context) error
	// Close releases resources.
	Close() error

	// ---- tenants, users, membership ----
	CreateTenant(ctx context.Context, t domain.Tenant) error
	GetTenant(ctx context.Context, id string) (domain.Tenant, error)
	GetTenantBySlug(ctx context.Context, slug string) (domain.Tenant, error)
	ListTenants(ctx context.Context, limit, offset int) ([]domain.Tenant, int, error)
	CreateUser(ctx context.Context, u domain.User) error
	GetUser(ctx context.Context, id string) (domain.User, error)
	GetUserByEmail(ctx context.Context, email string) (domain.User, error)
	CreateMembership(ctx context.Context, m domain.Membership) error
	GetMembership(ctx context.Context, tenantID, userID string) (domain.Membership, error)
	UpdateMembershipRole(ctx context.Context, tenantID, userID, role string) error
	ListMemberships(ctx context.Context, tenantID string, limit, offset int) ([]domain.Membership, int, error)

	// ---- projects, programs, authorization ----
	CreateProject(ctx context.Context, p domain.Project) error
	GetProject(ctx context.Context, tenantID, id string) (domain.Project, error)
	ListProjects(ctx context.Context, tenantID string, limit, offset int) ([]domain.Project, int, error)
	CreateProgram(ctx context.Context, p domain.Program) error
	ListPrograms(ctx context.Context, tenantID, projectID string, limit, offset int) ([]domain.Program, int, error)
	CreateAuthorizationEvidence(ctx context.Context, e domain.AuthorizationEvidence) error
	ListAuthorizationEvidence(ctx context.Context, tenantID, projectID string, limit, offset int) ([]domain.AuthorizationEvidence, int, error)

	// ---- scope ----
	// CreateScopeVersion appends a new immutable scope version (previous
	// version + 1) with its rules.
	CreateScopeVersion(ctx context.Context, sv domain.ScopeVersion, rules []domain.ScopeRule) (domain.ScopeVersion, error)
	GetScopeVersion(ctx context.Context, tenantID, projectID string, version int) (domain.ScopeVersion, []domain.ScopeRule, error)
	GetCurrentScope(ctx context.Context, tenantID, projectID string) (domain.ScopeVersion, []domain.ScopeRule, error)
	AuthorizeScope(ctx context.Context, tenantID, projectID string, version int, authorizedBy string, at time.Time) (domain.ScopeVersion, error)

	// ---- assets, endpoints ----
	UpsertAssets(ctx context.Context, tenantID, projectID string, assets []domain.Asset) (AssetUpsertResult, error)
	GetAsset(ctx context.Context, tenantID, id string) (domain.Asset, error)
	ListAssets(ctx context.Context, tenantID, projectID string, limit, offset int) ([]domain.Asset, int, error)
	CreateEndpoint(ctx context.Context, e domain.Endpoint) error
	ListEndpoints(ctx context.Context, tenantID, projectID string, limit, offset int) ([]domain.Endpoint, int, error)

	// ---- findings ----
	CreateFinding(ctx context.Context, f domain.Finding) (domain.Finding, bool, error)
	GetFinding(ctx context.Context, tenantID, id string) (domain.Finding, error)
	UpdateFinding(ctx context.Context, f domain.Finding) error
	ListFindings(ctx context.Context, tenantID, projectID, status string, limit, offset int) ([]domain.Finding, int, error)

	// ---- tasks ----
	CreateTask(ctx context.Context, t domain.Task) (domain.Task, bool, error)
	GetTask(ctx context.Context, tenantID, id string) (domain.Task, error)
	UpdateTaskStatus(ctx context.Context, tenantID, id, status, reason string) (domain.Task, error)
	ListTasks(ctx context.Context, tenantID, projectID, status string, limit, offset int) ([]domain.Task, int, error)
	ListTasksByStatus(ctx context.Context, status string, limit int) ([]domain.Task, error)
	CreateTaskAttempt(ctx context.Context, a domain.TaskAttempt) error
	ListTaskAttempts(ctx context.Context, tenantID, taskID string) ([]domain.TaskAttempt, error)

	// ---- events ----
	CreateEvent(ctx context.Context, e domain.DomainEvent) (domain.DomainEvent, bool, error)
	ListEvents(ctx context.Context, tenantID, projectID string, limit, offset int) ([]domain.DomainEvent, int, error)

	// ---- executions ----
	CreateExecution(ctx context.Context, e domain.ToolExecution) error
	GetExecution(ctx context.Context, tenantID, id string) (domain.ToolExecution, error)
	UpdateExecution(ctx context.Context, e domain.ToolExecution) error
	ListExecutions(ctx context.Context, tenantID, projectID string, limit, offset int) ([]domain.ToolExecution, int, error)

	// ---- workflows ----
	CreateWorkflow(ctx context.Context, w domain.Workflow) error
	GetWorkflow(ctx context.Context, tenantID, id string) (domain.Workflow, error)
	UpsertWorkflowNode(ctx context.Context, n domain.WorkflowNode) error
	ListWorkflowNodes(ctx context.Context, tenantID, workflowID string) ([]domain.WorkflowNode, error)
	ListWorkflows(ctx context.Context, tenantID, projectID string, limit, offset int) ([]domain.Workflow, int, error)

	// ---- workers ----
	CreateWorker(ctx context.Context, w domain.Worker) error
	GetWorker(ctx context.Context, id string) (domain.Worker, error)
	GetWorkerByTokenHash(ctx context.Context, tokenHash string) (domain.Worker, error)
	ListWorkers(ctx context.Context, tenantID string, limit, offset int) ([]domain.Worker, int, error)
	ListAllWorkers(ctx context.Context) ([]domain.Worker, error)
	UpdateWorkerHeartbeat(ctx context.Context, workerID string, runningJobs int, cpuLoad float64, at time.Time) error
	SetWorkerStatus(ctx context.Context, workerID, status string) error

	// ---- usage ----
	AddUsage(ctx context.Context, u domain.UsageRecord) error
	ListUsage(ctx context.Context, tenantID string, limit, offset int) ([]domain.UsageRecord, int, error)
}

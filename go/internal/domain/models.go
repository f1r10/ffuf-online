// Package domain holds the storage-agnostic data model of the control plane.
//
// The JSON tags match the field names of `packages/schemas/*.json` so a record
// can be returned verbatim from the API without a translation layer.
package domain

import "time"

// Tenant is an isolated customer organisation container.
type Tenant struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

// User is a human identity.
type User struct {
	ID           string    `json:"id"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
	DisplayName  string    `json:"display_name"`
	IsSuperAdmin bool      `json:"is_super_admin"`
	CreatedAt    time.Time `json:"created_at"`
}

// Membership binds a user to a tenant with a role.
type Membership struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	UserID    string    `json:"user_id"`
	Role      string    `json:"role"`
	Email     string    `json:"email,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// Project is the unit of scope and authorization.
type Project struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Name      string    `json:"name"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
}

// Program is a bug-bounty program attached to a project.
type Program struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	ProjectID string    `json:"project_id"`
	Name      string    `json:"name"`
	Source    string    `json:"source"`
	CreatedAt time.Time `json:"created_at"`
}

// AuthorizationEvidence is proof that testing a project is permitted.
type AuthorizationEvidence struct {
	ID         string     `json:"id"`
	TenantID   string     `json:"tenant_id"`
	ProjectID  string     `json:"project_id"`
	Kind       string     `json:"kind"`
	Reference  string     `json:"reference"`
	SHA256     string     `json:"sha256,omitempty"`
	RecordedBy string     `json:"recorded_by"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

// ScopeVersion is an immutable snapshot of a project's scope. A new version is
// appended whenever scope changes; the previous version is never edited.
type ScopeVersion struct {
	ID             string     `json:"id"`
	TenantID       string     `json:"tenant_id"`
	ProjectID      string     `json:"project_id"`
	Version        int        `json:"version"`
	PolicyVersion  int        `json:"policy_version"`
	PolicyProfile  string     `json:"policy_profile"`
	MaxRPS         int        `json:"max_rps"`
	MaxConcurrency int        `json:"max_concurrency"`
	WindowStartUTC string     `json:"window_start_utc,omitempty"`
	WindowEndUTC   string     `json:"window_end_utc,omitempty"`
	Authorized     bool       `json:"authorized"`
	AuthorizedAt   *time.Time `json:"authorized_at,omitempty"`
	AuthorizedBy   string     `json:"authorized_by,omitempty"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

// ScopeRule is one include/exclude rule inside a scope version.
type ScopeRule struct {
	ID             string    `json:"id"`
	TenantID       string    `json:"tenant_id"`
	ProjectID      string    `json:"project_id"`
	ScopeVersionID string    `json:"scope_version_id"`
	Kind           string    `json:"kind"`
	Value          string    `json:"value"`
	Action         string    `json:"action"`
	Note           string    `json:"note"`
	CreatedAt      time.Time `json:"created_at"`
}

// Asset is a normalized node of the shared asset graph.
type Asset struct {
	ID             string         `json:"id"`
	TenantID       string         `json:"tenant_id"`
	ProjectID      string         `json:"project_id"`
	AssetType      string         `json:"asset_type"`
	Value          string         `json:"value"`
	ParentAssetID  *string        `json:"parent_asset_id"`
	SourceTools    []string       `json:"source_tools"`
	ScopeStatus    string         `json:"scope_status"`
	Confidence     float64        `json:"confidence"`
	Metadata       map[string]any `json:"metadata"`
	FirstSeenAt    time.Time      `json:"first_seen_at"`
	LastSeenAt     time.Time      `json:"last_seen_at"`
	CorrelationKey string         `json:"correlation_key"`
}

// Endpoint is a discovered HTTP endpoint.
type Endpoint struct {
	ID             string    `json:"id"`
	TenantID       string    `json:"tenant_id"`
	ProjectID      string    `json:"project_id"`
	AssetID        string    `json:"asset_id"`
	URL            string    `json:"url"`
	Method         string    `json:"method"`
	StatusCode     *int      `json:"status_code"`
	ContentType    string    `json:"content_type,omitempty"`
	CorrelationKey string    `json:"correlation_key"`
	FirstSeenAt    time.Time `json:"first_seen_at"`
}

// Finding is a candidate or validated security finding.
type Finding struct {
	ID                string    `json:"id"`
	TenantID          string    `json:"tenant_id"`
	ProjectID         string    `json:"project_id"`
	AssetID           *string   `json:"asset_id"`
	Endpoint          *string   `json:"endpoint"`
	HTTPMethod        *string   `json:"http_method"`
	Parameter         *string   `json:"parameter"`
	FindingType       string    `json:"finding_type"`
	Title             string    `json:"title"`
	Severity          string    `json:"severity"`
	Confidence        float64   `json:"confidence"`
	Status            string    `json:"status"`
	SourceTools       []string  `json:"source_tools"`
	EvidenceIDs       []string  `json:"evidence_ids"`
	RelatedFindingIDs []string  `json:"related_finding_ids"`
	ScopeVersion      int       `json:"scope_version"`
	ApprovedBy        string    `json:"approved_by,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`

	// correlationKey is the tenant/project-scoped dedup identity of the
	// finding. It is deliberately unexported (and thus not part of the wire
	// schema, which uses additionalProperties:false): it is stored in its own
	// database column and recomputed whenever a finding is ingested.
	correlationKey string
}

// CorrelationKey returns the finding's dedup identity.
func (f Finding) CorrelationKey() string { return f.correlationKey }

// SetCorrelationKey sets the finding's dedup identity.
func (f *Finding) SetCorrelationKey(key string) { f.correlationKey = key }

// ToolExecution is one run of one tool.
type ToolExecution struct {
	ID            string         `json:"id"`
	TenantID      string         `json:"tenant_id"`
	ProjectID     string         `json:"project_id"`
	TaskID        string         `json:"task_id,omitempty"`
	ToolID        string         `json:"tool_id"`
	ToolVersion   string         `json:"tool_version"`
	WorkerID      string         `json:"worker_id,omitempty"`
	ScopeVersion  int            `json:"scope_version"`
	Status        string         `json:"status"`
	Input         map[string]any `json:"input"`
	OutputSummary map[string]any `json:"output_summary"`
	Error         string         `json:"error,omitempty"`
	StartedAt     *time.Time     `json:"started_at,omitempty"`
	FinishedAt    *time.Time     `json:"finished_at,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
}

// Workflow groups the tasks generated from one event chain.
type Workflow struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	ProjectID string    `json:"project_id"`
	Status    string    `json:"status"`
	MaxDepth  int       `json:"max_depth"`
	CreatedAt time.Time `json:"created_at"`
}

// WorkflowNode is one node of a workflow graph.
type WorkflowNode struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenant_id"`
	WorkflowID   string    `json:"workflow_id"`
	ToolID       string    `json:"tool_id"`
	TriggerEvent string    `json:"trigger_event"`
	Depth        int       `json:"depth"`
	Status       string    `json:"status"`
	Reason       string    `json:"reason"`
	CreatedAt    time.Time `json:"created_at"`
}

// Task is a unit of planned work.
type Task struct {
	ID               string         `json:"id"`
	TenantID         string         `json:"tenant_id"`
	ProjectID        string         `json:"project_id"`
	WorkflowID       string         `json:"workflow_id,omitempty"`
	NodeID           string         `json:"node_id,omitempty"`
	ToolID           string         `json:"tool_id"`
	ToolVersion      string         `json:"tool_version"`
	Input            map[string]any `json:"input"`
	ExecutionProfile string         `json:"execution_profile"`
	Priority         int            `json:"priority"`
	Depth            int            `json:"depth"`
	Status           string         `json:"status"`
	IdempotencyKey   string         `json:"idempotency_key"`
	Reason           string         `json:"reason"`
	CreatedAt        time.Time      `json:"created_at"`
}

// TaskAttempt records one dispatch attempt of a task to a worker.
type TaskAttempt struct {
	ID         string     `json:"id"`
	TenantID   string     `json:"tenant_id"`
	TaskID     string     `json:"task_id"`
	WorkerID   string     `json:"worker_id,omitempty"`
	Attempt    int        `json:"attempt"`
	Status     string     `json:"status"`
	Error      string     `json:"error,omitempty"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

// DomainEvent mirrors packages/schemas/event.schema.json.
type DomainEvent struct {
	EventID           string         `json:"event_id"`
	TenantID          string         `json:"tenant_id"`
	ProjectID         string         `json:"project_id"`
	EventType         string         `json:"event_type"`
	SourceTool        *string        `json:"source_tool"`
	SourceExecutionID *string        `json:"source_execution_id"`
	AssetRef          *string        `json:"asset_ref"`
	ScopeVersion      int            `json:"scope_version"`
	Timestamp         time.Time      `json:"timestamp"`
	SchemaVersion     string         `json:"schema_version"`
	Payload           map[string]any `json:"payload"`
}

// Worker is a registered worker agent.
type Worker struct {
	ID            string     `json:"id"`
	TenantID      string     `json:"tenant_id,omitempty"`
	Name          string     `json:"name"`
	Kind          string     `json:"kind"`
	Status        string     `json:"status"`
	AgentVersion  string     `json:"agent_version,omitempty"`
	PublicKey     string     `json:"public_key,omitempty"`
	ToolIDs       []string   `json:"tool_ids"`
	RunningJobs   int        `json:"running_jobs"`
	CPULoad       float64    `json:"cpu_load"`
	LastHeartbeat *time.Time `json:"last_heartbeat,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	TokenHash     string     `json:"-"`
}

// UsageRecord is one billing/usage sample.
type UsageRecord struct {
	ID              string    `json:"id"`
	TenantID        string    `json:"tenant_id"`
	ProjectID       string    `json:"project_id,omitempty"`
	ToolExecutionID string    `json:"tool_execution_id,omitempty"`
	ScanSeconds     float64   `json:"scan_seconds"`
	CPUSeconds      float64   `json:"cpu_seconds"`
	MemoryMBS       float64   `json:"memory_mb_s"`
	Requests        int       `json:"requests"`
	ArtifactsBytes  int64     `json:"artifacts_bytes"`
	RecordedAt      time.Time `json:"recorded_at"`
}

// JobLimits mirrors the `limits` object of job.schema.json.
type JobLimits struct {
	CPU            string `json:"cpu"`
	Memory         string `json:"memory"`
	TimeoutSeconds int    `json:"timeout_seconds"`
	MaxRequests    *int   `json:"max_requests"`
	MaxRPS         *int   `json:"max_rps"`
}

// Job mirrors packages/schemas/job.schema.json. It never carries a shell
// string; `Input` is a structured argument map.
type Job struct {
	JobID            string         `json:"job_id"`
	TenantID         string         `json:"tenant_id"`
	ProjectID        string         `json:"project_id"`
	ScopeVersion     int            `json:"scope_version"`
	PolicyVersion    int            `json:"policy_version"`
	ToolID           string         `json:"tool_id"`
	ToolVersion      string         `json:"tool_version"`
	ExecutionProfile string         `json:"execution_profile,omitempty"`
	Input            map[string]any `json:"input"`
	Limits           JobLimits      `json:"limits"`
	TaskID           *string        `json:"task_id"`
	CreatedAt        time.Time      `json:"created_at"`
	ExpiresAt        time.Time      `json:"expires_at"`
	IdempotencyKey   string         `json:"idempotency_key"`
	Signature        *string        `json:"signature"`
}

// Tool is an entry of the tool registry.
type Tool struct {
	ToolID                      string         `json:"tool_id"`
	Name                        string         `json:"name"`
	Category                    string         `json:"category"`
	Version                     string         `json:"version"`
	Image                       string         `json:"image,omitempty"`
	Capabilities                []string       `json:"capabilities"`
	RequiredInputs              []string       `json:"required_inputs"`
	OptionalInputs              []string       `json:"optional_inputs,omitempty"`
	OutputTypes                 []string       `json:"output_types"`
	SupportedAssetTypes         []string       `json:"supported_asset_types,omitempty"`
	ApplicableExecutionProfiles []string       `json:"applicable_execution_profiles,omitempty"`
	ResourceProfile             map[string]any `json:"resource_profile,omitempty"`
	NetworkProfile              string         `json:"network_profile,omitempty"`
	Enabled                     bool           `json:"enabled"`
	Priority                    int            `json:"priority"`
	Trigger                     []string       `json:"trigger,omitempty"`
}

// EventTypes is the complete event_type enumeration from event.schema.json.
var EventTypes = []string{
	"asset.discovered", "asset.updated",
	"dns.record.discovered", "http.service.discovered", "http.endpoint.discovered",
	"http.redirect.discovered", "api.endpoint.discovered", "api.schema.discovered",
	"parameter.discovered", "technology.detected", "javascript.discovered",
	"tool.execution.started", "tool.execution.completed", "tool.execution.failed",
	"finding.candidate.created", "finding.evidence.added", "finding.validated", "finding.rejected",
	"scope.changed", "scope.expired", "task.created", "task.cancelled",
}

// AssetTypes is the complete asset_type enumeration from asset.schema.json.
var AssetTypes = []string{
	"root_domain", "subdomain", "hostname", "ip", "cidr", "service", "port",
	"http_service", "endpoint", "url", "parameter", "technology", "javascript",
	"api_spec", "finding",
}

// FindingStatuses is the complete status enumeration from finding.schema.json.
var FindingStatuses = []string{
	"discovered", "candidate", "needs_validation", "validated", "rejected",
	"confirmed_impact", "report_ready", "submitted", "accepted", "duplicate", "informative",
}

// ScopeRuleKinds is the rule kind enumeration from scope-request.schema.json.
var ScopeRuleKinds = []string{"domain", "wildcard_domain", "hostname", "ip", "cidr", "url_prefix"}

// PolicyProfiles is the policy_profile enumeration from scope-request.schema.json.
var PolicyProfiles = []string{"passive", "low_impact_discovery", "authorized_vulnerability_testing"}

// Task statuses used by the control plane.
const (
	TaskPending   = "pending"
	TaskRunning   = "running"
	TaskCompleted = "completed"
	TaskFailed    = "failed"
	TaskCancelled = "cancelled"
	TaskBlocked   = "blocked"
)

// Contains reports whether needle is in haystack.
func Contains(haystack []string, needle string) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}

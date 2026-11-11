-- FFUF Online — initial schema (Milestone 1 + 2 + 3 core tables)
-- Tenant isolation: every tenant-owned row carries tenant_id AND a composite FK
-- guarantees it can never reference a resource owned by another tenant.
-- Row-Level Security is enforced with the transaction-local setting app.tenant_id.

BEGIN;

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ---------------------------------------------------------------------------
-- Control plane: tenants, identities, membership, organization
-- ---------------------------------------------------------------------------
CREATE TABLE tenants (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    slug         TEXT NOT NULL UNIQUE,
    status       TEXT NOT NULL DEFAULT 'active',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id             TEXT PRIMARY KEY,
    email          TEXT NOT NULL UNIQUE,
    password_hash  TEXT NOT NULL,
    display_name   TEXT NOT NULL DEFAULT '',
    is_super_admin BOOLEAN NOT NULL DEFAULT false,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE organizations (
    id         TEXT PRIMARY KEY,
    tenant_id  TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id)
);

CREATE TABLE tenant_memberships (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    organization_id TEXT,
    role            TEXT NOT NULL,   -- org_owner | org_admin | researcher | analyst | read_only
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, user_id),
    FOREIGN KEY (tenant_id, organization_id) REFERENCES organizations(tenant_id, id)
);

-- ---------------------------------------------------------------------------
-- Projects, programs, authorization evidence, scope
-- ---------------------------------------------------------------------------
CREATE TABLE projects (
    id         TEXT PRIMARY KEY,
    tenant_id  TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id)
);

CREATE TABLE programs (
    id         TEXT PRIMARY KEY,
    tenant_id  TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id TEXT NOT NULL,
    name       TEXT NOT NULL,
    source     TEXT NOT NULL DEFAULT 'manual',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id) ON DELETE CASCADE
);

CREATE TABLE authorization_evidence (
    id           TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id   TEXT NOT NULL,
    kind         TEXT NOT NULL,          -- url | document | email | attestation
    reference    TEXT NOT NULL,
    sha256       TEXT,
    recorded_by  TEXT NOT NULL REFERENCES users(id),
    expires_at   TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id) ON DELETE CASCADE
);

CREATE TABLE scope_versions (
    id                  TEXT PRIMARY KEY,
    tenant_id           TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id          TEXT NOT NULL,
    version             INTEGER NOT NULL,
    policy_version      INTEGER NOT NULL DEFAULT 1,
    policy_profile      TEXT NOT NULL DEFAULT 'passive', -- passive | low_impact_discovery | authorized_vulnerability_testing
    max_rps             INTEGER NOT NULL DEFAULT 5,
    max_concurrency     INTEGER NOT NULL DEFAULT 2,
    window_start_utc    TIME,
    window_end_utc      TIME,
    authorized          BOOLEAN NOT NULL DEFAULT false,
    authorized_at       TIMESTAMPTZ,
    authorized_by       TEXT REFERENCES users(id),
    expires_at          TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id) ON DELETE CASCADE,
    UNIQUE (tenant_id, project_id, version)
);

CREATE TABLE scope_rules (
    id               TEXT PRIMARY KEY,
    tenant_id        TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id       TEXT NOT NULL,
    scope_version_id TEXT NOT NULL,
    kind             TEXT NOT NULL,     -- domain | wildcard_domain | hostname | ip | cidr | url_prefix
    value            TEXT NOT NULL,
    action           TEXT NOT NULL,     -- include | exclude
    note             TEXT NOT NULL DEFAULT '',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (scope_version_id) REFERENCES scope_versions(id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------
-- Asset graph
-- ---------------------------------------------------------------------------
CREATE TABLE assets (
    id               TEXT PRIMARY KEY,
    tenant_id        TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id       TEXT NOT NULL,
    asset_type       TEXT NOT NULL,
    value            TEXT NOT NULL,
    parent_asset_id  TEXT,
    source_tools     TEXT[] NOT NULL DEFAULT '{}',
    scope_status     TEXT NOT NULL DEFAULT 'unknown',
    confidence       DOUBLE PRECISION NOT NULL DEFAULT 1.0,
    metadata         JSONB NOT NULL DEFAULT '{}'::jsonb,
    first_seen_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    correlation_key  TEXT NOT NULL,
    FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id) ON DELETE CASCADE,
    UNIQUE (tenant_id, project_id, correlation_key)
);

CREATE TABLE asset_relationships (
    id             TEXT PRIMARY KEY,
    tenant_id      TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id     TEXT NOT NULL,
    from_asset_id  TEXT NOT NULL,
    to_asset_id    TEXT NOT NULL,
    rel_type       TEXT NOT NULL,    -- resolves_to | serves | contains | uses_technology | derived_from
    source_tool    TEXT NOT NULL DEFAULT '',
    source_execution_id TEXT NOT NULL DEFAULT '',
    scope_version  INTEGER NOT NULL DEFAULT 1,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (from_asset_id) REFERENCES assets(id) ON DELETE CASCADE,
    FOREIGN KEY (to_asset_id) REFERENCES assets(id) ON DELETE CASCADE
);

CREATE TABLE endpoints (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id      TEXT NOT NULL,
    asset_id        TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    url             TEXT NOT NULL,
    method          TEXT NOT NULL DEFAULT 'GET',
    status_code     INTEGER,
    content_type    TEXT,
    correlation_key TEXT NOT NULL,
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, project_id, correlation_key)
);

CREATE TABLE endpoint_parameters (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    endpoint_id TEXT NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    location    TEXT NOT NULL DEFAULT 'query',  -- query | body | header | path
    discovered_by TEXT NOT NULL DEFAULT '',
    UNIQUE (endpoint_id, name, location)
);

-- ---------------------------------------------------------------------------
-- Tool registry, executions
-- ---------------------------------------------------------------------------
CREATE TABLE tool_registry (
    tool_id          TEXT PRIMARY KEY,
    name             TEXT NOT NULL,
    category         TEXT NOT NULL,
    image            TEXT NOT NULL,
    capabilities     JSONB NOT NULL DEFAULT '[]'::jsonb,
    required_inputs  JSONB NOT NULL DEFAULT '[]'::jsonb,
    output_types     JSONB NOT NULL DEFAULT '[]'::jsonb,
    resource_profile JSONB NOT NULL DEFAULT '{}'::jsonb,
    network_profile  TEXT NOT NULL DEFAULT 'controlled_http',
    enabled          BOOLEAN NOT NULL DEFAULT false
);

CREATE TABLE tool_versions (
    id          TEXT PRIMARY KEY,
    tool_id     TEXT NOT NULL REFERENCES tool_registry(tool_id) ON DELETE CASCADE,
    version     TEXT NOT NULL,
    image_digest TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    license     TEXT NOT NULL DEFAULT '',
    sbom_url    TEXT NOT NULL DEFAULT '',
    pinned_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tool_id, version)
);

CREATE TABLE tool_executions (
    id             TEXT PRIMARY KEY,
    tenant_id      TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id     TEXT NOT NULL,
    task_id        TEXT,
    tool_id        TEXT NOT NULL,
    tool_version   TEXT NOT NULL,
    worker_id      TEXT,
    scope_version  INTEGER NOT NULL,
    status         TEXT NOT NULL DEFAULT 'queued',  -- queued|running|completed|failed|cancelled
    input          JSONB NOT NULL DEFAULT '{}'::jsonb,
    output_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
    error          TEXT NOT NULL DEFAULT '',
    started_at     TIMESTAMPTZ,
    finished_at    TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Workflows, tasks, dependencies
-- ---------------------------------------------------------------------------
CREATE TABLE workflows (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id  TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'running',  -- running|paused|cancelled|completed
    max_depth   INTEGER NOT NULL DEFAULT 5,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id) ON DELETE CASCADE
);

CREATE TABLE workflow_nodes (
    id            TEXT PRIMARY KEY,
    tenant_id     TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    workflow_id   TEXT NOT NULL REFERENCES workflows(id) ON DELETE CASCADE,
    tool_id       TEXT NOT NULL,
    trigger_event TEXT NOT NULL DEFAULT '',
    depth         INTEGER NOT NULL DEFAULT 0,
    status        TEXT NOT NULL DEFAULT 'pending',
    reason        TEXT NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE tasks (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id      TEXT NOT NULL,
    workflow_id     TEXT,
    node_id         TEXT,
    tool_id         TEXT NOT NULL,
    tool_version    TEXT NOT NULL,
    input           JSONB NOT NULL DEFAULT '{}'::jsonb,
    execution_profile TEXT NOT NULL DEFAULT 'passive',
    priority        INTEGER NOT NULL DEFAULT 100,
    depth           INTEGER NOT NULL DEFAULT 0,
    status          TEXT NOT NULL DEFAULT 'pending',
    idempotency_key TEXT NOT NULL,
    reason          TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id) ON DELETE CASCADE,
    UNIQUE (tenant_id, idempotency_key)
);

CREATE TABLE task_dependencies (
    id             TEXT PRIMARY KEY,
    tenant_id      TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    task_id        TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    depends_on_id  TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    UNIQUE (task_id, depends_on_id)
);

CREATE TABLE task_attempts (
    id           TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    task_id      TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    worker_id    TEXT,
    attempt      INTEGER NOT NULL DEFAULT 1,
    status       TEXT NOT NULL DEFAULT 'started',
    error        TEXT NOT NULL DEFAULT '',
    started_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at  TIMESTAMPTZ
);

-- ---------------------------------------------------------------------------
-- Events, findings, evidence
-- ---------------------------------------------------------------------------
CREATE TABLE domain_events (
    id                  TEXT PRIMARY KEY,
    tenant_id           TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id          TEXT NOT NULL,
    event_type          TEXT NOT NULL,
    source_tool         TEXT,
    source_execution_id TEXT,
    asset_ref           TEXT,
    scope_version       INTEGER NOT NULL DEFAULT 1,
    schema_version       TEXT NOT NULL DEFAULT '1.0',
    payload             JSONB NOT NULL DEFAULT '{}'::jsonb,
    occurred_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE findings (
    id                 TEXT PRIMARY KEY,
    tenant_id          TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id         TEXT NOT NULL,
    asset_id           TEXT,
    endpoint           TEXT,
    http_method        TEXT,
    parameter          TEXT,
    finding_type       TEXT NOT NULL,
    title              TEXT NOT NULL,
    severity           TEXT NOT NULL DEFAULT 'unknown',
    confidence         DOUBLE PRECISION NOT NULL DEFAULT 0.5,
    status             TEXT NOT NULL DEFAULT 'candidate',
    source_tools       TEXT[] NOT NULL DEFAULT '{}',
    scope_version      INTEGER NOT NULL,
    correlation_key    TEXT NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id) ON DELETE CASCADE,
    UNIQUE (tenant_id, project_id, correlation_key)
);

CREATE TABLE finding_evidence (
    id                  TEXT PRIMARY KEY,
    tenant_id           TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    finding_id          TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    tool_execution_id   TEXT,
    kind                TEXT NOT NULL,     -- request | response | screenshot | artifact | note
    storage_path        TEXT NOT NULL DEFAULT '',
    sha256              TEXT NOT NULL DEFAULT '',
    summary             TEXT NOT NULL DEFAULT '',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE finding_relationships (
    id                TEXT PRIMARY KEY,
    tenant_id         TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    finding_id        TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    related_finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    relation          TEXT NOT NULL DEFAULT 'duplicate_of',
    score             DOUBLE PRECISION NOT NULL DEFAULT 0,
    UNIQUE (finding_id, related_finding_id)
);

-- ---------------------------------------------------------------------------
-- Workers, reports, audit, billing
-- ---------------------------------------------------------------------------
CREATE TABLE workers (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT,                       -- NULL => platform-managed shared pool
    name            TEXT NOT NULL,
    kind            TEXT NOT NULL DEFAULT 'platform',  -- platform | customer | dedicated
    status          TEXT NOT NULL DEFAULT 'offline',
    agent_version   TEXT NOT NULL DEFAULT '',
    public_key      TEXT NOT NULL DEFAULT '',
    last_heartbeat  TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE worker_capabilities (
    id         TEXT PRIMARY KEY,
    worker_id  TEXT NOT NULL REFERENCES workers(id) ON DELETE CASCADE,
    tool_id    TEXT NOT NULL,
    UNIQUE (worker_id, tool_id)
);

CREATE TABLE worker_heartbeats (
    id          TEXT PRIMARY KEY,
    worker_id   TEXT NOT NULL REFERENCES workers(id) ON DELETE CASCADE,
    running_jobs INTEGER NOT NULL DEFAULT 0,
    cpu_load    DOUBLE PRECISION NOT NULL DEFAULT 0,
    at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE reports (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id  TEXT NOT NULL,
    format      TEXT NOT NULL DEFAULT 'json',
    storage_path TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE audit_logs (
    id            BIGSERIAL PRIMARY KEY,
    tenant_id     TEXT,
    project_id    TEXT,
    actor_user_id TEXT,
    actor_kind    TEXT NOT NULL DEFAULT 'user',  -- user | worker | system
    action        TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id   TEXT,
    scope_version INTEGER,
    policy_version INTEGER,
    result        TEXT NOT NULL,
    execution_id  TEXT,
    prev_hash     TEXT NOT NULL DEFAULT '',
    entry_hash    TEXT NOT NULL,
    at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE subscriptions (
    id         TEXT PRIMARY KEY,
    tenant_id  TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    tier       TEXT NOT NULL DEFAULT 'free',  -- free|researcher|professional|team|enterprise
    status     TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE usage_records (
    id           TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id   TEXT,
    tool_execution_id TEXT,
    scan_seconds DOUBLE PRECISION NOT NULL DEFAULT 0,
    cpu_seconds  DOUBLE PRECISION NOT NULL DEFAULT 0,
    memory_mb_s  DOUBLE PRECISION NOT NULL DEFAULT 0,
    requests     INTEGER NOT NULL DEFAULT 0,
    artifacts_bytes BIGINT NOT NULL DEFAULT 0,
    recorded_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Indexes
-- ---------------------------------------------------------------------------
CREATE INDEX idx_projects_tenant ON projects(tenant_id);
CREATE INDEX idx_assets_tenant_project ON assets(tenant_id, project_id);
CREATE INDEX idx_assets_type ON assets(tenant_id, asset_type);
CREATE INDEX idx_endpoints_tenant ON endpoints(tenant_id, project_id);
CREATE INDEX idx_tasks_tenant_status ON tasks(tenant_id, status);
CREATE INDEX idx_findings_tenant_status ON findings(tenant_id, status);
CREATE INDEX idx_events_tenant_type ON domain_events(tenant_id, event_type, occurred_at DESC);
CREATE INDEX idx_executions_tenant ON tool_executions(tenant_id, created_at DESC);
CREATE INDEX idx_audit_tenant ON audit_logs(tenant_id, at DESC);

-- ---------------------------------------------------------------------------
-- Row-Level Security
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    t TEXT;
    tenant_tables TEXT[] := ARRAY[
        'organizations','tenant_memberships','projects','programs',
        'authorization_evidence','scope_versions','scope_rules',
        'assets','asset_relationships','endpoints','endpoint_parameters',
        'tool_executions','workflows','workflow_nodes','tasks','task_dependencies',
        'task_attempts','domain_events','findings','finding_evidence',
        'finding_relationships','reports','usage_records','subscriptions'
    ];
BEGIN
    FOREACH t IN ARRAY tenant_tables LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format(
            'CREATE POLICY tenant_isolation ON %I '
            'USING (tenant_id = current_setting(''app.tenant_id'', true)) '
            'WITH CHECK (tenant_id = current_setting(''app.tenant_id'', true))',
            t
        );
    END LOOP;
END $$;

COMMIT;

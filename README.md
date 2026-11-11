# FFUF Online

Multi-tenant, event-driven bug-bounty intelligence platform. Security tools cooperate
through a shared asset graph, a common data model, a dependency engine and an adaptive
workflow system.

This repository is a **polyglot** implementation. Each language owns the part of the
system it is genuinely best at:

| Language | Owns | Why |
|---|---|---|
| **Rust** | Scope Enforcement Engine, Egress Policy, fast result normalization | The security boundary is a memory-safe, allocation-light, deterministic kernel. Every single network operation passes through it. |
| **Go** | Control Plane API, Worker Manager, scheduler, event publisher | Concurrency-heavy, long-lived networked services. Single static binary, first-class context/cancellation, excellent RLS-aware database handling. |
| **Python** | Tool adapters (the CLI-tool ecosystem), Intelligence Engine, AI analysis | Hostile, ever-changing CLI output formats and a huge parsing/ML/AI ecosystem. Fast iteration without touching the security kernel. |

```
                 ┌──────────────────────────────┐
   React UI ────▶│  Go Control Plane (api:8080)  │
                 │  auth · tenants · RBAC · RLS │
                 │  projects · scope · assets   │
                 │  findings · tasks · audit    │
                 └───────┬──────────────┬───────┘
                         │ HTTP         │ NATS JetStream
                         ▼              ▼
        ┌────────────────────────┐  ┌────────────────────────────────┐
        │ Rust Scope Engine      │◀─│ Python Intelligence Engine      │
        │   :8090                │  │  event processor · asset graph  │
        │  rules · CIDR · IP     │  │  dependency resolver · planner  │
        │  guards · egress policy│  │  correlation · AI explain       │
        └───────────▲────────────┘  └───────────────┬────────────────┘
                    │                               │ tasks
                    │ every network op              ▼
        ┌───────────┴────────────────────────────────────────────────┐
        │ Python Tool Adapters (subfinder, dnsx, httpx, katana, gau,  │
        │ ffuf, feroxbuster, kiterunner, arjun, nuclei, nmap)         │
        │  argv arrays only — never a shell string                    │
        └───────────┬────────────────────────────────────────────────┘
                    │ Go Worker Manager dispatches signed Jobs
                    ▼
              Docker execution runtime
```

## The central product idea

> **One tool's discovery automatically creates useful tasks for other tools.**

`subfinder` finds `api.example.com` → the Intelligence Engine emits `asset.discovered`
→ the dependency resolver sees a subdomain with no HTTP service → it schedules `httpx`
→ `httpx` returns a live `https://api.example.com` → `katana` is scheduled → katana
finds `/api/v2/users` → an `api.endpoint.discovered` event schedules `arjun`
→ arjun finds a `user_id` parameter → an approved parameter test is scheduled
→ `nuclei` produces a candidate finding → a **validation** task is created and
requires human approval. No step is hardcoded into a single mega-workflow.

## Quick start

```bash
# 1. Rust security kernel (build once, used by everything)
cd rust/scope-engine && cargo build --release

# 2. Go control plane + worker manager
cd ../../go && go build ./...

# 3. Python adapters + intelligence engine
cd ../python && python -m pip install -e ".[dev]"

# 4. Run the whole pipeline end-to-end (no Docker / no external DB required)
python ../tests/e2e/run_pipeline.py
```

`tests/e2e/run_pipeline.py` boots the real Rust scope service, the real Go API (in-memory
storage driver), the real Python intelligence engine and the real Python adapters, then
runs the subfinder → httpx → katana → arjun → nuclei chain and prints the generated task
graph. See [docs/architecture/overview.md](docs/architecture/overview.md).

Full stack with the real datastores:

```bash
cp .env.example .env
docker compose up --build
```

## Repository layout

```
apps/            frontend (React), api, worker-manager, admin
services/        intelligence-engine, scope-engine, event-processor, correlation-engine, report-engine
workers/         base, recon, http, content, api, vulnerability, network, validation
adapters/        one directory per external tool
packages/        schemas, event-contracts, auth, scope-sdk, logging, common
rust/            Rust workspace  (scope-engine)
go/              Go module       (cmd/api, cmd/worker-manager, internal/*)
python/          Python packages (ffuf_intel, adapters)
infrastructure/  docker, compose, nats, temporal, postgres, monitoring, egress
migrations/      PostgreSQL migrations (incl. RLS policies)
tests/           unit, integration, e2e, security, tenant-isolation, scope-enforcement
docs/            architecture, api, adapters, events, deployment, security
```

## Safety model (non-negotiable)

- Scope is decided by the Rust kernel **before** any network operation. A worker that
  skips it simply cannot reach the target: the egress gateway enforces the same policy
  independently.
- Worker agents accept **structured arguments**, never shell strings.
- Private / loopback / link-local / reserved / cloud-metadata destinations are blocked
  by default.
- A scanner result is never silently promoted to a confirmed vulnerability. Findings
  move through an explicit lifecycle: `discovered → candidate → needs_validation → validated`.
- AI never changes scope, never disables rate limits and never approves its own
  sensitive operations. Its output is always re-checked by the deterministic policy engine.

## Documentation

- [Architecture overview](docs/architecture/overview.md)
- [ADR 0001 — polyglot split](docs/architecture/decisions/0001-polyglot-architecture.md)
- [ADR 0002 — scope enforcement in Rust](docs/architecture/decisions/0002-scope-enforcement-in-rust.md)
- [Events](docs/events/README.md) · [Adapters](docs/adapters/README.md) · [API](docs/api/README.md)
- [AGENTS.md](AGENTS.md) — instructions for AI coding agents working in this repo

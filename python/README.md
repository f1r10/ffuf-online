# FFUF Online — Python: Tool Adapters + Intelligence Engine

This directory owns two of the three planes of FFUF Online:

* **Tool adapters** — thin, typed wrappers around the CLI security tools
  (`subfinder`, `dnsx`, `httpx`, `katana`, `gau`, `ffuf`, `feroxbuster`,
  `kiterunner`, `arjun`, `nuclei`, `nmap`). They translate a *task* into an
  **argv array**, run it through a hardened runner, and parse the tool's real
  output into a normalized result.
* **Intelligence Engine** — the event-driven core: an asset relationship graph,
  a data-driven dependency resolver, an anti-loop task planner, a finding
  correlator, an AI analysis layer and a small HTTP service.

The Rust scope engine remains the security kernel: every active task passes
through it before it is emitted.

## Layout

```
python/
├── ffuf_intel/            # Intelligence Engine (stdlib only)
│   ├── config.py          # env-driven configuration
│   ├── models.py          # dataclasses mirroring packages/schemas/*.json
│   ├── scope_client.py    # HTTP / subprocess / fake scope transports
│   ├── graph.py           # tenant-scoped asset relationship graph
│   ├── dependency.py      # TOOL_DEPENDENCIES data table + resolver
│   ├── planner.py         # anti-loop, scope-aware task planner
│   ├── correlation.py     # finding correlation (never auto-promotes)
│   ├── events.py          # EventProcessor (graph + resolver + planner)
│   ├── ai.py              # Analyzer + PolicyGuard (+ injection hardening)
│   └── server.py          # stdlib http.server intelligence service
├── adapters/              # ALL tool-specific knowledge
│   ├── base.py            # BaseToolAdapter contract + schema builders
│   ├── runner.py          # DockerRunner / LocalProcessRunner
│   ├── registry.py        # adapter registry + tool-registry.json loader
│   ├── tool-registry.json # generated from dependency.TOOL_DEPENDENCIES
│   └── <tool>.py          # 11 real adapters
├── tools/bin/             # DEMO STAND-INS (local runner only, no network)
└── tests/                 # pytest suite + real-format fixtures
```

## Install & test

Runtime is the **Python standard library only**; the sole dev dependency is
`pytest`.

```bash
cd python
python -m pytest -q
python -m compileall ffuf_intel adapters
```

## Run the Intelligence Engine

```bash
cd python
python -m ffuf_intel.server      # binds INTEL_HTTP_ADDR (default 127.0.0.1:8091)
```

Endpoints:

| Method | Path | Purpose |
|---|---|---|
| `GET`  | `/healthz` | liveness |
| `GET`  | `/v1/graph` | asset graph + stats |
| `GET`  | `/v1/workflow/<id>` | workflow node graph |
| `POST` | `/v1/events` | ingest a `DomainEvent`, receive generated tasks |
| `POST` | `/v1/reset` | clear in-process state |

Example: one HTTP-service discovery auto-schedules the downstream toolset.

```powershell
$body = @{
  event_id   = "evt-demo-1"
  tenant_id  = "tenant-1"
  project_id = "project-1"
  event_type = "http.endpoint.discovered"
  payload    = @{ url = "https://api.example.com/api/v2/users"; endpoint = "/api/v2/users"; host = "api.example.com" }
  asset_ref  = "https://api.example.com/api/v2/users"
  source_tool = "katana"
} | ConvertTo-Json
Invoke-RestMethod -Method POST -Uri http://127.0.0.1:8091/v1/events -Body $body -ContentType application/json
```

## Demo stand-ins vs. real tools

The tools are normally executed as pinned Docker images with a hardened,
network-restricted profile. For local development and CI,
`TOOL_RUNNER=local` resolves `tools/bin/<tool_id>.py` instead. Those scripts are
**honest demo stand-ins** — they print representative output for a fixed demo
target (`example.com`), perform **no** network activity, and are never used in
production.

## Configuration

All configuration is read from the environment (see the repo `.env.example`):

| Variable | Default | Meaning |
|---|---|---|
| `INTEL_HTTP_ADDR` | `127.0.0.1:8091` | Intelligence Engine bind address |
| `API_URL` | `http://127.0.0.1:8080` | Go control plane (task forwarding) |
| `SCOPE_ENGINE_URL` | `http://127.0.0.1:8090` | Rust scope engine (HTTP) |
| `SCOPE_ENGINE_BIN` | `rust/scope-engine/target/release/scope-engine` | Rust scope engine (binary) |
| `INTEL_TENANT_MAX_TASKS` | `400` | per-tenant task budget |
| `INTEL_MAX_WORKFLOW_DEPTH` | `5` | max workflow depth |
| `INTEL_MAX_TASKS_PER_ASSET` | `12` | per-asset task cap |
| `INTEL_TASK_COOLDOWN_SECONDS` | `900` | per-(tool,asset) cooldown |
| `INTEL_MAX_TASKS_PER_PROJECT_RUN` | `1500` | per-project-run task cap |
| `TOOL_RUNNER` | `docker` | `docker` or `local` |
| `TOOL_LOCAL_BINDIR` | `python/tools/bin` | local stand-in directory |
| `TOOL_TIMEOUT_SECONDS` | `900` | per-task wall-clock timeout |
| `TOOL_NETWORK` | `none` | Docker network mode |
| `AI_ENABLED` | `false` | enable the OpenAI-compatible analyzer |
| `AI_BASE_URL` / `AI_API_KEY` / `AI_MODEL` | — | model endpoint config |

## Safety invariants (enforced in code and tests)

* A scanner result is **never** a confirmed vulnerability. Findings start as
  `candidate` / `needs_validation`; correlation never promotes a status; a
  candidate finding schedules a human-gated **validation** task.
* `build_arguments` returns `list[str]` only — never a shell string. Values
  containing shell metacharacters are rejected. Runners use `shell=False`.
* Every emitted task must pass `ScopeClient.require_approved`; a rejection is
  recorded (with the scope `reason_code`) and the task is never emitted.
* The AI layer can never change scope, exclusions, rate limits or
  authorization, run a shell, or self-approve a finding — `PolicyGuard` blocks
  it, and all target-derived text is wrapped in `<untrusted-data>` markers.
* Tenant isolation: the asset graph is keyed by
  `(tenant_id, project_id, correlation_key)`.

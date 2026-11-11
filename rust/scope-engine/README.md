# scope-engine

The **Scope Enforcement Engine** for FFUF Online. This crate is the single
authority that answers two questions:

1. *Is this target inside the authorized scope?* (`POST /v1/scope/decide`)
2. *Is this specific outbound connection allowed?* (`POST /v1/egress/authorize`)

It implements the cross-language contracts:

- `packages/schemas/scope-request.schema.json`
- `packages/schemas/scope-decision.schema.json`

The Go control plane and the Python tool adapters **call** this engine; they must
never re-implement scope rules, CIDR matching or IP guards.

---

## scope-engine checklist

- [ ] **This binary is the ONLY place scope decisions are made.** No other
      service, handler, worker or adapter may decide whether a target is in
      scope, whether a redirect is allowed, or whether a destination IP is
      reachable.
- [ ] Callers pass the request through the HTTP API or the CLI and obey the
      returned `decision`.
- [ ] Hard IP guards (metadata / loopback / link-local / private / reserved) are
      **never** disabled "for internal convenience".
- [ ] Exclusions always win over inclusions.
- [ ] `EGRESS_REVALIDATE_REDIRECTS` / egress checks route through
      `POST /v1/egress/authorize`, not ad-hoc logic elsewhere.

---

## Build & test

```bash
cargo build --release
cargo test
cargo clippy --all-targets
```

> Note: on a machine without the MSVC linker (`link.exe`) this crate is built
> with the GNU host toolchain (`1.85.0-x86_64-pc-windows-gnu`) and the mingw
> `gcc` linker. The dependency `uuid` is pinned to `=1.11.0` because newer
> releases raised their MSRV above Rust 1.85.

---

## Evaluation pipeline (`engine::evaluate`)

Checks run **in this exact order**; the first failure produces the decision.

| # | Step | Failure reason code(s) |
|---|------|------------------------|
| 1 | Normalize / validate the target | `INVALID_TARGET` |
| 2 | Authorization present & granted & not expired | `AUTHORIZATION_MISSING`, `AUTHORIZATION_EXPIRED` |
| 3 | Profile gating | `RATE_POLICY_MISSING`, `PROFILE_NOT_PERMITTED` |
| 4 | Scope rules (exclusions win, then includes) | `NO_SCOPE_RULES`, `EXCLUDED`, `OUT_OF_SCOPE` |
| 5 | IP guards over `resolved_ips` + `dest_ip` | `METADATA_IP_BLOCKED`, `LOOPBACK_IP_BLOCKED`, `LINK_LOCAL_IP_BLOCKED`, `PRIVATE_IP_BLOCKED`, `RESERVED_IP_BLOCKED` |
| 6 | Redirect re-validation | `REDIRECT_OUT_OF_SCOPE` |
| 7 | Risk flags (non-fatal) | — |
| 8 | Approved | `IN_SCOPE` |

### Step 2 — Authorization

- `authorization` missing **or** `authorized == false` → `AUTHORIZATION_MISSING`.
- `expires_at` is `Some` and `<= now` → `AUTHORIZATION_EXPIRED`
  (`now` is `req.now` when supplied, otherwise the current time).

### Step 3 — Profile gating

| Profile | Requirement |
|---------|-------------|
| `passive` | none |
| `low_impact_discovery` | `rate_policy` must be present → else `RATE_POLICY_MISSING` |
| `authorized_vulnerability_testing` | `rate_policy.max_concurrency` **and** `authorization.expires_at` must both be set → else `PROFILE_NOT_PERMITTED` |

### Step 4 — Scope rules

- Empty `scope_rules` → `NO_SCOPE_RULES`.
- Any matching `exclude` rule → `EXCLUDED` (**exclusions always win**), reporting
  the exclude rule id.
- No matching `include` rule → `OUT_OF_SCOPE`.
- Otherwise the matched include rule id is reported.

### Step 5 — IP guards

Every entry of `resolved_ips` and `dest_ip` that parses as an `IpAddr` is
classified; the **first** blocked address decides the rejection. Order:

1. cloud metadata — `169.254.169.254`, `fd00:ec2::254` → `METADATA_IP_BLOCKED`
2. loopback — `127.0.0.0/8`, `::1` → `LOOPBACK_IP_BLOCKED`
3. link-local — `169.254.0.0/16`, `fe80::/10` → `LINK_LOCAL_IP_BLOCKED`
4. private — `10/8`, `172.16/12`, `192.168/16`, `fc00::/7` → `PRIVATE_IP_BLOCKED`
5. reserved — `0.0.0.0/8`, `100.64.0.0/10`, `192.0.0.0/24`, `192.0.2.0/24`,
   `198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24`, `224.0.0.0/4`,
   `240.0.0.0/4`, `255.255.255.255/32`, `::/128`, `::/8`, `2001:db8::/32`,
   `ff00::/8` → `RESERVED_IP_BLOCKED`
6. otherwise allowed.

### Step 7 — Risk flags

If `dest_ip` is present, `resolved_ips` is non-empty, and `dest_ip` is not a
member of `resolved_ips`, the flag `dns_rebinding_suspected` is added (this does
**not** reject the request).

### Egress (`egress::authorize_egress`)

Runs `evaluate` first; a rejection is returned unchanged. Then:

- `dest_ip` missing / empty / not parseable as an IP → `INVALID_TARGET`
  (`"dest_ip is required for egress authorization"`).
- `dest_ip` blocked by an IP guard → that specific guard code.
- Otherwise the approved decision from `evaluate` is returned.

---

## Target normalization (`rules::normalize_target`)

- everything is lowercased; a single trailing `.` is stripped;
- a value that is a bare URL (`http://Host:8443/a/b`) is split into
  scheme/host/port/path — **explicit `scheme`/`host`/`port`/`path` fields win**;
- IPv6 brackets are stripped (`[::1]` → `::1`);
- empty values, whitespace, control characters, or any of
  `` ; | & $ ` ' " `` are rejected with `INVALID_TARGET`;
- an `ip` target must parse as `IpAddr` and a `cidr` target as `IpNet`
  (both `INVALID_TARGET` otherwise).

The normalized form carries a lowercase `host` and, when a scheme is known, a
normalized `full_url` (lowercase scheme+host, single slashes, no trailing slash).

---

## Rule matching semantics

| Rule kind | Matches |
|-----------|---------|
| `domain` | the apex **and** any sub-domain, on label boundaries (`example.com` matches `example.com` and `a.example.com`, never `notexample.com`) |
| `wildcard_domain` | sub-domains only, **never** the apex; a leading `*.` is optional |
| `hostname` | **exact** case-insensitive equality only |
| `ip` | both sides parse as `IpAddr` and are equal |
| `cidr` | the host (or the destination IP being checked) parses as an `IpAddr` inside the `IpNet` |
| `url_prefix` | the normalized full URL matches the normalized rule on a boundary (case, single slashes, no trailing slash) |

**Exclusions always win.** If any `exclude` rule matches, the decision is
`EXCLUDED` even when an `include` rule also matches.

---

## Reason codes

`IN_SCOPE`, `OUT_OF_SCOPE`, `EXCLUDED`, `NO_SCOPE_RULES`, `INVALID_TARGET`,
`PRIVATE_IP_BLOCKED`, `LOOPBACK_IP_BLOCKED`, `LINK_LOCAL_IP_BLOCKED`,
`METADATA_IP_BLOCKED`, `RESERVED_IP_BLOCKED`, `AUTHORIZATION_EXPIRED`,
`AUTHORIZATION_MISSING`, `PROFILE_NOT_PERMITTED`, `REDIRECT_OUT_OF_SCOPE`,
`RATE_POLICY_MISSING`, `DNS_REBINDING_SUSPECTED`.

`decision` is `approved` or `rejected`; `evaluated_at` is an RFC3339 timestamp.

---

## HTTP API

Bind address from `SCOPE_ENGINE_ADDR` (default `127.0.0.1:8090`). Request bodies
are limited to **256 KiB**.

| Method | Path | Purpose |
|--------|------|---------|
| `GET`  | `/healthz` | `{"status":"ok","service":"scope-engine","version":"…"}` |
| `GET`  | `/v1/version` | `{"name":"scope-engine","version":"…"}` |
| `POST` | `/v1/scope/decide` | body `ScopeRequest` → `ScopeDecision` (always HTTP 200) |
| `POST` | `/v1/egress/authorize` | body `ScopeRequest` → `ScopeDecision` (always HTTP 200) |

Malformed or schema-invalid JSON returns **HTTP 400** with
`{"error":"invalid_request","detail":"…"}`.

The *decision* carries the verdict — a rejected target still returns HTTP 200
with `"decision":"rejected"`.

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8090/v1/scope/decide `
  -ContentType application/json -Body '<ScopeRequest JSON>'
```

### Example request

```json
{
  "request_id": "req-1",
  "tenant_id": "t1",
  "project_id": "p1",
  "scope_version": 3,
  "policy_profile": "passive",
  "target": { "kind": "domain", "value": "app.example.com" },
  "scope_rules": [
    { "id": "r1", "kind": "domain", "value": "example.com", "action": "include" }
  ],
  "authorization": { "authorized": true, "expires_at": "2999-01-01T00:00:00Z" }
}
```

### Example response

```json
{
  "request_id": "req-1",
  "decision": "approved",
  "reason_code": "IN_SCOPE",
  "reason": "target `app.example.com` is in scope",
  "matched_rule_id": "r1",
  "normalized_target": "app.example.com",
  "risk_flags": [],
  "scope_version": 3,
  "evaluated_at": "2026-11-11T08:45:17.438116100Z"
}
```

---

## CLI

```
scope-engine serve                                   # run the HTTP server
scope-engine check   [--input <path>]                # scope decision → stdout
scope-engine egress  [--input <path>]                # egress decision → stdout
scope-engine health                                  # prints "ok"
scope-engine version                                 # prints the version
```

`--input` reads a file, or stdin when omitted or set to `-`. `check`/`egress`
print a compact `ScopeDecision` JSON document to stdout and use these exit codes:

| Exit | Meaning |
|------|---------|
| `0` | approved |
| `2` | rejected |
| `1` | error (bad file / invalid JSON); the error is printed to stderr as JSON |

```powershell
Get-Content request.json | .\target\release\scope-engine.exe check --input -
# → {"decision":"approved", ...}  (exit 0)
```

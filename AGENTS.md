# AGENTS.md — operating instructions for AI coding agents

This file is the contract for any agent (or human) changing this repository.

## 0. Non-negotiables

1. **Inspect before you change.** Do not assume a module is empty or unused.
2. **Preserve working functionality.** Never delete a passing test to make a change land.
3. **No placeholder modules.** Do not add a file that "pretends to work". If something
   cannot run yet, it does not get committed.
4. **No silent schema changes.** Every `migrations/*.sql` addition is append-only; a
   `000N_*.down.sql` rollback ships with it.
5. **No secrets in source.** Everything comes from the environment; see `.env.example`.
6. **Scope enforcement is never bypassed "just for internal convenience".**
7. **Tenants never get shell access.** Jobs carry structured arguments only.
8. **Scanner output is never a confirmed vulnerability.** It is a candidate.

## 1. Language ownership — do not blur the boundaries

| Concern | Owner | Rule |
|---|---|---|
| Scope rules, CIDR/IP guards, egress policy | **Rust** (`rust/scope-engine`) | Go and Python must **call** it, never re-implement it. |
| HTTP API, auth, RBAC, tenant context, worker dispatch | **Go** (`go/`) | Do not put security policy in handlers; call the scope engine. |
| Tool CLI invocation + output parsing | **Python** (`python/adapters`) | Tool-specific code lives here and *only* here. |
| Event processing, asset graph, dependency resolution, planning | **Python** (`python/ffuf_intel`) | The core engine contains no tool-specific branching. |

The core engine must never special-case a tool. Tool knowledge belongs in the adapter
registry and the dependency table, both of which are data.

## 2. Cross-language contracts

These files are the API between languages. Changing one requires changing all consumers
in the same commit:

- `packages/schemas/scope-request.schema.json` / `scope-decision.schema.json` — Rust ⇄ Go ⇄ Python
- `packages/schemas/event.schema.json` — Go ⇄ Python
- `packages/schemas/job.schema.json` — Go ⇄ Python workers
- `packages/schemas/asset.schema.json` / `finding.schema.json` — everyone

Bump `schema_version` on breaking changes.

## 3. Build & test

```bash
make check        # everything: rust + go + python
make test-rust    # cargo test
make test-go      # go test ./...
make test-python  # pytest
make e2e          # full cross-language pipeline
```

## 4. Definition of done for any change

- [ ] Code implemented and compiling.
- [ ] Unit tests exist and pass.
- [ ] Security-relevant behaviour has a dedicated test (scope rejection, tenant
      isolation, injection attempt).
- [ ] Docs updated if a contract changed.
- [ ] Migration + rollback if the schema changed.
- [ ] The runtime behaviour matches what the commit message claims.

## 5. Milestones

Work one milestone at a time (see README / the specification). Do not integrate every
tool in one commit. Update this file after each completed milestone.

## 6. Reporting

Every milestone report lists: implemented features, changed files, database changes,
tool integrations, tests executed with PASS/FAIL, known limitations, remaining risks,
and the next milestone.

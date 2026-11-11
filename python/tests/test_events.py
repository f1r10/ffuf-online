"""Marquee test: the event-driven discovery chain.

Feeds the real specification chain through the event processor and asserts that
each tool's discovery automatically produces useful work for the next tool:

    subfinder -> httpx -> katana -> arjun -> nuclei -> validation task

It also pins idempotency (replaying an event changes nothing) and the hard rule
that a scanner finding is never auto-confirmed.
"""

from __future__ import annotations

from ffuf_intel.config import Config
from ffuf_intel.events import EventProcessor
from ffuf_intel.models import make_event
from ffuf_intel.scope_client import FakeTransport, ScopeClient


def _processor() -> EventProcessor:
    # Generous budgets + no cooldown so the chain is not throttled; the budget
    # logic itself is covered exhaustively in test_planner.py.
    config = Config(
        intel_task_cooldown_seconds=0,
        intel_max_tasks_per_asset=100,
        intel_max_workflow_depth=20,
        intel_tenant_max_tasks=1000,
        intel_max_tasks_per_project_run=5000,
    )
    return EventProcessor(config=config, scope_client=ScopeClient(FakeTransport()))


def _ids(plan):
    return {t.tool_id for t in plan.tasks}


def test_subfinder_discovery_schedules_http_probing():
    proc = _processor()
    event = make_event(
        "tenant-1",
        "project-1",
        "asset.discovered",
        payload={"asset_type": "subdomain", "value": "api.example.com"},
        asset_ref="api.example.com",
        source_tool="subfinder",
    )
    plan = proc.process(event)
    assert "httpx" in _ids(plan)
    assert "dnsx" in _ids(plan)
    # the subdomain is now in the asset graph, attributed to subfinder
    assets = proc.graph.all_assets("tenant-1", "project-1")
    api = [a for a in assets if a.value == "api.example.com"][0]
    assert "subfinder" in api.source_tools
    # every emitted task has a machine-readable reason
    assert all(t.reason for t in plan.tasks)


def test_full_chain_from_subdomain_to_validation_task():
    proc = _processor()

    # 1. subfinder finds a subdomain
    plan1 = proc.process(
        make_event(
            "tenant-1",
            "project-1",
            "asset.discovered",
            payload={"asset_type": "subdomain", "value": "api.example.com"},
            asset_ref="api.example.com",
            source_tool="subfinder",
        )
    )
    assert "httpx" in _ids(plan1)

    # 2. httpx returns a live HTTP service -> crawlers/scanners scheduled
    url = "https://api.example.com"
    plan2 = proc.process(
        make_event(
            "tenant-1",
            "project-1",
            "http.service.discovered",
            payload={"url": url, "host": "api.example.com", "status_code": 200, "title": "Example API"},
            asset_ref=url,
            source_tool="httpx",
        )
    )
    assert {"katana", "ffuf", "feroxbuster", "nuclei"} <= _ids(plan2)

    # 3. katana finds an API endpoint -> parameter discovery scheduled
    endpoint = "https://api.example.com/api/v2/users"
    plan3 = proc.process(
        make_event(
            "tenant-1",
            "project-1",
            "http.endpoint.discovered",
            payload={"url": endpoint, "endpoint": "/api/v2/users", "host": "api.example.com", "method": "GET"},
            asset_ref=endpoint,
            source_tool="katana",
        )
    )
    assert "arjun" in _ids(plan3)

    # 4. arjun finds a parameter -> authorized parameter test scheduled
    plan4 = proc.process(
        make_event(
            "tenant-1",
            "project-1",
            "parameter.discovered",
            payload={"parameter": "user_id", "endpoint": endpoint, "url": endpoint},
            asset_ref=endpoint,
            source_tool="arjun",
        )
    )
    assert "nuclei" in _ids(plan4)
    nuclei_task = [t for t in plan4.tasks if t.tool_id == "nuclei"][0]
    assert nuclei_task.execution_profile == "authorized_vulnerability_testing"

    # 5. nuclei emits a candidate finding -> a human-gated VALIDATION task
    finding = {
        "id": "finding-demo-1",
        "tenant_id": "tenant-1",
        "project_id": "project-1",
        "finding_type": "exposed-api-swagger",
        "title": "Exposed API Swagger UI",
        "severity": "low",
        "confidence": 0.5,
        "status": "needs_validation",
        "endpoint": endpoint,
        "source_tools": ["nuclei"],
    }
    plan5 = proc.process(
        make_event(
            "tenant-1",
            "project-1",
            "finding.candidate.created",
            payload={"finding": finding, "template_id": "exposed-api-swagger", "endpoint": endpoint},
            asset_ref=endpoint,
            source_tool="nuclei",
        )
    )
    validation = [t for t in plan5.tasks if t.tool_id == "validation"]
    assert validation, "a candidate finding must schedule a validation task"
    assert validation[0].status == "awaiting_approval"

    # the candidate finding is retained but never auto-confirmed
    assert proc.findings
    assert proc.findings[0]["status"] not in {"validated", "confirmed_impact", "accepted", "report_ready"}

    # the graph accumulated the whole chain and its provenance
    a = proc.graph.all_assets("tenant-1", "project-1")
    assert len(a) >= 4
    sources = {tool for asset in a for tool in asset.source_tools}
    assert {"subfinder", "httpx", "katana", "arjun", "nuclei"} <= sources


def test_replaying_an_event_is_idempotent():
    proc = _processor()
    event = make_event(
        "tenant-1",
        "project-1",
        "http.service.discovered",
        payload={"url": "https://api.example.com", "host": "api.example.com"},
        asset_ref="https://api.example.com",
        source_tool="httpx",
    )
    first = proc.process(event)
    assert first.tasks
    second = proc.process(event)
    assert second.tasks == []
    assert second.skipped[0]["reason_code"] == "duplicate_event"


def test_scope_changed_event_generates_no_active_tasks():
    proc = _processor()
    plan = proc.process(
        make_event("tenant-1", "project-1", "scope.changed", payload={"scope_version": 2})
    )
    assert plan.tasks == []


def test_task_created_events_are_emitted():
    proc = _processor()
    proc.process(
        make_event(
            "tenant-1",
            "project-1",
            "http.service.discovered",
            payload={"url": "https://api.example.com", "host": "api.example.com"},
            asset_ref="https://api.example.com",
            source_tool="httpx",
        )
    )
    emitted = proc.drain_emitted()
    assert any(e.event_type == "task.created" for e in emitted)
    assert proc.drain_emitted() == []  # drained

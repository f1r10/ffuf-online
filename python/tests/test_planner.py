"""Task planner tests: the anti-loop controls and scope enforcement."""

from __future__ import annotations

from ffuf_intel.config import Config
from ffuf_intel.dependency import EligibleTool
from ffuf_intel.graph import normalize_value
from ffuf_intel.models import ScopeDecision, make_event
from ffuf_intel.planner import TaskPlanner
from ffuf_intel.scope_client import FakeTransport, ScopeClient


def _tool(tool_id="nuclei", required_input="https://api.example.com/a", value=9, token="url", profile="low_impact_discovery"):
    return EligibleTool(
        tool_id=tool_id,
        reason=f"{tool_id} eligible",
        required_input=required_input,
        expected_value=value,
        execution_profile=profile,
        required_input_token=token,
        tool_version="v1",
    )


def _event(asset_ref="https://api.example.com/a", **payload):
    base = {"url": asset_ref}
    base.update(payload)
    return make_event("t1", "p1", "http.endpoint.discovered", payload=base, asset_ref=asset_ref)


def _approving_client():
    return ScopeClient(FakeTransport())


def test_plan_creates_scope_approved_tasks_with_reasons():
    planner = TaskPlanner(Config(), _approving_client())
    result = planner.plan(_event(), [_tool()])
    assert len(result.tasks) == 1
    task = result.tasks[0]
    assert task.tool_id == "nuclei"
    assert task.workflow_id == "p1:default"
    assert task.reason
    assert task.status == "created"
    assert task.input == {"url": "https://api.example.com/a"}


def test_duplicate_plan_is_skipped_by_idempotency():
    planner = TaskPlanner(Config(), _approving_client())
    event = _event()
    assert len(planner.plan(event, [_tool()]).tasks) == 1
    second = planner.plan(event, [_tool()])
    assert second.tasks == []
    assert second.skipped[0]["reason_code"] == "duplicate"


def test_max_workflow_depth_blocks_deep_workflows():
    planner = TaskPlanner(Config(intel_max_workflow_depth=5), _approving_client())
    event = _event(depth=10)
    result = planner.plan(event, [_tool()])
    assert result.tasks == []
    assert result.skipped[0]["reason_code"] == "max_workflow_depth"


def test_max_tasks_per_asset_caps_explosion():
    planner = TaskPlanner(Config(intel_max_tasks_per_asset=1), _approving_client())
    result = planner.plan(_event(), [_tool("nuclei"), _tool("ffuf", value=7)])
    assert len(result.tasks) == 1
    assert result.skipped[0]["reason_code"] == "max_tasks_per_asset"


def test_tenant_quota_caps_total_tasks():
    planner = TaskPlanner(
        Config(intel_tenant_max_tasks=1, intel_max_tasks_per_asset=100), _approving_client()
    )
    result = planner.plan(_event(), [_tool("nuclei"), _tool("ffuf", value=7)])
    assert len(result.tasks) == 1
    assert result.skipped[0]["reason_code"] == "tenant_quota_exceeded"


def test_project_run_quota():
    planner = TaskPlanner(
        Config(intel_max_tasks_per_project_run=1, intel_max_tasks_per_asset=100), _approving_client()
    )
    result = planner.plan(_event(), [_tool("nuclei"), _tool("ffuf", value=7)])
    assert len(result.tasks) == 1
    assert result.skipped[0]["reason_code"] == "max_tasks_per_project_run"


def test_cooldown_prevents_immediate_reruns_of_same_tool_on_same_asset():
    clock = {"now": 1000.0}
    planner = TaskPlanner(
        Config(intel_task_cooldown_seconds=900),
        _approving_client(),
        clock=lambda: clock["now"],
    )
    # Same asset (same node) but a different fuzz target => different
    # idempotency key, so the cooldown (not dedup) is what suppresses the rerun.
    first = planner.plan(_event("https://api.example.com/a"), [_tool(required_input="https://api.example.com/a")])
    assert len(first.tasks) == 1
    second = planner.plan(
        _event("https://api.example.com/a"), [_tool(required_input="https://api.example.com/b")]
    )
    assert second.tasks == []
    assert second.skipped[0]["reason_code"] == "cooldown_active"

    clock["now"] += 1000.0  # window elapsed
    third = planner.plan(
        _event("https://api.example.com/a"), [_tool(required_input="https://api.example.com/c")]
    )
    assert len(third.tasks) == 1


def test_cycle_detection_is_graph_based():
    planner = TaskPlanner(Config(), _approving_client())
    planner.record_edge("wf", "A", "B")
    assert planner.would_create_cycle("wf", parent_node_id="B", child_node_id="A") is True
    assert planner.would_create_cycle("wf", parent_node_id="A", child_node_id="C") is False


def test_plan_skips_tasks_that_would_create_a_cycle():
    planner = TaskPlanner(Config(), _approving_client())
    workflow_id = "p1:default"
    asset_ref = "https://api.example.com/a"
    asset_key = normalize_value("hostname", asset_ref)
    node = planner.node_id(workflow_id, "nuclei", asset_key)
    planner.record_edge(workflow_id, node, "parent-node")
    event = _event(asset_ref=asset_ref, node_id="parent-node", workflow_id=workflow_id)
    result = planner.plan(event, [_tool()])
    assert result.tasks == []
    assert result.skipped[0]["reason_code"] == "cycle_detected"


def test_scope_rejection_blocks_task_with_reason_code():
    rejected = ScopeDecision(
        request_id="r", decision="rejected", reason_code="OUT_OF_SCOPE", reason="not in scope"
    )
    client = ScopeClient(FakeTransport(decide_fn=lambda req: rejected))
    planner = TaskPlanner(Config(), client)
    result = planner.plan(_event(), [_tool()])
    assert result.tasks == []
    assert result.blocked[0]["reason_code"] == "OUT_OF_SCOPE"


def test_idempotency_key_is_deterministic():
    a = TaskPlanner.idempotency_key("t1", "p1", "nuclei", "https://x/a", "node-1")
    b = TaskPlanner.idempotency_key("t1", "p1", "nuclei", "https://x/a", "node-1")
    c = TaskPlanner.idempotency_key("t1", "p1", "nuclei", "https://x/b", "node-1")
    assert a == b
    assert a != c


def test_workflow_graph_records_nodes_and_edges():
    planner = TaskPlanner(Config(), _approving_client())
    event = _event(node_id="parent", workflow_id="wf-1")
    planner.plan(event, [_tool()])
    graph = planner.workflow_graph("wf-1")
    assert graph["tasks"]
    assert {"from": "parent", "to": graph["tasks"][0]["node_id"]} in graph["edges"]

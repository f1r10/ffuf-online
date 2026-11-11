"""Dynamic task planner — the anti-loop, scope-aware task generator.

Every generated task carries a human-readable ``reason`` (why it was created).
Every *skipped* task carries a ``reason`` and ``reason_code`` (why it was not).
A task whose derived target is rejected by the scope engine is *blocked* with the
scope ``reason_code`` and is never emitted.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional
from urllib.parse import urlsplit

from .config import Config
from .dependency import EligibleTool
from .graph import normalize_value
from .models import DomainEvent, ScopeRequest, Task
from .scope_client import ScopeClient, ScopeDenied


@dataclass
class PlanResult:
    tasks: List[Task] = field(default_factory=list)
    skipped: List[Dict] = field(default_factory=list)
    blocked: List[Dict] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "tasks": [t.to_dict() for t in self.tasks],
            "skipped": list(self.skipped),
            "blocked": list(self.blocked),
        }


def _target_kind_and_fields(target: str) -> Dict:
    target = (target or "").strip()
    if "://" in target:
        parts = urlsplit(target)
        return {
            "kind": "url",
            "value": target,
            "scheme": parts.scheme or None,
            "host": (parts.hostname or None),
            "port": parts.port,
            "path": parts.path or "/",
        }
    return {"kind": "hostname", "value": target, "host": target}


class TaskPlanner:
    """Generates tasks from eligible tools while enforcing every budget."""

    def __init__(
        self,
        config: Optional[Config] = None,
        scope_client: Optional[ScopeClient] = None,
        scope_rules: Optional[List[Dict]] = None,
        authorization: Optional[Dict] = None,
        clock: Optional[Callable[[], float]] = None,
    ):
        self.config = config or Config()
        self.scope_client = scope_client
        self.scope_rules = scope_rules or []
        self.authorization = authorization or {"authorized": True}
        self._clock = clock or time.time

        # anti-loop state
        self._idempotency: Dict[str, Task] = {}
        self._tasks_by_asset: Dict[str, int] = {}
        self._tasks_by_tenant: Dict[str, int] = {}
        self._tasks_by_project: Dict[str, int] = {}
        self._cooldown: Dict[str, float] = {}
        # workflow node graph: workflow_id -> parent -> set(child)
        self._wf_children: Dict[str, Dict[str, set]] = {}
        self._workflow_tasks: Dict[str, List[Dict]] = {}

    # -------------------------------------------------------------- helpers
    @staticmethod
    def idempotency_key(tenant_id: str, project_id: str, tool_id: str, normalized_input: str, node_id: str) -> str:
        raw = "|".join([tenant_id, project_id, tool_id, normalized_input, node_id])
        return "idem-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]

    def node_id(self, workflow_id: str, tool_id: str, node_input: str) -> str:
        raw = f"{workflow_id}|{tool_id}|{node_input}"
        return "node-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]

    def record_edge(self, workflow_id: str, parent_node_id: str, child_node_id: str) -> None:
        self._wf_children.setdefault(workflow_id, {}).setdefault(parent_node_id, set()).add(child_node_id)

    def _reachable(self, workflow_id: str, start: str, target: str) -> bool:
        """Is ``target`` reachable from ``start`` following parent->child edges?"""
        children = self._wf_children.get(workflow_id, {})
        seen = set()
        stack = [start]
        while stack:
            node = stack.pop()
            if node == target:
                return True
            if node in seen:
                continue
            seen.add(node)
            stack.extend(children.get(node, ()))
        return False

    def would_create_cycle(self, workflow_id: str, parent_node_id: str, child_node_id: str) -> bool:
        # Adding parent->child creates a cycle iff child already reaches parent.
        return self._reachable(workflow_id, child_node_id, parent_node_id)

    # ---------------------------------------------------------------- plan
    def plan(self, event: DomainEvent, eligible_tools: List[EligibleTool]) -> PlanResult:
        result = PlanResult()
        tenant_id = event.tenant_id
        project_id = event.project_id
        payload = event.payload or {}
        workflow_id = payload.get("workflow_id") or f"{project_id}:default"
        parent_node = payload.get("node_id")
        depth = int(payload.get("depth", 0)) + 1
        asset_key = normalize_value("hostname", event.asset_ref or payload.get("url") or payload.get("value") or "")
        if not asset_key:
            asset_key = "unknown"
        now = self._clock()

        for tool in eligible_tools:
            normalized_input = normalize_value("url", tool.required_input or asset_key) or asset_key
            # Parameter-scoped work is a distinct unit of work from the generic
            # endpoint-level task, so the discovered parameter is part of the
            # task identity (otherwise a per-parameter test would be deduped away).
            parameter = payload.get("parameter")
            if parameter:
                normalized_input = f"{normalized_input}|param:{parameter}"
            node = self.node_id(workflow_id, tool.tool_id, asset_key)
            idem = self.idempotency_key(tenant_id, project_id, tool.tool_id, normalized_input, node)
            entry = {
                "tool_id": tool.tool_id,
                "reason": tool.reason,
                "asset_key": asset_key,
                "idempotency_key": idem,
            }

            if parent_node and self.would_create_cycle(workflow_id, parent_node, node):
                result.skipped.append({**entry, "reason_code": "cycle_detected"})
                continue
            if idem in self._idempotency:
                result.skipped.append({**entry, "reason_code": "duplicate"})
                continue
            if depth > self.config.intel_max_workflow_depth:
                result.skipped.append({**entry, "reason_code": "max_workflow_depth"})
                continue
            if self._tasks_by_asset.get(f"{tenant_id}|{project_id}|{asset_key}", 0) >= self.config.intel_max_tasks_per_asset:
                result.skipped.append({**entry, "reason_code": "max_tasks_per_asset"})
                continue
            if self._tasks_by_tenant.get(tenant_id, 0) >= self.config.intel_tenant_max_tasks:
                result.skipped.append({**entry, "reason_code": "tenant_quota_exceeded"})
                continue
            if self._tasks_by_project.get(f"{tenant_id}|{project_id}", 0) >= self.config.intel_max_tasks_per_project_run:
                result.skipped.append({**entry, "reason_code": "max_tasks_per_project_run"})
                continue
            cooldown_key = f"{tenant_id}|{project_id}|{tool.tool_id}|{asset_key}"
            last = self._cooldown.get(cooldown_key)
            if last is not None and (now - last) < self.config.intel_task_cooldown_seconds:
                result.skipped.append({**entry, "reason_code": "cooldown_active"})
                continue

            # Scope approval is mandatory before a task may be emitted.
            target = tool.required_input or event.asset_ref or asset_key
            if self.scope_client is not None:
                request = ScopeRequest(
                    tenant_id=tenant_id,
                    project_id=project_id,
                    policy_profile=tool.execution_profile,
                    target=_target_kind_and_fields(target),
                    scope_rules=self.scope_rules,
                    request_id=f"{idem}",
                    scope_version=event.scope_version,
                    authorization=self.authorization,
                )
                try:
                    self.scope_client.require_approved(request)
                except ScopeDenied as denied:
                    result.blocked.append({**entry, "reason_code": denied.reason_code, "reason": denied.reason or tool.reason})
                    continue

            task = Task(
                id="task-" + hashlib.sha256(idem.encode("utf-8")).hexdigest()[:16],
                tenant_id=tenant_id,
                project_id=project_id,
                workflow_id=workflow_id,
                node_id=node,
                tool_id=tool.tool_id,
                tool_version=tool.tool_version,
                input={tool.required_input_token: tool.required_input},
                execution_profile=tool.execution_profile,
                priority=tool.expected_value,
                depth=depth,
                status="created",
                idempotency_key=idem,
                reason=tool.reason,
            )

            # commit state
            self._idempotency[idem] = task
            self._tasks_by_asset[f"{tenant_id}|{project_id}|{asset_key}"] = (
                self._tasks_by_asset.get(f"{tenant_id}|{project_id}|{asset_key}", 0) + 1
            )
            self._tasks_by_tenant[tenant_id] = self._tasks_by_tenant.get(tenant_id, 0) + 1
            self._tasks_by_project[f"{tenant_id}|{project_id}"] = (
                self._tasks_by_project.get(f"{tenant_id}|{project_id}", 0) + 1
            )
            self._cooldown[cooldown_key] = now
            if parent_node:
                self.record_edge(workflow_id, parent_node, node)
            self._workflow_tasks.setdefault(workflow_id, []).append(task.to_dict())

            result.tasks.append(task)

        return result

    # ------------------------------------------------------------ querying
    def workflow_graph(self, workflow_id: str) -> Dict:
        edges = []
        for parent, children in self._wf_children.get(workflow_id, {}).items():
            for child in children:
                edges.append({"from": parent, "to": child})
        return {
            "workflow_id": workflow_id,
            "tasks": self._workflow_tasks.get(workflow_id, []),
            "nodes": sorted(
                {e["from"] for e in edges} | {e["to"] for e in edges} | {t["node_id"] for t in self._workflow_tasks.get(workflow_id, [])}
            ),
            "edges": edges,
        }

    def reset(self) -> None:
        self._idempotency.clear()
        self._tasks_by_asset.clear()
        self._tasks_by_tenant.clear()
        self._tasks_by_project.clear()
        self._cooldown.clear()
        self._wf_children.clear()
        self._workflow_tasks.clear()


__all__ = ["TaskPlanner", "PlanResult"]

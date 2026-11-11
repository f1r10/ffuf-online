"""Event processor — wires the graph, resolver, planner and correlator.

``process(event)`` validates the envelope, upserts the referenced asset(s) into
the graph, applies the specification's feedback rules, plans downstream tasks
and emits derived :class:`DomainEvent` records for everything it learns.

Processing is **idempotent**: replaying the same logical event creates no
duplicate tasks and no duplicate derived events.
"""

from __future__ import annotations

import hashlib
from typing import Dict, List, Optional

from .config import Config
from .correlation import FindingCorrelator
from .dependency import DependencyResolver
from .graph import AssetGraph, correlation_key
from .models import Asset, DomainEvent, Task, make_event
from .planner import PlanResult, TaskPlanner
from .scope_client import ScopeClient

_INFERRED_ASSET_TYPE: Dict[str, str] = {
    "http.service.discovered": "http_service",
    "http.endpoint.discovered": "endpoint",
    "http.redirect.discovered": "url",
    "api.endpoint.discovered": "endpoint",
    "api.schema.discovered": "api_spec",
    "parameter.discovered": "parameter",
    "technology.detected": "technology",
    "javascript.discovered": "javascript",
    "dns.record.discovered": "hostname",
    "asset.discovered": "hostname",
    "finding.candidate.created": "finding",
}


class EventProcessor:
    def __init__(
        self,
        graph: Optional[AssetGraph] = None,
        resolver: Optional[DependencyResolver] = None,
        planner: Optional[TaskPlanner] = None,
        correlator: Optional[FindingCorrelator] = None,
        scope_client: Optional[ScopeClient] = None,
        config: Optional[Config] = None,
    ):
        self.config = config or Config()
        self.graph = graph or AssetGraph()
        self.resolver = resolver or DependencyResolver()
        self.correlator = correlator or FindingCorrelator()
        self.scope_client = scope_client
        self.planner = planner or TaskPlanner(self.config, scope_client)
        self.emitted: List[DomainEvent] = []
        self.findings: List[Dict] = []
        self._processed: set = set()

    # ------------------------------------------------------------- public
    def process(self, event: DomainEvent) -> PlanResult:
        event.validate()

        # Idempotency: replaying the same logical event is a no-op.
        fingerprint = event.fingerprint()
        if fingerprint in self._processed:
            result = PlanResult()
            result.skipped.append(
                {"reason": "event already processed", "reason_code": "duplicate_event"}
            )
            return result
        self._processed.add(fingerprint)

        if event.event_type in ("scope.changed", "scope.expired"):
            # Scope changes never generate new active tasks here.
            return PlanResult()

        self._upsert_assets(event)
        self._apply_feedback(event)

        eligible = self.resolver.eligible_next_tools(event)
        plan = self.planner.plan(event, eligible)

        if event.event_type == "finding.candidate.created":
            vt = self.validation_task(event)
            if vt is not None and vt.idempotency_key not in self.planner._idempotency:
                self.planner._idempotency[vt.idempotency_key] = vt
                plan.tasks.append(vt)

        for task in plan.tasks:
            self._emit(
                "task.created",
                event,
                payload={"task_id": task.id, "tool_id": task.tool_id, "reason": task.reason},
                asset_ref=event.asset_ref,
            )

        return plan

    def drain_emitted(self) -> List[DomainEvent]:
        out = self.emitted
        self.emitted = []
        return out

    def reset(self) -> None:
        self.graph.reset()
        self.planner.reset()
        self.emitted.clear()
        self.findings.clear()
        self._processed.clear()

    # ------------------------------------------------------------ internal
    def _emit(
        self,
        event_type: str,
        origin: DomainEvent,
        payload: Optional[Dict] = None,
        asset_ref: Optional[str] = None,
        source_tool: Optional[str] = None,
    ) -> DomainEvent:
        derived = make_event(
            tenant_id=origin.tenant_id,
            project_id=origin.project_id,
            event_type=event_type,
            payload=payload or {},
            asset_ref=asset_ref if asset_ref is not None else origin.asset_ref,
            source_tool=source_tool if source_tool is not None else origin.source_tool,
            source_execution_id=origin.source_execution_id,
            scope_version=origin.scope_version,
        )
        self.emitted.append(derived)
        return derived

    def _asset_from_event(self, event: DomainEvent) -> Optional[Asset]:
        payload = event.payload or {}
        asset_type = payload.get("asset_type") or _INFERRED_ASSET_TYPE.get(event.event_type)
        value = (
            payload.get("value")
            or payload.get("url")
            or payload.get("endpoint")
            or payload.get("host")
            or payload.get("hostname")
            or event.asset_ref
        )
        if not asset_type or not value:
            return None
        tools = [event.source_tool] if event.source_tool else []
        return Asset(
            id="",
            tenant_id=event.tenant_id,
            project_id=event.project_id,
            asset_type=asset_type,
            value=str(value),
            source_tools=tools,
            scope_status=payload.get("scope_status", "unknown"),
            confidence=float(payload.get("confidence", 1.0)),
        )

    def _upsert_assets(self, event: DomainEvent) -> None:
        asset = self._asset_from_event(event)
        if asset is None:
            return
        stored, created = self.graph.upsert_asset(asset)
        if created:
            self._emit(
                "asset.discovered",
                event,
                payload={"asset_type": stored.asset_type, "value": stored.value, "asset_id": stored.id},
                asset_ref=stored.value,
            )
        # best-effort: relate an endpoint / http service to its host
        host = (event.payload or {}).get("host")
        if host and stored.asset_type in ("endpoint", "http_service", "parameter", "technology", "javascript"):
            host_key = correlation_key("hostname", host)
            host_asset = self.graph._assets.get((event.tenant_id, event.project_id, host_key))
            if host_asset is not None:
                self.graph.link(
                    host_asset.id,
                    stored.id,
                    "contains" if stored.asset_type in ("endpoint", "parameter") else "serves",
                    source_tool=event.source_tool,
                    source_execution_id=event.source_execution_id,
                    scope_version=event.scope_version,
                    tenant_id=event.tenant_id,
                    project_id=event.project_id,
                )

    def _apply_feedback(self, event: DomainEvent) -> None:
        """Specification feedback rules that are not pure task generation."""
        payload = event.payload or {}

        if event.event_type == "parameter.discovered":
            # update endpoint metadata with the discovered parameter
            endpoint = payload.get("endpoint") or payload.get("url")
            if endpoint:
                key = correlation_key("endpoint", endpoint)
                asset = self.graph._assets.get((event.tenant_id, event.project_id, key))
                if asset is not None:
                    params = list(asset.metadata.get("parameters", []))
                    if payload.get("parameter") and payload["parameter"] not in params:
                        params.append(payload["parameter"])
                        asset.metadata["parameters"] = params

        if event.event_type == "finding.candidate.created":
            # correlate and keep an explicit candidate (never auto-confirmed)
            finding = dict(payload.get("finding") or {})
            finding.setdefault("tenant_id", event.tenant_id)
            finding.setdefault("project_id", event.project_id)
            finding.setdefault("status", "candidate")
            corr = self.correlator.correlate([finding], self.findings)
            for merged in corr.merged:
                for i, existing in enumerate(self.findings):
                    if self.correlator_key(existing) == self.correlator_key(merged):
                        self.findings[i] = merged
            for new_finding in corr.new:
                self.findings.append(new_finding)

    @staticmethod
    def correlator_key(finding: Dict) -> str:
        from .correlation import correlation_key as _ck

        return _ck(finding)

    def validation_task(self, event: DomainEvent) -> Optional[Task]:
        """Create an explicit validation task for a candidate finding.

        Scanner output is never auto-confirmed: the task is created with status
        ``awaiting_approval`` because a validation task is a sensitive operation.
        """
        payload = event.payload or {}
        finding = payload.get("finding") or {}
        endpoint = finding.get("endpoint") or payload.get("endpoint") or event.asset_ref or ""
        raw = "|".join([event.tenant_id, event.project_id, endpoint, str(finding.get("finding_type") or "")])
        idem = "idem-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]
        return Task(
            id="task-" + hashlib.sha256(idem.encode("utf-8")).hexdigest()[:16],
            tenant_id=event.tenant_id,
            project_id=event.project_id,
            workflow_id=(payload.get("workflow_id") or f"{event.project_id}:default"),
            node_id=None,
            tool_id="validation",
            tool_version="0.1.0",
            input={"target": endpoint},
            execution_profile="authorized_vulnerability_testing",
            priority=10,
            depth=1,
            status="awaiting_approval",
            idempotency_key=idem,
            reason="candidate finding requires safe validation; human approval required by policy",
        )


__all__ = ["EventProcessor"]

"""Dataclasses mirroring ``packages/schemas/*.json`` exactly.

Each class provides ``to_dict()`` / ``from_dict()``. ``from_dict`` ignores
unknown keys so the models tolerate forward-compatible envelopes, but the
required-vs-optional semantics match the JSON schemas.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

SCHEMA_VERSION = "1.0.0"

#: The full ``event_type`` enumeration from ``event.schema.json``.
EVENT_TYPES: tuple = (
    "asset.discovered",
    "asset.updated",
    "dns.record.discovered",
    "http.service.discovered",
    "http.endpoint.discovered",
    "http.redirect.discovered",
    "api.endpoint.discovered",
    "api.schema.discovered",
    "parameter.discovered",
    "technology.detected",
    "javascript.discovered",
    "tool.execution.started",
    "tool.execution.completed",
    "tool.execution.failed",
    "finding.candidate.created",
    "finding.evidence.added",
    "finding.validated",
    "finding.rejected",
    "scope.changed",
    "scope.expired",
    "task.created",
    "task.cancelled",
)

#: Finding lifecycle from ``finding.schema.json``.
FINDING_STATUSES: tuple = (
    "discovered",
    "candidate",
    "needs_validation",
    "validated",
    "rejected",
    "confirmed_impact",
    "report_ready",
    "submitted",
    "accepted",
    "duplicate",
    "informative",
)

ASSET_TYPES: tuple = (
    "root_domain",
    "subdomain",
    "hostname",
    "ip",
    "cidr",
    "service",
    "port",
    "http_service",
    "endpoint",
    "url",
    "parameter",
    "technology",
    "javascript",
    "api_spec",
    "finding",
)

EXECUTION_PROFILES: tuple = (
    "passive",
    "low_impact_discovery",
    "authorized_vulnerability_testing",
)

SCOPE_REASON_CODES: tuple = (
    "IN_SCOPE",
    "OUT_OF_SCOPE",
    "EXCLUDED",
    "NO_SCOPE_RULES",
    "INVALID_TARGET",
    "PRIVATE_IP_BLOCKED",
    "LOOPBACK_IP_BLOCKED",
    "LINK_LOCAL_IP_BLOCKED",
    "METADATA_IP_BLOCKED",
    "RESERVED_IP_BLOCKED",
    "AUTHORIZATION_EXPIRED",
    "AUTHORIZATION_MISSING",
    "PROFILE_NOT_PERMITTED",
    "REDIRECT_OUT_OF_SCOPE",
    "RATE_POLICY_MISSING",
    "DNS_REBINDING_SUSPECTED",
)

RELATIONSHIP_TYPES: tuple = (
    "resolves_to",
    "serves",
    "contains",
    "uses_technology",
    "derived_from",
)


def utc_now() -> str:
    """RFC3339 UTC timestamp with a trailing ``Z`` (schema date-time format)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


class _Serializable:
    """Mixin providing ``to_dict``/``from_dict`` over the dataclass fields."""

    def to_dict(self) -> Dict[str, Any]:
        return {f.name: getattr(self, f.name) for f in dataclasses.fields(self)}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]):
        names = {f.name for f in dataclasses.fields(cls)}
        return cls(**{k: v for k, v in (data or {}).items() if k in names})


@dataclass
class DomainEvent(_Serializable):
    event_id: str
    tenant_id: str
    project_id: str
    event_type: str
    timestamp: str = field(default_factory=utc_now)
    schema_version: str = SCHEMA_VERSION
    source_tool: Optional[str] = None
    source_execution_id: Optional[str] = None
    asset_ref: Optional[str] = None
    scope_version: int = 1
    payload: Dict[str, Any] = field(default_factory=dict)

    def fingerprint(self) -> str:
        """Stable identity of the *content* (ignores event_id and timestamp).

        Replaying the same logical event therefore yields the same fingerprint,
        which is what makes event processing idempotent.
        """
        return event_fingerprint(self)

    def validate(self) -> None:
        if not self.event_id:
            raise ValueError("event_id is required")
        if not self.tenant_id:
            raise ValueError("tenant_id is required")
        if not self.project_id:
            raise ValueError("project_id is required")
        if self.event_type not in EVENT_TYPES:
            raise ValueError(f"unknown event_type: {self.event_type!r}")
        if not isinstance(self.payload, dict):
            raise ValueError("payload must be an object")


@dataclass
class Asset(_Serializable):
    id: str
    tenant_id: str
    project_id: str
    asset_type: str
    value: str
    first_seen_at: str = field(default_factory=utc_now)
    last_seen_at: str = field(default_factory=utc_now)
    parent_asset_id: Optional[str] = None
    source_tools: List[str] = field(default_factory=list)
    scope_status: str = "unknown"
    confidence: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding(_Serializable):
    id: str
    tenant_id: str
    project_id: str
    finding_type: str
    title: str
    scope_version: int = 1
    severity: str = "unknown"
    confidence: float = 0.5
    status: str = "candidate"
    asset_id: Optional[str] = None
    endpoint: Optional[str] = None
    http_method: Optional[str] = None
    parameter: Optional[str] = None
    source_tools: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    related_finding_ids: List[str] = field(default_factory=list)


@dataclass
class Task(_Serializable):
    tool_id: str
    tenant_id: str
    project_id: str
    idempotency_key: str
    input: Dict[str, Any] = field(default_factory=dict)
    id: str = ""
    workflow_id: Optional[str] = None
    node_id: Optional[str] = None
    tool_version: str = ""
    execution_profile: str = "low_impact_discovery"
    priority: int = 5
    depth: int = 0
    status: str = "created"
    reason: str = ""


@dataclass
class Job(_Serializable):
    job_id: str
    tenant_id: str
    project_id: str
    tool_id: str
    idempotency_key: str
    created_at: str = field(default_factory=utc_now)
    expires_at: str = ""
    scope_version: int = 1
    policy_version: int = 1
    tool_version: str = ""
    execution_profile: str = "low_impact_discovery"
    input: Dict[str, Any] = field(default_factory=dict)
    limits: Dict[str, Any] = field(default_factory=dict)
    task_id: Optional[str] = None
    signature: Optional[str] = None


@dataclass
class ToolSpec(_Serializable):
    tool_id: str
    name: str
    category: str
    version: str = "pinned"
    image: str = ""
    capabilities: List[str] = field(default_factory=list)
    required_inputs: List[str] = field(default_factory=list)
    optional_inputs: List[str] = field(default_factory=list)
    output_types: List[str] = field(default_factory=list)
    supported_asset_types: List[str] = field(default_factory=list)
    applicable_execution_profiles: List[str] = field(default_factory=list)
    resource_profile: Dict[str, Any] = field(default_factory=dict)
    network_profile: str = "none"
    enabled: bool = True
    priority: int = 5
    trigger: List[str] = field(default_factory=list)
    input_schema: Dict[str, Any] = field(default_factory=dict)
    output_schema: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScopeRequest(_Serializable):
    tenant_id: str
    project_id: str
    policy_profile: str
    target: Dict[str, Any]
    scope_rules: List[Dict[str, Any]] = field(default_factory=list)
    request_id: str = ""
    scope_version: int = 1
    resolved_ips: List[str] = field(default_factory=list)
    redirect_chain: List[str] = field(default_factory=list)
    dest_ip: Optional[str] = None
    rate_policy: Dict[str, Any] = field(default_factory=dict)
    authorization: Dict[str, Any] = field(default_factory=dict)
    now: Optional[str] = None


@dataclass
class ScopeDecision(_Serializable):
    request_id: str
    decision: str
    reason_code: str
    evaluated_at: str = field(default_factory=utc_now)
    reason: str = ""
    matched_rule_id: Optional[str] = None
    normalized_target: Optional[str] = None
    risk_flags: List[str] = field(default_factory=list)
    scope_version: int = 1

    @property
    def approved(self) -> bool:
        return self.decision == "approved"


# --------------------------------------------------------------------------
# Deterministic event identity + dedup helpers
# --------------------------------------------------------------------------


def deterministic_event_id(
    tenant_id: str,
    project_id: str,
    event_type: str,
    source_tool: Optional[str] = None,
    source_execution_id: Optional[str] = None,
    asset_ref: Optional[str] = None,
    payload: Optional[Dict[str, Any]] = None,
) -> str:
    """Deterministic id derived from the logical content of an event.

    Two identical logical events (same tenant/project/type/source/asset/payload)
    produce the same id, which is what lets the processor deduplicate replays
    even before the fingerprint check.
    """
    h = hashlib.sha256()
    for part in (
        tenant_id,
        project_id,
        event_type,
        source_tool or "",
        source_execution_id or "",
        asset_ref or "",
        canonical_json(payload or {}),
    ):
        h.update(part.encode("utf-8"))
        h.update(b"\x00")
    return "evt-" + h.hexdigest()[:32]


def event_fingerprint(event: DomainEvent) -> str:
    """Content fingerprint of an event (excludes event_id and timestamp)."""
    h = hashlib.sha256()
    for part in (
        event.tenant_id,
        event.project_id,
        event.event_type,
        event.source_tool or "",
        event.source_execution_id or "",
        event.asset_ref or "",
        canonical_json(event.payload),
    ):
        h.update(part.encode("utf-8"))
        h.update(b"\x00")
    return h.hexdigest()


def dedup_events(events: List[DomainEvent]) -> List[DomainEvent]:
    """Return the unique events (by fingerprint), preserving first-seen order."""
    seen = set()
    out: List[DomainEvent] = []
    for ev in events:
        fp = ev.fingerprint()
        if fp in seen:
            continue
        seen.add(fp)
        out.append(ev)
    return out


def make_event(
    tenant_id: str,
    project_id: str,
    event_type: str,
    payload: Optional[Dict[str, Any]] = None,
    asset_ref: Optional[str] = None,
    source_tool: Optional[str] = None,
    source_execution_id: Optional[str] = None,
    scope_version: int = 1,
    event_id: Optional[str] = None,
) -> DomainEvent:
    """Build a :class:`DomainEvent` with a deterministic id by default."""
    payload = payload or {}
    return DomainEvent(
        event_id=event_id
        or deterministic_event_id(
            tenant_id,
            project_id,
            event_type,
            source_tool,
            source_execution_id,
            asset_ref,
            payload,
        ),
        tenant_id=tenant_id,
        project_id=project_id,
        event_type=event_type,
        source_tool=source_tool,
        source_execution_id=source_execution_id,
        asset_ref=asset_ref,
        scope_version=scope_version,
        payload=payload,
    )


__all__ = [
    "SCHEMA_VERSION",
    "EVENT_TYPES",
    "FINDING_STATUSES",
    "ASSET_TYPES",
    "EXECUTION_PROFILES",
    "SCOPE_REASON_CODES",
    "RELATIONSHIP_TYPES",
    "utc_now",
    "canonical_json",
    "DomainEvent",
    "Asset",
    "Finding",
    "Task",
    "Job",
    "ToolSpec",
    "ScopeRequest",
    "ScopeDecision",
    "deterministic_event_id",
    "event_fingerprint",
    "dedup_events",
    "make_event",
]

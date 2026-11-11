"""Tool adapter base contract.

All tool knowledge lives here and in the concrete adapters. The core engine
never imports a specific adapter.

Safety rules enforced by this module:

* ``build_arguments`` returns ``list[str]`` only — never a shell string.
* Values containing shell metacharacters or whitespace-only values are rejected.
* ``validate_input`` rejects unknown keys and missing required inputs.
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ffuf_intel.models import SCHEMA_VERSION, DomainEvent, utc_now

#: Characters that must never appear in an adapter argument value. URLs (which
#: legitimately contain ``?``, ``&``, ``=``, ``#``, ``%``, ``/``, ``:``) are
#: explicitly allowed.
SHELL_METACHARS = set(";|`$><\n\r\x00")


class AdapterInputError(ValueError):
    """Raised when a task's input is not acceptable for a tool adapter."""


def _stable_id(prefix: str, *parts: str) -> str:
    raw = "|".join(str(p) for p in parts)
    return f"{prefix}-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]


@dataclass
class ToolExecutionResult:
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    duration: float = 0.0
    artifacts: Dict[str, Any] = field(default_factory=dict)


class NormalizedResult(dict):
    """Container with the six canonical keys (and a ``to_dict`` alias)."""

    KEYS = ("assets", "endpoints", "parameters", "technologies", "findings", "events")

    def __init__(
        self,
        assets: Optional[List[Dict]] = None,
        endpoints: Optional[List[Dict]] = None,
        parameters: Optional[List[Dict]] = None,
        technologies: Optional[List[Dict]] = None,
        findings: Optional[List[Dict]] = None,
        events: Optional[List[Dict]] = None,
    ):
        super().__init__(
            assets=list(assets or []),
            endpoints=list(endpoints or []),
            parameters=list(parameters or []),
            technologies=list(technologies or []),
            findings=list(findings or []),
            events=list(events or []),
        )

    def to_dict(self) -> Dict[str, List[Dict]]:
        return dict(self)


# --------------------------------------------------------------------------
# Schema-shaped builders (mirror packages/schemas/*.json)
# --------------------------------------------------------------------------


def asset_dict(
    tenant_id: str,
    project_id: str,
    asset_type: str,
    value: str,
    source_tools: Optional[List[str]] = None,
    metadata: Optional[Dict] = None,
    scope_status: str = "unknown",
    confidence: float = 1.0,
    parent_asset_id: Optional[str] = None,
) -> Dict:
    now = utc_now()
    return {
        "id": _stable_id("asset", tenant_id, project_id, asset_type, value),
        "tenant_id": tenant_id,
        "project_id": project_id,
        "asset_type": asset_type,
        "value": value,
        "parent_asset_id": parent_asset_id,
        "source_tools": list(source_tools or []),
        "scope_status": scope_status,
        "confidence": confidence,
        "metadata": dict(metadata or {}),
        "first_seen_at": now,
        "last_seen_at": now,
    }


def endpoint_asset(tenant_id: str, project_id: str, url: str, source_tool: str, **metadata) -> Dict:
    return asset_dict(tenant_id, project_id, "endpoint", url, [source_tool], metadata)


def parameter_asset(tenant_id: str, project_id: str, endpoint: str, name: str, source_tool: str, **metadata) -> Dict:
    value = f"{endpoint}?{name}=FUZZ"
    return asset_dict(tenant_id, project_id, "parameter", value, [source_tool], {"endpoint": endpoint, "name": name, **metadata})


def technology_asset(tenant_id: str, project_id: str, name: str, source_tool: str, **metadata) -> Dict:
    return asset_dict(tenant_id, project_id, "technology", name, [source_tool], metadata)


def finding_dict(
    tenant_id: str,
    project_id: str,
    finding_type: str,
    title: str,
    source_tool: str,
    severity: str = "unknown",
    confidence: float = 0.5,
    status: str = "candidate",
    endpoint: Optional[str] = None,
    http_method: Optional[str] = None,
    parameter: Optional[str] = None,
    asset_id: Optional[str] = None,
    evidence_ids: Optional[List[str]] = None,
    scope_version: int = 1,
) -> Dict:
    # Scanner output is never a confirmed vulnerability.
    if status in ("validated", "confirmed_impact", "report_ready", "accepted", "submitted"):
        status = "candidate"
    return {
        "id": _stable_id("finding", tenant_id, project_id, finding_type, endpoint or "", parameter or ""),
        "tenant_id": tenant_id,
        "project_id": project_id,
        "asset_id": asset_id,
        "endpoint": endpoint,
        "http_method": http_method,
        "parameter": parameter,
        "finding_type": finding_type,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "status": status,
        "source_tools": [source_tool],
        "evidence_ids": list(evidence_ids or []),
        "related_finding_ids": [],
        "scope_version": scope_version,
    }


def emit_event(
    tenant_id: str,
    project_id: str,
    event_type: str,
    payload: Optional[Dict] = None,
    asset_ref: Optional[str] = None,
    source_tool: Optional[str] = None,
    source_execution_id: Optional[str] = None,
    scope_version: int = 1,
) -> Dict:
    """Build a :class:`DomainEvent` with the correct ``event_type``."""
    event = DomainEvent(
        event_id=_stable_id("evt", tenant_id, project_id, event_type, asset_ref or "", source_tool or ""),
        tenant_id=tenant_id,
        project_id=project_id,
        event_type=event_type,
        source_tool=source_tool,
        source_execution_id=source_execution_id,
        asset_ref=asset_ref,
        scope_version=scope_version,
        schema_version=SCHEMA_VERSION,
        payload=payload or {},
    )
    return event.to_dict()


class BaseToolAdapter(ABC):
    tool_id: str = ""
    tool_version: str = "pinned"
    CATEGORY: str = "unknown"
    CAPABILITIES: List[str] = []
    REQUIRED_INPUTS: tuple = ()
    ALLOWED_INPUTS: set = set()
    INPUT_SCHEMA: Dict[str, Any] = {}
    OUTPUT_SCHEMA: Dict[str, Any] = {}
    EXECUTION_PROFILE: str = "low_impact_discovery"

    def __init__(self) -> None:
        self._ctx: Dict[str, Any] = {
            "tenant_id": "tenant-demo",
            "project_id": "project-demo",
            "scope_version": 1,
            "execution_id": None,
        }
        self._last_parsed: Dict[str, Any] = {}

    # ------------------------------------------------------------- context
    def set_context(
        self,
        tenant_id: str = "tenant-demo",
        project_id: str = "project-demo",
        scope_version: int = 1,
        execution_id: Optional[str] = None,
    ) -> None:
        self._ctx = {
            "tenant_id": tenant_id,
            "project_id": project_id,
            "scope_version": scope_version,
            "execution_id": execution_id,
        }

    @property
    def tenant_id(self) -> str:
        return self._ctx["tenant_id"]

    @property
    def project_id(self) -> str:
        return self._ctx["project_id"]

    @property
    def scope_version(self) -> int:
        return self._ctx["scope_version"]

    # ------------------------------------------------------------ contract
    def validate_input(self, task) -> Dict:
        data = self._task_input(task)
        unknown = set(data) - set(self.ALLOWED_INPUTS)
        if unknown:
            raise AdapterInputError(
                f"{self.tool_id}: unknown input keys {sorted(unknown)}"
            )
        missing = [k for k in self.REQUIRED_INPUTS if not data.get(k)]
        if missing:
            raise AdapterInputError(f"{self.tool_id}: missing required inputs {missing}")
        for key, value in data.items():
            if isinstance(value, str):
                self._validate_value(key, value)
        return data

    @abstractmethod
    def build_arguments(self, task) -> List[str]: ...

    @abstractmethod
    def execute(self, task, runner) -> ToolExecutionResult: ...

    @abstractmethod
    def parse_output(self, output: str) -> Dict: ...

    @abstractmethod
    def normalize_results(self, parsed_output: Dict) -> Dict: ...

    def get_capabilities(self) -> List[str]:
        return list(self.CAPABILITIES)

    def get_spec(self) -> Dict:
        return {
            "tool_id": self.tool_id,
            "name": type(self).__name__,
            "category": self.CATEGORY,
            "version": self.tool_version,
            "capabilities": self.get_capabilities(),
            "required_inputs": list(self.REQUIRED_INPUTS),
            "optional_inputs": sorted(set(self.ALLOWED_INPUTS) - set(self.REQUIRED_INPUTS)),
            "input_schema": self.INPUT_SCHEMA,
            "output_schema": self.OUTPUT_SCHEMA,
            "execution_profile": self.EXECUTION_PROFILE,
        }

    # ------------------------------------------------------------- helpers
    @staticmethod
    def _task_input(task) -> Dict:
        if isinstance(task, dict):
            return dict(task.get("input") or {})
        return dict(getattr(task, "input", {}) or {})

    @staticmethod
    def _validate_value(key: str, value: str) -> None:
        if value.strip() == "":
            raise AdapterInputError(f"{key}: whitespace-only value is not allowed")
        bad = SHELL_METACHARS & set(value)
        if bad:
            raise AdapterInputError(
                f"{key}: forbidden shell metacharacter(s) {sorted(bad)}"
            )

    def _arg(self, key: str, value: Any) -> str:
        text = str(value)
        self._validate_value(key, text)
        return text

    def get_default_wordlist(self) -> str:
        return "/wordlists/default.txt"

    def get_default_templates(self) -> str:
        return "/templates/"

    # ---------------------------------------------------------- execution
    def _task_context(self, task) -> None:
        if isinstance(task, dict):
            self.set_context(
                task.get("tenant_id", "tenant-demo"),
                task.get("project_id", "project-demo"),
                task.get("scope_version", 1),
                task.get("id"),
            )
        else:
            self.set_context(
                getattr(task, "tenant_id", "tenant-demo"),
                getattr(task, "project_id", "project-demo"),
                getattr(task, "scope_version", 1),
                getattr(task, "id", None),
            )

    def _execute(self, task, runner) -> ToolExecutionResult:
        """Shared execute: validate -> context -> argv -> run -> parse."""
        self.validate_input(task)
        self._task_context(task)
        argv = self.build_arguments(task)
        result = runner.run(self.tool_id, argv, image=getattr(self, "IMAGE", None))
        self._last_parsed = self.parse_output(result.stdout)
        result.artifacts["parsed"] = self._last_parsed
        return result

"""Arjun adapter — HTTP parameter discovery.

Real argv: ``arjun -u <url> -j``.
Real output (JSON on stdout), e.g.::

    {"https://api.example.com/api/v2/users":
        {"GET": {"params":["user_id","token"], "status":200}}}
"""

from __future__ import annotations

import json
from typing import Dict, List

from .base import (
    BaseToolAdapter,
    NormalizedResult,
    ToolExecutionResult,
    emit_event,
    parameter_asset,
)


class ArjunAdapter(BaseToolAdapter):
    tool_id = "arjun"
    tool_version = "v2.2.1"
    IMAGE = "s0md3v/arjun:2.2.1"
    CATEGORY = "api_discovery"
    CAPABILITIES = ["parameter_discovery"]
    REQUIRED_INPUTS = ("endpoint",)
    ALLOWED_INPUTS = {"endpoint", "url", "target", "wordlist", "methods"}
    EXECUTION_PROFILE = "authorized_vulnerability_testing"
    INPUT_SCHEMA = {"endpoint": {"type": "string"}, "url": {"type": "string"}}
    OUTPUT_SCHEMA = {"endpoints": {"type": "array"}}

    def _target(self, data: Dict) -> str:
        return data.get("url") or data.get("target") or data["endpoint"]

    def build_arguments(self, task) -> List[str]:
        data = self.validate_input(task)
        return ["-u", self._arg("url", self._target(data)), "-j"]

    def execute(self, task, runner) -> ToolExecutionResult:
        return self._execute(task, runner)

    def parse_output(self, output: str) -> Dict:
        text = (output or "").strip()
        if not text:
            return {"endpoints": []}
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return {"endpoints": []}
        endpoints = []
        for url, methods in (data or {}).items():
            if not isinstance(methods, dict):
                continue
            for method, info in methods.items():
                endpoints.append(
                    {
                        "url": url,
                        "method": method,
                        "params": (info or {}).get("params", []),
                        "status": (info or {}).get("status"),
                    }
                )
        return {"endpoints": endpoints}

    def normalize_results(self, parsed_output: Dict) -> Dict:
        parameters, events = [], []
        for item in parsed_output.get("endpoints", []):
            for name in item.get("params", []):
                parameters.append(
                    parameter_asset(self.tenant_id, self.project_id, item["url"], name, self.tool_id)
                )
                events.append(
                    emit_event(
                        self.tenant_id,
                        self.project_id,
                        "parameter.discovered",
                        payload={"parameter": name, "endpoint": item["url"], "url": item["url"], "method": item.get("method", "GET")},
                        asset_ref=item["url"],
                        source_tool=self.tool_id,
                        scope_version=self.scope_version,
                    )
                )
        return NormalizedResult(parameters=parameters, events=events)

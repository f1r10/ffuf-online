"""Kiterunner adapter — API route discovery.

Real argv: ``kr scan <url> -w <wordlist> -o json``.
Real output: JSON objects (one per line, or a JSON array), e.g.
``{"method":"GET","url":"https://api.example.com/api/v2/users","status":200,
"length":123,"words":5,"attrs":[]}``.
"""

from __future__ import annotations

import json
from typing import Dict, List
from urllib.parse import urlsplit

from .base import (
    BaseToolAdapter,
    NormalizedResult,
    ToolExecutionResult,
    emit_event,
    endpoint_asset,
)


class KiterunnerAdapter(BaseToolAdapter):
    tool_id = "kiterunner"
    tool_version = "v1.0.2"
    IMAGE = "assetnote/kiterunner:1.0.2"
    CATEGORY = "api_discovery"
    CAPABILITIES = ["api_route_discovery", "api_schema_analysis"]
    REQUIRED_INPUTS = ("api_host",)
    ALLOWED_INPUTS = {"api_host", "url", "target", "wordlist", "methods"}
    EXECUTION_PROFILE = "authorized_vulnerability_testing"
    INPUT_SCHEMA = {"api_host": {"type": "string"}, "url": {"type": "string"}}
    OUTPUT_SCHEMA = {"routes": {"type": "array"}}

    def _target(self, data: Dict) -> str:
        return data.get("url") or data.get("target") or data["api_host"]

    def build_arguments(self, task) -> List[str]:
        data = self.validate_input(task)
        return [
            "scan",
            self._arg("url", self._target(data)),
            "-w",
            self._arg("wordlist", data.get("wordlist") or self.get_default_wordlist()),
            "-o",
            "json",
        ]

    def execute(self, task, runner) -> ToolExecutionResult:
        return self._execute(task, runner)

    def parse_output(self, output: str) -> Dict:
        text = (output or "").strip()
        if not text:
            return {"routes": []}
        items: List[Dict] = []
        try:
            parsed = json.loads(text)
            if isinstance(parsed, list):
                items = parsed
            elif isinstance(parsed, dict):
                items = [parsed]
        except json.JSONDecodeError:
            for line in text.splitlines():
                line = line.strip()
                if line.startswith("{"):
                    try:
                        items.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        routes = []
        for obj in items:
            if obj.get("url"):
                routes.append(
                    {
                        "url": obj["url"],
                        "method": obj.get("method", "GET"),
                        "status": obj.get("status"),
                        "length": obj.get("length"),
                        "words": obj.get("words"),
                    }
                )
        return {"routes": routes}

    def normalize_results(self, parsed_output: Dict) -> Dict:
        endpoints, events = [], []
        for r in parsed_output.get("routes", []):
            endpoints.append(endpoint_asset(self.tenant_id, self.project_id, r["url"], self.tool_id, method=r.get("method")))
            events.append(
                emit_event(
                    self.tenant_id,
                    self.project_id,
                    "api.endpoint.discovered",
                    payload={
                        "url": r["url"],
                        "endpoint": urlsplit(r["url"]).path or "/",
                        "host": urlsplit(r["url"]).hostname,
                        "method": r.get("method", "GET"),
                    },
                    asset_ref=r["url"],
                    source_tool=self.tool_id,
                    scope_version=self.scope_version,
                )
            )
        return NormalizedResult(endpoints=endpoints, events=events)

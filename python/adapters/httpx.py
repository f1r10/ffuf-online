"""HTTPx adapter — HTTP probing and technology detection.

Real argv: ``httpx -json -silent -u <target>``.
Real output: one JSON object per line, e.g.
``{"url":"https://api.example.com","input":"api.example.com","status_code":200,
"title":"...","tech":["nginx"],"webserver":"nginx","content_length":1234,"failed":false}``.
"""

from __future__ import annotations

import json
from typing import Dict, List

from .base import (
    BaseToolAdapter,
    NormalizedResult,
    ToolExecutionResult,
    emit_event,
    endpoint_asset,
    technology_asset,
)


class HttpxAdapter(BaseToolAdapter):
    tool_id = "httpx"
    tool_version = "v1.6.9"
    IMAGE = "projectdiscovery/httpx:1.6.9"
    CATEGORY = "reconnaissance"
    CAPABILITIES = ["http_probe", "technology_detection", "title_extraction"]
    REQUIRED_INPUTS = ("hostname",)
    ALLOWED_INPUTS = {"hostname", "url", "target", "ports", "status_codes"}
    EXECUTION_PROFILE = "low_impact_discovery"
    INPUT_SCHEMA = {"hostname": {"type": "string"}, "url": {"type": "string"}}
    OUTPUT_SCHEMA = {"services": {"type": "array"}}

    def _target(self, data: Dict) -> str:
        return data.get("url") or data.get("target") or data["hostname"]

    def build_arguments(self, task) -> List[str]:
        data = self.validate_input(task)
        return ["-json", "-silent", "-u", self._arg("target", self._target(data))]

    def execute(self, task, runner) -> ToolExecutionResult:
        return self._execute(task, runner)

    def parse_output(self, output: str) -> Dict:
        services = []
        for line in (output or "").splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("url"):
                services.append(
                    {
                        "url": obj["url"],
                        "input": obj.get("input"),
                        "host": obj.get("host"),
                        "port": obj.get("port"),
                        "status_code": obj.get("status_code"),
                        "title": obj.get("title"),
                        "tech": obj.get("tech", []) or [],
                        "webserver": obj.get("webserver"),
                        "content_length": obj.get("content_length"),
                    }
                )
        return {"services": services}

    def normalize_results(self, parsed_output: Dict) -> Dict:
        assets, technologies, events = [], [], []
        for svc in parsed_output.get("services", []):
            assets.append(
                endpoint_asset(
                    self.tenant_id,
                    self.project_id,
                    svc["url"],
                    self.tool_id,
                    status_code=svc.get("status_code"),
                    title=svc.get("title"),
                    webserver=svc.get("webserver"),
                    content_length=svc.get("content_length"),
                )
            )
            for tech in svc.get("tech", []):
                technologies.append(technology_asset(self.tenant_id, self.project_id, tech, self.tool_id))
                events.append(
                    emit_event(
                        self.tenant_id,
                        self.project_id,
                        "technology.detected",
                        payload={"technology": tech, "url": svc["url"], "host": svc.get("host")},
                        asset_ref=svc["url"],
                        source_tool=self.tool_id,
                        scope_version=self.scope_version,
                    )
                )
            if svc.get("webserver"):
                technologies.append(
                    technology_asset(self.tenant_id, self.project_id, svc["webserver"], self.tool_id)
                )
            events.append(
                emit_event(
                    self.tenant_id,
                    self.project_id,
                    "http.service.discovered",
                    payload={
                        "url": svc["url"],
                        "host": svc.get("host"),
                        "status_code": svc.get("status_code"),
                        "title": svc.get("title"),
                    },
                    asset_ref=svc["url"],
                    source_tool=self.tool_id,
                    scope_version=self.scope_version,
                )
            )
        return NormalizedResult(assets=assets, technologies=technologies, events=events)

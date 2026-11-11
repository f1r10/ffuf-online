"""Katana adapter — web crawling and endpoint/JS discovery.

Real argv: ``katana -json -silent -u <target> -jc``.
Real output: one JSON object per line, e.g.
``{"timestamp":"...","url":"https://api.example.com/api/v2/users","method":"GET",
"tag":"a","source":"https://api.example.com/","attribute":"href","status_code":200}``.
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


class KatanaAdapter(BaseToolAdapter):
    tool_id = "katana"
    tool_version = "v1.1.0"
    IMAGE = "projectdiscovery/katana:1.1.0"
    CATEGORY = "reconnaissance"
    CAPABILITIES = ["crawling", "endpoint_discovery", "js_endpoint_extraction"]
    REQUIRED_INPUTS = ("http_service",)
    ALLOWED_INPUTS = {"http_service", "url", "target", "js_crawl", "depth"}
    EXECUTION_PROFILE = "low_impact_discovery"
    INPUT_SCHEMA = {"http_service": {"type": "string"}, "url": {"type": "string"}}
    OUTPUT_SCHEMA = {"endpoints": {"type": "array"}, "javascript": {"type": "array"}}

    def _target(self, data: Dict) -> str:
        return data.get("url") or data.get("target") or data["http_service"]

    def build_arguments(self, task) -> List[str]:
        data = self.validate_input(task)
        return ["-json", "-silent", "-u", self._arg("target", self._target(data)), "-jc"]

    def execute(self, task, runner) -> ToolExecutionResult:
        return self._execute(task, runner)

    def parse_output(self, output: str) -> Dict:
        endpoints, javascript = [], []
        for line in (output or "").splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = obj.get("url")
            if not url:
                continue
            item = {
                "url": url,
                "method": obj.get("method", "GET"),
                "source": obj.get("source"),
                "attribute": obj.get("attribute"),
                "status_code": obj.get("status_code"),
            }
            path = urlsplit(url).path.lower()
            if path.endswith(".js") or obj.get("tag") == "script":
                javascript.append(url)
            else:
                endpoints.append(item)
        return {"endpoints": endpoints, "javascript": javascript}

    def normalize_results(self, parsed_output: Dict) -> Dict:
        assets, events = [], []
        for item in parsed_output.get("endpoints", []):
            host = urlsplit(item["url"]).hostname
            assets.append(endpoint_asset(self.tenant_id, self.project_id, item["url"], self.tool_id, method=item.get("method")))
            events.append(
                emit_event(
                    self.tenant_id,
                    self.project_id,
                    "http.endpoint.discovered",
                    payload={
                        "url": item["url"],
                        "endpoint": urlsplit(item["url"]).path or "/",
                        "host": host,
                        "method": item.get("method", "GET"),
                    },
                    asset_ref=item["url"],
                    source_tool=self.tool_id,
                    scope_version=self.scope_version,
                )
            )
        for js_url in parsed_output.get("javascript", []):
            assets.append(endpoint_asset(self.tenant_id, self.project_id, js_url, self.tool_id, kind="javascript"))
            events.append(
                emit_event(
                    self.tenant_id,
                    self.project_id,
                    "javascript.discovered",
                    payload={"url": js_url, "host": urlsplit(js_url).hostname},
                    asset_ref=js_url,
                    source_tool=self.tool_id,
                    scope_version=self.scope_version,
                )
            )
        return NormalizedResult(assets=assets, events=events)

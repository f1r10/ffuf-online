"""GAU adapter — historical URL collection (passive).

Real argv: ``gau --threads 2 <domain>``.
Real output: one URL per plain-text line.
"""

from __future__ import annotations

from typing import Dict, List
from urllib.parse import urlsplit

from .base import (
    BaseToolAdapter,
    NormalizedResult,
    ToolExecutionResult,
    asset_dict,
    emit_event,
)


class GauAdapter(BaseToolAdapter):
    tool_id = "gau"
    tool_version = "v2.2.3"
    IMAGE = "lc/gau:2.2.3"
    CATEGORY = "reconnaissance"
    CAPABILITIES = ["historical_urls", "passive_asset_intelligence"]
    REQUIRED_INPUTS = ("domain",)
    ALLOWED_INPUTS = {"domain", "providers"}
    EXECUTION_PROFILE = "passive"
    INPUT_SCHEMA = {"domain": {"type": "string"}}
    OUTPUT_SCHEMA = {"urls": {"type": "array"}}

    def build_arguments(self, task) -> List[str]:
        data = self.validate_input(task)
        return ["--threads", "2", self._arg("domain", data["domain"])]

    def execute(self, task, runner) -> ToolExecutionResult:
        return self._execute(task, runner)

    def parse_output(self, output: str) -> Dict:
        urls = []
        for line in (output or "").splitlines():
            line = line.strip()
            if line.startswith("http://") or line.startswith("https://"):
                urls.append(line)
        return {"urls": urls}

    def normalize_results(self, parsed_output: Dict) -> Dict:
        assets, endpoints, events = [], [], []
        for url in parsed_output.get("urls", []):
            assets.append(asset_dict(self.tenant_id, self.project_id, "url", url, [self.tool_id]))
            endpoints.append(asset_dict(self.tenant_id, self.project_id, "endpoint", url, [self.tool_id]))
            events.append(
                emit_event(
                    self.tenant_id,
                    self.project_id,
                    "http.endpoint.discovered",
                    payload={"url": url, "endpoint": urlsplit(url).path or "/", "host": urlsplit(url).hostname},
                    asset_ref=url,
                    source_tool=self.tool_id,
                    scope_version=self.scope_version,
                )
            )
        return NormalizedResult(assets=assets, endpoints=endpoints, events=events)

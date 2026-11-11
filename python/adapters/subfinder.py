"""Subfinder adapter — passive subdomain enumeration.

Real argv: ``subfinder -d <domain> -silent -json -oJ``.
Real output: one JSON object per line, e.g.
``{"host":"api.example.com","input":"example.com","source":"crtsh"}``.
"""

from __future__ import annotations

import json
from typing import Dict, List

from .base import (
    BaseToolAdapter,
    NormalizedResult,
    ToolExecutionResult,
    asset_dict,
    emit_event,
)


class SubfinderAdapter(BaseToolAdapter):
    tool_id = "subfinder"
    tool_version = "v2.6.6"
    IMAGE = "projectdiscovery/subfinder:2.6.6"
    CATEGORY = "reconnaissance"
    CAPABILITIES = ["subdomain_enumeration", "passive_recon"]
    REQUIRED_INPUTS = ("domain",)
    ALLOWED_INPUTS = {"domain"}
    EXECUTION_PROFILE = "passive"
    INPUT_SCHEMA = {"domain": {"type": "string"}}
    OUTPUT_SCHEMA = {"subdomains": {"type": "array"}}

    def build_arguments(self, task) -> List[str]:
        data = self.validate_input(task)
        return ["-d", self._arg("domain", data["domain"]), "-silent", "-json", "-oJ"]

    def execute(self, task, runner) -> ToolExecutionResult:
        return self._execute(task, runner)

    def parse_output(self, output: str) -> Dict:
        subdomains = []
        for line in (output or "").splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("host"):
                subdomains.append(
                    {"host": obj["host"], "input": obj.get("input"), "source": obj.get("source", "subfinder")}
                )
        return {"subdomains": subdomains}

    def normalize_results(self, parsed_output: Dict) -> Dict:
        assets, events = [], []
        for item in parsed_output.get("subdomains", []):
            asset = asset_dict(self.tenant_id, self.project_id, "subdomain", item["host"], [self.tool_id])
            assets.append(asset)
            events.append(
                emit_event(
                    self.tenant_id,
                    self.project_id,
                    "asset.discovered",
                    payload={"asset_type": "subdomain", "value": item["host"], "source": item.get("source")},
                    asset_ref=item["host"],
                    source_tool=self.tool_id,
                    scope_version=self.scope_version,
                )
            )
        return NormalizedResult(assets=assets, events=events)

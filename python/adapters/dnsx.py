"""DNSx adapter — DNS resolution.

Real argv: ``dnsx -silent -json -a -aaaa -cname -d <host>``.
Real output: one JSON object per line, e.g.
``{"host":"api.example.com","a":["93.184.216.34"],"aaaa":[],"cname":[],"status_code":"NOERROR"}``.
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


class DnsxAdapter(BaseToolAdapter):
    tool_id = "dnsx"
    tool_version = "v1.2.1"
    IMAGE = "projectdiscovery/dnsx:1.2.1"
    CATEGORY = "reconnaissance"
    CAPABILITIES = ["dns_resolution", "dns_records"]
    REQUIRED_INPUTS = ("hostname",)
    ALLOWED_INPUTS = {"hostname", "record_types"}
    EXECUTION_PROFILE = "passive"
    INPUT_SCHEMA = {"hostname": {"type": "string"}}
    OUTPUT_SCHEMA = {"records": {"type": "array"}}

    def build_arguments(self, task) -> List[str]:
        data = self.validate_input(task)
        return ["-silent", "-json", "-a", "-aaaa", "-cname", "-d", self._arg("hostname", data["hostname"])]

    def execute(self, task, runner) -> ToolExecutionResult:
        return self._execute(task, runner)

    def parse_output(self, output: str) -> Dict:
        records = []
        for line in (output or "").splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("host"):
                records.append(
                    {
                        "host": obj["host"],
                        "a": obj.get("a", []),
                        "aaaa": obj.get("aaaa", []),
                        "cname": obj.get("cname", []),
                        "status_code": obj.get("status_code"),
                    }
                )
        return {"records": records}

    def normalize_results(self, parsed_output: Dict) -> Dict:
        assets, events = [], []
        for rec in parsed_output.get("records", []):
            host_asset = asset_dict(
                self.tenant_id, self.project_id, "hostname", rec["host"], [self.tool_id],
                metadata={"status_code": rec.get("status_code")},
            )
            assets.append(host_asset)
            for ip in list(rec.get("a", [])) + list(rec.get("aaaa", [])):
                assets.append(asset_dict(self.tenant_id, self.project_id, "ip", ip, [self.tool_id]))
            events.append(
                emit_event(
                    self.tenant_id,
                    self.project_id,
                    "dns.record.discovered",
                    payload={
                        "host": rec["host"],
                        "a": rec.get("a", []),
                        "aaaa": rec.get("aaaa", []),
                        "cname": rec.get("cname", []),
                    },
                    asset_ref=rec["host"],
                    source_tool=self.tool_id,
                    scope_version=self.scope_version,
                )
            )
        return NormalizedResult(assets=assets, events=events)

"""Nuclei adapter — safe, template-driven vulnerability checks.

Real argv: ``nuclei -jsonl -silent -t <templates> -u <target>``.
Real output: one JSON object per line, e.g.
``{"template-id":"...","info":{"name":"...","severity":"low"},"type":"http",
"host":"api.example.com","matched-at":"https://api.example.com/api/v2/users?id=1",
"ip":"1.2.3.4","timestamp":"..."}``.

A positive template match is a **candidate** finding — never a confirmed
vulnerability.
"""

from __future__ import annotations

import json
from typing import Dict, List

from .base import (
    BaseToolAdapter,
    NormalizedResult,
    ToolExecutionResult,
    emit_event,
    finding_dict,
)


class NucleiAdapter(BaseToolAdapter):
    tool_id = "nuclei"
    tool_version = "v3.3.5"
    IMAGE = "projectdiscovery/nuclei:3.3.5"
    CATEGORY = "web_vulnerability_testing"
    CAPABILITIES = ["safe_vulnerability_templates", "technology_templates", "parameter_checks"]
    REQUIRED_INPUTS = ("url",)
    ALLOWED_INPUTS = {"url", "target", "templates", "severity"}
    EXECUTION_PROFILE = "low_impact_discovery"
    INPUT_SCHEMA = {"url": {"type": "string"}, "templates": {"type": "string"}}
    OUTPUT_SCHEMA = {"findings": {"type": "array"}}

    def _target(self, data: Dict) -> str:
        return data.get("url") or data.get("target")

    def build_arguments(self, task) -> List[str]:
        data = self.validate_input(task)
        args = [
            "-jsonl",
            "-silent",
            "-t",
            self._arg("templates", data.get("templates") or self.get_default_templates()),
            "-u",
            self._arg("url", self._target(data)),
        ]
        if data.get("severity"):
            args += ["-severity", self._arg("severity", data["severity"])]
        return args

    def execute(self, task, runner) -> ToolExecutionResult:
        return self._execute(task, runner)

    def parse_output(self, output: str) -> Dict:
        findings = []
        for line in (output or "").splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = obj.get("info", {}) or {}
            findings.append(
                {
                    "template_id": obj.get("template-id") or obj.get("templateID"),
                    "name": info.get("name"),
                    "severity": (info.get("severity") or "unknown").lower(),
                    "type": obj.get("type", "http"),
                    "host": obj.get("host"),
                    "matched_at": obj.get("matched-at"),
                    "ip": obj.get("ip"),
                    "tags": info.get("tags", []),
                }
            )
        return {"findings": findings}

    def normalize_results(self, parsed_output: Dict) -> Dict:
        findings, events = [], []
        for item in parsed_output.get("findings", []):
            endpoint = item.get("matched_at") or item.get("host")
            finding = finding_dict(
                self.tenant_id,
                self.project_id,
                finding_type=item.get("template_id") or "nuclei_template_match",
                title=item.get("name") or "Nuclei template match",
                source_tool=self.tool_id,
                severity=item.get("severity", "unknown"),
                confidence=0.5,
                status="needs_validation",
                endpoint=endpoint,
                scope_version=self.scope_version,
            )
            findings.append(finding)
            events.append(
                emit_event(
                    self.tenant_id,
                    self.project_id,
                    "finding.candidate.created",
                    payload={"finding": finding, "template_id": item.get("template_id"), "endpoint": endpoint},
                    asset_ref=endpoint,
                    source_tool=self.tool_id,
                    scope_version=self.scope_version,
                )
            )
        return NormalizedResult(findings=findings, events=events)

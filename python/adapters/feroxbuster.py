"""Feroxbuster adapter — recursive content discovery.

Real argv: ``feroxbuster --json --url <url> --wordlist <wordlist> --silent``.
Real output: one JSON object per line, e.g.
``{"type":"response","url":"https://example.com/admin/","status":200,
"content_length":1234,"line_count":5,"word_count":10,"method":"GET"}``.
"""

from __future__ import annotations

import json
from typing import Dict, List

from .base import (
    BaseToolAdapter,
    NormalizedResult,
    ToolExecutionResult,
    endpoint_asset,
)


class FeroxbusterAdapter(BaseToolAdapter):
    tool_id = "feroxbuster"
    tool_version = "v2.10.4"
    IMAGE = "epi052/feroxbuster:2.10.4"
    CATEGORY = "content_discovery"
    CAPABILITIES = ["directory_discovery", "recursive_discovery"]
    REQUIRED_INPUTS = ("url",)
    ALLOWED_INPUTS = {"url", "target", "wordlist", "status_codes"}
    EXECUTION_PROFILE = "low_impact_discovery"
    INPUT_SCHEMA = {"url": {"type": "string"}, "wordlist": {"type": "string"}}
    OUTPUT_SCHEMA = {"responses": {"type": "array"}}

    def _target(self, data: Dict) -> str:
        return data.get("url") or data.get("target")

    def build_arguments(self, task) -> List[str]:
        data = self.validate_input(task)
        args = [
            "--json",
            "--silent",
            "--url",
            self._arg("url", self._target(data)),
            "--wordlist",
            self._arg("wordlist", data.get("wordlist") or self.get_default_wordlist()),
        ]
        if data.get("status_codes"):
            args += ["--status-codes", self._arg("status_codes", data["status_codes"])]
        return args

    def execute(self, task, runner) -> ToolExecutionResult:
        return self._execute(task, runner)

    def parse_output(self, output: str) -> Dict:
        responses, statistics = [], None
        for line in (output or "").splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("type") == "response":
                responses.append(
                    {
                        "url": obj.get("url"),
                        "status": obj.get("status"),
                        "content_length": obj.get("content_length"),
                        "line_count": obj.get("line_count"),
                        "word_count": obj.get("word_count"),
                        "method": obj.get("method", "GET"),
                    }
                )
            elif obj.get("type") == "statistics":
                statistics = obj
        return {"responses": responses, "statistics": statistics}

    def normalize_results(self, parsed_output: Dict) -> Dict:
        endpoints = []
        for r in parsed_output.get("responses", []):
            if not r.get("url"):
                continue
            endpoints.append(
                endpoint_asset(
                    self.tenant_id,
                    self.project_id,
                    r["url"],
                    self.tool_id,
                    status_code=r.get("status"),
                    length=r.get("content_length"),
                    method=r.get("method", "GET"),
                )
            )
        return NormalizedResult(endpoints=endpoints)

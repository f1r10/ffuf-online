"""FFUF adapter — content discovery.

Real argv: ``ffuf -u <url> -w <wordlist> -mc <codes> -o <file> -of json``.
The ``-o``/``-of json`` report has this shape::

    {"commandline":"...","results":[{"input":{"FUZZ":"admin"},"position":1,
     "status":200,"length":1234,"words":10,"lines":5,"content-type":"text/html",
     "url":"https://example.com/admin"}]}
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


class FfufAdapter(BaseToolAdapter):
    tool_id = "ffuf"
    tool_version = "v2.1.0"
    IMAGE = "ffuf/ffuf:2.1.0"
    CATEGORY = "content_discovery"
    CAPABILITIES = ["directory_discovery", "file_discovery", "parameter_fuzzing"]
    REQUIRED_INPUTS = ("url",)
    ALLOWED_INPUTS = {"url", "target", "wordlist", "status_codes", "extensions"}
    EXECUTION_PROFILE = "low_impact_discovery"
    INPUT_SCHEMA = {"url": {"type": "string"}, "wordlist": {"type": "string"}}
    OUTPUT_SCHEMA = {"results": {"type": "array"}}

    def _target(self, data: Dict) -> str:
        return data.get("url") or data.get("target")

    def build_arguments(self, task) -> List[str]:
        data = self.validate_input(task)
        codes = data.get("status_codes") or "200,204,301,302,307,401,403,405"
        return [
            "-u",
            self._arg("url", self._target(data)),
            "-w",
            self._arg("wordlist", data.get("wordlist") or self.get_default_wordlist()),
            "-mc",
            self._arg("status_codes", codes),
            "-o",
            "/tmp/ffuf-report.json",
            "-of",
            "json",
        ]

    def execute(self, task, runner) -> ToolExecutionResult:
        return self._execute(task, runner)

    def parse_output(self, output: str) -> Dict:
        text = (output or "").strip()
        if not text:
            return {"results": []}
        try:
            report = json.loads(text)
        except json.JSONDecodeError:
            return {"results": []}
        results = []
        for r in report.get("results", []):
            results.append(
                {
                    "input": r.get("input", {}),
                    "status": r.get("status"),
                    "length": r.get("length"),
                    "words": r.get("words"),
                    "lines": r.get("lines"),
                    "content_type": r.get("content-type"),
                    "url": r.get("url"),
                }
            )
        return {"results": results, "commandline": report.get("commandline")}

    def normalize_results(self, parsed_output: Dict) -> Dict:
        endpoints = []
        for r in parsed_output.get("results", []):
            if not r.get("url"):
                continue
            endpoints.append(
                endpoint_asset(
                    self.tenant_id,
                    self.project_id,
                    r["url"],
                    self.tool_id,
                    status_code=r.get("status"),
                    length=r.get("length"),
                    content_type=r.get("content_type"),
                )
            )
        return NormalizedResult(endpoints=endpoints)

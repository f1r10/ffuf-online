"""Nmap adapter — authorized service discovery.

Real argv: ``nmap -oX - -Pn -sV -p <ports> <host>`` (XML to stdout).
Real output: Nmap XML (``<nmaprun>...<host>...<ports><port>...``).
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Dict, List

from .base import (
    BaseToolAdapter,
    NormalizedResult,
    ToolExecutionResult,
    asset_dict,
    emit_event,
)


class NmapAdapter(BaseToolAdapter):
    tool_id = "nmap"
    tool_version = "v7.95"
    IMAGE = "instrumentisto/nmap:7.95"
    CATEGORY = "network"
    CAPABILITIES = ["port_scan", "service_discovery"]
    REQUIRED_INPUTS = ("hostname",)
    ALLOWED_INPUTS = {"hostname", "target", "ports", "scan_type"}
    EXECUTION_PROFILE = "low_impact_discovery"
    INPUT_SCHEMA = {"hostname": {"type": "string"}, "ports": {"type": "string"}}
    OUTPUT_SCHEMA = {"hosts": {"type": "array"}}

    def _target(self, data: Dict) -> str:
        return data.get("target") or data["hostname"]

    def build_arguments(self, task) -> List[str]:
        data = self.validate_input(task)
        ports = data.get("ports") or "80,443"
        args = ["-oX", "-", "-Pn"]
        if data.get("scan_type") == "service":
            args.append("-sV")
        else:
            args.append("-sV")
        args += ["-p", self._arg("ports", ports), self._arg("hostname", self._target(data))]
        return args

    def execute(self, task, runner) -> ToolExecutionResult:
        return self._execute(task, runner)

    def parse_output(self, output: str) -> Dict:
        text = (output or "").strip()
        if not text:
            return {"hosts": []}
        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            return {"hosts": []}
        hosts = []
        for host in root.findall("host"):
            addr_el = host.find("address")
            address = addr_el.get("addr") if addr_el is not None else None
            ports = []
            for port in host.findall("./ports/port"):
                state_el = port.find("state")
                service_el = port.find("service")
                ports.append(
                    {
                        "port": int(port.get("portid")),
                        "protocol": port.get("protocol"),
                        "state": state_el.get("state") if state_el is not None else None,
                        "service": service_el.get("name") if service_el is not None else None,
                        "product": service_el.get("product") if service_el is not None else None,
                        "version": service_el.get("version") if service_el is not None else None,
                    }
                )
            hosts.append({"address": address, "ports": ports})
        return {"hosts": hosts}

    def normalize_results(self, parsed_output: Dict) -> Dict:
        assets, events = [], []
        for host in parsed_output.get("hosts", []):
            address = host.get("address")
            if address:
                assets.append(asset_dict(self.tenant_id, self.project_id, "ip", address, [self.tool_id]))
            for port in host.get("ports", []):
                if port.get("state") != "open":
                    continue
                value = f"{address}:{port['port']}"
                assets.append(
                    asset_dict(
                        self.tenant_id,
                        self.project_id,
                        "port",
                        value,
                        [self.tool_id],
                        metadata={"service": port.get("service"), "product": port.get("product")},
                    )
                )
                events.append(
                    emit_event(
                        self.tenant_id,
                        self.project_id,
                        "http.service.discovered" if port["port"] in (80, 443, 8080, 8443) else "asset.discovered",
                        payload={
                            "value": value,
                            "host": address,
                            "port": port["port"],
                            "service": port.get("service"),
                        },
                        asset_ref=value,
                        source_tool=self.tool_id,
                        scope_version=self.scope_version,
                    )
                )
        return NormalizedResult(assets=assets, events=events)

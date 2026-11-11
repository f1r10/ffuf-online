"""Tool dependency table and resolver.

This module is **data**: it is the single source of truth for the tool
inventory, their triggers, inputs and dependency edges. The core engine never
names a tool directly — it only consults :data:`TOOL_DEPENDENCIES`.

The registry JSON at ``adapters/tool-registry.json`` is generated from this
table (see :func:`adapters.registry.export_tool_registry`) and the loader
asserts the two agree.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set

from .models import Asset, DomainEvent

# ---------------------------------------------------------------------------
# Input tokens understood by the dependency engine
# ---------------------------------------------------------------------------

KNOWN_INPUT_TOKENS: Set[str] = {
    "domain",
    "subdomain",
    "hostname",
    "ip",
    "cidr",
    "http_service",
    "url",
    "endpoint",
    "api_host",
    "api_endpoint",
    "openapi_schema",
    "javascript",
    "parameter",
    "technology",
    "finding",
    "candidate_finding",
    "dns_record",
    "wordlist",
}

#: What each event type *provides* to downstream tools.
EVENT_INPUTS: Dict[str, Set[str]] = {
    "asset.discovered": set(),
    "asset.updated": set(),
    "dns.record.discovered": {"hostname", "ip", "dns_record", "domain"},
    "http.service.discovered": {"http_service", "url", "hostname", "endpoint"},
    "http.endpoint.discovered": {"endpoint", "url", "http_service", "api_host", "api_endpoint"},
    "http.redirect.discovered": {"url", "endpoint", "http_service"},
    "api.endpoint.discovered": {"api_endpoint", "endpoint", "url", "api_host"},
    "api.schema.discovered": {"openapi_schema", "api_host", "url", "endpoint"},
    "parameter.discovered": {"parameter", "endpoint", "url"},
    "technology.detected": {"technology", "http_service", "hostname", "url"},
    "javascript.discovered": {"javascript", "url", "http_service"},
    "finding.candidate.created": {"finding", "candidate_finding", "endpoint", "url"},
    "finding.evidence.added": {"finding", "endpoint", "url"},
    "finding.validated": {"finding"},
    "finding.rejected": {"finding"},
    "tool.execution.started": set(),
    "tool.execution.completed": set(),
    "tool.execution.failed": set(),
    "scope.changed": set(),
    "scope.expired": set(),
    "task.created": set(),
    "task.cancelled": set(),
}

#: What each asset type *provides*.
ASSET_TYPE_INPUTS: Dict[str, Set[str]] = {
    "root_domain": {"domain", "hostname"},
    "subdomain": {"subdomain", "hostname", "domain"},
    "hostname": {"hostname", "domain"},
    "ip": {"ip", "hostname"},
    "cidr": {"cidr"},
    "service": {"http_service", "hostname"},
    "port": {"ip", "hostname"},
    "http_service": {"http_service", "url", "hostname"},
    "endpoint": {"endpoint", "url", "http_service"},
    "url": {"url", "endpoint", "http_service"},
    "parameter": {"parameter", "endpoint", "url"},
    "technology": {"technology", "http_service", "hostname", "url"},
    "javascript": {"javascript", "url", "http_service"},
    "api_spec": {"openapi_schema", "api_host", "url"},
    "finding": {"finding", "candidate_finding", "endpoint", "url"},
}

#: Per-(event, tool) execution-profile override. Everything else uses the
#: tool's first (least invasive) applicable profile.
PROFILE_OVERRIDES: Dict[tuple, str] = {
    ("parameter.discovered", "nuclei"): "authorized_vulnerability_testing",
    ("parameter.discovered", "arjun"): "authorized_vulnerability_testing",
    ("finding.candidate.created", "nuclei"): "authorized_vulnerability_testing",
}

_DEFAULT_RESOURCE = {"cpu": "low", "memory": "low"}


def _tool(**kw) -> Dict:
    base = {
        "version": "pinned",
        "image": "",
        "capabilities": [],
        "required_inputs": [],
        "optional_inputs": [],
        "output_types": [],
        "supported_asset_types": [],
        "applicable_execution_profiles": ["low_impact_discovery"],
        "resource_profile": dict(_DEFAULT_RESOURCE),
        "network_profile": "controlled_http",
        "enabled": True,
        "priority": 5,
        "trigger": [],
        "input_schema": {},
        "output_schema": {},
    }
    base.update(kw)
    return base


# ---------------------------------------------------------------------------
# The tool inventory (11 enabled MVP tools + documented-but-disabled ones)
# ---------------------------------------------------------------------------

TOOL_DEPENDENCIES: List[Dict] = [
    # ---- Enabled MVP tools (Milestone 5 order) --------------------------
    _tool(
        tool_id="subfinder",
        name="Subfinder",
        category="reconnaissance",
        version="v2.6.6",
        image="projectdiscovery/subfinder:2.6.6",
        capabilities=["subdomain_enumeration", "passive_recon"],
        required_inputs=["domain"],
        optional_inputs=["resolvers", "sources"],
        output_types=["subdomain"],
        supported_asset_types=["root_domain", "subdomain"],
        applicable_execution_profiles=["passive"],
        resource_profile={"cpu": "low", "memory": "low"},
        network_profile="passive_dns",
        priority=9,
        trigger=["asset.discovered", "asset.updated"],
    ),
    _tool(
        tool_id="dnsx",
        name="DNSx",
        category="reconnaissance",
        version="v1.2.1",
        image="projectdiscovery/dnsx:1.2.1",
        capabilities=["dns_resolution", "dns_records"],
        required_inputs=["hostname"],
        optional_inputs=["resolvers", "record_types"],
        output_types=["dns_record", "ip"],
        supported_asset_types=["hostname", "subdomain", "ip"],
        applicable_execution_profiles=["passive", "low_impact_discovery"],
        network_profile="dns",
        priority=7,
        trigger=["asset.discovered", "asset.updated", "dns.record.discovered"],
    ),
    _tool(
        tool_id="httpx",
        name="HTTPx",
        category="reconnaissance",
        version="v1.6.9",
        image="projectdiscovery/httpx:1.6.9",
        capabilities=["http_probe", "technology_detection", "title_extraction"],
        required_inputs=["hostname"],
        optional_inputs=["ports", "status_codes"],
        output_types=["http_service", "technology"],
        supported_asset_types=["hostname", "subdomain", "http_service"],
        applicable_execution_profiles=["low_impact_discovery"],
        network_profile="controlled_http",
        priority=9,
        trigger=["asset.discovered", "asset.updated", "dns.record.discovered"],
    ),
    _tool(
        tool_id="katana",
        name="Katana",
        category="reconnaissance",
        version="v1.1.0",
        image="projectdiscovery/katana:1.1.0",
        capabilities=["crawling", "endpoint_discovery", "js_endpoint_extraction"],
        required_inputs=["http_service"],
        optional_inputs=["depth", "js_crawl", "headless"],
        output_types=["endpoint", "javascript", "parameter"],
        supported_asset_types=["http_service", "endpoint", "javascript"],
        applicable_execution_profiles=["low_impact_discovery"],
        network_profile="controlled_http",
        priority=8,
        trigger=["http.service.discovered", "javascript.discovered"],
    ),
    _tool(
        tool_id="gau",
        name="GetAllUrls",
        category="reconnaissance",
        version="v2.2.3",
        image="lc/gau:2.2.3",
        capabilities=["historical_urls", "passive_asset_intelligence"],
        required_inputs=["domain"],
        optional_inputs=["providers", "filters"],
        output_types=["url"],
        supported_asset_types=["root_domain", "url"],
        applicable_execution_profiles=["passive"],
        network_profile="passive_http",
        priority=6,
        trigger=["asset.discovered", "asset.updated"],
    ),
    _tool(
        tool_id="ffuf",
        name="FFUF",
        category="content_discovery",
        version="v2.1.0",
        image="ffuf/ffuf:2.1.0",
        capabilities=["directory_discovery", "file_discovery", "parameter_fuzzing"],
        required_inputs=["url"],
        optional_inputs=["wordlist", "status_codes", "extensions"],
        output_types=["endpoint"],
        supported_asset_types=["http_service", "endpoint"],
        applicable_execution_profiles=["low_impact_discovery"],
        network_profile="controlled_http",
        priority=7,
        trigger=["http.service.discovered", "http.endpoint.discovered"],
    ),
    _tool(
        tool_id="feroxbuster",
        name="Feroxbuster",
        category="content_discovery",
        version="v2.10.4",
        image="epi052/feroxbuster:2.10.4",
        capabilities=["directory_discovery", "recursive_discovery"],
        required_inputs=["url"],
        optional_inputs=["wordlist", "status_codes"],
        output_types=["endpoint"],
        supported_asset_types=["http_service", "endpoint"],
        applicable_execution_profiles=["low_impact_discovery"],
        network_profile="controlled_http",
        priority=6,
        trigger=["http.service.discovered", "http.endpoint.discovered"],
    ),
    _tool(
        tool_id="kiterunner",
        name="Kiterunner",
        category="api_discovery",
        version="v1.0.2",
        image="assetnote/kiterunner:1.0.2",
        capabilities=["api_route_discovery", "api_schema_analysis"],
        required_inputs=["api_host"],
        optional_inputs=["wordlist", "methods"],
        output_types=["api_endpoint"],
        supported_asset_types=["http_service", "api_spec", "endpoint"],
        applicable_execution_profiles=["authorized_vulnerability_testing"],
        network_profile="controlled_http",
        priority=7,
        trigger=["api.endpoint.discovered", "api.schema.discovered", "http.endpoint.discovered"],
    ),
    _tool(
        tool_id="arjun",
        name="Arjun",
        category="api_discovery",
        version="v2.2.1",
        image="s0md3v/arjun:2.2.1",
        capabilities=["parameter_discovery"],
        required_inputs=["endpoint"],
        optional_inputs=["wordlist", "methods"],
        output_types=["parameter"],
        supported_asset_types=["endpoint", "parameter"],
        applicable_execution_profiles=["authorized_vulnerability_testing"],
        network_profile="controlled_http",
        priority=8,
        trigger=["http.endpoint.discovered", "api.endpoint.discovered", "parameter.discovered"],
    ),
    _tool(
        tool_id="nuclei",
        name="Nuclei",
        category="web_vulnerability_testing",
        version="v3.3.5",
        image="projectdiscovery/nuclei:3.3.5",
        capabilities=["safe_vulnerability_templates", "technology_templates", "parameter_checks"],
        required_inputs=["url"],
        optional_inputs=["templates", "severity", "rate_limit"],
        output_types=["finding"],
        supported_asset_types=["http_service", "endpoint", "technology"],
        applicable_execution_profiles=["low_impact_discovery", "authorized_vulnerability_testing"],
        network_profile="controlled_http",
        priority=9,
        trigger=[
            "http.service.discovered",
            "http.endpoint.discovered",
            "api.endpoint.discovered",
            "technology.detected",
            "parameter.discovered",
        ],
    ),
    _tool(
        tool_id="nmap",
        name="Nmap",
        category="network",
        version="v7.95",
        image="instrumentisto/nmap:7.95",
        capabilities=["port_scan", "service_discovery"],
        required_inputs=["hostname"],
        optional_inputs=["ports", "scan_type"],
        output_types=["port", "service"],
        supported_asset_types=["hostname", "ip", "port", "service"],
        applicable_execution_profiles=["low_impact_discovery", "authorized_vulnerability_testing"],
        network_profile="tcp",
        priority=6,
        trigger=["dns.record.discovered", "asset.discovered"],
    ),
    # ---- Documented but disabled -----------------------------------------
    _tool(tool_id="amass", name="Amass", category="reconnaissance", version="v4.2.0", image="caffix/amass:4.2.0", capabilities=["subdomain_enumeration"], required_inputs=["domain"], output_types=["subdomain"], supported_asset_types=["subdomain"], applicable_execution_profiles=["passive"], priority=7, trigger=["asset.discovered"], enabled=False),
    _tool(tool_id="gobuster", name="Gobuster", category="content_discovery", version="v3.6.0", image="ghcr.io/oj/gobuster:3.6.0", capabilities=["directory_discovery"], required_inputs=["url"], output_types=["endpoint"], supported_asset_types=["http_service"], applicable_execution_profiles=["low_impact_discovery"], priority=5, trigger=["http.service.discovered"], enabled=False),
    _tool(tool_id="dirsearch", name="Dirsearch", category="content_discovery", version="v0.4.3", image="python:3.12-slim", capabilities=["directory_discovery"], required_inputs=["url"], output_types=["endpoint"], supported_asset_types=["http_service"], applicable_execution_profiles=["low_impact_discovery"], priority=5, trigger=["http.service.discovered"], enabled=False),
    _tool(tool_id="wfuzz", name="Wfuzz", category="content_discovery", version="v3.1.0", image="wfuzz/wfuzz:3.1.0", capabilities=["parameter_fuzzing"], required_inputs=["url"], output_types=["endpoint"], supported_asset_types=["http_service"], applicable_execution_profiles=["authorized_vulnerability_testing"], priority=4, trigger=["http.service.discovered"], enabled=False),
    _tool(tool_id="dalfox", name="Dalfox", category="web_vulnerability_testing", version="v2.10.1", image="hahwul/dalfox:2.10.1", capabilities=["xss_scanning"], required_inputs=["url"], output_types=["finding"], supported_asset_types=["endpoint"], applicable_execution_profiles=["authorized_vulnerability_testing"], priority=8, trigger=["parameter.discovered"], enabled=False),
    _tool(tool_id="sqlmap", name="SQLmap", category="web_vulnerability_testing", version="v1.8.5", image="sqlmapproject/sqlmap:1.8.5", capabilities=["sql_injection_testing"], required_inputs=["url"], output_types=["finding"], supported_asset_types=["endpoint"], applicable_execution_profiles=["authorized_vulnerability_testing"], priority=8, trigger=["parameter.discovered"], enabled=False),
    _tool(tool_id="ghauri", name="Ghauri", category="web_vulnerability_testing", version="v1.2.4", image="ghauri/ghauri:1.2.4", capabilities=["sql_injection_testing"], required_inputs=["url"], output_types=["finding"], supported_asset_types=["endpoint"], applicable_execution_profiles=["authorized_vulnerability_testing"], priority=7, trigger=["parameter.discovered"], enabled=False),
    _tool(tool_id="sstimap", name="SSTImap", category="web_vulnerability_testing", version="v1.1.0", image="python:3.12-slim", capabilities=["ssti_testing"], required_inputs=["url"], output_types=["finding"], supported_asset_types=["endpoint"], applicable_execution_profiles=["authorized_vulnerability_testing"], priority=6, trigger=["parameter.discovered"], enabled=False),
    _tool(tool_id="ssrfmap", name="SSRFmap", category="web_vulnerability_testing", version="v1.0.0", image="python:3.12-slim", capabilities=["ssrf_testing"], required_inputs=["url"], output_types=["finding"], supported_asset_types=["endpoint"], applicable_execution_profiles=["authorized_vulnerability_testing"], priority=6, trigger=["parameter.discovered"], enabled=False),
    _tool(tool_id="jwt_tool", name="JWT Tool", category="web_vulnerability_testing", version="v2.2.6", image="python:3.12-slim", capabilities=["jwt_analysis"], required_inputs=["url"], output_types=["finding"], supported_asset_types=["endpoint"], applicable_execution_profiles=["authorized_vulnerability_testing"], priority=6, trigger=["http.endpoint.discovered"], enabled=False),
    _tool(tool_id="schemathesis", name="Schemathesis", category="advanced_testing", version="v3.29.0", image="python:3.12-slim", capabilities=["api_schema_testing"], required_inputs=["openapi_schema"], output_types=["finding"], supported_asset_types=["api_spec"], applicable_execution_profiles=["authorized_vulnerability_testing"], priority=8, trigger=["api.schema.discovered"], enabled=False),
    _tool(tool_id="restler", name="RESTler", category="advanced_testing", version="v9.0.0", image="mcr.microsoft.com/restler:9.0.0", capabilities=["stateful_api_testing"], required_inputs=["openapi_schema"], output_types=["finding"], supported_asset_types=["api_spec"], applicable_execution_profiles=["authorized_vulnerability_testing"], priority=7, trigger=["api.schema.discovered"], enabled=False),
    _tool(tool_id="graphqlmap", name="GraphQLmap", category="advanced_testing", version="v1.0.0", image="python:3.12-slim", capabilities=["graphql_testing"], required_inputs=["url"], output_types=["finding"], supported_asset_types=["api_spec"], applicable_execution_profiles=["authorized_vulnerability_testing"], priority=6, trigger=["api.schema.discovered"], enabled=False),
    _tool(tool_id="semgrep", name="Semgrep", category="source_code", version="v1.86.0", image="semgrep/semgrep:1.86.0", capabilities=["sast"], required_inputs=["source_path"], output_types=["finding"], supported_asset_types=[], applicable_execution_profiles=["passive"], priority=7, trigger=[], enabled=False),
    _tool(tool_id="codeql", name="CodeQL", category="source_code", version="v2.19.0", image="ghcr.io/github/codeql:2.19.0", capabilities=["sast"], required_inputs=["source_path"], output_types=["finding"], supported_asset_types=[], applicable_execution_profiles=["passive"], priority=7, trigger=[], enabled=False),
    _tool(tool_id="trivy", name="Trivy", category="source_code", version="v0.56.1", image="aquasec/trivy:0.56.1", capabilities=["sca", "container_scan"], required_inputs=["source_path"], output_types=["finding"], supported_asset_types=[], applicable_execution_profiles=["passive"], priority=7, trigger=[], enabled=False),
    _tool(tool_id="prowler", name="Prowler", category="cloud", version="v5.5.0", image="toniblyx/prowler:5.5.0", capabilities=["cloud_posture"], required_inputs=["cloud_account"], output_types=["finding"], supported_asset_types=[], applicable_execution_profiles=["passive"], priority=6, trigger=[], enabled=False),
    _tool(tool_id="scoutsuite", name="ScoutSuite", category="cloud", version="v5.13.0", image="python:3.12-slim", capabilities=["cloud_posture"], required_inputs=["cloud_account"], output_types=["finding"], supported_asset_types=[], applicable_execution_profiles=["passive"], priority=6, trigger=[], enabled=False),
    _tool(tool_id="cloudfox", name="CloudFox", category="cloud", version="v1.14.1", image="bishopfox/cloudfox:1.14.1", capabilities=["cloud_enumeration"], required_inputs=["cloud_account"], output_types=["asset"], supported_asset_types=[], applicable_execution_profiles=["passive"], priority=5, trigger=[], enabled=False),
    _tool(tool_id="rustscan", name="RustScan", category="network", version="v2.1.1", image="rustscan/rustscan:2.1.1", capabilities=["port_scan"], required_inputs=["hostname"], output_types=["port"], supported_asset_types=["hostname", "ip"], applicable_execution_profiles=["low_impact_discovery"], priority=6, trigger=["asset.discovered"], enabled=False),
    _tool(tool_id="testssl", name="testssl.sh", category="network", version="v3.2.0", image="drwetter/testssl.sh:3.2", capabilities=["tls_analysis"], required_inputs=["hostname"], output_types=["finding"], supported_asset_types=["http_service"], applicable_execution_profiles=["low_impact_discovery"], priority=5, trigger=["http.service.discovered"], enabled=False),
    _tool(tool_id="bbot", name="BBOT", category="reconnaissance", version="v2.3.0", image="blacklanternsecurity/bbot:2.3.0", capabilities=["subdomain_enumeration", "passive_recon"], required_inputs=["domain"], output_types=["subdomain", "http_service"], supported_asset_types=["subdomain"], applicable_execution_profiles=["passive"], priority=8, trigger=["asset.discovered"], enabled=False),
    _tool(tool_id="paramspider", name="ParamSpider", category="api_discovery", version="v2.0.0", image="python:3.12-slim", capabilities=["parameter_discovery"], required_inputs=["domain"], output_types=["parameter"], supported_asset_types=["endpoint"], applicable_execution_profiles=["passive"], priority=5, trigger=["asset.discovered"], enabled=False),
    _tool(tool_id="js-luice", name="JSluice", category="api_discovery", version="v1.0.0", image="python:3.12-slim", capabilities=["js_endpoint_extraction"], required_inputs=["javascript"], output_types=["endpoint"], supported_asset_types=["javascript"], applicable_execution_profiles=["passive"], priority=7, trigger=["javascript.discovered"], enabled=False),
    _tool(tool_id="linkfinder", name="LinkFinder", category="api_discovery", version="v1.0.0", image="python:3.12-slim", capabilities=["js_endpoint_extraction"], required_inputs=["javascript"], output_types=["endpoint"], supported_asset_types=["javascript"], applicable_execution_profiles=["passive"], priority=6, trigger=["javascript.discovered"], enabled=False),
    _tool(tool_id="x8", name="x8", category="api_discovery", version="v3.1.0", image="sh1yo/x8:3.1.0", capabilities=["parameter_discovery"], required_inputs=["url"], output_types=["parameter"], supported_asset_types=["endpoint"], applicable_execution_profiles=["authorized_vulnerability_testing"], priority=7, trigger=["http.endpoint.discovered"], enabled=False),
    _tool(tool_id="param-miner", name="Param Miner", category="advanced_testing", version="v1.0.0", image="portswigger/param-miner:1.0.0", capabilities=["parameter_mining"], required_inputs=["url"], output_types=["parameter"], supported_asset_types=["endpoint"], applicable_execution_profiles=["authorized_vulnerability_testing"], priority=6, trigger=["http.endpoint.discovered"], enabled=False),
]

#: dedupe by tool_id (first occurrence wins; the enabled MVP entry is first).
_seen: Set[str] = set()
_deduped: List[Dict] = []
for _t in TOOL_DEPENDENCIES:
    if _t["tool_id"] in _seen:
        continue
    _seen.add(_t["tool_id"])
    _deduped.append(_t)
TOOL_DEPENDENCIES = _deduped

TOOL_INDEX: Dict[str, Dict] = {t["tool_id"]: t for t in TOOL_DEPENDENCIES}

ENABLED_TOOL_IDS: List[str] = [t["tool_id"] for t in TOOL_DEPENDENCIES if t["enabled"]]
DISABLED_TOOL_IDS: List[str] = [t["tool_id"] for t in TOOL_DEPENDENCIES if not t["enabled"]]

#: Heuristic expected-value score (1-10) per tool.
EXPECTED_VALUE: Dict[str, int] = {
    "subfinder": 9,
    "dnsx": 7,
    "httpx": 9,
    "katana": 8,
    "gau": 6,
    "ffuf": 7,
    "feroxbuster": 6,
    "kiterunner": 7,
    "arjun": 8,
    "nuclei": 9,
    "nmap": 6,
}


@dataclass
class EligibleTool:
    tool_id: str
    reason: str
    required_input: str
    expected_value: int
    execution_profile: str
    required_input_token: str = "target"
    tool_version: str = ""
    capabilities: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "tool_id": self.tool_id,
            "reason": self.reason,
            "required_input": self.required_input,
            "required_input_token": self.required_input_token,
            "expected_value": self.expected_value,
            "execution_profile": self.execution_profile,
            "tool_version": self.tool_version,
            "capabilities": list(self.capabilities),
        }


def _event_parts(event_or_asset) -> Dict:
    """Normalize the resolver input into event_type/asset_type/payload/asset_ref."""
    if isinstance(event_or_asset, DomainEvent):
        payload = event_or_asset.payload or {}
        asset_type = payload.get("asset_type")
        return {
            "event_type": event_or_asset.event_type,
            "asset_type": asset_type,
            "payload": payload,
            "asset_ref": event_or_asset.asset_ref,
        }
    if isinstance(event_or_asset, Asset):
        return {
            "event_type": "asset.discovered",
            "asset_type": event_or_asset.asset_type,
            "payload": {"value": event_or_asset.value},
            "asset_ref": event_or_asset.value,
        }
    if isinstance(event_or_asset, dict):
        if "event_type" in event_or_asset:
            payload = event_or_asset.get("payload") or {}
            return {
                "event_type": event_or_asset["event_type"],
                "asset_type": payload.get("asset_type"),
                "payload": payload,
                "asset_ref": event_or_asset.get("asset_ref"),
            }
        return {
            "event_type": "asset.discovered",
            "asset_type": event_or_asset.get("asset_type"),
            "payload": event_or_asset,
            "asset_ref": event_or_asset.get("value"),
        }
    raise TypeError(f"unsupported resolver input: {type(event_or_asset)!r}")


def _provided_inputs(event_type: str, asset_type: Optional[str], payload: Dict) -> Set[str]:
    provided = set(EVENT_INPUTS.get(event_type, set()))
    if asset_type:
        provided |= ASSET_TYPE_INPUTS.get(asset_type, set())
    # a few explicit payload hints that are safe to trust as "provided"
    for token in ("url", "endpoint", "host", "hostname", "domain", "api_host", "parameter"):
        if payload.get(token):
            provided.add(token if token != "host" else "hostname")
    return provided


def _value_for(token: str, payload: Dict, asset_ref: Optional[str]) -> str:
    mapping = {
        "domain": payload.get("domain"),
        "subdomain": payload.get("host") or payload.get("hostname"),
        "hostname": payload.get("host") or payload.get("hostname"),
        "ip": payload.get("ip"),
        "http_service": payload.get("url"),
        "url": payload.get("url"),
        # a tool that needs an "endpoint" target must receive a full URL when one
        # is available, not just the bare path.
        "endpoint": payload.get("url") or payload.get("endpoint"),
        "api_host": payload.get("host") or payload.get("api_host"),
        "api_endpoint": payload.get("url") or payload.get("endpoint"),
        "openapi_schema": payload.get("url") or payload.get("openapi_schema"),
        "javascript": payload.get("url") or payload.get("javascript"),
        "parameter": payload.get("parameter"),
        "technology": payload.get("technology"),
    }
    return str(mapping.get(token) or asset_ref or payload.get("value") or "")


class DependencyResolver:
    """Resolves which tools are eligible for a given event or asset."""

    def __init__(self, tools: Optional[Iterable[Dict]] = None):
        self.tools: Dict[str, Dict] = {t["tool_id"]: t for t in (tools or TOOL_DEPENDENCIES)}

    def get(self, tool_id: str) -> Optional[Dict]:
        return self.tools.get(tool_id)

    def eligible_next_tools(
        self,
        event_or_asset,
        permitted_profiles: Optional[Set[str]] = None,
    ) -> List[EligibleTool]:
        parts = _event_parts(event_or_asset)
        event_type = parts["event_type"]
        asset_type = parts["asset_type"]
        payload = parts["payload"]
        asset_ref = parts["asset_ref"]

        provided = _provided_inputs(event_type, asset_type, payload)
        eligible: List[EligibleTool] = []

        for tool in self.tools.values():
            if not tool.get("enabled", False):
                continue
            if event_type not in tool.get("trigger", []):
                continue
            required = tool.get("required_inputs", [])
            if not set(required) <= provided:
                continue
            profile = PROFILE_OVERRIDES.get(
                (event_type, tool["tool_id"]),
                (tool.get("applicable_execution_profiles") or ["low_impact_discovery"])[0],
            )
            if permitted_profiles is not None and profile not in permitted_profiles:
                continue
            required_input = _value_for(required[0], payload, asset_ref) if required else ""
            reason = (
                f"{event_type} provides {sorted(set(required))}; "
                f"{tool['tool_id']} ({tool.get('category')}) produces "
                f"{tool.get('output_types') or ['results']}"
            )
            eligible.append(
                EligibleTool(
                    tool_id=tool["tool_id"],
                    reason=reason,
                    required_input=required_input,
                    required_input_token=required[0] if required else "target",
                    expected_value=EXPECTED_VALUE.get(tool["tool_id"], tool.get("priority", 5)),
                    execution_profile=profile,
                    tool_version=tool.get("version", ""),
                    capabilities=list(tool.get("capabilities", [])),
                )
            )

        eligible.sort(key=lambda e: (-e.expected_value, e.tool_id))
        return eligible


__all__ = [
    "TOOL_DEPENDENCIES",
    "TOOL_INDEX",
    "ENABLED_TOOL_IDS",
    "DISABLED_TOOL_IDS",
    "EXPECTED_VALUE",
    "EVENT_INPUTS",
    "ASSET_TYPE_INPUTS",
    "PROFILE_OVERRIDES",
    "EligibleTool",
    "DependencyResolver",
]

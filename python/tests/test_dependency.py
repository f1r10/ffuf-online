"""Dependency table + resolver tests. The engine is data-driven; these tests
pin the inventory and the resolution rules."""

from __future__ import annotations

from ffuf_intel.dependency import (
    DISABLED_TOOL_IDS,
    ENABLED_TOOL_IDS,
    TOOL_DEPENDENCIES,
    DependencyResolver,
)
from ffuf_intel.models import make_event

MVP_TOOLS = {
    "subfinder",
    "dnsx",
    "httpx",
    "katana",
    "gau",
    "ffuf",
    "feroxbuster",
    "kiterunner",
    "arjun",
    "nuclei",
    "nmap",
}

# Documented-but-disabled tools required by the specification.
DOCUMENTED_DISABLED = {
    "amass",
    "gobuster",
    "dirsearch",
    "wfuzz",
    "dalfox",
    "sqlmap",
    "ghauri",
    "sstimap",
    "ssrfmap",
    "jwt_tool",
    "schemathesis",
    "restler",
    "graphqlmap",
    "semgrep",
    "codeql",
    "trivy",
    "prowler",
    "scoutsuite",
    "cloudfox",
    "rustscan",
    "testssl",
    "bbot",
    "paramspider",
    "js-luice",
    "linkfinder",
    "x8",
    "param-miner",
}


def test_enabled_inventory_is_exactly_the_mvp_set():
    assert set(ENABLED_TOOL_IDS) == MVP_TOOLS
    assert len(ENABLED_TOOL_IDS) == 11


def test_disabled_tools_are_documented_and_disabled():
    assert DOCUMENTED_DISABLED <= set(DISABLED_TOOL_IDS)
    for tool in TOOL_DEPENDENCIES:
        if tool["tool_id"] in DISABLED_TOOL_IDS:
            assert tool["enabled"] is False


def test_tool_ids_are_unique():
    ids = [t["tool_id"] for t in TOOL_DEPENDENCIES]
    assert len(ids) == len(set(ids))


def test_http_endpoint_event_resolves_expected_tools():
    event = make_event(
        "t1",
        "p1",
        "http.endpoint.discovered",
        payload={
            "url": "https://api.example.com/api/v2/users",
            "endpoint": "/api/v2/users",
            "host": "api.example.com",
        },
        asset_ref="https://api.example.com/api/v2/users",
    )
    resolver = DependencyResolver()
    eligible = resolver.eligible_next_tools(event)
    ids = [e.tool_id for e in eligible]
    assert set(ids) == {"nuclei", "arjun", "ffuf", "kiterunner", "feroxbuster"}


def test_http_service_event_resolves_crawlers_and_scanners():
    event = make_event(
        "t1",
        "p1",
        "http.service.discovered",
        payload={"url": "https://api.example.com", "host": "api.example.com"},
        asset_ref="https://api.example.com",
    )
    ids = [e.tool_id for e in DependencyResolver().eligible_next_tools(event)]
    assert set(ids) == {"katana", "ffuf", "feroxbuster", "nuclei"}


def test_results_are_sorted_by_expected_value_desc():
    event = make_event(
        "t1",
        "p1",
        "http.endpoint.discovered",
        payload={"url": "https://api.example.com/api/v2/users", "endpoint": "/api/v2/users", "host": "api.example.com"},
        asset_ref="https://api.example.com/api/v2/users",
    )
    eligible = DependencyResolver().eligible_next_tools(event)
    values = [e.expected_value for e in eligible]
    assert values == sorted(values, reverse=True)
    assert eligible[0].tool_id == "nuclei"  # highest expected value


def test_disabled_tools_are_never_eligible():
    event = make_event(
        "t1",
        "p1",
        "asset.discovered",
        payload={"asset_type": "subdomain", "value": "api.example.com"},
        asset_ref="api.example.com",
    )
    ids = {e.tool_id for e in DependencyResolver().eligible_next_tools(event)}
    assert ids.isdisjoint(DOCUMENTED_DISABLED)


def test_required_input_value_and_token_are_reported():
    event = make_event(
        "t1",
        "p1",
        "http.endpoint.discovered",
        payload={"url": "https://api.example.com/api/v2/users", "endpoint": "/api/v2/users", "host": "api.example.com"},
        asset_ref="https://api.example.com/api/v2/users",
    )
    arjun = [e for e in DependencyResolver().eligible_next_tools(event) if e.tool_id == "arjun"][0]
    assert arjun.required_input_token == "endpoint"
    assert arjun.required_input == "https://api.example.com/api/v2/users"


def test_permitted_profiles_filter_restricts_sensitive_tools():
    event = make_event(
        "t1",
        "p1",
        "parameter.discovered",
        payload={"parameter": "user_id", "endpoint": "https://api.example.com/api/v2/users"},
        asset_ref="https://api.example.com/api/v2/users",
    )
    allowed = {e.tool_id for e in DependencyResolver().eligible_next_tools(event, permitted_profiles={"passive"})}
    assert "nuclei" not in allowed  # parameter-derived nuclei needs authorized testing
    assert "arjun" not in allowed

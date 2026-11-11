"""Adapter parsing + normalization tests against real-format fixtures.

Also pins the safety invariant: no adapter ever emits a *confirmed*
vulnerability — findings are always ``candidate`` or ``needs_validation``.
"""

from __future__ import annotations

import pathlib

import pytest

from adapters.arjun import ArjunAdapter
from adapters.base import NormalizedResult
from adapters.dnsx import DnsxAdapter
from adapters.feroxbuster import FeroxbusterAdapter
from adapters.ffuf import FfufAdapter
from adapters.gau import GauAdapter
from adapters.httpx import HttpxAdapter
from adapters.katana import KatanaAdapter
from adapters.kiterunner import KiterunnerAdapter
from adapters.nmap import NmapAdapter
from adapters.nuclei import NucleiAdapter
from adapters.subfinder import SubfinderAdapter

FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures"
SAFE_STATUSES = {"candidate", "needs_validation", "discovered"}


def _fixture(tool: str, name: str) -> str:
    return (FIXTURES / tool / name).read_text(encoding="utf-8")


CASES = [
    (SubfinderAdapter, "subfinder/sample.jsonl"),
    (DnsxAdapter, "dnsx/sample.jsonl"),
    (HttpxAdapter, "httpx/sample.jsonl"),
    (KatanaAdapter, "katana/sample.jsonl"),
    (GauAdapter, "gau/sample.txt"),
    (FfufAdapter, "ffuf/sample.json"),
    (FeroxbusterAdapter, "feroxbuster/sample.jsonl"),
    (KiterunnerAdapter, "kiterunner/sample.jsonl"),
    (ArjunAdapter, "arjun/sample.json"),
    (NucleiAdapter, "nuclei/sample.jsonl"),
    (NmapAdapter, "nmap/sample.xml"),
]


def test_subfinder_parses_subdomains():
    parsed = SubfinderAdapter().parse_output(_fixture("subfinder", "sample.jsonl"))
    assert len(parsed["subdomains"]) == 2
    assert parsed["subdomains"][0]["host"] == "api.example.com"


def test_dnsx_parses_records():
    parsed = DnsxAdapter().parse_output(_fixture("dnsx", "sample.jsonl"))
    assert len(parsed["records"]) == 2
    assert "93.184.216.34" in parsed["records"][0]["a"]


def test_httpx_parses_service_and_tech():
    parsed = HttpxAdapter().parse_output(_fixture("httpx", "sample.jsonl"))
    assert len(parsed["services"]) == 1
    svc = parsed["services"][0]
    assert svc["url"] == "https://api.example.com"
    assert svc["tech"] == ["nginx", "Express"]

    normalized = HttpxAdapter().normalize_results(parsed)
    assert len(normalized["assets"]) == 1
    tech_names = {t["value"] for t in normalized["technologies"]}
    assert {"nginx", "Express"} <= tech_names
    assert any(e["event_type"] == "http.service.discovered" for e in normalized["events"])


def test_katana_splits_endpoints_and_javascript():
    parsed = KatanaAdapter().parse_output(_fixture("katana", "sample.jsonl"))
    assert len(parsed["endpoints"]) == 1
    assert parsed["endpoints"][0]["url"] == "https://api.example.com/api/v2/users"
    assert parsed["javascript"] == ["https://api.example.com/static/app.js"]

    normalized = KatanaAdapter().normalize_results(parsed)
    assert len(normalized["assets"]) == 2
    types = {e["event_type"] for e in normalized["events"]}
    assert types == {"http.endpoint.discovered", "javascript.discovered"}


def test_gau_parses_urls():
    parsed = GauAdapter().parse_output(_fixture("gau", "sample.txt"))
    assert parsed["urls"] == [
        "https://api.example.com/api/v2/users?id=1",
        "https://api.example.com/api/v2/orders",
    ]
    normalized = GauAdapter().normalize_results(parsed)
    assert len(normalized["endpoints"]) == 2


def test_ffuf_parses_json_report():
    parsed = FfufAdapter().parse_output(_fixture("ffuf", "sample.json"))
    assert len(parsed["results"]) == 2
    assert parsed["results"][0]["url"] == "https://api.example.com/admin"
    normalized = FfufAdapter().normalize_results(parsed)
    assert len(normalized["endpoints"]) == 2


def test_feroxbuster_parses_responses_and_statistics():
    parsed = FeroxbusterAdapter().parse_output(_fixture("feroxbuster", "sample.jsonl"))
    assert len(parsed["responses"]) == 2
    assert parsed["statistics"]["total_requests"] == 100


def test_kiterunner_parses_routes():
    parsed = KiterunnerAdapter().parse_output(_fixture("kiterunner", "sample.jsonl"))
    assert len(parsed["routes"]) == 2
    normalized = KiterunnerAdapter().normalize_results(parsed)
    assert all(e["event_type"] == "api.endpoint.discovered" for e in normalized["events"])


def test_arjun_parses_parameters():
    parsed = ArjunAdapter().parse_output(_fixture("arjun", "sample.json"))
    assert parsed["endpoints"][0]["params"] == ["user_id", "token"]
    normalized = ArjunAdapter().normalize_results(parsed)
    names = {p["metadata"]["name"] for p in normalized["parameters"]}
    assert names == {"user_id", "token"}
    assert all(e["event_type"] == "parameter.discovered" for e in normalized["events"])


def test_nuclei_parses_candidate_finding():
    parsed = NucleiAdapter().parse_output(_fixture("nuclei", "sample.jsonl"))
    assert len(parsed["findings"]) == 1
    assert parsed["findings"][0]["severity"] == "low"

    normalized = NucleiAdapter().normalize_results(parsed)
    assert len(normalized["findings"]) == 1
    finding = normalized["findings"][0]
    assert finding["status"] == "needs_validation"
    assert finding["status"] not in {"validated", "confirmed_impact", "accepted", "report_ready"}
    assert normalized["events"][0]["event_type"] == "finding.candidate.created"


def test_nmap_parses_xml_ports():
    parsed = NmapAdapter().parse_output(_fixture("nmap", "sample.xml"))
    assert len(parsed["hosts"]) == 1
    ports = {p["port"]: p for p in parsed["hosts"][0]["ports"]}
    assert ports[443]["state"] == "open"
    assert ports[80]["state"] == "closed"

    normalized = NmapAdapter().normalize_results(parsed)
    # the open port (and the host IP) become assets; the closed port does not
    values = {a["value"] for a in normalized["assets"]}
    assert "93.184.216.34" in values
    assert "93.184.216.34:443" in values
    assert "93.184.216.34:80" not in values


def test_parse_outputs_are_robust_to_garbage():
    for adapter_cls, _path in CASES:
        adapter = adapter_cls()
        assert adapter.parse_output("") is not None
        assert adapter.parse_output("not the expected format at all") is not None


@pytest.mark.parametrize("adapter_cls,fixture_path", CASES)
def test_normalized_result_shape_and_safe_statuses(adapter_cls, fixture_path):
    tool_dir, name = fixture_path.split("/")
    adapter = adapter_cls()
    adapter.set_context("tenant-x", "project-x", scope_version=3)
    parsed = adapter.parse_output(_fixture(tool_dir, name))
    normalized = adapter.normalize_results(parsed)

    assert isinstance(normalized, NormalizedResult)
    assert set(normalized.keys()) == set(NormalizedResult.KEYS)

    for finding in normalized["findings"]:
        assert finding["status"] in SAFE_STATUSES
        assert finding["tenant_id"] == "tenant-x"
        assert finding["project_id"] == "project-x"

    for asset in normalized["assets"] + normalized["endpoints"] + normalized["parameters"] + normalized["technologies"]:
        assert asset["tenant_id"] == "tenant-x"
        assert asset["project_id"] == "project-x"

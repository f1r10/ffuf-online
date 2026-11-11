"""Asset graph tests: normalization, merging, provenance, tenant isolation."""

from __future__ import annotations

from ffuf_intel.graph import (
    AssetGraph,
    correlation_key,
    normalize_value,
)
from ffuf_intel.models import Asset


def _asset(tenant, project, asset_type, value, **kw):
    return Asset(
        id="",
        tenant_id=tenant,
        project_id=project,
        asset_type=asset_type,
        value=value,
        **kw,
    )


def test_normalize_value_lowercases_and_strips_default_ports():
    assert normalize_value("url", "HTTPS://API.Example.com:443/Path/") == "https://api.example.com/Path"
    assert normalize_value("url", "http://example.com:80/") == "http://example.com"
    assert normalize_value("hostname", "API.Example.com") == "api.example.com"
    assert normalize_value("hostname", "api.example.com:443") == "api.example.com"
    assert normalize_value("hostname", "api.example.com:8443") == "api.example.com:8443"


def test_normalize_value_sorts_query_parameters():
    assert (
        normalize_value("url", "https://example.com/search?z=26&a=1")
        == normalize_value("url", "https://example.com/search?a=1&z=26")
    )


def test_upsert_creates_then_merges_with_provenance():
    graph = AssetGraph()
    first = _asset("t1", "p1", "subdomain", "api.example.com", source_tools=["subfinder"])
    stored, created = graph.upsert_asset(first)
    assert created is True
    assert stored.id.startswith("asset-")

    second = _asset("t1", "p1", "subdomain", "API.example.com", source_tools=["httpx"])
    merged, created = graph.upsert_asset(second)
    assert created is False
    assert merged.id == stored.id
    assert merged.source_tools == ["subfinder", "httpx"]
    assert len(graph.all_assets("t1", "p1")) == 1


def test_merge_keeps_earliest_first_seen_and_latest_last_seen():
    graph = AssetGraph()
    graph.upsert_asset(_asset("t1", "p1", "hostname", "h", first_seen_at="2026-01-02T00:00:00Z", last_seen_at="2026-01-02T00:00:00Z"))
    merged, _ = graph.upsert_asset(_asset("t1", "p1", "hostname", "h", first_seen_at="2026-01-01T00:00:00Z", last_seen_at="2026-03-01T00:00:00Z"))
    assert merged.first_seen_at == "2026-01-01T00:00:00Z"
    assert merged.last_seen_at == "2026-03-01T00:00:00Z"


def test_tenant_isolation_same_value_different_tenants():
    graph = AssetGraph()
    a, _ = graph.upsert_asset(_asset("t1", "p1", "subdomain", "api.example.com"))
    b, _ = graph.upsert_asset(_asset("t2", "p1", "subdomain", "api.example.com"))
    assert a.id != b.id
    assert graph.get(a.id, "t1", "p1") is not None
    # tenant 1's id is invisible to tenant 2
    assert graph.get(a.id, "t2", "p1") is None
    assert len(graph.all_assets("t1", "p1")) == 1
    assert len(graph.all_assets("t2", "p1")) == 1


def test_links_neighbors_and_provenance():
    graph = AssetGraph()
    host, _ = graph.upsert_asset(_asset("t1", "p1", "hostname", "api.example.com", source_tools=["httpx"]))
    ep, _ = graph.upsert_asset(_asset("t1", "p1", "endpoint", "https://api.example.com/api/v2/users", source_tools=["katana"]))
    graph.link(host.id, ep.id, "serves", source_tool="katana", source_execution_id="exec-1", tenant_id="t1", project_id="p1")

    neighbors = graph.neighbors(host.id, "t1", "p1", rel_type="serves")
    assert len(neighbors) == 1
    assert neighbors[0]["neighbor_id"] == ep.id
    assert neighbors[0]["direction"] == "out"

    prov = graph.provenance(ep.id, "t1", "p1")
    assert prov["source_tools"] == ["katana"]
    assert prov["relationships"][0]["provenance"]["source_tool"] == "katana"


def test_endpoints_for_host_uses_serves_and_contains():
    graph = AssetGraph()
    host, _ = graph.upsert_asset(_asset("t1", "p1", "hostname", "api.example.com"))
    ep, _ = graph.upsert_asset(_asset("t1", "p1", "endpoint", "https://api.example.com/a"))
    graph.link(host.id, ep.id, "contains", tenant_id="t1", project_id="p1")
    found = graph.endpoints_for_host("api.example.com", "t1", "p1")
    assert [a.id for a in found] == [ep.id]


def test_assets_by_type_stats_and_reset():
    graph = AssetGraph()
    graph.upsert_asset(_asset("t1", "p1", "subdomain", "a.example.com"))
    graph.upsert_asset(_asset("t1", "p1", "subdomain", "b.example.com"))
    graph.upsert_asset(_asset("t1", "p1", "hostname", "api.example.com"))

    assert len(graph.assets_by_type("subdomain", "t1", "p1")) == 2
    stats = graph.stats("t1", "p1")
    assert stats["assets"] == 3
    assert stats["assets_by_type"]["subdomain"] == 2

    graph.reset()
    assert graph.all_assets() == []


def test_correlation_key_is_type_scoped():
    assert correlation_key("subdomain", "API.example.com") == "subdomain:api.example.com"
    assert correlation_key("hostname", "API.example.com") == "hostname:api.example.com"

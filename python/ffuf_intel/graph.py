"""In-memory asset relationship graph.

Nodes are keyed by ``(tenant_id, project_id, correlation_key)`` so one tenant
can never observe another tenant's node. Relationships carry provenance
(source tool, execution id, scope version).
"""

from __future__ import annotations

import hashlib
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit

from .models import RELATIONSHIP_TYPES, Asset, utc_now


def normalize_value(asset_type: str, value: str) -> str:
    """Deterministic normalization of an asset value.

    * lowercase host
    * strip default ports (443 for https, 80 for http)
    * stable ordering of query parameters
    * strip trailing slash
    """
    raw = (value or "").strip()
    if not raw:
        return ""

    if "://" in raw:
        parts = urlsplit(raw)
        scheme = (parts.scheme or "").lower()
        host = (parts.hostname or "").lower()
        try:
            port = parts.port
        except ValueError:
            port = None
        netloc = host
        if port is not None and not (
            (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
        ):
            netloc = f"{host}:{port}"
        path = (parts.path or "").rstrip("/")
        query = ""
        if parts.query:
            pairs = sorted(parse_qsl(parts.query, keep_blank_values=True))
            query = urlencode(pairs)
        result = f"{scheme}://{netloc}{path}"
        if query:
            result += "?" + query
        if parts.fragment:
            result += "#" + parts.fragment
        return result

    # host[:port] form
    lowered = raw.lower()
    if lowered.count(":") == 1:
        host, maybe_port = lowered.rsplit(":", 1)
        if maybe_port.isdigit():
            if maybe_port in ("80", "443"):
                return host
            return f"{host}:{maybe_port}"
    return lowered.rstrip("/") if asset_type in ("url", "endpoint") else lowered


def correlation_key(asset_type: str, value: str) -> str:
    return f"{asset_type}:{normalize_value(asset_type, value)}"


def deterministic_asset_id(tenant_id: str, project_id: str, key: str) -> str:
    h = hashlib.sha256(f"{tenant_id}|{project_id}|{key}".encode("utf-8"))
    return "asset-" + h.hexdigest()[:24]


class AssetGraph:
    """Tenant-scoped in-memory asset graph."""

    def __init__(self) -> None:
        # (tenant_id, project_id, correlation_key) -> Asset
        self._assets: Dict[Tuple[str, str, str], Asset] = {}
        # (tenant_id, project_id, asset_id) -> correlation_key
        self._by_id: Dict[Tuple[str, str, str], str] = {}
        # list of relationship dicts (provenance included)
        self._relationships: List[Dict] = []

    # ------------------------------------------------------------------ write
    def upsert_asset(self, asset: Asset) -> Tuple[Asset, bool]:
        """Insert or merge an asset. Returns ``(asset, created)``."""
        key = correlation_key(asset.asset_type, asset.value)
        index = (asset.tenant_id, asset.project_id, key)
        existing = self._assets.get(index)
        if existing is not None:
            # merge source tools (stable order, deduplicated)
            tools = list(existing.source_tools)
            for tool in asset.source_tools:
                if tool and tool not in tools:
                    tools.append(tool)
            existing.source_tools = tools
            # earliest first_seen / latest last_seen
            existing.first_seen_at = min(existing.first_seen_at, asset.first_seen_at)
            existing.last_seen_at = max(existing.last_seen_at, asset.last_seen_at)
            # fill parent if we did not have one
            if not existing.parent_asset_id and asset.parent_asset_id:
                existing.parent_asset_id = asset.parent_asset_id
            # prefer a concrete scope status over "unknown"
            if asset.scope_status and asset.scope_status != "unknown":
                existing.scope_status = asset.scope_status
            existing.confidence = max(existing.confidence, asset.confidence)
            existing.metadata.update(asset.metadata or {})
            self._by_id[(asset.tenant_id, asset.project_id, existing.id)] = key
            return existing, False

        if not asset.id:
            asset.id = deterministic_asset_id(asset.tenant_id, asset.project_id, key)
        if not asset.first_seen_at:
            asset.first_seen_at = utc_now()
        if not asset.last_seen_at:
            asset.last_seen_at = asset.first_seen_at
        self._assets[index] = asset
        self._by_id[(asset.tenant_id, asset.project_id, asset.id)] = key
        return asset, True

    def link(
        self,
        from_id: str,
        to_id: str,
        rel_type: str,
        source_tool: Optional[str] = None,
        source_execution_id: Optional[str] = None,
        scope_version: int = 1,
        tenant_id: Optional[str] = None,
        project_id: Optional[str] = None,
    ) -> Dict:
        if rel_type not in RELATIONSHIP_TYPES:
            raise ValueError(f"unknown rel_type: {rel_type!r}")
        rel = {
            "from_id": from_id,
            "to_id": to_id,
            "rel_type": rel_type,
            "source_tool": source_tool,
            "source_execution_id": source_execution_id,
            "scope_version": scope_version,
            "tenant_id": tenant_id,
            "project_id": project_id,
            "created_at": utc_now(),
            "provenance": {
                "source_tool": source_tool,
                "source_execution_id": source_execution_id,
                "scope_version": scope_version,
            },
        }
        self._relationships.append(rel)
        return rel

    # ------------------------------------------------------------------- read
    def _key_for(self, asset_id: str, tenant_id: str, project_id: str) -> Optional[str]:
        return self._by_id.get((tenant_id, project_id, asset_id))

    def get(self, asset_id: str, tenant_id: str, project_id: str) -> Optional[Asset]:
        key = self._key_for(asset_id, tenant_id, project_id)
        if key is None:
            return None
        return self._assets.get((tenant_id, project_id, key))

    def which_tool_discovered(self, asset_id: str, tenant_id: str, project_id: str) -> List[str]:
        asset = self.get(asset_id, tenant_id, project_id)
        return list(asset.source_tools) if asset else []

    def provenance(self, asset_id: str, tenant_id: str, project_id: str) -> Dict:
        asset = self.get(asset_id, tenant_id, project_id)
        if asset is None:
            return {}
        rels = [
            r
            for r in self._relationships
            if r.get("tenant_id") == tenant_id
            and r.get("project_id") == project_id
            and (r["from_id"] == asset_id or r["to_id"] == asset_id)
        ]
        return {
            "asset_id": asset_id,
            "source_tools": list(asset.source_tools),
            "scope_status": asset.scope_status,
            "first_seen_at": asset.first_seen_at,
            "last_seen_at": asset.last_seen_at,
            "relationships": rels,
            "scope_versions": sorted({r["scope_version"] for r in rels}),
        }

    def neighbors(
        self, asset_id: str, tenant_id: str, project_id: str, rel_type: Optional[str] = None
    ) -> List[Dict]:
        out = []
        for r in self._relationships:
            if r.get("tenant_id") != tenant_id or r.get("project_id") != project_id:
                continue
            if rel_type and r["rel_type"] != rel_type:
                continue
            if r["from_id"] == asset_id:
                out.append({**r, "direction": "out", "neighbor_id": r["to_id"]})
            elif r["to_id"] == asset_id:
                out.append({**r, "direction": "in", "neighbor_id": r["from_id"]})
        return out

    def endpoints_for_host(self, host: str, tenant_id: str, project_id: str) -> List[Asset]:
        host_key = correlation_key("hostname", host)
        host_asset = self._assets.get((tenant_id, project_id, host_key))
        results = []
        endpoint_ids = set()
        if host_asset is not None:
            for r in self.neighbors(host_asset.id, tenant_id, project_id, rel_type="serves"):
                if r["direction"] == "out":
                    endpoint_ids.add(r["to_id"])
            for r in self.neighbors(host_asset.id, tenant_id, project_id, rel_type="contains"):
                if r["direction"] == "out":
                    endpoint_ids.add(r["to_id"])
        for aid in endpoint_ids:
            asset = self.get(aid, tenant_id, project_id)
            if asset is not None:
                results.append(asset)
        return results

    def assets_by_type(self, asset_type: str, tenant_id: str, project_id: str) -> List[Asset]:
        return [
            a
            for (t, p, _key), a in self._assets.items()
            if t == tenant_id and p == project_id and a.asset_type == asset_type
        ]

    def all_assets(self, tenant_id: Optional[str] = None, project_id: Optional[str] = None) -> List[Asset]:
        return [
            a
            for (t, p, _key), a in self._assets.items()
            if (tenant_id is None or t == tenant_id)
            and (project_id is None or p == project_id)
        ]

    def to_dict(self, tenant_id: Optional[str] = None, project_id: Optional[str] = None) -> Dict:
        nodes = [
            {
                "id": a.id,
                "tenant_id": a.tenant_id,
                "project_id": a.project_id,
                "asset_type": a.asset_type,
                "value": a.value,
                "label": a.value,
                "source_tools": list(a.source_tools),
                "scope_status": a.scope_status,
                "confidence": a.confidence,
            }
            for a in self.all_assets(tenant_id, project_id)
        ]
        edges = [
            r
            for r in self._relationships
            if (tenant_id is None or r.get("tenant_id") == tenant_id)
            and (project_id is None or r.get("project_id") == project_id)
        ]
        return {"nodes": nodes, "edges": edges}

    def stats(self, tenant_id: Optional[str] = None, project_id: Optional[str] = None) -> Dict:
        assets = self.all_assets(tenant_id, project_id)
        by_type: Dict[str, int] = {}
        for a in assets:
            by_type[a.asset_type] = by_type.get(a.asset_type, 0) + 1
        edges = [
            r
            for r in self._relationships
            if (tenant_id is None or r.get("tenant_id") == tenant_id)
            and (project_id is None or r.get("project_id") == project_id)
        ]
        return {
            "assets": len(assets),
            "assets_by_type": by_type,
            "relationships": len(edges),
            "tenants": sorted({a.tenant_id for a in assets}),
            "projects": sorted({a.project_id for a in assets}),
        }

    def reset(self) -> None:
        self._assets.clear()
        self._by_id.clear()
        self._relationships.clear()


__all__ = ["AssetGraph", "correlation_key", "normalize_value", "deterministic_asset_id"]

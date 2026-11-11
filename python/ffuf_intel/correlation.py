"""Finding correlation engine.

The deterministic correlation key is
``normalized URL + HTTP method + parameter name + vulnerability category``.

Evidence similarity (a Jaccard score over token sets) is reported as a
*secondary* signal only. Correlation **never** promotes a finding's status: a
scanner result stays ``candidate`` unless a human/validation workflow changes
it.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urlsplit

from .graph import normalize_value

_TOKEN_RE = re.compile(r"[a-zA-Z0-9_]+")


def _tokens(text: str) -> set:
    return set(t.lower() for t in _TOKEN_RE.findall(text or ""))


def correlation_key(finding: Dict) -> str:
    """Deterministic key: url | method | parameter | category."""
    url = normalize_value("url", finding.get("endpoint") or finding.get("asset_value") or "")
    method = (finding.get("http_method") or "").upper()
    parameter = (finding.get("parameter") or "").lower()
    category = (finding.get("finding_type") or finding.get("category") or "").lower()
    raw = "|".join([url, method, parameter, category])
    return "corr-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def _finding_id(finding: Dict) -> str:
    if finding.get("id"):
        return finding["id"]
    return "finding-" + hashlib.sha256(correlation_key(finding).encode("utf-8")).hexdigest()[:16]


def evidence_tokens(finding: Dict) -> set:
    """Token set used for the advisory Jaccard similarity."""
    parts = [
        finding.get("title") or "",
        finding.get("finding_type") or "",
        finding.get("endpoint") or "",
        " ".join(finding.get("evidence_ids") or []),
        " ".join(finding.get("source_tools") or []),
        " ".join(str(e) for e in (finding.get("evidence") or [])),
    ]
    return _tokens(" ".join(parts))


def jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


@dataclass
class CorrelationResult:
    merged: List[Dict] = field(default_factory=list)
    new: List[Dict] = field(default_factory=list)
    related: List[Dict] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {"merged": self.merged, "new": self.new, "related": self.related}


class FindingCorrelator:
    """Merges duplicate findings and reports advisory relationships."""

    def __init__(self, similarity_threshold: float = 0.3):
        self.similarity_threshold = similarity_threshold

    def correlate(self, new_findings: List[Dict], existing: List[Dict]) -> CorrelationResult:
        result = CorrelationResult()
        index: Dict[str, Dict] = {correlation_key(f): dict(f) for f in existing}
        existing_list = list(existing)

        for finding in new_findings:
            key = correlation_key(finding)
            candidate_tokens = evidence_tokens(finding)

            # Secondary, advisory: relationships to non-identical findings.
            for other in existing_list:
                if correlation_key(other) == key:
                    continue
                score = jaccard(candidate_tokens, evidence_tokens(other))
                if score >= self.similarity_threshold:
                    result.related.append(
                        {
                            "finding_id": _finding_id(finding),
                            "related_finding_id": _finding_id(other),
                            "similarity": round(score, 4),
                            "signal": "advisory",
                        }
                    )

            if key in index:
                merged = self._merge(index[key], finding)
                index[key] = merged
                result.merged.append(merged)
            else:
                stored = dict(finding)
                stored.setdefault("id", _finding_id(finding))
                # A merged/new finding never gains a validated status here.
                if stored.get("status") in (None, "validated", "confirmed_impact", "report_ready"):
                    stored["status"] = "candidate"
                index[key] = stored
                existing_list.append(stored)
                result.new.append(stored)

        return result

    @staticmethod
    def _merge(existing: Dict, incoming: Dict) -> Dict:
        merged = dict(existing)
        # union source tools / evidence / related ids (stable, deduplicated)
        for field_name in ("source_tools", "evidence_ids", "related_finding_ids"):
            merged[field_name] = _union(existing.get(field_name), incoming.get(field_name))
        # Never auto-promote status: correlation keeps the stored status.
        merged["status"] = existing.get("status") or "candidate"
        # keep the higher confidence, but do not change status
        merged["confidence"] = max(
            float(existing.get("confidence") or 0.0),
            float(incoming.get("confidence") or 0.0),
        )
        return merged


def _union(a: Optional[List], b: Optional[List]) -> List:
    out: List = []
    for item in list(a or []) + list(b or []):
        if item not in out:
            out.append(item)
    return out


__all__ = [
    "FindingCorrelator",
    "CorrelationResult",
    "correlation_key",
    "evidence_tokens",
    "jaccard",
]

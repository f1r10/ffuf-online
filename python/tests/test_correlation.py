"""Finding correlation tests: deterministic keys, advisory similarity, and the
hard rule that correlation never promotes a finding's status."""

from __future__ import annotations

from ffuf_intel.correlation import (
    FindingCorrelator,
    correlation_key,
    evidence_tokens,
    jaccard,
)


def _finding(**kw):
    base = {
        "endpoint": "https://api.example.com/api/v2/users",
        "http_method": "GET",
        "parameter": "user_id",
        "finding_type": "sql_injection",
        "title": "Possible SQL injection via user_id",
        "severity": "high",
        "confidence": 0.5,
        "status": "candidate",
        "source_tools": ["nuclei"],
        "evidence_ids": ["ev-1"],
    }
    base.update(kw)
    return base


def test_correlation_key_is_deterministic_and_field_scoped():
    a = correlation_key(_finding())
    b = correlation_key(_finding(title="different title", severity="low"))
    assert a == b  # title/severity do not affect the key
    c = correlation_key(_finding(parameter="token"))
    assert a != c
    d = correlation_key(_finding(http_method="POST"))
    assert a != d


def test_jaccard_basics():
    assert jaccard(set(), set()) == 1.0
    assert jaccard({"a"}, set()) == 0.0
    assert jaccard({"a", "b"}, {"a", "b"}) == 1.0
    assert 0.0 < jaccard({"a", "b"}, {"b", "c"}) < 1.0


def test_correlate_files_new_finding_as_candidate():
    correlator = FindingCorrelator()
    result = correlator.correlate([_finding()], [])
    assert len(result.new) == 1
    assert result.new[0]["status"] == "candidate"
    assert result.new[0]["id"]


def test_correlation_never_promotes_status():
    correlator = FindingCorrelator()
    # Even if a scanner claims "validated", correlation downgrades to candidate.
    result = correlator.correlate([_finding(status="validated")], [])
    assert result.new[0]["status"] == "candidate"


def test_identical_findings_merge_and_union_tools():
    correlator = FindingCorrelator()
    existing = [_finding(id="f-1", source_tools=["nuclei"], evidence_ids=["ev-1"])]
    result = correlator.correlate([_finding(source_tools=["ffuf"], evidence_ids=["ev-2"])], existing)
    assert result.new == []
    assert len(result.merged) == 1
    merged = result.merged[0]
    assert merged["status"] == "candidate"
    assert set(merged["source_tools"]) == {"nuclei", "ffuf"}
    assert set(merged["evidence_ids"]) == {"ev-1", "ev-2"}


def test_similar_but_distinct_findings_are_related_advisory_only():
    correlator = FindingCorrelator(similarity_threshold=0.3)
    existing = [_finding(endpoint="https://api.example.com/api/v2/orders")]
    new = _finding(endpoint="https://api.example.com/api/v2/users")
    result = correlator.correlate([new], existing)
    # different correlation keys => not merged
    assert result.merged == []
    assert len(result.new) == 1
    assert len(result.related) == 1
    assert result.related[0]["signal"] == "advisory"
    assert 0.0 <= result.related[0]["similarity"] <= 1.0


def test_evidence_tokens_are_lowercased_words():
    tokens = evidence_tokens(_finding())
    assert "users" in tokens
    assert all(t == t.lower() for t in tokens)

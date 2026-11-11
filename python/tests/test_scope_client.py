"""Scope client tests: transports, fail-closed behaviour, ScopeDenied."""

from __future__ import annotations

import pytest

import ffuf_intel.scope_client as sc
from ffuf_intel.models import ScopeDecision, ScopeRequest
from ffuf_intel.scope_client import (
    FakeTransport,
    HttpTransport,
    ScopeClient,
    ScopeDenied,
    SubprocessTransport,
    _decision_from_stdout,
)


def _request(request_id: str = "req-1") -> ScopeRequest:
    return ScopeRequest(
        tenant_id="tenant-a",
        project_id="project-a",
        policy_profile="low_impact_discovery",
        target={"kind": "hostname", "value": "api.example.com"},
        request_id=request_id,
    )


def test_fake_transport_approves_by_default():
    client = ScopeClient(FakeTransport())
    decision = client.require_approved(_request())
    assert decision.approved
    assert decision.reason_code == "IN_SCOPE"


def test_require_approved_raises_with_reason_code():
    rejected = ScopeDecision(
        request_id="r", decision="rejected", reason_code="EXCLUDED", reason="listed exclusion"
    )
    client = ScopeClient(FakeTransport([rejected]))
    with pytest.raises(ScopeDenied) as excinfo:
        client.require_approved(_request())
    assert excinfo.value.reason_code == "EXCLUDED"
    assert "listed exclusion" in excinfo.value.reason


def test_fake_transport_consumes_canned_decisions_in_order():
    decisions = [
        ScopeDecision(request_id="1", decision="approved", reason_code="IN_SCOPE"),
        ScopeDecision(request_id="2", decision="rejected", reason_code="OUT_OF_SCOPE"),
    ]
    transport = FakeTransport(decisions)
    client = ScopeClient(transport)
    assert client.evaluate(_request()).approved
    assert not client.evaluate(_request()).approved
    # exhausted -> default (approved)
    assert client.evaluate(_request()).approved
    assert len(transport.calls) == 3


def test_fake_transport_decide_fn_records_calls():
    seen = []

    def decide(request: ScopeRequest) -> ScopeDecision:
        seen.append(request.request_id)
        return ScopeDecision(request_id=request.request_id, decision="approved", reason_code="IN_SCOPE")

    client = ScopeClient(FakeTransport(decide_fn=decide))
    client.evaluate(_request("x"))
    assert seen == ["x"]


def test_http_transport_fails_closed_when_unreachable():
    # Port 1 is never listening: the client must reject, never approve.
    decision = HttpTransport("http://127.0.0.1:1", timeout=1.0).decide(_request())
    assert not decision.approved
    assert decision.reason_code == "INVALID_TARGET"


def test_subprocess_transport_maps_exit_codes(monkeypatch):
    captured = {}

    class FakeProc:
        def __init__(self, rc, out):
            self.returncode = rc
            self.stdout = out
            self.stderr = b""

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return FakeProc(captured["rc"], captured["out"])

    monkeypatch.setattr(sc.subprocess, "run", fake_run)
    transport = SubprocessTransport("scope-engine")

    captured.update(rc=0, out=b'{"reason_code":"IN_SCOPE","decision":"approved"}')
    approved = transport.decide(_request())
    assert approved.approved
    assert captured["kwargs"]["shell"] is False
    assert captured["command"] == ["scope-engine", "check", "--input", "-"]

    captured.update(rc=2, out=b"")
    rejected = transport.decide(_request())
    assert not rejected.approved
    assert rejected.reason_code == "OUT_OF_SCOPE"

    captured.update(rc=1, out=b"")
    errored = transport.decide(_request())
    assert not errored.approved  # fail closed on any unexpected exit code


def test_decision_from_stdout_parses_json_and_defaults():
    parsed = _decision_from_stdout(
        '{"matched_rule_id":"rule-7"}', _request("abc"), "approved", "IN_SCOPE"
    )
    assert parsed.approved
    assert parsed.matched_rule_id == "rule-7"
    assert parsed.request_id == "abc"

    fallback = _decision_from_stdout("not json", _request("z"), "rejected", "OUT_OF_SCOPE")
    assert not fallback.approved
    assert fallback.reason_code == "OUT_OF_SCOPE"

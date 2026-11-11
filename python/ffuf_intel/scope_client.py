"""Scope client — every active network operation must pass through here.

Three transports are supported:

* :class:`HttpTransport`       — POST to the Rust scope engine over HTTP.
* :class:`SubprocessTransport` — run the Rust binary, exit 0 = approved, 2 = rejected.
* :class:`FakeTransport`       — canned decisions, used by tests.

The tool-execution path calls :meth:`ScopeClient.require_approved` before any
network operation; a rejection raises :class:`ScopeDenied`.
"""

from __future__ import annotations

import json
import subprocess
import urllib.error
import urllib.request
from typing import Callable, List, Optional

from .models import ScopeDecision, ScopeRequest, utc_now


class ScopeDenied(Exception):
    """Raised when the scope engine rejects a target."""

    def __init__(self, reason_code: str, reason: str = ""):
        self.reason_code = reason_code
        self.reason = reason
        super().__init__(f"{reason_code}: {reason}" if reason else reason_code)


class Transport:
    """Transport protocol: ``decide(request) -> ScopeDecision``."""

    def decide(self, request: ScopeRequest) -> ScopeDecision:  # pragma: no cover
        raise NotImplementedError


class HttpTransport(Transport):
    """POST the ScopeRequest to ``{base_url}/v1/scope/decide``."""

    def __init__(self, base_url: str, timeout: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def decide(self, request: ScopeRequest) -> ScopeDecision:
        url = f"{self.base_url}/v1/scope/decide"
        body = json.dumps(request.to_dict()).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.URLError as exc:
            # Fail closed: an unreachable scope engine never means "approved".
            return ScopeDecision(
                request_id=request.request_id,
                decision="rejected",
                reason_code="INVALID_TARGET",
                reason=f"scope engine unreachable: {exc}",
                scope_version=request.scope_version,
            )
        payload.setdefault("request_id", request.request_id)
        payload.setdefault("scope_version", request.scope_version)
        return ScopeDecision.from_dict(payload)


class SubprocessTransport(Transport):
    """Run ``[bin, "check", "--input", "-"]`` with the JSON on stdin.

    Exit code ``0`` = approved, ``2`` = rejected, anything else is an error and
    treated as a rejection (fail closed). ``shell=False`` always.
    """

    def __init__(self, binary: str, timeout: float = 30.0):
        self.binary = binary
        self.timeout = timeout

    def decide(self, request: ScopeRequest) -> ScopeDecision:
        proc = subprocess.run(
            [self.binary, "check", "--input", "-"],
            input=json.dumps(request.to_dict()).encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=self.timeout,
            shell=False,
        )
        stdout = (proc.stdout or b"").decode("utf-8", "replace").strip()
        if proc.returncode == 0:
            decision = _decision_from_stdout(stdout, request, "approved", "IN_SCOPE")
        elif proc.returncode == 2:
            decision = _decision_from_stdout(stdout, request, "rejected", "OUT_OF_SCOPE")
        else:
            decision = ScopeDecision(
                request_id=request.request_id,
                decision="rejected",
                reason_code="INVALID_TARGET",
                reason=f"scope engine exit code {proc.returncode}",
                scope_version=request.scope_version,
            )
        return decision


class FakeTransport(Transport):
    """Deterministic transport for tests.

    Provide either a list of canned :class:`ScopeDecision` objects (consumed in
    order) or a callable ``decide(request) -> ScopeDecision``. When the canned
    list is exhausted, ``default`` is returned (approved by default).
    """

    def __init__(self, decisions: Optional[List[ScopeDecision]] = None, default: Optional[ScopeDecision] = None, decide_fn: Optional[Callable[[ScopeRequest], ScopeDecision]] = None):
        self.decisions = list(decisions or [])
        self.default = default or ScopeDecision(
            request_id="fake", decision="approved", reason_code="IN_SCOPE", scope_version=1
        )
        self.decide_fn = decide_fn
        self.calls: List[ScopeRequest] = []

    def decide(self, request: ScopeRequest) -> ScopeDecision:
        self.calls.append(request)
        if self.decide_fn is not None:
            return self.decide_fn(request)
        if self.decisions:
            return self.decisions.pop(0)
        decision = ScopeDecision.from_dict(self.default.to_dict())
        decision.request_id = request.request_id or decision.request_id
        return decision


def _decision_from_stdout(stdout: str, request: ScopeRequest, decision: str, reason_code: str) -> ScopeDecision:
    if stdout:
        try:
            payload = json.loads(stdout)
            payload.setdefault("request_id", request.request_id)
            payload.setdefault("decision", decision)
            payload.setdefault("reason_code", reason_code)
            payload.setdefault("evaluated_at", utc_now())
            payload.setdefault("scope_version", request.scope_version)
            return ScopeDecision.from_dict(payload)
        except json.JSONDecodeError:
            pass
    return ScopeDecision(
        request_id=request.request_id,
        decision=decision,
        reason_code=reason_code,
        scope_version=request.scope_version,
    )


class ScopeClient:
    """Evaluates scope requests through a transport."""

    def __init__(self, transport: Transport):
        self.transport = transport

    def evaluate(self, request: ScopeRequest) -> ScopeDecision:
        return self.transport.decide(request)

    def require_approved(self, request: ScopeRequest) -> ScopeDecision:
        decision = self.evaluate(request)
        if not decision.approved:
            raise ScopeDenied(decision.reason_code, decision.reason)
        return decision


__all__ = [
    "ScopeDenied",
    "Transport",
    "HttpTransport",
    "SubprocessTransport",
    "FakeTransport",
    "ScopeClient",
]

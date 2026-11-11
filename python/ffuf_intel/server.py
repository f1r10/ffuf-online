"""Intelligence Engine HTTP service (standard library only).

Endpoints:

* ``GET  /healthz``
* ``GET  /v1/graph``                       — asset graph ``to_dict()`` + ``stats()``
* ``POST /v1/events``                      — ingest a DomainEvent, plan tasks
* ``POST /v1/reset``                       — clear state (test helper)
* ``GET  /v1/workflow/<workflow_id>``      — workflow node graph for visualisation

This is the process the Go control plane forwards events to.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlsplit

from .config import Config
from .dependency import DependencyResolver
from .events import EventProcessor
from .graph import AssetGraph
from .models import DomainEvent, utc_now
from .planner import TaskPlanner
from .scope_client import (
    FakeTransport,
    HttpTransport,
    ScopeClient,
    SubprocessTransport,
)

_LOCK = threading.Lock()
_LOG_LOCK = threading.Lock()


def log(**fields: Any) -> None:
    """Emit a single JSON log line."""
    record = {"ts": utc_now(), **fields}
    with _LOG_LOCK:
        sys.stdout.write(json.dumps(record, default=str) + "\n")
        sys.stdout.flush()


def _default_scope_client(config: Config) -> ScopeClient:
    """Pick a scope transport.

    Prefers the real Rust binary, then the HTTP service, and finally falls back
    to an approving in-process transport so the engine can be demonstrated
    without the other planes running. The choice is always logged.
    """
    if os.path.isfile(config.scope_engine_bin):
        log(event="scope_transport", transport="subprocess", binary=config.scope_engine_bin)
        return ScopeClient(SubprocessTransport(config.scope_engine_bin))
    try:
        probe = urllib.request.Request(f"{config.scope_engine_url.rstrip('/')}/healthz")
        with urllib.request.urlopen(probe, timeout=0.5):
            pass
        log(event="scope_transport", transport="http", url=config.scope_engine_url)
        return ScopeClient(HttpTransport(config.scope_engine_url))
    except Exception:  # noqa: BLE001 - fall back for standalone/demo runs
        log(
            event="scope_transport",
            transport="fake",
            warning="scope engine unavailable; using approving demo transport",
        )
        return ScopeClient(FakeTransport())


class _State:
    def __init__(self, config: Config):
        self.config = config
        self.lock = threading.Lock()
        self.build()

    def build(self) -> None:
        self.graph = AssetGraph()
        self.resolver = DependencyResolver()
        self.scope_client = _default_scope_client(self.config)
        self.planner = TaskPlanner(self.config, self.scope_client)
        self.processor = EventProcessor(
            graph=self.graph,
            resolver=self.resolver,
            planner=self.planner,
            scope_client=self.scope_client,
            config=self.config,
        )

    def reset(self) -> None:
        self.build()


STATE: Optional[_State] = None


def _split_addr(addr: str) -> Tuple[str, int]:
    if ":" in addr:
        host, port = addr.rsplit(":", 1)
        return host or "127.0.0.1", int(port)
    return addr, 8091


def forward_tasks(config: Config, tasks) -> Dict:
    """Best-effort forward generated tasks to the Go control plane."""
    url = f"{config.api_url.rstrip('/')}/api/v1/tasks"
    forwarded = 0
    failures = []
    for task in tasks:
        body = json.dumps(task.to_dict() if hasattr(task, "to_dict") else task).encode("utf-8")
        req = urllib.request.Request(
            url, data=body, headers={"Content-Type": "application/json"}, method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=3) as resp:
                resp.read()
            forwarded += 1
        except (urllib.error.URLError, OSError) as exc:
            failures.append(str(exc))
            log(event="forward_task_failed", task=(task.get("id") if isinstance(task, dict) else getattr(task, "id", None)), error=str(exc), url=url)
    if failures:
        log(event="forward_summary", forwarded=forwarded, failed=len(failures), api_url=url)
    return {"forwarded": forwarded, "failed": len(failures)}


class Handler(BaseHTTPRequestHandler):
    server_version = "ffuf-intel/0.1"
    protocol_version = "HTTP/1.1"

    # ------------------------------------------------------------------ utils
    def _send(self, code: int, payload: Any) -> None:
        body = json.dumps(payload, default=str).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> Dict:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        if not raw:
            return {}
        return json.loads(raw.decode("utf-8"))

    def log_message(self, fmt: str, *args) -> None:  # silence default logging
        log(event="http_access", client=self.address_string(), message=fmt % args)

    # ------------------------------------------------------------------- GET
    def do_GET(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        assert STATE is not None
        if path == "/healthz":
            self._send(200, {"status": "ok", "service": "ffuf-intel", "time": utc_now()})
        elif path == "/v1/graph":
            with STATE.lock:
                graph = STATE.graph.to_dict()
                stats = STATE.graph.stats()
            self._send(200, {"graph": graph, "stats": stats})
        elif path.startswith("/v1/workflow/"):
            workflow_id = path[len("/v1/workflow/") :]
            with STATE.lock:
                wf = STATE.planner.workflow_graph(workflow_id)
            self._send(200, wf)
        else:
            self._send(404, {"error": "not_found", "path": path})

    # ------------------------------------------------------------------ POST
    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        assert STATE is not None
        try:
            body = self._read_json()
        except json.JSONDecodeError as exc:
            self._send(400, {"error": "invalid_json", "detail": str(exc)})
            return

        if path == "/v1/reset":
            with STATE.lock:
                STATE.reset()
            log(event="state_reset")
            self._send(200, {"status": "reset"})
            return

        if path == "/v1/events":
            try:
                event = DomainEvent.from_dict(body)
                event.validate()
            except (ValueError, KeyError, TypeError) as exc:
                self._send(400, {"error": "invalid_event", "detail": str(exc)})
                return

            with STATE.lock:
                plan = STATE.processor.process(event)
                forward = forward_tasks(STATE.config, plan.tasks)
            log(
                event="event_processed",
                event_type=event.event_type,
                tenant_id=event.tenant_id,
                project_id=event.project_id,
                tasks=len(plan.tasks),
                skipped=len(plan.skipped),
                blocked=len(plan.blocked),
            )
            self._send(
                200,
                {
                    "tasks": [t.to_dict() for t in plan.tasks],
                    "skipped": plan.skipped,
                    "blocked": plan.blocked,
                    "forwarded": forward,
                },
            )
            return

        self._send(404, {"error": "not_found", "path": path})


def build_server(config: Optional[Config] = None) -> Tuple[ThreadingHTTPServer, Config]:
    global STATE
    config = config or Config.from_env()
    STATE = _State(config)
    host, port = _split_addr(config.intel_http_addr)
    server = ThreadingHTTPServer((host, port), Handler)
    return server, config


def main() -> None:
    server, config = build_server()
    host, port = _split_addr(config.intel_http_addr)
    log(event="server_start", addr=f"{host}:{port}", api_url=config.api_url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        log(event="server_stop")


if __name__ == "__main__":
    main()

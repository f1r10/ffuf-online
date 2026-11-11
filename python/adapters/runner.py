"""Tool runners.

* :class:`DockerRunner` — production path. A hardened ``docker run`` with an
  argv list, ``shell=False`` and a wall-clock timeout that kills the container.
* :class:`LocalProcessRunner` — development/CI. Resolves ``<bindir>/<tool_id>.py``
  (else ``.exe``, else the bare name), refuses any path outside the allowlisted
  bindir, and always uses ``shell=False`` with a timeout.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from typing import List, Optional, Sequence

from .base import AdapterInputError, ToolExecutionResult
from ffuf_intel.config import Config


class RunnerError(RuntimeError):
    pass


class DockerRunner:
    """Runs a pinned tool image with a hardened container profile."""

    def __init__(self, config: Optional[Config] = None, docker_bin: str = "docker"):
        self.config = config or Config()
        self.docker_bin = docker_bin

    def build_command(self, tool_id: str, image: str, argv: Sequence[str]) -> List[str]:
        return [
            self.docker_bin,
            "run",
            "--rm",
            "--network",
            self.config.tool_network,
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            "256",
            "--memory",
            self.config.tool_memory_limit,
            "--cpus",
            self.config.tool_cpu_limit,
            "--user",
            "65534:65534",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=64m",
            image,
            *argv,
        ]

    def run(
        self,
        tool_id: str,
        argv: Sequence[str],
        image: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> ToolExecutionResult:
        if not image:
            raise RunnerError(f"DockerRunner requires a pinned image for '{tool_id}'")
        command = self.build_command(tool_id, image, argv)
        timeout = timeout or self.config.tool_timeout_seconds
        start = time.time()
        try:
            proc = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                shell=False,
            )
        except subprocess.TimeoutExpired as exc:
            return ToolExecutionResult(
                stdout=(exc.stdout or b"").decode("utf-8", "replace") if exc.stdout else "",
                stderr=f"timeout after {timeout}s; container killed",
                exit_code=124,
                duration=time.time() - start,
                artifacts={"timeout": True, "command": command},
            )
        return ToolExecutionResult(
            stdout=(proc.stdout or b"").decode("utf-8", "replace"),
            stderr=(proc.stderr or b"").decode("utf-8", "replace"),
            exit_code=proc.returncode,
            duration=time.time() - start,
            artifacts={"command": command},
        )


class LocalProcessRunner:
    """Development/CI runner using ``python/tools/bin`` demo stand-ins."""

    def __init__(self, config: Optional[Config] = None, bindir: Optional[str] = None, base: Optional[str] = None):
        self.config = config or Config()
        base = base or os.getcwd()
        raw = bindir or self.config.tool_local_bindir
        self.bindir = os.path.abspath(raw if os.path.isabs(raw) else os.path.join(base, raw))

    def resolve(self, tool_id: str) -> List[str]:
        """Resolve the executable for a tool, refusing paths outside the bindir."""
        if any(sep in tool_id for sep in ("/", "\\", "..")):
            raise AdapterInputError(f"illegal tool id: {tool_id!r}")

        candidates = [
            os.path.join(self.bindir, f"{tool_id}.py"),
            os.path.join(self.bindir, f"{tool_id}.exe"),
            os.path.join(self.bindir, tool_id),
        ]
        for candidate in candidates:
            real = os.path.realpath(candidate)
            if not self._within_bindir(real):
                raise RunnerError(f"refusing path outside bindir: {real}")
            if os.path.isfile(real):
                if real.endswith(".py"):
                    return [sys.executable, real]
                return [real]
        raise RunnerError(f"tool '{tool_id}' not found under bindir {self.bindir}")

    def _within_bindir(self, path: str) -> bool:
        bindir = os.path.realpath(self.bindir)
        try:
            return os.path.commonpath([path, bindir]) == bindir
        except ValueError:
            return False

    def run(
        self,
        tool_id: str,
        argv: Sequence[str],
        image: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> ToolExecutionResult:
        # ``image`` is accepted for interface parity with DockerRunner and ignored.
        command = self.resolve(tool_id) + list(argv)
        timeout = timeout or self.config.tool_timeout_seconds
        start = time.time()
        try:
            proc = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                shell=False,
            )
        except subprocess.TimeoutExpired as exc:
            return ToolExecutionResult(
                stdout=(exc.stdout or b"").decode("utf-8", "replace") if exc.stdout else "",
                stderr=f"timeout after {timeout}s; process killed",
                exit_code=124,
                duration=time.time() - start,
                artifacts={"timeout": True, "command": command},
            )
        return ToolExecutionResult(
            stdout=(proc.stdout or b"").decode("utf-8", "replace"),
            stderr=(proc.stderr or b"").decode("utf-8", "replace"),
            exit_code=proc.returncode,
            duration=time.time() - start,
            artifacts={"command": command, "bindir": self.bindir},
        )


def runner_from_config(config: Optional[Config] = None, base: Optional[str] = None):
    config = config or Config()
    if config.tool_runner == "local":
        return LocalProcessRunner(config, base=base)
    return DockerRunner(config)


__all__ = ["RunnerError", "DockerRunner", "LocalProcessRunner", "runner_from_config"]

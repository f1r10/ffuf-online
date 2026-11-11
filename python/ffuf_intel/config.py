"""Environment-driven configuration for the Intelligence Engine and adapters.

Every value is read from the environment with the defaults declared in
``.env.example``. Nothing here is a secret-bearing constant; all secrets come
from the environment.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, fields
from typing import Mapping, Optional


def _env_str(env: Mapping[str, str], key: str, default: str) -> str:
    value = env.get(key)
    if value is None or value.strip() == "":
        return default
    return value.strip()


def _env_int(env: Mapping[str, str], key: str, default: int) -> int:
    value = env.get(key)
    if value is None or value.strip() == "":
        return default
    try:
        return int(value.strip())
    except ValueError:
        return default


def _env_bool(env: Mapping[str, str], key: str, default: bool) -> bool:
    value = env.get(key)
    if value is None or value.strip() == "":
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


@dataclass
class Config:
    """Runtime configuration. Field names mirror the env variable names."""

    api_url: str = "http://127.0.0.1:8080"
    scope_engine_url: str = "http://127.0.0.1:8090"
    scope_engine_bin: str = "rust/scope-engine/target/release/scope-engine"
    intel_http_addr: str = "127.0.0.1:8091"

    intel_tenant_max_tasks: int = 400
    intel_max_workflow_depth: int = 5
    intel_max_tasks_per_asset: int = 12
    intel_task_cooldown_seconds: int = 900
    intel_max_tasks_per_project_run: int = 1500

    tool_runner: str = "docker"
    tool_local_bindir: str = "python/tools/bin"
    tool_timeout_seconds: int = 900
    tool_cpu_limit: str = "1.0"
    tool_memory_limit: str = "1g"
    tool_network: str = "none"

    ai_enabled: bool = False
    ai_base_url: str = "https://api.openai.com/v1"
    ai_api_key: str = ""
    ai_model: str = "gpt-4o-mini"

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> "Config":
        env = os.environ if env is None else env
        return cls(
            api_url=_env_str(env, "API_URL", "http://127.0.0.1:8080"),
            scope_engine_url=_env_str(env, "SCOPE_ENGINE_URL", "http://127.0.0.1:8090"),
            scope_engine_bin=_env_str(
                env,
                "SCOPE_ENGINE_BIN",
                "rust/scope-engine/target/release/scope-engine",
            ),
            intel_http_addr=_env_str(env, "INTEL_HTTP_ADDR", "127.0.0.1:8091"),
            intel_tenant_max_tasks=_env_int(env, "INTEL_TENANT_MAX_TASKS", 400),
            intel_max_workflow_depth=_env_int(env, "INTEL_MAX_WORKFLOW_DEPTH", 5),
            intel_max_tasks_per_asset=_env_int(env, "INTEL_MAX_TASKS_PER_ASSET", 12),
            intel_task_cooldown_seconds=_env_int(env, "INTEL_TASK_COOLDOWN_SECONDS", 900),
            intel_max_tasks_per_project_run=_env_int(
                env, "INTEL_MAX_TASKS_PER_PROJECT_RUN", 1500
            ),
            tool_runner=_env_str(env, "TOOL_RUNNER", "docker"),
            tool_local_bindir=_env_str(env, "TOOL_LOCAL_BINDIR", "python/tools/bin"),
            tool_timeout_seconds=_env_int(env, "TOOL_TIMEOUT_SECONDS", 900),
            tool_cpu_limit=_env_str(env, "TOOL_CPU_LIMIT", "1.0"),
            tool_memory_limit=_env_str(env, "TOOL_MEMORY_LIMIT", "1g"),
            tool_network=_env_str(env, "TOOL_NETWORK", "none"),
            ai_enabled=_env_bool(env, "AI_ENABLED", False),
            ai_base_url=_env_str(env, "AI_BASE_URL", "https://api.openai.com/v1"),
            ai_api_key=_env_str(env, "AI_API_KEY", ""),
            ai_model=_env_str(env, "AI_MODEL", "gpt-4o-mini"),
        )

    def to_dict(self) -> dict:
        return {f.name: getattr(self, f.name) for f in fields(self)}

    def bindir_abs(self, base: Optional[str] = None) -> str:
        """Absolute path of the local tool bindir (relative to the repo root)."""
        base = base or os.getcwd()
        path = self.tool_local_bindir
        if not os.path.isabs(path):
            path = os.path.abspath(os.path.join(base, path))
        return path

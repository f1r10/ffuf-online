"""Adapter registry.

Maps ``tool_id -> adapter instance`` and loads/validates the JSON tool registry
stored at ``adapters/tool-registry.json``. The JSON is *generated* from
:data:`ffuf_intel.dependency.TOOL_DEPENDENCIES`; the loader asserts the two
agree so the data table and the registry can never silently diverge.
"""

from __future__ import annotations

import json
import os
from typing import Dict, List, Optional

from ffuf_intel.dependency import TOOL_DEPENDENCIES

from .arjun import ArjunAdapter
from .base import BaseToolAdapter
from .dnsx import DnsxAdapter
from .feroxbuster import FeroxbusterAdapter
from .ffuf import FfufAdapter
from .gau import GauAdapter
from .httpx import HttpxAdapter
from .katana import KatanaAdapter
from .kiterunner import KiterunnerAdapter
from .nmap import NmapAdapter
from .nuclei import NucleiAdapter
from .subfinder import SubfinderAdapter

REGISTRY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tool-registry.json")

ADAPTER_CLASSES = [
    SubfinderAdapter,
    DnsxAdapter,
    HttpxAdapter,
    KatanaAdapter,
    GauAdapter,
    FfufAdapter,
    FeroxbusterAdapter,
    KiterunnerAdapter,
    ArjunAdapter,
    NucleiAdapter,
    NmapAdapter,
]


class RegistryMismatch(RuntimeError):
    pass


class AdapterRegistry:
    def __init__(self, adapters: Optional[List[BaseToolAdapter]] = None):
        self._adapters: Dict[str, BaseToolAdapter] = {}
        for adapter in adapters if adapters is not None else [cls() for cls in ADAPTER_CLASSES]:
            self.register(adapter)

    def register(self, adapter: BaseToolAdapter) -> None:
        self._adapters[adapter.tool_id] = adapter

    def get(self, tool_id: str) -> BaseToolAdapter:
        if tool_id not in self._adapters:
            raise KeyError(f"no adapter registered for tool '{tool_id}'")
        return self._adapters[tool_id]

    def has(self, tool_id: str) -> bool:
        return tool_id in self._adapters

    def ids(self) -> List[str]:
        return sorted(self._adapters)

    def specs(self) -> List[Dict]:
        return [self._adapters[tid].get_spec() for tid in self.ids()]


def export_tool_registry(path: str = REGISTRY_PATH) -> str:
    """Write the JSON registry from the dependency table; return the path."""
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(TOOL_DEPENDENCIES, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return path


def load_tool_registry(path: str = REGISTRY_PATH) -> List[Dict]:
    """Load the JSON registry and assert it agrees with the data table."""
    with open(path, "r", encoding="utf-8") as handle:
        loaded = json.load(handle)
    if loaded != TOOL_DEPENDENCIES:
        raise RegistryMismatch(
            f"tool registry at {path} is out of sync with dependency.TOOL_DEPENDENCIES"
        )
    return loaded


def default_registry() -> AdapterRegistry:
    return AdapterRegistry()


__all__ = [
    "AdapterRegistry",
    "RegistryMismatch",
    "REGISTRY_PATH",
    "ADAPTER_CLASSES",
    "export_tool_registry",
    "load_tool_registry",
    "default_registry",
]

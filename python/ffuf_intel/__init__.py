"""FFUF Online Intelligence Engine.

Event-driven asset intelligence: an in-memory asset graph, a dependency
resolver, an anti-loop task planner and a finding correlator. The core engine
contains **zero** tool-specific branching — all tool knowledge lives in
:mod:`adapters` and in the data table :mod:`ffuf_intel.dependency`.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]

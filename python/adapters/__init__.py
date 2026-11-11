"""FFUF Online tool adapters.

Tool-specific knowledge (argv construction and output parsing) lives here and
*only* here. Adapters never build a shell string; they return ``list[str]``.
"""

from __future__ import annotations

from .base import (
    AdapterInputError,
    BaseToolAdapter,
    NormalizedResult,
    ToolExecutionResult,
    asset_dict,
    emit_event,
    endpoint_asset,
    finding_dict,
    parameter_asset,
    technology_asset,
)

__all__ = [
    "AdapterInputError",
    "BaseToolAdapter",
    "NormalizedResult",
    "ToolExecutionResult",
    "asset_dict",
    "endpoint_asset",
    "parameter_asset",
    "technology_asset",
    "finding_dict",
    "emit_event",
]

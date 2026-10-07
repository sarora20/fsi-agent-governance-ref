"""Tool registry: one source of truth for what the agent can call and how risky it is.

Exports the same tools in three wire formats: MCP (tools/list), Anthropic Messages API,
and Amazon Bedrock Converse. Governance metadata travels in MCP `annotations` and `_meta`.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Callable


class RiskTier(IntEnum):
    READ = 0  # no side effects
    LOW = 1  # reversible, internal (e.g. a saved draft)
    MEDIUM = 2  # changes a client record
    HIGH = 3  # moves money or is irreversible


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    input_schema: dict[str, Any]
    # handler(args, meta) -> dict; meta carries principal, run id and idempotency key
    handler: Callable[..., dict[str, Any]] = field(compare=False, repr=False)
    required_scope: str
    risk_tier: RiskTier
    client_arg: str | None = "client_id"
    data_classes: tuple[str, ...] = ()
    # Field-level minimisation of what reaches the model (gateway.py stage "output"), independent of
    # guardrails.redact() (which only protects what the audit log writes):
    returns: frozenset[str] | None = None  # top-level result fields allowed through; None = unrestricted
    mask: frozenset[str] = frozenset()  # result field names masked recursively wherever they appear
    # Input arg names that may arrive already masked (gateway.py stage "minimise", right after
    # schema) -- resolved against the system of record before policy, velocity or the handler see
    # them. A real, unmasked value is left untouched; only a masked one is looked up.
    resolve: frozenset[str] = frozenset()

    @property
    def side_effect(self) -> bool:
        return self.risk_tier > RiskTier.READ


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}

    def register(self, spec: ToolSpec) -> None:
        if spec.name in self._tools:
            raise ValueError(f"tool '{spec.name}' already registered")
        if spec.input_schema.get("type") != "object":
            raise ValueError(f"tool '{spec.name}' input_schema must be a JSON object schema")
        self._tools[spec.name] = spec

    def get(self, name: str) -> ToolSpec | None:
        return self._tools.get(name)

    def specs(self) -> list[ToolSpec]:
        return list(self._tools.values())

    def names(self) -> list[str]:
        return list(self._tools)

    # --- wire formats -------------------------------------------------------------

    def to_mcp(self) -> dict[str, Any]:
        return {
            "tools": [
                {
                    "name": s.name,
                    "description": s.description,
                    "inputSchema": s.input_schema,
                    "annotations": {
                        "readOnlyHint": s.risk_tier == RiskTier.READ,
                        "destructiveHint": s.risk_tier == RiskTier.HIGH,
                        "idempotentHint": s.risk_tier == RiskTier.READ,
                        "openWorldHint": False,
                    },
                    "_meta": {
                        "govagent/riskTier": s.risk_tier.name,
                        "govagent/requiredScope": s.required_scope,
                        "govagent/dataClasses": list(s.data_classes),
                    },
                }
                for s in self._tools.values()
            ]
        }

    def to_anthropic(self) -> list[dict[str, Any]]:
        return [
            {"name": s.name, "description": s.description, "input_schema": s.input_schema}
            for s in self._tools.values()
        ]

    def to_bedrock(self) -> dict[str, Any]:
        return {
            "tools": [
                {
                    "toolSpec": {
                        "name": s.name,
                        "description": s.description,
                        "inputSchema": {"json": s.input_schema},
                    }
                }
                for s in self._tools.values()
            ]
        }

    def fingerprint(self) -> str:
        canonical = json.dumps(self.to_mcp(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()

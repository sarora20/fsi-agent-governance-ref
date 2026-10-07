"""Deterministic offline adapter: replays a scripted sequence of model turns.

Used for tests, CI, and the control-layer evals, where the point is to prove the gateway
holds even when the "model" deliberately tries forbidden actions.
"""

from __future__ import annotations

from typing import Any

from ..agent.types import AssistantTurn, HistoryItem, ToolCall
from ..registry import ToolSpec


class ScriptedAdapter:
    name = "scripted"
    model_id = "scripted-replay"

    def __init__(self, turns: list[dict[str, Any]]):
        self._turns = list(turns)
        self._i = 0

    def complete(self, system: str, history: list[HistoryItem], tools: list[ToolSpec]) -> AssistantTurn:
        if self._i >= len(self._turns):
            return AssistantTurn(text="(script ended)", stop_reason="end_turn")
        turn = self._turns[self._i]
        self._i += 1
        calls = [
            ToolCall(id=f"toolu_scripted_{self._i}_{j}", name=c["name"], args=dict(c.get("args", {})))
            for j, c in enumerate(turn.get("tool_calls", []) or [])
        ]
        return AssistantTurn(
            text=turn.get("text", ""),
            tool_calls=calls,
            stop_reason="tool_use" if calls else "end_turn",
        )

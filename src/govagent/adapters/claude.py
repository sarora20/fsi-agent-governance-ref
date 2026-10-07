"""Anthropic Claude adapter (Messages API with tool use).

Env:
  ANTHROPIC_API_KEY   required
  CLAUDE_MODEL        optional, defaults to claude-sonnet-5
"""

from __future__ import annotations

import json
import os
from typing import Any

from ..agent.types import AssistantTurn, HistoryItem, ToolCall, ToolResults, UserMessage
from ..registry import ToolSpec

DEFAULT_MODEL = "claude-sonnet-5"


def to_anthropic_messages(history: list[HistoryItem]) -> list[dict[str, Any]]:
    messages: list[dict[str, Any]] = []
    for item in history:
        if isinstance(item, UserMessage):
            messages.append({"role": "user", "content": item.text})
        elif isinstance(item, ToolResults):
            messages.append({"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": r.call_id,
                 "content": json.dumps(r.content, default=str), "is_error": r.is_error}
                for r in item.results
            ]})
        else:  # AssistantTurn
            blocks: list[dict[str, Any]] = []
            if item.text:
                blocks.append({"type": "text", "text": item.text})
            blocks += [{"type": "tool_use", "id": c.id, "name": c.name, "input": c.args} for c in item.tool_calls]
            messages.append({"role": "assistant", "content": blocks or [{"type": "text", "text": "(no content)"}]})
    return messages


def parse_anthropic_response(resp: Any) -> AssistantTurn:
    texts, calls = [], []
    for block in resp.content:
        if block.type == "text":
            texts.append(block.text)
        elif block.type == "tool_use":
            calls.append(ToolCall(id=block.id, name=block.name, args=dict(block.input or {})))
    usage = getattr(resp, "usage", None)
    return AssistantTurn(
        text="\n".join(t for t in texts if t).strip(),
        tool_calls=calls,
        stop_reason=getattr(resp, "stop_reason", "") or "",
        usage={"input_tokens": getattr(usage, "input_tokens", 0) or 0,
               "output_tokens": getattr(usage, "output_tokens", 0) or 0} if usage else {},
    )


class ClaudeAdapter:
    name = "claude"

    def __init__(self, model: str | None = None, client: Any | None = None, max_tokens: int = 1024):
        self.model_id = model or os.environ.get("CLAUDE_MODEL", DEFAULT_MODEL)
        self.max_tokens = max_tokens
        if client is None:
            import anthropic  # optional dependency: pip install ".[claude]"

            client = anthropic.Anthropic()
        self.client = client

    def complete(self, system: str, history: list[HistoryItem], tools: list[ToolSpec]) -> AssistantTurn:
        resp = self.client.messages.create(
            model=self.model_id,
            max_tokens=self.max_tokens,
            system=system,
            tools=[{"name": t.name, "description": t.description, "input_schema": t.input_schema} for t in tools],
            messages=to_anthropic_messages(history),
        )
        return parse_anthropic_response(resp)

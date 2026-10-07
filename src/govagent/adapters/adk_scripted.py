"""A scripted ADK model (BaseLlm) so the ADK integration runs offline in tests and CI."""

from __future__ import annotations

from typing import Any, AsyncGenerator

from google.adk.models import BaseLlm, LlmRequest, LlmResponse
from google.genai import types
from pydantic import PrivateAttr


class ScriptedAdkLlm(BaseLlm):
    model: str = "scripted-adk"
    turns: list[dict[str, Any]] = []
    _i: int = PrivateAttr(default=0)

    async def generate_content_async(
        self, llm_request: LlmRequest, stream: bool = False
    ) -> AsyncGenerator[LlmResponse, None]:
        if self._i >= len(self.turns):
            turn: dict[str, Any] = {"text": "(script ended)"}
        else:
            turn = self.turns[self._i]
            self._i += 1
        parts: list[types.Part] = []
        if turn.get("text"):
            parts.append(types.Part(text=turn["text"]))
        for call in turn.get("tool_calls", []) or []:
            parts.append(types.Part(function_call=types.FunctionCall(name=call["name"], args=call.get("args", {}))))
        yield LlmResponse(content=types.Content(role="model", parts=parts))

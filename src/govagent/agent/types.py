"""Provider-neutral conversation types. Adapters translate these to each vendor's wire format."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, Union

from ..registry import ToolSpec


@dataclass
class ToolCall:
    id: str
    name: str
    args: dict[str, Any]


@dataclass
class UserMessage:
    text: str


@dataclass
class AssistantTurn:
    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    stop_reason: str = ""
    usage: dict[str, int] = field(default_factory=dict)


@dataclass
class ToolResult:
    call_id: str
    name: str
    content: dict[str, Any]
    is_error: bool = False


@dataclass
class ToolResults:
    results: list[ToolResult]


HistoryItem = Union[UserMessage, AssistantTurn, ToolResults]


class ModelAdapter(Protocol):
    """One method: given the system prompt, conversation and tools, return the model's next turn."""

    name: str
    model_id: str

    def complete(self, system: str, history: list[HistoryItem], tools: list[ToolSpec]) -> AssistantTurn: ...

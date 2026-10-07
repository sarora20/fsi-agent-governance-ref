"""Amazon Bedrock adapter (Converse API with toolConfig). Works with any Bedrock model
that supports tool use, including Claude on Bedrock.

Env:
  BEDROCK_MODEL_ID    required: a model id or inference-profile id enabled in your account
  AWS_REGION          optional (falls back to your AWS config)
  plus standard AWS credentials
"""

from __future__ import annotations

import os
from typing import Any

from ..agent.types import AssistantTurn, HistoryItem, ToolCall, ToolResults, UserMessage
from ..registry import ToolSpec


def to_bedrock_messages(history: list[HistoryItem]) -> list[dict[str, Any]]:
    messages: list[dict[str, Any]] = []
    for item in history:
        if isinstance(item, UserMessage):
            messages.append({"role": "user", "content": [{"text": item.text}]})
        elif isinstance(item, ToolResults):
            messages.append({"role": "user", "content": [
                {"toolResult": {"toolUseId": r.call_id, "content": [{"json": r.content}],
                                "status": "error" if r.is_error else "success"}}
                for r in item.results
            ]})
        else:  # AssistantTurn
            content: list[dict[str, Any]] = []
            if item.text:
                content.append({"text": item.text})
            content += [{"toolUse": {"toolUseId": c.id, "name": c.name, "input": c.args}} for c in item.tool_calls]
            messages.append({"role": "assistant", "content": content or [{"text": "(no content)"}]})
    return messages


def parse_bedrock_response(resp: dict[str, Any]) -> AssistantTurn:
    texts, calls = [], []
    for block in resp.get("output", {}).get("message", {}).get("content", []):
        if "text" in block:
            texts.append(block["text"])
        elif "toolUse" in block:
            tu = block["toolUse"]
            calls.append(ToolCall(id=tu["toolUseId"], name=tu["name"], args=dict(tu.get("input") or {})))
    usage = resp.get("usage", {})
    return AssistantTurn(
        text="\n".join(t for t in texts if t).strip(),
        tool_calls=calls,
        stop_reason=resp.get("stopReason", ""),
        usage={"input_tokens": usage.get("inputTokens", 0), "output_tokens": usage.get("outputTokens", 0)},
    )


class BedrockAdapter:
    name = "bedrock"

    def __init__(self, model_id: str | None = None, client: Any | None = None, max_tokens: int = 1024,
                 region: str | None = None):
        self.model_id = model_id or os.environ.get("BEDROCK_MODEL_ID", "")
        if not self.model_id:
            raise ValueError("set BEDROCK_MODEL_ID to a tool-use capable model or inference profile")
        self.max_tokens = max_tokens
        if client is None:
            import boto3  # optional dependency: pip install ".[bedrock]"

            client = boto3.client("bedrock-runtime", region_name=region or os.environ.get("AWS_REGION"))
        self.client = client

    def complete(self, system: str, history: list[HistoryItem], tools: list[ToolSpec]) -> AssistantTurn:
        resp = self.client.converse(
            modelId=self.model_id,
            system=[{"text": system}],
            messages=to_bedrock_messages(history),
            toolConfig={"tools": [
                {"toolSpec": {"name": t.name, "description": t.description, "inputSchema": {"json": t.input_schema}}}
                for t in tools
            ]},
            inferenceConfig={"maxTokens": self.max_tokens},
        )
        return parse_bedrock_response(resp)

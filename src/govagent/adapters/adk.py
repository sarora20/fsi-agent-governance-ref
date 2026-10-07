"""Google Agent Development Kit (ADK) integration.

ADK owns its own agent loop, so instead of a ModelAdapter we plug governance into ADK:

  * every registry tool becomes a GovernedAdkTool whose run_async() calls ToolGateway.invoke()
    (so ADK never executes a tool directly), and
  * a before_tool_callback blocks any tool that is NOT a GovernedAdkTool, so a developer who
    later adds a raw FunctionTool cannot bypass the gateway.

The delegation token travels in ADK session state; the run id is bound inside the token.

Env:
  ADK_MODEL        optional, defaults to gemini-2.5-flash (any ADK-supported model string)
  GOOGLE_API_KEY   or Vertex AI credentials, as ADK expects
"""

from __future__ import annotations

import asyncio
import os
import warnings
from typing import Any

from google.adk.agents import LlmAgent
from google.adk.runners import InMemoryRunner
from google.adk.tools import BaseTool
from google.genai import types

from ..agent.prompts import SYSTEM_PROMPT
from ..agent.runner import GatewayClient, RunResult
from ..audit import AuditLog
from ..identity import peek_run_id
from ..registry import ToolSpec

# we pass JSON schemas straight through to ADK's function declarations
warnings.filterwarnings("ignore", message=r".*JSON_SCHEMA_FOR_FUNC_DECL.*")

TOKEN_KEY = "govagent_delegation_token"
DEFAULT_MODEL = "gemini-2.5-flash"


class GovernedAdkTool(BaseTool):
    def __init__(self, spec: ToolSpec, gateway: GatewayClient):
        super().__init__(name=spec.name, description=spec.description)
        self._spec = spec
        self._gateway = gateway

    def _get_declaration(self) -> types.FunctionDeclaration:
        return types.FunctionDeclaration(
            name=self._spec.name,
            description=self._spec.description,
            parameters_json_schema=self._spec.input_schema,
        )

    async def run_async(self, *, args: dict[str, Any], tool_context: Any) -> Any:
        token = tool_context.state.get(TOKEN_KEY, "")
        key = f"{peek_run_id(token)}:{getattr(tool_context, 'function_call_id', None) or self._spec.name}"
        return self._gateway.invoke(token, self._spec.name, dict(args), idempotency_key=key).to_model()


def make_governance_guard(gateway: GatewayClient):
    """before_tool_callback: defence in depth against ungoverned tools. Blocks and audits them."""

    def governance_guard(tool: BaseTool, args: dict[str, Any], tool_context: Any) -> dict[str, Any] | None:
        if isinstance(tool, GovernedAdkTool):
            return None
        reasons = [f"registry: '{tool.name}' is not a registered tool (blocked by the ADK governance guard)"]
        record = getattr(gateway, "record_external_denial", None)
        if record:
            record(tool_context.state.get(TOKEN_KEY, ""), tool.name, dict(args), reasons)
        return {"status": "denied", "reasons": reasons,
                "guidance": "Do not retry. Tell the user this action is not available."}

    return governance_guard


class GovernedAdkAgent:
    """Builds an ADK LlmAgent whose tools all route through the gateway (local or remote)."""

    name = "adk"

    def __init__(self, gateway: GatewayClient, tools: Any, model: Any | None = None,
                 instruction: str = SYSTEM_PROMPT, extra_tools: list[Any] | None = None,
                 audit: AuditLog | None = None):
        self.gateway = gateway
        self.audit = audit or getattr(gateway, "audit", None) or AuditLog()
        self.model = model or os.environ.get("ADK_MODEL", DEFAULT_MODEL)
        self.model_id = self.model if isinstance(self.model, str) else type(self.model).__name__
        specs = tools.specs() if hasattr(tools, "specs") else list(tools)
        adk_tools: list[Any] = [GovernedAdkTool(s, gateway) for s in specs]
        adk_tools += extra_tools or []
        self.agent = LlmAgent(
            name="advisor_assist_agent",
            model=self.model,
            instruction=instruction,
            tools=adk_tools,
            before_tool_callback=make_governance_guard(gateway),
        )

    def run(self, request: str, token: str, user_id: str = "advisor") -> RunResult:
        return asyncio.run(self.run_async(request, token, user_id))

    async def run_async(self, request: str, token: str, user_id: str = "advisor") -> RunResult:
        run_id = peek_run_id(token)
        self.audit.record("run_started", run_id=run_id, adapter=self.name, model=self.model_id, request=request)
        runner = InMemoryRunner(agent=self.agent, app_name="govagent")
        session = await runner.session_service.create_session(
            app_name="govagent", user_id=user_id, state={TOKEN_KEY: token}
        )
        final_text, steps, stop_reason = "", 0, "completed"
        try:
            async for event in runner.run_async(
                user_id=user_id, session_id=session.id,
                new_message=types.Content(role="user", parts=[types.Part(text=request)]),
            ):
                if event.get_function_calls():
                    steps += 1
                if event.is_final_response() and event.content and event.content.parts:
                    text = "".join(p.text or "" for p in event.content.parts if getattr(p, "text", None))
                    if text:
                        final_text = text
                        steps += 1
        except Exception as exc:
            self.audit.record("model_error", run_id=run_id, adapter=self.name,
                              error=f"{type(exc).__name__}: {str(exc)[:200]}")
            final_text = "The assistant could not complete this request because the model was unavailable."
            stop_reason = "model_error"
        self.gateway.close_run(token)
        self.audit.record("run_finished", run_id=run_id, stop_reason=stop_reason, steps=steps, final_text=final_text)
        return RunResult(run_id, self.name, self.model_id, request, final_text,
                         self.gateway.run_calls(run_id, token), steps, stop_reason)

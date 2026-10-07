"""The agent harness: the runtime around a model that turns it into an agent.

    request ─► [context] ─► model turn ─► tool calls ─► gateway (or a delegated agent) ─► results ─┐
                   ▲                                                                                │
                   └──────────────────────────── until an answer or a budget ◄──────────────────────┘

What the harness owns (and the model does not):
  budgets        steps, tool calls, wall-clock time
  resilience     retries on transient model errors (backoff); a timeout per tool call
  context        oversized tool results are truncated; old turns are dropped in pairs when the
                 conversation outgrows the budget (a tool result never loses its tool call)
  output check   the final answer is checked against what the gateway actually did
                 (guardrails.check_final_answer)
  telemetry      OpenTelemetry spans: invoke_agent / chat / execute_tool (GenAI conventions)

What it does not own: permissions, run state, approvals. The run id comes from the token; every
side effect is decided by the gateway. `gateway` can be the in-process ToolGateway or a
RemoteGateway; the harness cannot tell the difference, which is the point.
"""

from __future__ import annotations

import concurrent.futures
import contextvars
import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

from .. import AGENT_ID, telemetry
from ..agent.prompts import SYSTEM_PROMPT
from ..agent.types import AssistantTurn, HistoryItem, ModelAdapter, ToolResult, ToolResults, UserMessage
from ..audit import AuditLog
from ..gateway import GatewayResult, ToolCallRecord
from ..guardrails import check_final_answer, redact
from ..identity import peek_run_id

TRACER = "govagent.harness"
_POOL = concurrent.futures.ThreadPoolExecutor(max_workers=16, thread_name_prefix="harness-tool")
_TRANSIENT = ("ratelimit", "overloaded", "apiconnection", "timeout", "internalserver", "serviceunavailable",
              "throttl", "529", "503")
_PROVIDERS = {"claude": "anthropic", "bedrock": "aws.bedrock", "adk": "gcp.gemini", "scripted": "scripted"}


class GatewayClient(Protocol):
    def invoke(self, token: str, tool_name: str, args: dict[str, Any],
               idempotency_key: str | None = None, traceparent: str | None = None) -> GatewayResult: ...
    def close_run(self, token: str) -> None: ...
    def run_calls(self, run_id: str, token: str = "") -> list[ToolCallRecord]: ...


@dataclass
class HarnessConfig:
    max_steps: int = 6
    max_tool_calls: int = 12
    max_seconds: float = 180.0
    model_retries: int = 2
    retry_backoff_seconds: float = 0.5
    tool_timeout_seconds: float = 30.0
    max_tool_result_chars: int = 6000
    max_context_chars: int = 80_000
    output_guardrail: bool = True


@dataclass(frozen=True)
class LocalTool:
    """A tool the harness runs itself instead of sending to the gateway (e.g. delegating to another
    agent). `fn(args, token)` returns the result content for the model."""

    name: str
    description: str
    input_schema: dict[str, Any]
    fn: Callable[[dict[str, Any], str], dict[str, Any]]


@dataclass
class RunResult:
    run_id: str
    adapter: str
    model_id: str
    request: str
    final_text: str
    calls: list[ToolCallRecord]
    steps: int
    stop_reason: str
    history: list[HistoryItem] = field(default_factory=list, repr=False)
    usage: dict[str, int] = field(default_factory=dict)
    agent_id: str = AGENT_ID
    guardrail_flags: list[str] = field(default_factory=list)
    trace_id: str | None = None
    delegations: list[dict[str, Any]] = field(default_factory=list)  # sub-agent runs (orchestrator)
    raw_final_text: str = ""  # what the model said, before the output check

    def summary(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id, "agent_id": self.agent_id, "adapter": self.adapter, "model_id": self.model_id,
            "steps": self.steps, "stop_reason": self.stop_reason, "final_text": self.final_text,
            "usage": self.usage, "guardrail_flags": self.guardrail_flags, "trace_id": self.trace_id,
            "calls": [{"call_id": c.call_id, "tool": c.tool, "outcome": c.outcome, "reasons": c.reasons,
                       "risk_tier": c.risk_tier, "flags": c.flags, "action_id": c.action_id, "args": c.args}
                      for c in self.calls],
            "delegations": self.delegations,
        }


def _is_transient(exc: Exception) -> bool:
    text = f"{type(exc).__name__} {exc}".lower()
    return any(t in text for t in _TRANSIENT)


class AgentHarness:
    def __init__(
        self,
        adapter: ModelAdapter,
        gateway: GatewayClient,
        tools: list[Any] | Any,
        system_prompt: str = SYSTEM_PROMPT,
        max_steps: int | None = None,
        audit: AuditLog | None = None,
        *,
        agent_id: str = AGENT_ID,
        agent_name: str | None = None,
        config: HarnessConfig | None = None,
        local_tools: list[LocalTool] | None = None,
    ):
        self.adapter = adapter
        self.gateway = gateway
        # accept a ToolRegistry or a list of specs (a remote gateway publishes its tool list)
        self.tools = tools.specs() if hasattr(tools, "specs") else list(tools)
        self.local_tools = {t.name: t for t in (local_tools or [])}
        self.system_prompt = system_prompt
        self.config = config or HarnessConfig()
        if max_steps is not None:
            self.config.max_steps = max_steps
        self.audit = audit or getattr(gateway, "audit", None) or AuditLog()
        self.agent_id = agent_id
        self.agent_name = agent_name or agent_id

    @property
    def max_steps(self) -> int:
        return self.config.max_steps

    # ------------------------------------------------------------------ the loop

    def run(self, request: str, token: str) -> RunResult:
        run_id = peek_run_id(token)
        with telemetry.span(TRACER, f"invoke_agent {self.agent_name}", "INTERNAL", **{
                "gen_ai.operation.name": "invoke_agent", "gen_ai.agent.id": self.agent_id,
                "gen_ai.agent.name": self.agent_name, "gen_ai.conversation.id": run_id,
                "gen_ai.provider.name": _PROVIDERS.get(self.adapter.name, self.adapter.name),
                "gen_ai.request.model": self.adapter.model_id}) as sp:
            result = self._run(request, token, run_id)
            result.trace_id = telemetry.current_trace_id()
            telemetry.set_attrs(sp, **{"govagent.stop_reason": result.stop_reason, "govagent.steps": result.steps,
                                       "govagent.guardrail_flags": result.guardrail_flags or None,
                                       "gen_ai.usage.input_tokens": result.usage.get("input_tokens"),
                                       "gen_ai.usage.output_tokens": result.usage.get("output_tokens")})
            if result.stop_reason not in ("completed",):
                telemetry.mark_error(sp, result.stop_reason)
            return result

    def _run(self, request: str, token: str, run_id: str) -> RunResult:
        cfg = self.config
        self.audit.record("run_started", run_id=run_id, adapter=self.adapter.name, model=self.adapter.model_id,
                          agent=self.agent_id, request=request)
        history: list[HistoryItem] = [UserMessage(request)]
        usage: dict[str, int] = {}
        delegations: list[dict[str, Any]] = []
        late: list[concurrent.futures.Future] = []  # gateway calls that timed out but may still finish
        final_text, stop_reason, steps, tool_calls = "", "step_budget_exhausted", 0, 0
        started = time.monotonic()
        specs = self.tools + list(self.local_tools.values())

        for steps in range(1, cfg.max_steps + 1):
            if time.monotonic() - started > cfg.max_seconds:
                stop_reason = "time_budget_exhausted"
                final_text = "Stopped: the time budget for this request was reached."
                break
            self._compact(history)
            turn = self._model_turn(history, specs, run_id, steps)
            if turn is None:
                final_text = "The assistant could not complete this request because the model was unavailable."
                stop_reason = "model_error"
                break
            for k, v in turn.usage.items():
                usage[k] = usage.get(k, 0) + int(v or 0)
            history.append(turn)
            self.audit.record("model_turn", run_id=run_id, step=steps, text=turn.text, agent=self.agent_id,
                              tool_calls=[{"name": tc.name, "args": tc.args} for tc in turn.tool_calls],
                              stop_reason=turn.stop_reason)
            if not turn.tool_calls:
                final_text, stop_reason = turn.text, "completed"
                break
            results = []
            for tc in turn.tool_calls:
                tool_calls += 1
                if tool_calls > cfg.max_tool_calls:
                    results.append(ToolResult(tc.id, tc.name, {"status": "denied", "reasons": [
                        "harness: tool-call budget for this request is spent"]}, is_error=True))
                    continue
                results.append(self._tool_call(tc, token, run_id, delegations, late))
            history.append(ToolResults(results))
        else:
            last = next((h for h in reversed(history) if isinstance(h, AssistantTurn) and h.text), None)
            final_text = (last.text if last else "") or "Stopped: the step budget for this request was reached."

        if late:  # let timed-out calls land before the run is closed, so the record and the answer check see them
            done, still = concurrent.futures.wait(late, timeout=cfg.tool_timeout_seconds)
            self.audit.record("late_tool_results", run_id=run_id, agent=self.agent_id, arrived=len(done),
                              still_unknown=len(still))
        self.gateway.close_run(token)
        calls = self.gateway.run_calls(run_id, token)
        raw, flags = final_text, []
        if cfg.output_guardrail:
            with telemetry.span(TRACER, "guardrail final_answer", "INTERNAL") as gsp:
                final_text, flags = check_final_answer(final_text, calls)
                telemetry.set_attrs(gsp, **{"govagent.guardrail_flags": flags or None})
            if flags:
                self.audit.record("output_guardrail", run_id=run_id, agent=self.agent_id, flags=flags)
        self.audit.record("run_finished", run_id=run_id, stop_reason=stop_reason, steps=steps,
                          final_text=redact(final_text))
        return RunResult(run_id, self.adapter.name, self.adapter.model_id, request, final_text, calls, steps,
                         stop_reason, history, usage, self.agent_id, flags, None, delegations, raw)

    # ------------------------------------------------------------------ steps

    def _model_turn(self, history: list[HistoryItem], specs: list[Any], run_id: str,
                    step: int) -> AssistantTurn | None:
        cfg = self.config
        with telemetry.span(TRACER, f"chat {self.adapter.model_id}", "CLIENT", **{
                "gen_ai.operation.name": "chat", "gen_ai.request.model": self.adapter.model_id,
                "gen_ai.provider.name": _PROVIDERS.get(self.adapter.name, self.adapter.name),
                "gen_ai.agent.id": self.agent_id, "govagent.step": step}) as sp:
            for attempt in range(cfg.model_retries + 1):
                try:
                    turn = self.adapter.complete(self.system_prompt, history, specs)
                    telemetry.set_attrs(sp, **{
                        "gen_ai.usage.input_tokens": turn.usage.get("input_tokens"),
                        "gen_ai.usage.output_tokens": turn.usage.get("output_tokens"),
                        "gen_ai.response.finish_reasons": [turn.stop_reason] if turn.stop_reason else None,
                        "govagent.tool_calls": [tc.name for tc in turn.tool_calls] or None})
                    return turn
                except Exception as exc:  # provider outage, auth, throttling
                    error = f"{type(exc).__name__}: {str(exc)[:200]}"
                    sp.add_event("model_error", {"error": error, "attempt": attempt + 1})
                    if attempt < cfg.model_retries and _is_transient(exc):
                        time.sleep(cfg.retry_backoff_seconds * (2 ** attempt))
                        continue
                    self.audit.record("model_error", run_id=run_id, adapter=self.adapter.name, error=error)
                    telemetry.mark_error(sp, error)
                    return None
        return None

    def _tool_call(self, tc: Any, token: str, run_id: str, delegations: list[dict[str, Any]],
                   late: list[concurrent.futures.Future] | None = None) -> ToolResult:
        local = self.local_tools.get(tc.name)
        with telemetry.span(TRACER, f"execute_tool {tc.name}", "INTERNAL", **{
                "gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": tc.name, "gen_ai.tool.call.id": tc.id,
                "gen_ai.tool.type": "extension" if local else "function", "gen_ai.agent.id": self.agent_id}) as sp:
            if local is not None:
                try:
                    content = local.fn(tc.args, token)
                except Exception as exc:  # a failed delegation is a result the model should see
                    content = {"status": "error", "reasons": [f"delegation failed: {type(exc).__name__}: {exc}"]}
                if content.get("delegation"):
                    delegations.append(content.pop("delegation"))
                telemetry.set_attrs(sp, **{"govagent.outcome": content.get("status")})
                return ToolResult(tc.id, tc.name, self._fit(content), is_error=content.get("status") == "error")
            # the model's tool-call id makes a stable idempotency key: a transport retry of this
            # call replays the stored result instead of acting twice
            key = f"{run_id}:{tc.id}"
            ctx = contextvars.copy_context()  # keeps the trace context in the worker thread
            future = _POOL.submit(ctx.run, self.gateway.invoke, token, tc.name, tc.args, key,
                                  telemetry.current_traceparent())
            try:
                gr = future.result(timeout=self.config.tool_timeout_seconds)
            except concurrent.futures.TimeoutError:
                if late is not None:
                    late.append(future)
                gr = GatewayResult("error", "", reasons=[
                    f"harness: no answer from the gateway within {self.config.tool_timeout_seconds:.0f}s; the "
                    "outcome is unknown. Do not retry; report it so a person can check."])
            telemetry.set_attrs(sp, **{"govagent.outcome": gr.status, "govagent.reason": (gr.reasons or [None])[0],
                                       "govagent.call_id": gr.call_id})
            if not gr.ok:
                telemetry.mark_error(sp, (gr.reasons or [gr.status])[0])
            return ToolResult(tc.id, tc.name, self._fit(gr.to_model()), is_error=not gr.ok)

    # ------------------------------------------------------------------ context

    def _fit(self, content: dict[str, Any]) -> dict[str, Any]:
        text = json.dumps(content, default=str)
        if len(text) <= self.config.max_tool_result_chars:
            return content
        return {"status": content.get("status"), "truncated": True,
                "note": f"result shortened by the harness from {len(text)} characters",
                "partial": text[: self.config.max_tool_result_chars]}

    def _compact(self, history: list[HistoryItem]) -> None:
        """Drop the oldest (assistant turn, tool results) pairs until the conversation fits."""
        def size() -> int:
            return sum(len(json.dumps(h.__dict__, default=str)) for h in history)

        dropped = 0
        while size() > self.config.max_context_chars and len(history) > 3 \
                and isinstance(history[1], AssistantTurn) and isinstance(history[2], ToolResults):
            del history[1:3]
            dropped += 1
        if dropped:
            self.audit.record("context_compacted", dropped_turns=dropped, agent=self.agent_id)

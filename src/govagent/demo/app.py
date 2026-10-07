"""Demo web app: front-end API + dev IdP + agent runtime. Talks to the gateway only over HTTP."""

from __future__ import annotations

import json
import os
import threading
import time
import uuid
from pathlib import Path
from typing import Any

import httpx
from fastapi import Body, FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse

from .. import AGENT_ID
from ..adapters.scripted import ScriptedAdapter
from ..agent.runner import AgentRunner, RunResult
from ..agent.types import AssistantTurn, ToolResults, UserMessage
from ..agents import AgentRegistry
from ..app import PRINCIPALS, dev_keyring
from ..audit import AuditLog
from ..identity import AGENT_SCOPES, ROLE_SCOPES, TokenService
from ..pipeline import STAGES, pipeline, stage_for_reason
from ..remote import RemoteGateway
from .. import telemetry
from ..orchestrator import DevTokenBroker, Orchestrator, TokenLedger
from .oidc import KeycloakTokenBroker, LoginRequired, OidcError, OidcIdentity
from .scenarios import (C1002, COMPARE_PAIRS, EXTRA_DEMOS, MULTI_EXTRA, MULTI_SCENARIOS, SCENARIOS, by_id,
                        multi_by_id, wire)

STATIC = Path(__file__).parent / "static"


def available_models() -> dict[str, bool]:
    def has(mod: str) -> bool:
        try:
            __import__(mod)
            return True
        except ImportError:
            return False

    return {
        "scripted": True,
        "claude": bool(os.environ.get("ANTHROPIC_API_KEY")) and has("anthropic"),
        "bedrock": bool(os.environ.get("BEDROCK_MODEL_ID")) and has("boto3"),
        "adk": bool(os.environ.get("GOOGLE_API_KEY") or os.environ.get("GOOGLE_GENAI_USE_VERTEXAI")) and has("google.adk"),
    }


def _transcript(run: RunResult) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for item in run.history:
        if isinstance(item, UserMessage):
            continue
        if isinstance(item, AssistantTurn):
            if item.text:
                events.append({"kind": "assistant", "text": item.text})
            for tc in item.tool_calls:
                events.append({"kind": "tool_call", "tool": tc.name, "args": tc.args})
        elif isinstance(item, ToolResults):
            for r in item.results:
                events.append({"kind": "tool_result", "tool": r.name, "result": r.content})
    return events


class DevIdentity:
    """Dev mode: this process mints tokens with the shared dev signing seed. No sign-in."""

    mode = "dev"

    def __init__(self) -> None:
        # AgentRegistry.from_file() is deterministic (same agents.yaml, same resulting specs), so a
        # second instance here mints audiences consistent with whatever gateway process actually
        # enforces them -- this process never holds that gateway's own Environment.
        self.tokens = TokenService(dev_keyring(shared=True), agent_registry=AgentRegistry.from_file())
        self.broker = DevTokenBroker(self.tokens, PRINCIPALS)

    def agent_token(self, who: str) -> str:
        # as in Keycloak: an agent's token never carries approval or audit scopes
        return self.tokens.issue(PRINCIPALS[who], AGENT_ID, ROLE_SCOPES[PRINCIPALS[who].role] & AGENT_SCOPES)

    def console_token(self, who: str) -> str:
        return self.tokens.issue(PRINCIPALS[who], "demo-console")

    def signed_in(self) -> list[str]:
        return list(PRINCIPALS)


_SIGNED_IN_PAGE = """<!doctype html><meta charset="utf-8"><title>Signed in</title>
<body style="font:15px system-ui;padding:24px">{msg}<script>
if (window.opener) {{ window.opener.postMessage({payload}, location.origin); window.close(); }}
</script></body>"""


def create_demo_app(gateway_url: str = "http://127.0.0.1:8080", gateway_client: httpx.Client | None = None,
                    identity: DevIdentity | OidcIdentity | None = None) -> FastAPI:
    app = FastAPI(title="govagent live demo", version="1.0.0")
    identity = identity or DevIdentity()
    broker = identity.broker if identity.mode == "dev" else KeycloakTokenBroker(identity)
    ledger: TokenLedger = broker.ledger
    telemetry.setup("advisor-console")
    remote = RemoteGateway(gateway_url, client=gateway_client)
    agent_audit = AuditLog()  # the agent runtime's own trace; the gateway keeps the authoritative log
    history: dict[str, list[tuple[str, str]]] = {}
    lock = threading.Lock()

    def token_for(who: str) -> str:
        """A token for one agent run (dev: minted here; Keycloak: RFC 8693 exchange of the person's token)."""
        return broker.person_to_agent(who, AGENT_ID)

    def auth(who: str) -> dict[str, str]:
        """The person's own token, for console actions (approve, read audit)."""
        return {"Authorization": f"Bearer {identity.console_token(who)}"}

    @app.exception_handler(LoginRequired)
    def login_required(_: Request, exc: LoginRequired):
        p = PRINCIPALS[exc.who]
        return JSONResponse({"error": "login_required", "who": exc.who, "name": p.display_name, "role": p.role,
                             "login_url": f"/auth/login?as={exc.who}"}, status_code=401)

    @app.exception_handler(OidcError)
    def oidc_error(_: Request, exc: OidcError):
        return JSONResponse({"error": f"authorization server: {exc}"}, status_code=502)

    # ------------------------------------------------------------------ sign-in (Keycloak mode)

    @app.get("/auth/login")
    def login(request: Request):
        who = request.query_params.get("as", "ana")
        if identity.mode != "keycloak" or who not in PRINCIPALS:
            return RedirectResponse("/")
        redirect_uri = str(request.url_for("auth_callback"))
        return RedirectResponse(identity.authorize_url(who, redirect_uri), status_code=302)

    @app.get("/auth/callback", name="auth_callback")
    def auth_callback(code: str = "", state: str = "", error: str = "", error_description: str = ""):
        if error:
            msg, payload = f"Sign-in failed: {error} {error_description}", {"type": "signin-failed", "error": error}
        else:
            try:
                who = identity.complete_login(state, code)
                msg = f"Signed in as {PRINCIPALS[who].display_name}. You can close this window."
                payload = {"type": "signed-in", "who": who}
            except OidcError as exc:
                msg, payload = f"Sign-in failed: {exc}", {"type": "signin-failed", "error": exc.error}
        import json as _json

        return HTMLResponse(_SIGNED_IN_PAGE.format(msg=msg.replace("<", "&lt;"), payload=_json.dumps(payload)))

    @app.post("/auth/logout")
    def logout(body: dict[str, Any] = Body(...)):
        if identity.mode == "keycloak":
            identity.sign_out(str(body.get("as", "")))
        return {"signed_in": identity.signed_in()}

    def adapter_for(model: str, script: list[dict] | None):
        if model == "claude":
            from ..adapters.claude import ClaudeAdapter

            return ClaudeAdapter()
        if model == "bedrock":
            from ..adapters.bedrock import BedrockAdapter

            return BedrockAdapter()
        return ScriptedAdapter(script or [{"text": "(scripted mode: pick a scenario, or add an API key for live chat)"}])

    def run_once(who: str, message: str, model: str, script: list[dict] | None = None,
                 context: str = "") -> dict[str, Any]:
        token = token_for(who)
        request = f"{context}\n\nCurrent request: {message}" if context else message
        if model == "adk":
            from ..adapters.adk import GovernedAdkAgent

            run = GovernedAdkAgent(remote, remote.tools(token), audit=agent_audit).run(request, token)
        else:
            run = AgentRunner(adapter_for(model, script), remote, remote.tools(token), audit=agent_audit).run(
                request, token)
        calls = []
        for c in run.calls:
            d = c.__dict__.copy()
            d["agent"] = AGENT_ID
            d["pipeline"] = pipeline(d)
            calls.append(d)
        return {"run_id": run.run_id, "principal": who, "model": run.model_id, "message": message, "mode": "single",
                "final_text": run.final_text, "stop_reason": run.stop_reason, "calls": calls,
                "guardrail_flags": getattr(run, "guardrail_flags", []), "trace_id": telemetry.current_trace_id(),
                "transcript": _transcript(run), "token": token}

    def run_multi(who: str, message: str, model: str, scripts: dict[str, list] | None = None,
                  context: str = "") -> dict[str, Any]:
        """Orchestrator + specialists. Scripted scenarios give each agent its own script(s)."""
        queues = {k: list(v) for k, v in (scripts or {}).items()}

        def adapter_for_agent(agent_id: str):
            if model == "scripted":
                q = queues.get(agent_id) or [[{"text": "(scripted mode: pick a multi-agent scenario, or add an "
                                                      "API key for live chat)"}]]
                return ScriptedAdapter(q.pop(0))
            return adapter_for(model, None)

        request = f"{context}\n\nCurrent request: {message}" if context else message
        orch = Orchestrator(remote, None, broker, adapter_for_agent, audit=agent_audit)
        run = orch.run(who, request)

        def view(summary_calls: list[dict], agent: str) -> list[dict]:
            out = []
            for c in summary_calls:
                d = {**c, "agent": agent, "approval": c.get("approval"), "replayed": c.get("replayed", False)}
                d["pipeline"] = pipeline(d)
                out.append(d)
            return out

        calls = view(run.summary()["calls"], "orchestrator-agent")
        delegations = []
        for dlg in run.delegations:
            sub = view(dlg.get("calls", []), dlg.get("agent_id", "?"))
            calls += sub
            delegations.append({"agent_id": dlg.get("agent_id"), "task": dlg.get("task"),
                                "final_text": dlg.get("final_text", dlg.get("refused", "")), "calls": sub,
                                "guardrail_flags": dlg.get("guardrail_flags", []), "run_id": dlg.get("run_id")})
        return {"run_id": run.run_id, "principal": who, "model": run.model_id, "message": message, "mode": "multi",
                "final_text": run.final_text, "stop_reason": run.stop_reason, "calls": calls,
                "delegations": delegations, "guardrail_flags": run.guardrail_flags,
                "trace_id": telemetry.current_trace_id(), "transcript": _transcript(run)}

    def traced(name: str, who: str, fn, *args, **kwargs) -> dict[str, Any]:
        """Root span for one advisor request; every downstream span (harness, IdP, gateway) joins it.

        new_trace keeps it a root even under a framework request span, so the two runs behind one
        /api/compare call stay in separate traces.
        """
        with telemetry.span("govagent.console", name, "SERVER", new_trace=True,
                            **{"enduser.id": PRINCIPALS[who].user_id,
                               "govagent.idp": identity.mode}):
            last_trace[0] = telemetry.current_trace_id()
            out = fn(*args, **kwargs)
            if isinstance(out, dict):
                out.setdefault("trace_id", last_trace[0])
            return out

    last_trace: list[str | None] = [None]

    # ------------------------------------------------------------------ pages

    @app.get("/")
    def index():
        return FileResponse(STATIC / "index.html")

    @app.get("/api/config")
    def config() -> dict[str, Any]:
        return {
            "gateway_url": gateway_url,
            "idp": {"mode": identity.mode, "signed_in": identity.signed_in(),
                    **({"issuer": identity.config.issuer} if identity.mode == "keycloak" else {})},
            "models": available_models(),
            "principals": [{"key": k, "id": p.user_id, "name": p.display_name, "role": p.role,
                            "clients": sorted(p.entitled_clients)} for k, p in PRINCIPALS.items()],
            "scenarios": [{k: s[k] for k in ("id", "title", "principal", "why")} for s in SCENARIOS],
            "extra_demos": EXTRA_DEMOS,
            "multi_scenarios": [{k: s[k] for k in ("id", "title", "principal", "why")} for s in MULTI_SCENARIOS]
                               + MULTI_EXTRA,
            "compare_pairs": COMPARE_PAIRS,
            "jaeger_url": os.environ.get("JAEGER_UI_URL"),
            "stages": [{"stage": k, "label": v} for k, v in STAGES],
        }

    # ------------------------------------------------------------------ advisor chat

    @app.post("/api/chat")
    def chat(body: dict[str, Any] = Body(...)):
        who = body.get("principal", "ana")
        model = body.get("model", "scripted")
        message = str(body.get("message", "")).strip()
        if who not in PRINCIPALS or not message:
            return JSONResponse({"error": "principal and message required"}, status_code=400)
        if not available_models().get(model):
            return JSONResponse({"error": f"model '{model}' is not configured"}, status_code=400)
        session = body.get("session", who)
        with lock:
            past = history.setdefault(session, [])[-3:]
        context = "\n".join(f"Earlier, the advisor asked: {q}\nYou answered: {a}" for q, a in past)
        multi = body.get("mode") == "multi"
        try:
            if multi:
                result = traced("advisor request (multi-agent)", who, run_multi, who, message, model, context=context)
            else:
                result = traced("advisor request", who, run_once, who, message, model, context=context)
        except (LoginRequired, OidcError):
            raise
        except Exception as exc:  # surface provider/config errors to the UI instead of a 500
            return JSONResponse({"error": f"{type(exc).__name__}: {str(exc)[:300]}"}, status_code=502)
        with lock:
            history[session].append((message, result["final_text"]))
        result.pop("token", None)
        return {"runs": [result]}

    @app.post("/api/scenario/{scenario_id}")
    def scenario(scenario_id: str):
        if scenario_id == "retry":
            return _with_trace(traced("scenario retry", "ana", retry_demo))
        if scenario_id == "token-replay":
            return _with_trace(traced("scenario token-replay", "ana", token_replay_demo))
        if scenario_id == "four-eyes":
            return _with_trace(traced("scenario four-eyes", "ana", four_eyes_demo))
        if scenario_id == "multi-skip-orchestrator":
            return skip_orchestrator_demo()
        return run_scenario(scenario_id)

    def _with_trace(out: dict[str, Any]) -> dict[str, Any]:
        for r in out.get("runs", []):
            r.setdefault("trace_id", out.get("trace_id"))
        return out

    def run_scenario(scenario_id: str) -> dict[str, Any] | JSONResponse:
        m = multi_by_id(scenario_id)
        if m is not None:
            out = traced(f"scenario {scenario_id}", m["principal"], run_multi, m["principal"], m["message"],
                         "scripted", m["scripts"])
            return {"scenario": {k: m[k] for k in ("id", "title", "why")}, "runs": [out]}
        s = by_id(scenario_id)
        if s is None:
            return JSONResponse({"error": "unknown scenario"}, status_code=404)
        runs = []
        for r in s["runs"]:
            out = traced(f"scenario {scenario_id}", s["principal"], run_once, s["principal"], r["message"],
                         "scripted", r["script"])
            out.pop("token", None)
            runs.append(out)
        return {"scenario": {k: s[k] for k in ("id", "title", "why")}, "runs": runs}

    def skip_orchestrator_demo():
        def attempt() -> dict[str, Any]:
            wire_args = wire(1000)["args"]
            try:
                if identity.mode == "keycloak":
                    token = identity.exchange(identity.console_token("ana"), "payments-agent",
                                              frozenset({"payments:initiate"}))
                else:
                    token = identity.tokens.issue(PRINCIPALS["ana"], "payments-agent", ["payments:initiate"])
                    ledger.record("dev-issue", token, requester="payments-agent", agent="payments-agent",
                                  note="payments agent asked for a token straight from Ana's (no orchestrator)")
            except OidcError as exc:
                return {"final_text": f"Keycloak refused the token exchange: {exc}. The payments agent is not in "
                                      "the audience of Ana's token, so it cannot act for her directly.",
                        "calls": []}
            with telemetry.span("govagent.harness", "execute_tool initiate_wire_transfer", "INTERNAL",
                                **{"gen_ai.agent.id": "payments-agent"}):
                r = remote.invoke(token, "initiate_wire_transfer", wire_args, idempotency_key=uuid.uuid4().hex,
                                  traceparent=telemetry.current_traceparent())
            remote.close_run(token)
            view = _call_view("initiate_wire_transfer", r.to_dict(), wire_args)
            view["agent"] = "payments-agent"
            return {"final_text": "; ".join(r.reasons) or r.status, "calls": [view]}

        out = traced("scenario multi-skip-orchestrator", "ana", attempt)
        return {"scenario": MULTI_EXTRA[0], "runs": [{
            "run_id": "direct", "principal": "ana", "model": "direct HTTP", "mode": "multi",
            "message": "Payments agent: get a token from Ana's directly and send a wire",
            "trace_id": out.pop("trace_id", None) or last_trace[0], **out, "transcript": []}]}

    # ------------------------------------------------------------------ traces, tokens, compare

    @app.get("/api/trace/{trace_id}")
    def trace(trace_id: str):
        own = telemetry.store().get(trace_id) if telemetry.store() else []
        try:
            gw_spans = remote.client.get(f"/v1/dev/traces/{trace_id}").json().get("spans", [])
        except (httpx.HTTPError, ValueError):
            gw_spans = []
        by_id = {sp["span_id"]: sp for sp in own + gw_spans}  # in-process tests share one store
        spans = sorted(by_id.values(), key=lambda sp: sp["start_ns"])
        return {"trace_id": trace_id, "spans": spans,
                "jaeger": f"{os.environ['JAEGER_UI_URL'].rstrip('/')}/trace/{trace_id}"
                          if os.environ.get("JAEGER_UI_URL") else None}

    @app.get("/api/tokens")
    def tokens(trace_id: str):
        return {"trace_id": trace_id, "idp": identity.mode, "events": ledger.for_trace(trace_id)}

    @app.post("/api/tokens/{event_id}/validate")
    def validate_token(event_id: str):
        event = ledger.get(event_id)
        if event is None:
            return JSONResponse({"error": "unknown token (the demo keeps recent tokens in memory only)"}, 404)
        resp = remote.client.post("/v1/dev/explain-token", json={"token": event["token"]})
        return JSONResponse(resp.json(), status_code=resp.status_code)

    @app.post("/api/compare/{pair_id}")
    def compare(pair_id: str):
        pair = next((p for p in COMPARE_PAIRS if p["id"] == pair_id), None)
        if pair is None:
            return JSONResponse({"error": "unknown pair"}, status_code=404)
        out = {"pair": pair}
        for side in ("allowed", "denied"):
            res = run_scenario(pair[side])
            if isinstance(res, JSONResponse):
                return res
            out[side] = {**res, "run": res["runs"][-1]}
        return out

    def _call_view(tool: str, result: dict[str, Any], args: dict[str, Any]) -> dict[str, Any]:
        d = {"call_id": result.get("call_id", ""), "tool": tool, "args": args, "outcome": result.get("status"),
             "reasons": result.get("reasons", []), "action_id": result.get("action_id"),
             "replayed": result.get("replayed", False), "flags": [], "approval": None, "risk_tier": None}
        d["pipeline"] = pipeline(d)
        return d

    def retry_demo():
        token = token_for("ana")
        args = {"client_id": "C-1001", "subject": "Annual review",
                "body": "A reminder that your annual review is due this quarter."}
        key = f"retry-{uuid.uuid4().hex[:8]}"
        first = remote.invoke(token, "draft_client_email", args, idempotency_key=key)
        second = remote.invoke(token, "draft_client_email", args, idempotency_key=key)
        changed = remote.invoke(token, "draft_client_email", {**args, "body": "Different text"}, idempotency_key=key)
        remote.close_run(token)
        calls = [_call_view("draft_client_email", r.to_dict(), a) for r, a in
                 ((first, args), (second, args), (changed, {**args, "body": "Different text"}))]
        notes = [f"1st call: {first.status}, draft {((first.data or {}).get('draft_id'))}",
                 f"2nd call, same key: {second.status}, replayed={second.replayed}, same draft "
                 f"{((second.data or {}).get('draft_id'))}",
                 f"3rd call, same key, different body: {changed.status} ({'; '.join(changed.reasons)})"]
        return {"scenario": next(d for d in EXTRA_DEMOS if d["id"] == "retry"),
                "runs": [{"run_id": "retry-demo", "principal": "ana", "model": "direct HTTP",
                          "message": "Send the same request three times with one Idempotency-Key",
                          "final_text": "\n".join(notes), "calls": calls, "transcript": []}]}

    def token_replay_demo():
        first = run_once("ana", "What does C-1001 hold?", "scripted",
                         [{"tool_calls": [{"name": "get_positions", "args": {"client_id": "C-1001"}}]},
                          {"text": "C-1001 holds VTI, BND and VXUS."}])
        replay = remote.invoke(first.pop("token"), "get_positions", {"client_id": "C-1001"})
        second = {"run_id": first["run_id"] + " (replayed)", "principal": "ana", "model": "direct HTTP",
                  "message": "Re-use the finished run's token", "final_text": "; ".join(replay.reasons),
                  "calls": [_call_view("get_positions", replay.to_dict(), {"client_id": "C-1001"})],
                  "transcript": []}
        return {"scenario": next(d for d in EXTRA_DEMOS if d["id"] == "token-replay"), "runs": [first, second]}

    def four_eyes_demo():
        created = run_once("ana", "Wire $5,000 from 40055555555 to B-2002 for C-1002.", "scripted",
                           [{"tool_calls": [wire(5000, **C1002)]}, {"text": "Submitted for approval."}])
        created.pop("token", None)
        action_id = next((c["action_id"] for c in created["calls"] if c.get("action_id")), None)
        attempt = describe_decision(action_id, "ana", decide_as(action_id, "ana", True, "approving my own request")) \
            if action_id else {}
        created["final_text"] += f"\n\nAna tries to approve {action_id} herself: {attempt.get('status')}. " \
                                 f"{'; '.join(attempt.get('reasons', []))}"
        return {"scenario": next(d for d in EXTRA_DEMOS if d["id"] == "four-eyes"), "runs": [created]}

    # ------------------------------------------------------------------ supervisor

    def decide_as(action_id: str, who: str, approve: bool, note: str) -> dict[str, Any]:
        resp = remote.client.post(f"/v1/approvals/{action_id}/decision", headers=auth(who),
                                  json={"approve": approve, "note": note})
        data = resp.json()
        data["http_status"] = resp.status_code
        return data

    @app.get("/api/approvals")
    def approvals(who: str = "sup"):
        resp = remote.client.get("/v1/approvals", headers=auth(who))
        return JSONResponse(resp.json(), status_code=resp.status_code)

    @app.post("/api/approvals/{action_id}")
    def decide(action_id: str, body: dict[str, Any] = Body(...)):
        who = body.get("as", "sup")
        if who not in PRINCIPALS:
            return JSONResponse({"error": "unknown approver"}, status_code=400)
        data = decide_as(action_id, who, bool(body.get("approve")), str(body.get("note", "")))
        return describe_decision(action_id, who, data)

    def describe_decision(action_id: str, who: str, data: dict[str, Any]) -> dict[str, Any]:
        status = data.get("status")
        reasons = list(data.get("reasons") or [])
        if not status:  # refused before reaching the decision (HTTP 401/403)
            status = "approval_denied"
            if data.get("error") == "insufficient_scope":
                reasons = [f"{PRINCIPALS[who].display_name}'s token has no approvals:decide scope; "
                           "only supervisors can approve (the gateway also enforces four-eyes)"]
            else:
                reasons = [str(data.get("error_description") or data.get("error") or "refused")]
        view = {"tool": "", "args": {}, "outcome": status, "reasons": reasons, "action_id": action_id,
                "approval": {"approver": PRINCIPALS[who].user_id} if status == "executed" else None,
                "flags": [], "replayed": False}
        show_pipe = status == "executed" or any(r.startswith("revalidation") for r in reasons)
        return {"status": status, "reasons": reasons, "data": data.get("data"),
                "pipeline": pipeline(view) if show_pipe else None}

    @app.get("/api/actions/{action_id}")
    def action(action_id: str, who: str = "ana"):
        resp = remote.client.get(f"/v1/actions/{action_id}", headers=auth(who))
        return JSONResponse(resp.json(), status_code=resp.status_code)

    # ------------------------------------------------------------------ compliance

    @app.get("/api/audit")
    def audit(who: str = "cmp", run_id: str | None = None, limit: int = 300):
        """Reads with whichever identity the console names -- not always compliance. Naming it, and
        letting it be switched to any of the five people, is what makes 'audit:read is scope-gated'
        a demonstrable claim rather than a caption: point it at an advisor's token and watch the
        gateway refuse it, live."""
        if who not in PRINCIPALS:
            return JSONResponse({"error": "unknown principal"}, status_code=400)
        params = {"limit": limit, **({"run_id": run_id} if run_id else {})}
        resp = remote.client.get("/v1/audit/entries", headers=auth(who), params=params)
        data = resp.json()
        read_as = {"key": who, "name": PRINCIPALS[who].display_name, "role": PRINCIPALS[who].role}
        return JSONResponse({**data, "read_as": read_as}, status_code=resp.status_code)

    # ------------------------------------------------------- what the gateway enforces

    def _authority() -> dict[str, Any]:
        """Ask the gateway for the rules it is actually enforcing. The console has no policy of
        its own, so this is the only honest source — a copy here could drift from the gateway."""
        return remote.authority(identity.console_token("cmp"))

    @app.get("/api/registry")
    def registry_view():
        a = _authority()
        return {"tools": a["tools"], "agents": a["agents"], "role_scopes": a["role_scopes"],
                "stages": [{"stage": k, "label": v} for k, v in STAGES]}

    @app.get("/api/policy")
    def policy_view():
        a = _authority()
        return {"policy": a["policy"], "tools": a["tools"]}

    @app.get("/api/graph")
    def graph_view():
        a = _authority()
        try:
            resp = remote.client.get("/v1/audit/entries", headers=auth("cmp"), params={"limit": 5000})
            adt = resp.json() if resp.status_code == 200 else {"entries": [], "intact": None, "total": 0}
        except httpx.HTTPError:
            adt = {"entries": [], "intact": None, "total": 0}
        entries = adt.get("entries") or []

        by_stage: dict[str, int] = {}
        events: dict[str, int] = {}
        outcomes: dict[str, int] = {}
        tools_seen: dict[str, int] = {}
        for e in entries:
            events[e.get("event", "?")] = events.get(e.get("event", "?"), 0) + 1
            if e.get("outcome"):
                outcomes[e["outcome"]] = outcomes.get(e["outcome"], 0) + 1
            if e.get("tool"):
                tools_seen[e["tool"]] = tools_seen.get(e["tool"], 0) + 1
            for r in (e.get("reasons") or []):
                st = stage_for_reason(r)
                by_stage[st] = by_stage.get(st, 0) + 1

        known = {t["name"] for t in a["tools"]}
        gn: list[dict] = []
        ge: list[dict] = []
        for t in a["tools"]:
            gn.append({"id": "tool:" + t["name"], "label": t["name"], "group": "Tool",
                       "desc": t["description"], "tier": t["risk_tier"], "scope": t["required_scope"],
                       "decision": t["policy"]["decision"]})
            for r in t["policy"]["rules"]:
                rid = "rule:" + str(r["id"])
                gn.append({"id": rid, "label": str(r["id"]), "group": "Policy rule",
                           "desc": r["reason"], "decision": r["decision"]})
                ge.append({"s": "tool:" + t["name"], "t": rid, "rel": "constrained by"})
        for v in a["policy"]["velocity"]:
            vid = "vel:" + v["id"]
            lim = ", ".join(filter(None, [
                (str(v["max_count"]) + " calls") if v["max_count"] else "",
                ("$" + format(v["max_sum"], ",.0f")) if v["max_sum"] else ""]))
            gn.append({"id": vid, "label": v["id"], "group": "Velocity limit",
                       "desc": v["reason"], "per": v["per"] + " · " + lim})
            ge.append({"s": "tool:" + v["tool"], "t": vid, "rel": "rate-limited by"})

        an: list[dict] = []
        ae: list[dict] = []
        for role, scopes in a["role_scopes"].items():
            an.append({"id": "role:" + role, "label": role, "group": "Role",
                       "desc": str(len(scopes)) + " scopes"})
            for s in scopes:
                ae.append({"s": "role:" + role, "t": "scope:" + s, "rel": "grants"})
        for s in sorted({x for v in a["role_scopes"].values() for x in v}):
            an.append({"id": "scope:" + s, "label": s, "group": "OAuth scope"})
        for ag in ((a["agents"] or {}).get("list") or []):
            an.append({"id": "agent:" + ag["id"], "label": ag["id"], "group": "Agent",
                       "desc": ag["description"] or ag["name"]})
            for t in ag["tools"]:
                ae.append({"s": "agent:" + ag["id"], "t": "tool:" + t, "rel": "may call"})
            for d in ag["may_delegate_to"]:
                ae.append({"s": "agent:" + ag["id"], "t": "agent:" + d, "rel": "may delegate to"})
        for t in a["tools"]:
            an.append({"id": "tool:" + t["name"], "label": t["name"], "group": "Tool",
                       "tier": t["risk_tier"], "scope": t["required_scope"]})
            ae.append({"s": "scope:" + t["required_scope"], "t": "tool:" + t["name"], "rel": "required by"})

        rn: list[dict] = []
        re_: list[dict] = []
        for ev, n in sorted(events.items(), key=lambda kv: -kv[1]):
            rn.append({"id": "ev:" + ev, "label": ev, "group": "Audit event", "count": n})
        for o, n in sorted(outcomes.items(), key=lambda kv: -kv[1]):
            rn.append({"id": "out:" + o, "label": o, "group": "Outcome", "count": n})
        for t, n in sorted(tools_seen.items(), key=lambda kv: -kv[1]):
            rn.append({"id": "rt:" + t, "label": t, "group": "Tool", "count": n,
                       "desc": "registered" if t in known else "not registered — stopped at Tool registered"})
            re_.append({"s": "rt:" + t, "t": "out:executed" if t in known else "out:denied",
                        "rel": "resulted in"})
        for st, n in sorted(by_stage.items(), key=lambda kv: -kv[1]):
            label = dict(STAGES).get(st, st)
            rn.append({"id": "ctl:" + st, "label": label, "group": "Stage that stopped a call", "count": n})
            re_.append({"s": "ctl:" + st, "t": "out:denied", "rel": "produced"})

        return {
            "meta": {"audit_events": adt.get("total", len(entries)), "intact": adt.get("intact"),
                     "tools": len(a["tools"]),
                     "agents": len((a["agents"] or {}).get("list") or []),
                     "max_depth": (a["agents"] or {}).get("max_delegation_depth"),
                     "policy_version": a["policy"]["version"], "idp": identity.mode},
            "checks": [{"n": i + 1, "stage": k, "label": v, "fired": by_stage.get(k, 0)}
                       for i, (k, v) in enumerate(STAGES)],
            "layers": {
                "governance": {"name": "Governance", "nodes": gn, "edges": ge,
                               "blurb": "Tools and their risk tiers, with the policy rules and "
                                        "cross-run limits the gateway applies to each."},
                "identity": {"name": "Identity & agents", "nodes": an, "edges": ae,
                             "blurb": "Roles and the scopes they grant, and the agent registry — "
                                      "which agent may call which tool, and who may delegate to whom."},
                "runtime": {"name": "Runtime evidence", "nodes": rn, "edges": re_,
                            "blurb": "Measured from this gateway's audit log: what ran, what was "
                                     "refused, and which stage stopped it."},
            },
        }

    # ------------------------------------------------------------------ scored testing (evals)

    reports_dir = Path(os.environ.get("GOVAGENT_REPORTS", "reports"))
    cases_dir = Path(os.environ.get("GOVAGENT_CASES", "evals/cases"))
    job: dict[str, Any] = {"state": "idle"}
    job_lock = threading.Lock()

    def job_snapshot() -> dict[str, Any]:
        with job_lock:
            return {k: (list(v) if isinstance(v, list) else v) for k, v in job.items()}

    def _summary(data: dict[str, Any]) -> dict[str, Any]:
        return {k: data.get(k) for k in ("adapter", "model_id", "started_at", "gate_passed", "trials", "scores",
                                         "pass_rate")}

    @app.get("/api/evals")
    def evals_index():
        latest, history = [], []
        if reports_dir.exists():
            for f in sorted(reports_dir.glob("eval-*.json")):
                try:
                    latest.append(_summary(json.loads(f.read_text())))
                except (OSError, ValueError):
                    continue
            for f in sorted((reports_dir / "history").glob("eval-*.json"))[-60:]:
                try:
                    history.append(_summary(json.loads(f.read_text())))
                except (OSError, ValueError):
                    continue
        return {"latest": latest, "history": history, "cases_found": cases_dir.exists(),
                "live": {"claude": available_models()["claude"], "bedrock": available_models()["bedrock"]},
                "job": job_snapshot()}

    @app.get("/api/evals/report/{adapter}")
    def eval_report(adapter: str):
        f = reports_dir / f"eval-{adapter}.json"
        if not f.exists() or "/" in adapter:
            return JSONResponse({"error": "no report yet for this adapter"}, status_code=404)
        return json.loads(f.read_text())

    @app.post("/api/evals/run")
    def eval_run(body: dict[str, Any] = Body(default_factory=dict)):
        from ..evals import load_cases, run_suite, write_report

        adapter = str(body.get("adapter", "scripted"))
        trials = max(1, min(int(body.get("trials", 1)), 10))
        if adapter not in ("scripted", "scripted-remote", "adk-scripted", "claude", "bedrock"):
            return JSONResponse({"error": "unknown adapter"}, status_code=400)
        if adapter in ("claude", "bedrock") and not available_models()[adapter]:
            return JSONResponse({"error": f"{adapter} is not configured (API key)"}, status_code=400)
        if not cases_dir.exists():
            return JSONResponse({"error": f"eval cases not found at {cases_dir}"}, status_code=404)
        cases = load_cases(cases_dir)
        judge = None
        if body.get("judge") and available_models()["claude"]:
            from ..evals.graders import ClaudeJudge

            judge = ClaudeJudge()
        with job_lock:  # check-and-start is atomic: one run at a time
            if job.get("state") == "running":
                return JSONResponse({"error": "an eval run is already in progress"}, status_code=409)
            job.clear()
            job.update({"state": "running", "adapter": adapter, "trials": trials, "done": 0, "total": len(cases),
                        "failed": [], "started": time.time()})

        def progress(r):
            with job_lock:
                job["done"] += 1
                job["last"] = r.case_id
                if not r.passed and not r.skipped:
                    job["failed"].append(r.case_id)

        def work():
            try:
                report = run_suite(cases, adapter, audit_path=reports_dir / f"audit-{adapter}.jsonl", judge=judge,
                                   progress=progress, trials=trials)
                write_report(report, reports_dir)
                with job_lock:
                    job.update({"state": "done", "gate_passed": report.gate_passed, "scores": report.scores()})
            except Exception as exc:  # surface to the dashboard
                with job_lock:
                    job.update({"state": "error", "error": f"{type(exc).__name__}: {str(exc)[:300]}"})

        threading.Thread(target=work, daemon=True, name="eval-run").start()
        return job_snapshot()

    @app.post("/api/reset")
    def reset():
        resp = remote.client.post("/v1/dev/reset")
        ledger.clear()
        if telemetry.store():
            telemetry.store().clear()
        with lock:
            history.clear()
        return JSONResponse(resp.json(), status_code=resp.status_code)

    @app.get("/api/health")
    def health():
        try:
            ok = remote.client.get("/.well-known/oauth-protected-resource").status_code == 200
        except httpx.HTTPError:
            ok = False
        idp = True
        if identity.mode == "keycloak":
            try:
                idp = identity.http.get(identity.config.jwks_uri).status_code == 200
            except httpx.HTTPError:
                idp = False
        return {"gateway": ok, "idp": idp, "idp_mode": identity.mode}

    @app.get("/api/controls")
    def controls():
        """Kill-switch and breaker state, for the header indicator. /v1/metrics is public (no
        token), same as /v1/audit/verify."""
        try:
            data = remote.client.get("/v1/metrics").json()
        except httpx.HTTPError:
            return {"reachable": False, "stop": {"global": None, "tools": {}, "agents": {}}, "breakers": {}}
        return {"reachable": True, "stop": data.get("stop", {}), "breakers": data.get("breakers", {})}

    return app

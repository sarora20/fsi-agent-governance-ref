"""The gateway as its own service (policy enforcement point over HTTP).

Deployment boundary:
  agent runtime   holds a delegation token + this service's URL. No backend credentials.
  this service    holds public signing keys, the state store, policy, and backend credentials.
  backends        reachable only from this service (network policy / private endpoints).

Protocol choices follow the MCP authorization spec (current revision 2026-07-28) and the RFCs it cites:
  * bearer token in the Authorization header only, never in the query string (RFC 6750)
  * audience validation: tokens must be issued for this resource (RFC 8707)
  * 401 + WWW-Authenticate with resource_metadata (RFC 9728 §5.1) and the scope the call needs
  * 403 + WWW-Authenticate error="insufficient_scope", scope=..., resource_metadata=... when the
    token lacks a scope (RFC 6750 §3.1; MCP "Scope Challenge Handling"); plain 403 for policy denial
  * protected-resource metadata at /.well-known/oauth-protected-resource (RFC 9728)
  * no token passthrough: backends get a gateway-minted Transaction Token instead (txn.py)
  * pending approvals behave like MCP task handles: the caller polls GET /v1/actions/{id}
  * W3C `traceparent` is accepted and recorded, matching MCP's OpenTelemetry trace conventions
  * a policy decision point is exposed over OpenID AuthZEN Authorization API 1.0 (pdp.py)
Idempotency-Key header semantics follow draft-ietf-httpapi-idempotency-key-header:
  400 missing key, 409 same key in progress, 422 key reused with a different payload.
"""

from __future__ import annotations

from typing import Any

import json
import re

from fastapi import Body, FastAPI, Header, Request
from fastapi.responses import JSONResponse

from . import AGENT_VERSION, pdp, telemetry

from .app import Environment
from .gateway import (APPROVAL_DENIED, CONFLICT, DENIED, ERROR, EXECUTED, EXPIRED, PENDING, REJECTED,
                      GatewayResult)
from .identity import ROLE_SCOPES, TokenError, peek_run_id

METADATA_PATH = "/.well-known/oauth-protected-resource"


def _status_code(result: GatewayResult) -> int:
    first = result.reasons[0] if result.reasons else ""
    if result.status == DENIED and first.startswith("identity:"):
        return 401
    if result.status == REJECTED and first.startswith("idempotency: key reused"):
        return 422
    return {EXECUTED: 200, PENDING: 202, DENIED: 403, APPROVAL_DENIED: 403, REJECTED: 400,
            CONFLICT: 409, EXPIRED: 410, ERROR: 502}[result.status]


def create_app(env: Environment, base_url: str = "http://localhost:8080", dev_mode: bool = False) -> FastAPI:
    app = FastAPI(title="govagent gateway", version="0.3.0")
    gw = env.gateway
    www_auth = f'Bearer resource_metadata="{base_url}{METADATA_PATH}"'

    def unauthorized(detail: str, scope: str | None = None) -> JSONResponse:
        header = www_auth + (f', scope="{scope}"' if scope else "")
        return JSONResponse({"error": "invalid_token", "error_description": detail}, status_code=401,
                            headers={"WWW-Authenticate": header})

    def challenge_headers(result: GatewayResult, code: int) -> dict[str, str] | None:
        reason = result.reasons[0] if result.reasons else ""
        if code == 401:
            if reason.startswith("identity: dpop:") or "DPoP-bound" in reason:
                # RFC 9449 §7.1: a DPoP-specific challenge, not the generic bearer one, so a client
                # that only speaks Bearer gets an actionable signal rather than a bare 401.
                return {"WWW-Authenticate": f'DPoP error="invalid_dpop_proof", error_description="{reason}", '
                                            f'resource_metadata="{base_url}{METADATA_PATH}"'}
            return {"WWW-Authenticate": www_auth}
        match = re.match(r"scope: token lacks '([^']+)'", reason)
        if code == 403 and match:
            return {"WWW-Authenticate": f'Bearer error="insufficient_scope", scope="{match.group(1)}", '
                                        f'resource_metadata="{base_url}{METADATA_PATH}", '
                                        f'error_description="{match.group(1)} permission required"'}
        return None

    def bearer(authorization: str | None) -> str | None:
        """Accepts both the 'Bearer' and 'DPoP' auth schemes (RFC 9449 §7.1 asks a DPoP-bound
        token to use the latter) -- the token string itself is identical either way; which scheme
        was used names nothing the gateway checks. This is deliberately lenient so a caller
        presenting a DPoP-bound token with the plain 'Bearer' scheme (every existing caller in
        this codebase, and most real clients until they explicitly adopt DPoP) still reaches
        identity verification, where cnf.jkt is what actually decides whether a proof is required."""
        if not authorization:
            return None
        scheme, _, rest = authorization.partition(" ")
        if scheme.lower() not in ("bearer", "dpop"):
            return None
        return rest.strip() or None

    @app.get(METADATA_PATH)
    def resource_metadata() -> dict[str, Any]:
        return {
            "resource": env.verifier.audience,
            "authorization_servers": [env.verifier.issuer],
            "scopes_supported": sorted(set().union(*ROLE_SCOPES.values())),
            "bearer_methods_supported": ["header"],
            "resource_signing_alg_values_supported": ["EdDSA"],
            "resource_name": "govagent tool gateway",
        }

    @app.get("/v1/tools")
    def list_tools(authorization: str | None = Header(None)):
        token = bearer(authorization)
        if not token:
            return unauthorized("bearer token required")
        try:
            env.verifier.verify(token)
        except TokenError as exc:
            return unauthorized(str(exc))
        return env.registry.to_mcp()

    @app.get("/v1/authority")
    def authority(authorization: str | None = Header(None)):
        """What this gateway will enforce: the tool registry, the policy it loaded, and the agent
        registry. Read-only and derived from the live objects, so a console can show the rules in
        force rather than a copy of the YAML that may have drifted. Same auth as /v1/tools."""
        token = bearer(authorization)
        if not token:
            return unauthorized("bearer token required")
        try:
            env.verifier.verify(token)
        except TokenError as exc:
            return unauthorized(str(exc))
        pol = env.policy
        reg = gw.agent_registry
        return {
            "tools": [
                {"name": s.name, "description": s.description, "risk_tier": s.risk_tier.name,
                 "required_scope": s.required_scope, "side_effect": s.side_effect,
                 "data_classes": list(s.data_classes), "client_scoped": bool(s.client_arg),
                 "policy": {
                     "decision": (pol.tools.get(s.name) or {}).get("decision", pol.default),
                     "reason": (pol.tools.get(s.name) or {}).get("reason", ""),
                     "rules": [
                         {"id": r.get("id"), "decision": r.get("decision"), "reason": r.get("reason", ""),
                          "when": r.get("when", {})}
                         for r in ((pol.tools.get(s.name) or {}).get("rules") or [])
                     ],
                 }}
                for s in env.registry.specs()
            ],
            "policy": {
                "version": pol.version, "default_decision": pol.default,
                "max_tool_calls_per_run": pol.max_tool_calls_per_run,
                "max_high_risk_calls_per_run": pol.max_high_risk_calls_per_run,
                "max_risk_tier": pol.max_risk_tier,
                "approval_ttl_seconds": pol.approval_ttl_seconds,
                "velocity": [
                    {"id": r.id, "tool": r.tool, "per": r.per, "window_seconds": r.window_seconds,
                     "max_count": r.max_count, "sum_field": r.sum_field, "max_sum": r.max_sum,
                     "reason": r.reason}
                    for r in pol.velocity
                ],
            },
            # An agent registry is required to build a gateway (ToolGateway always enforces stage 4
            # against it). "unconstrained" is true only when the gateway was explicitly built with
            # AgentRegistry.unconstrained() -- an opt-out, not an absence -- in which case every
            # delegated call passes this stage unexamined and only token scopes apply.
            "agents": {
                "unconstrained": reg.is_unconstrained,
                "max_delegation_depth": reg.max_depth,
                "list": [
                    {"id": a.id, "name": a.name, "description": a.description,
                     "tools": sorted(a.tools), "delegated_by": sorted(a.delegated_by),
                     "may_delegate_to": sorted(a.may_delegate_to)}
                    for a in reg.agents.values()
                ],
            },
            "role_scopes": {k: sorted(v) for k, v in ROLE_SCOPES.items()},
        }

    @app.post("/v1/tools/{name}/invoke")
    def invoke(request: Request, name: str, body: dict[str, Any] = Body(default_factory=dict),
               authorization: str | None = Header(None),
               idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
               traceparent: str | None = Header(None),
               dpop: str | None = Header(None, alias="DPoP")):
        token = bearer(authorization)
        if not token:
            spec = env.registry.get(name)
            return unauthorized("bearer token required", spec.required_scope if spec else None)
        # http_url has no query string (RFC 9449 §4.2) and is the ACTUAL request this proof must be
        # for -- never cached, never assumed -- so a proof minted for one route can't be replayed
        # against another. Ignored entirely for a token with no cnf.jkt (every existing caller).
        http_url = f"{request.url.scheme}://{request.url.netloc}{request.url.path}"
        result = gw.invoke(token, name, body.get("arguments") or {}, idempotency_key=idempotency_key,
                           traceparent=traceparent, dpop_proof=dpop, http_method=request.method, http_url=http_url)
        code = _status_code(result)
        return JSONResponse(result.to_dict(), status_code=code, headers=challenge_headers(result, code))

    @app.get("/v1/actions/{action_id}")
    def action_status(action_id: str, authorization: str | None = Header(None)):
        """Task-style polling for a pending action (cf. MCP tasks extension's tasks/get)."""
        token = bearer(authorization)
        if not token:
            return unauthorized("bearer token required")
        try:
            grant = env.verifier.verify(token)
        except TokenError as exc:
            return unauthorized(str(exc))
        action = gw.get_action(action_id)
        is_owner = action is not None and action.principal == grant.principal_id
        is_approver = action is not None and "approvals:decide" in grant.scopes and action.client_id in grant.clients
        if not (is_owner or is_approver):
            return JSONResponse({"error": "not_found"}, status_code=404)  # don't reveal other people's actions
        return {"action_id": action_id, "status": action.status, "tool": action.tool,
                "expires_at": action.expires_at, "approver": action.approver}

    # ---- MCP (2026-07-28) JSON-RPC surface: one endpoint, same enforcement as the REST routes ----

    MCP_PROTOCOL_VERSION = "2026-07-28"

    @app.post("/mcp")
    def mcp_rpc(request: Request, body: dict[str, Any] = Body(...), authorization: str | None = Header(None),
               idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
               traceparent: str | None = Header(None), dpop: str | None = Header(None, alias="DPoP")):
        """JSON-RPC 2.0 over a single POST (MCP's Streamable HTTP transport). Every method that
        touches a tool goes through the exact same bearer()/env.verifier/gw.invoke() the REST routes
        above use -- a translation layer, not a second enforcement path that could drift from the
        first. An auth failure is a plain HTTP 401/403 carrying the same RFC 9728/DPoP challenge
        headers as /v1/tools/{name}/invoke, per this module's own documented protocol choices --
        never a 200 wrapping a JSON-RPC error, which is how MCP's authorization spec expects a
        resource server to behave (scope-challenge handling, "Protocol choices" at the top of
        this file).

        The tasks vocabulary below (tools/call returning a task for a pending approval; tasks/get
        polling it) is this reference build's own mapping onto /v1/actions/{id}'s existing
        semantics, written without a live copy of the 2026-07-28 tasks-extension text to check
        exact field names against -- it demonstrates the mechanism honestly, not a byte-for-byte
        certified implementation of that extension."""
        rpc_id = body.get("id")
        method = body.get("method")
        params = body.get("params") or {}

        def ok(result: Any) -> dict[str, Any]:
            return {"jsonrpc": "2.0", "id": rpc_id, "result": result}

        def rpc_error(code: int, message: str, status_code: int = 400,
                      headers: dict[str, str] | None = None) -> JSONResponse:
            return JSONResponse({"jsonrpc": "2.0", "id": rpc_id, "error": {"code": code, "message": message}},
                               status_code=status_code, headers=headers)

        if not method:
            return rpc_error(-32600, "invalid request: no method")

        if method == "initialize":
            return ok({"protocolVersion": MCP_PROTOCOL_VERSION,
                      "capabilities": {"tools": {"listChanged": False}},
                      "serverInfo": {"name": "govagent", "version": AGENT_VERSION}})
        if method == "notifications/initialized":
            return JSONResponse(None, status_code=202)  # a notification: no JSON-RPC response body

        if method == "tools/list":
            token = bearer(authorization)
            if not token:
                return unauthorized("bearer token required")
            try:
                env.verifier.verify(token)
            except TokenError as exc:
                return unauthorized(str(exc))
            return ok(env.registry.to_mcp())

        if method == "tools/call":
            name, args = params.get("name"), params.get("arguments") or {}
            if not name:
                return rpc_error(-32602, "invalid params: 'name' required")
            token = bearer(authorization)
            if not token:
                spec = env.registry.get(name)
                return unauthorized("bearer token required", spec.required_scope if spec else None)
            http_url = f"{request.url.scheme}://{request.url.netloc}{request.url.path}"
            result = gw.invoke(token, name, args, idempotency_key=idempotency_key, traceparent=traceparent,
                              dpop_proof=dpop, http_method=request.method, http_url=http_url)
            code = _status_code(result)
            if code in (401, 403):
                reason = "; ".join(result.reasons) or result.status
                return rpc_error(-32001 if code == 401 else -32002, reason, code, challenge_headers(result, code))
            if result.status == PENDING:
                return ok({"task": {"taskId": result.action_id, "status": "working",
                                   "statusMessage": "; ".join(result.reasons)}})
            if result.status == EXECUTED:
                return ok({"content": [{"type": "text", "text": json.dumps(result.data, default=str)}],
                          "isError": False})
            return ok({"content": [{"type": "text", "text": "; ".join(result.reasons) or result.status}],
                      "isError": True})

        if method == "tasks/get":
            task_id = params.get("taskId")
            token = bearer(authorization)
            if not token:
                return unauthorized("bearer token required")
            try:
                grant = env.verifier.verify(token)
            except TokenError as exc:
                return unauthorized(str(exc))
            action = gw.get_action(task_id) if task_id else None
            is_owner = action is not None and action.principal == grant.principal_id
            is_approver = (action is not None and "approvals:decide" in grant.scopes
                          and action.client_id in grant.clients)
            if action is None or not (is_owner or is_approver):
                return rpc_error(-32004, "task not found", 404)
            status_map = {"pending": "working", "executed": "completed", "approval_denied": "failed",
                         "expired": "failed"}
            return ok({"task": {"taskId": task_id, "status": status_map.get(action.status, "failed"),
                               "statusMessage": f"{action.tool}: {action.status}"}})

        return rpc_error(-32601, f"method not found: {method}", 404)

    @app.post("/v1/runs/close")
    def close_run(authorization: str | None = Header(None)):
        token = bearer(authorization)
        if not token:
            return unauthorized("bearer token required")
        gw.close_run(token)
        return {"closed": True}

    @app.get("/v1/runs/{run_id}/calls")
    def run_calls(run_id: str, authorization: str | None = Header(None)):
        token = bearer(authorization)
        if not token:
            return unauthorized("bearer token required")
        try:
            grant = env.verifier.verify(token)
        except TokenError as exc:
            if "expired" not in str(exc):
                return unauthorized(str(exc))
            grant = None
        owner = grant.run_id if grant else peek_run_id(token)
        if owner != run_id:
            return JSONResponse({"error": "forbidden"}, status_code=403)
        return {"run_id": run_id, "calls": [c.__dict__ for c in gw.run_calls(run_id)]}

    def approver(authorization: str | None):
        token = bearer(authorization)
        if not token:
            return None, unauthorized("bearer token required")
        try:
            grant = env.verifier.verify(token)
        except TokenError as exc:
            return None, unauthorized(str(exc))
        if "approvals:decide" not in grant.scopes:
            return None, JSONResponse({"error": "insufficient_scope", "scope": "approvals:decide"}, status_code=403)
        if is_agent(grant):
            return None, JSONResponse({"error": "agents_cannot_approve",
                                       "error_description": "approvals need the person's own token"}, status_code=403)
        return grant, None

    def is_agent(grant) -> bool:
        """Approving and reading the audit log are never delegated to an agent, whatever the token says.
        An agent registry is required to build a gateway, so this is always meaningful -- except under
        AgentRegistry.unconstrained(), where no agent is on record and this can only say False; that
        opt-out is exactly the tradeoff it documents."""
        return env.gateway.agent_registry.get(grant.agent_id) is not None

    @app.get("/v1/approvals")
    def pending(authorization: str | None = Header(None)):
        grant, err = approver(authorization)
        if err:
            return err
        return {"pending": [a.__dict__ for a in gw.pending_actions() if a.client_id in grant.clients]}

    @app.post("/v1/approvals/{action_id}/decision")
    def decide(action_id: str, body: dict[str, Any] = Body(...), authorization: str | None = Header(None),
               traceparent: str | None = Header(None)):
        grant, err = approver(authorization)
        if err:
            return err
        # the approver is whoever the token says, never a field in the body
        result = gw.decide(action_id, grant.principal_id, bool(body.get("approve")), str(body.get("note", "")),
                           traceparent=traceparent)
        return JSONResponse(result.to_dict(), status_code=_status_code(result))

    # ---- kill switch (never delegated to an agent, same pattern as approvals/audit) --------

    def admin(authorization: str | None):
        """Verifies the token, requires controls:admin, and refuses an agent token outright -- an
        emergency stop is a human-only action, exactly like approving a wire or reading the audit
        log. Returns (grant, None) or (None, an error response)."""
        token = bearer(authorization)
        if not token:
            return None, unauthorized("bearer token required", "controls:admin")
        try:
            grant = env.verifier.verify(token)
        except TokenError as exc:
            return None, unauthorized(str(exc))
        if is_agent(grant):
            return None, JSONResponse({"error": "agents_cannot_administer_controls",
                                       "error_description": "engaging or releasing a stop needs the "
                                       "person's own token"}, status_code=403)
        if "controls:admin" not in grant.scopes:
            return None, JSONResponse({"error": "insufficient_scope", "scope": "controls:admin"}, status_code=403,
                                      headers={"WWW-Authenticate": f'Bearer error="insufficient_scope", '
                                               f'scope="controls:admin", resource_metadata="{base_url}{METADATA_PATH}"'})
        return grant, None

    @app.post("/v1/controls/stop")
    def engage_stop(body: dict[str, Any] = Body(...), authorization: str | None = Header(None)):
        grant, err = admin(authorization)
        if err:
            return err
        scope, key = str(body.get("scope", "")), str(body.get("key", ""))
        if scope not in ("global", "tool", "agent") or (scope != "global" and not key):
            return JSONResponse({"error": "invalid_request", "error_description":
                                 "scope must be global, tool or agent; tool/agent need a key"}, status_code=400)
        key = "" if scope == "global" else key
        reason = str(body.get("reason", ""))
        env.store.engage_stop(scope, key, reason, grant.principal_id, env.gateway.clock())
        env.audit.record("stop_engaged", principal=grant.principal_id, scope=scope, key=key, reason=reason)
        return env.store.stop_state()

    @app.post("/v1/controls/release")
    def release_stop(body: dict[str, Any] = Body(...), authorization: str | None = Header(None)):
        grant, err = admin(authorization)
        if err:
            return err
        scope, key = str(body.get("scope", "")), str(body.get("key", ""))
        key = "" if scope == "global" else key
        released = env.store.release_stop(scope, key)
        env.audit.record("stop_released", principal=grant.principal_id, scope=scope, key=key, released=released)
        return env.store.stop_state()

    @app.get("/v1/metrics")
    def metrics() -> dict[str, Any]:
        """Plain JSON, no auth: decisions by outcome and by stage, approvals pending/expired, breaker
        state per tool, kill-switch state. Nothing here is more sensitive than /v1/audit/verify."""
        from collections import Counter

        from .pipeline import stage_for_reason

        entries = env.audit.entries()
        by_outcome = Counter(e["event"] for e in entries)
        by_stage = Counter(stage_for_reason((e.get("reasons") or [""])[0])
                           for e in entries if e["event"] in ("tool_denied", "tool_rejected", "tool_error"))
        return {
            "decisions": {"by_outcome": dict(by_outcome), "by_stage": dict(by_stage)},
            "approvals": {"pending": by_outcome.get("tool_pending_approval", 0),
                         "expired": by_outcome.get("approval_expired", 0)},
            "breakers": env.store.breaker_state(),
            "stop": env.store.stop_state(),
        }

    # ---- policy decision point (OpenID AuthZEN Authorization API 1.0) ----------------------

    @app.get(pdp.WELL_KNOWN)
    def authzen_configuration() -> dict[str, Any]:
        return pdp.configuration(base_url)

    def pdp_caller(authorization: str | None):
        token = bearer(authorization)
        if not token:
            return unauthorized("bearer token required")
        try:
            env.verifier.verify(token)
        except TokenError as exc:
            return unauthorized(str(exc))
        return None

    @app.post(pdp.EVALUATION_PATH)
    def access_evaluation(body: dict[str, Any] = Body(...), authorization: str | None = Header(None)):
        err = pdp_caller(authorization)
        if err:
            return err
        return pdp.evaluate(body, env.policy, env.registry, env.directory, env.backend.facts)

    @app.post(pdp.EVALUATIONS_PATH)
    def access_evaluations(body: dict[str, Any] = Body(...), authorization: str | None = Header(None)):
        err = pdp_caller(authorization)
        if err:
            return err
        defaults = {k: body[k] for k in ("subject", "resource", "action", "context") if k in body}
        return {"evaluations": [pdp.evaluate({**defaults, **item}, env.policy, env.registry, env.directory,
                                             env.backend.facts)
                                for item in body.get("evaluations", [])]}

    @app.get("/v1/audit/entries")
    def audit_entries(run_id: str | None = None, limit: int = 500, authorization: str | None = Header(None)):
        """Read-only audit access for compliance (scope audit:read). Entries are already redacted."""
        token = bearer(authorization)
        if not token:
            return unauthorized("bearer token required", "audit:read")
        try:
            grant = env.verifier.verify(token)
        except TokenError as exc:
            return unauthorized(str(exc))
        if is_agent(grant):
            return JSONResponse({"error": "agents_cannot_read_audit"}, status_code=403)
        if "audit:read" not in grant.scopes:
            return JSONResponse({"error": "insufficient_scope"}, status_code=403, headers={
                "WWW-Authenticate": f'Bearer error="insufficient_scope", scope="audit:read", '
                                    f'resource_metadata="{base_url}{METADATA_PATH}"'})
        ok, bad = env.audit.verify()
        entries = env.audit.entries(run_id)
        return {"intact": ok, "first_broken_seq": bad, "total": len(env.audit.entries()),
                "entries": entries[-max(1, min(limit, 5000)):]}

    if dev_mode:
        @app.post("/v1/dev/reset")
        def dev_reset():
            """Demo only (enabled by `serve --dev`): clear state and backend data. The audit log is kept,
            with a reset event, so the hash chain stays continuous."""
            env.store.reset()
            env.backend.reset()
            env.audit.record("dev_reset", note="demo state cleared")
            store = telemetry.store()
            if store is not None:
                store.clear()
            return {"reset": True}

        @app.get("/v1/dev/traces/{trace_id}")
        def dev_trace(trace_id: str):
            """Demo only: this process's spans for one trace (the dashboard merges them with its own).
            Jaeger shows the same spans when OTEL_EXPORTER_OTLP_ENDPOINT is set."""
            store = telemetry.store()
            return {"service": "tool-gateway", "spans": store.get(trace_id) if store else []}

        @app.post("/v1/dev/explain-token")
        def dev_explain(body: dict[str, Any] = Body(...)):
            """Demo only: every check the gateway runs on a token, for the token inspector. Never logs
            the token. (In production, token introspection would be an authenticated RFC 7662 endpoint.)"""
            steps, grant = env.verifier.explain(str(body.get("token", "")))
            if grant is not None:
                if not grant.delegated:
                    steps.append({"check": "may call tools", "ok": False,
                                  "detail": "no act claim: a person's own token cannot call tools"})
                else:
                    problem = env.gateway.agent_registry.check_chain(grant.actor_chain)
                    spec = env.gateway.agent_registry.get(grant.agent_id)
                    steps.append({"check": "agent registry", "ok": problem is None,
                                  "detail": problem or f"{grant.agent_id} may act via this chain; tools: "
                                  f"{', '.join(sorted(spec.tools)) or 'none (delegates only)'}"})
            return {"valid": grant is not None and all(st["ok"] for st in steps), "checks": steps,
                    "grant": None if grant is None else {
                        "principal": grant.principal_id, "role": grant.role, "agent": grant.agent_id,
                        "chain": list(grant.actor_chain), "scopes": sorted(grant.scopes), "run_id": grant.run_id,
                        "clients": sorted(grant.clients)}}

    @app.get("/v1/audit/verify")
    def audit_verify() -> dict[str, Any]:
        ok, bad = env.audit.verify()
        return {"intact": ok, "first_broken_seq": bad, "entries": len(env.audit.entries())}

    return app

"""RemoteGateway: the agent runtime's HTTP client for the gateway service.

It holds nothing but a base URL. It implements the same interface as the in-process ToolGateway,
so AgentRunner and the ADK integration run unchanged against a remote enforcement point.
Transport retries reuse the same Idempotency-Key, so a retried side effect is never repeated.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

from . import dpop as dpop_module
from .gateway import GatewayResult, ToolCallRecord
from .guardrails import redact
from .identity import peek_run_id


@dataclass(frozen=True)
class RemoteToolSpec:
    """The part of a tool the model needs: name, description, schema. Governance metadata stays server-side."""

    name: str
    description: str
    input_schema: dict[str, Any]


class RemoteGateway:
    def __init__(self, base_url: str = "", client: httpx.Client | None = None, retries: int = 2,
                 timeout: float = 10.0, dpop_key: "dpop_module.DPoPKey | None" = None):
        self.client = client or httpx.Client(base_url=base_url, timeout=timeout)
        self.retries = retries
        # Present only when this runtime holds a DPoP key pair (RFC 9449): invoke() then mints a
        # fresh proof per call, bound to that exact request. A token with no cnf.jkt is unaffected
        # either way -- this key only matters when the caller actually asked for a bound token.
        # Scope note: wired into invoke() only, the one route that executes an action and the one
        # the gateway actually enforces cnf.jkt against; tools()/authority()/action_status()/
        # run_calls() stay plain bearer calls, a named boundary of this reference build, not an
        # oversight.
        self.dpop_key = dpop_key
        # what this runtime observed, for when the gateway (rightly) refuses to show its records,
        # e.g. to a caller whose token was rejected
        self._observed: dict[str, list[ToolCallRecord]] = {}

    @staticmethod
    def _auth(token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    def tools(self, token: str) -> list[RemoteToolSpec]:
        resp = self.client.get("/v1/tools", headers=self._auth(token))
        resp.raise_for_status()
        return [RemoteToolSpec(t["name"], t["description"], t["inputSchema"]) for t in resp.json()["tools"]]

    def authority(self, token: str) -> dict[str, Any]:
        """The rules this gateway enforces: tool registry, policy, agent registry."""
        resp = self.client.get("/v1/authority", headers=self._auth(token))
        resp.raise_for_status()
        return resp.json()

    def invoke(self, token: str, tool_name: str, args: dict[str, Any],
               idempotency_key: str | None = None, traceparent: str | None = None) -> GatewayResult:
        path = f"/v1/tools/{tool_name}/invoke"
        headers = self._auth(token)
        if self.dpop_key is not None:
            # One proof per attempt, not reused across retries (its own fresh jti and iat) --
            # replaying the same proof is exactly what the gateway's replay check refuses.
            url = str(httpx.URL(self.client.base_url).join(path))
            headers["Authorization"] = f"DPoP {token}"
            headers["DPoP"] = self.dpop_key.proof("POST", url, access_token=token)
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        if traceparent:
            headers["traceparent"] = traceparent
        last_exc: Exception | None = None
        for attempt in range(self.retries + 1):
            if self.dpop_key is not None and attempt > 0:  # a fresh proof for each retried attempt too
                headers["DPoP"] = self.dpop_key.proof("POST", url, access_token=token)
            try:
                resp = self.client.post(path, json={"arguments": args}, headers=headers)
            except httpx.TransportError as exc:  # network blip: retry with the same key
                last_exc = exc
                continue
            result = GatewayResult(**resp.json())
            break
        else:
            result = GatewayResult("error", "", reasons=[f"transport: gateway unreachable ({type(last_exc).__name__})"])
        self._observed.setdefault(peek_run_id(token), []).append(ToolCallRecord(
            result.call_id, tool_name, redact(args), result.status, result.reasons, action_id=result.action_id))
        return result

    def action_status(self, token: str, action_id: str) -> dict[str, Any]:
        """Poll a pending action, like an MCP task handle."""
        return self.client.get(f"/v1/actions/{action_id}", headers=self._auth(token)).json()

    def close_run(self, token: str) -> None:
        try:
            self.client.post("/v1/runs/close", headers=self._auth(token))
        except httpx.TransportError:
            pass

    def run_calls(self, run_id: str, token: str = "") -> list[ToolCallRecord]:
        resp = self.client.get(f"/v1/runs/{run_id}/calls", headers=self._auth(token))
        if resp.status_code != 200:
            return list(self._observed.get(run_id, []))
        return [ToolCallRecord(**c) for c in resp.json()["calls"]]

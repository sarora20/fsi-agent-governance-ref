"""Transaction Tokens: how the gateway tells backends who is acting, without passing the user's token.

The gateway never forwards the agent's access token (MCP authorization spec: no token passthrough).
Instead, for every backend call it mints a short-lived Transaction Token
(draft-ietf-oauth-transaction-tokens-08, in IETF working-group last call as of March 2026):

  header  typ=txntoken+jwt                                   (§10.1)
  aud     the trust domain                                   (required)
  txn     unique transaction id (the pending-action / call id) (required)
  sub     the human principal                                 (required)
  scope   the narrow purpose: this one tool                   (required)
  req_wl  the workload that requested it: the gateway          (required)
  iat/exp lifetime of 60 seconds ("minutes or less", §7)
  tctx    immutable transaction context: tool, argument hash, run, approval, acting agent
  rctx    requester context: agent id, trace id

Backends validate signature, audience (trust domain), expiry, and that `tctx.args_sha256` matches
what they are asked to do, so a compromised hop cannot change the action in flight.
Agent-specific claims follow the direction of draft-oauth-transaction-tokens-for-agents (an
individual draft), kept inside tctx/rctx here until that work settles.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from typing import Any, Callable

import jwt

from .identity import KeyRing

TXN_TYPE = "txntoken+jwt"
TRUST_DOMAIN = "https://trust.govagent.example"
GATEWAY_WORKLOAD = "spiffe://govagent.example/gateway"
LIFETIME_SECONDS = 60


class TxnTokenError(Exception):
    pass


def args_hash(args: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(args, sort_keys=True, default=str).encode()).hexdigest()


class TxnTokenService:
    """Runs inside the gateway (the Transaction Token Service for this trust domain)."""

    def __init__(self, keys: KeyRing | None = None, trust_domain: str = TRUST_DOMAIN,
                 clock: Callable[[], float] = time.time):
        self.keys = keys or KeyRing()
        self.trust_domain = trust_domain
        self._clock = clock

    def mint(self, *, principal: str, tool: str, args: dict[str, Any], run_id: str, agent_id: str,
             txn: str | None = None, approval: dict[str, Any] | None = None, trace_id: str | None = None) -> str:
        now = int(self._clock())
        claims = {
            "aud": self.trust_domain,
            "txn": txn or uuid.uuid4().hex,
            "sub": principal,
            "scope": f"tool:{tool}",
            "req_wl": GATEWAY_WORKLOAD,
            "iat": now,
            "exp": now + LIFETIME_SECONDS,
            "tctx": {"tool": tool, "args_sha256": args_hash(args), "run_id": run_id,
                     "acting_agent": agent_id, "approval": approval or None},
            "rctx": {"agent": agent_id, "trace_id": trace_id},
        }
        kid, key = self.keys.signing_key()
        return jwt.encode(claims, key, algorithm="EdDSA", headers={"kid": kid, "typ": TXN_TYPE})


class TxnTokenVerifier:
    """Runs inside each backend (a workload in the trust domain)."""

    def __init__(self, public_keys: Callable[[], dict] | dict, trust_domain: str = TRUST_DOMAIN,
                 clock: Callable[[], float] = time.time):
        self.public_keys = public_keys
        self.trust_domain = trust_domain
        self._clock = clock

    def verify(self, token: str | None, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        if not token:
            raise TxnTokenError("missing transaction token")
        header = jwt.get_unverified_header(token)
        if header.get("typ") != TXN_TYPE or header.get("alg") != "EdDSA":
            raise TxnTokenError("not a transaction token")
        keys = self.public_keys() if callable(self.public_keys) else self.public_keys
        key = keys.get(header.get("kid", ""))
        if key is None:
            raise TxnTokenError("unknown signing key")
        try:
            claims = jwt.decode(token, key, algorithms=["EdDSA"], audience=self.trust_domain,
                                options={"require": ["aud", "txn", "sub", "scope", "req_wl", "iat", "exp"],
                                         "verify_exp": False, "verify_iat": False})
        except jwt.PyJWTError as exc:
            raise TxnTokenError(f"invalid transaction token: {type(exc).__name__}") from None
        if self._clock() >= claims["exp"]:
            raise TxnTokenError("transaction token expired")
        if claims["scope"] != f"tool:{tool}":
            raise TxnTokenError("transaction token is for a different operation")
        if claims.get("tctx", {}).get("args_sha256") != args_hash(args):
            raise TxnTokenError("request does not match the transaction context")
        return claims

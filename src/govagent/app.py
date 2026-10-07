"""Wiring: build a fresh, fully governed environment (fixtures for demos, tests and evals).

In a real deployment these pieces live in different places:
  TokenService   the identity provider (holds private signing keys)
  ToolGateway    its own service (holds public keys, state store, backend credentials)
  AgentRunner    the agent runtime (holds only a delegation token and the gateway URL)
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from pathlib import Path

from . import AGENT_ID
from .agents import AgentRegistry
from .approvals import ApprovalBroker, InlineApprovals
from .audit import AuditLog
from .domain import WealthBackend, build_registry
from .gateway import ToolGateway
from .identity import (DEFAULT_AUDIENCE, DEFAULT_ISSUER, OIDC_PROFILE, Directory, JwksKeySource, KeyRing,
                       Principal, TokenService, TokenVerifier)
from .policy import PolicyEngine
from .registry import ToolRegistry
from .state import StateStore
from .txn import TxnTokenService, TxnTokenVerifier

DEFAULT_POLICY = Path(__file__).resolve().parent / "policies" / "policy.yaml"

PRINCIPALS: dict[str, Principal] = {
    "ana": Principal("ana.ruiz", "Ana Ruiz", "advisor", frozenset({"C-1001", "C-1002"})),
    "sam": Principal("sam.okafor", "Sam Okafor", "service_associate", frozenset({"C-1001", "C-1002"})),
    "lee": Principal("lee.park", "Lee Park", "analyst", frozenset({"C-1001"})),
    "sup": Principal("casey.morgan", "Casey Morgan", "supervisor", frozenset({"C-1001", "C-1002"})),
    "cmp": Principal("riley.brooks", "Riley Brooks", "compliance", frozenset()),
}


@dataclass
class Environment:
    backend: WealthBackend
    registry: ToolRegistry
    policy: PolicyEngine
    keys: KeyRing
    tokens: TokenService
    verifier: TokenVerifier
    directory: Directory
    store: StateStore
    gateway: ToolGateway
    audit: AuditLog
    approvals: ApprovalBroker

    def token_for(self, who: str, scopes: list[str] | None = None, ttl_seconds: int = 900,
                  expired: bool = False, audience: str = DEFAULT_AUDIENCE, run_id: str | None = None) -> str:
        """Ask the (simulated) IdP for a delegation token bound to a new agent run."""
        principal = PRINCIPALS.get(who) or self.directory.get(who)
        issuer = self.tokens
        if expired:
            # Same agent registry as self.tokens, so this mints audience-narrowed exactly like any
            # other token -- only the clock differs. Otherwise the verifier's audience-narrowing
            # check (identity.py) would deny this token for the wrong reason before expiry is reached.
            issuer = TokenService(self.keys, self.tokens.issuer, clock=lambda: time.time() - 7200,
                                  agent_registry=self.tokens.agent_registry)
        return issuer.issue(principal, AGENT_ID, scopes, ttl_seconds, audience=audience, run_id=run_id)


    def person_token(self, who: str) -> str:
        """The person's own token (a console session, not an agent): for approvals and the audit view."""
        principal = PRINCIPALS.get(who) or self.directory.get(who)
        return self.tokens.issue(principal, "demo-console")

    def revoke_token(self, token: str) -> None:
        import jwt as _jwt

        jti = _jwt.decode(token, options={"verify_signature": False})["jti"]
        self.store.revoke("jti", jti, time.time())

    def revoke_subject(self, user_id: str) -> None:
        self.store.revoke("sub", user_id, time.time())


@dataclass(frozen=True)
class OidcIdp:
    """A real OAuth 2.0 / OpenID Connect authorization server (e.g. Keycloak). The gateway trusts its
    issuer and fetches its public keys from `jwks_uri`; it never sees a private key."""

    issuer: str
    jwks_uri: str
    audience: str = DEFAULT_AUDIENCE

    @classmethod
    def discover(cls, issuer: str, audience: str = DEFAULT_AUDIENCE, timeout: float = 5.0) -> "OidcIdp":
        """RFC 8414 / OIDC discovery. The issuer in the document must match exactly (RFC 8414 §3.3)."""
        import json
        import urllib.request

        url = issuer.rstrip("/") + "/.well-known/openid-configuration"
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 (configured URL)
            meta = json.loads(resp.read().decode())
        if meta.get("issuer") != issuer:
            raise ValueError(f"issuer mismatch: configured {issuer!r}, discovery says {meta.get('issuer')!r}")
        return cls(issuer=issuer, jwks_uri=meta["jwks_uri"], audience=audience)


DEV_SEED = "govagent-dev-seed-NOT-for-production"


def dev_keyring(shared: bool = False) -> KeyRing:
    """Random keys by default. `shared=True` (serve/token CLI) derives a key from
    GOVAGENT_DEV_SIGNING_SEED so a separate process can mint tokens the service accepts.
    Production: the IdP holds private keys; the gateway fetches public keys from its JWKS."""
    seed = os.environ.get("GOVAGENT_DEV_SIGNING_SEED") or (DEV_SEED if shared else None)
    return KeyRing.from_seed(seed.encode()) if seed else KeyRing()


def build_environment(
    approvals: ApprovalBroker | None = None,
    audit: AuditLog | None = None,
    policy_path: str | Path | None = None,
    store: StateStore | None = None,
    keys: KeyRing | None = None,
    clock=time.time,
    idp: OidcIdp | None = None,
    key_source=None,
    agent_registry: AgentRegistry | None = None,
) -> Environment:
    txn_keys = KeyRing()  # the gateway's own Transaction Token signing key (not the IdP's)
    txn_tokens = TxnTokenService(txn_keys, clock=clock)
    backend = WealthBackend(txn_verifier=TxnTokenVerifier(txn_keys.public_keys, clock=clock))
    registry = build_registry(backend)
    policy = PolicyEngine.from_file(policy_path or os.environ.get("GOVAGENT_POLICY", DEFAULT_POLICY))
    keys = keys or dev_keyring()
    store = store or StateStore()
    agent_registry = agent_registry or AgentRegistry.from_file()  # one instance, shared below
    tokens = TokenService(keys, DEFAULT_ISSUER, clock=clock, agent_registry=agent_registry)
    directory = Directory(PRINCIPALS.values())
    if idp is None:
        verifier = TokenVerifier(keys.public_keys, DEFAULT_AUDIENCE, DEFAULT_ISSUER, store=store, clock=clock,
                                 agent_registry=agent_registry)
    else:  # tokens from the real authorization server; role and client book from the directory
        verifier = TokenVerifier(key_source or JwksKeySource(idp.jwks_uri, clock=clock), idp.audience, idp.issuer,
                                 store=store, clock=clock, profile=OIDC_PROFILE, directory=directory,
                                 agent_registry=agent_registry)
    audit = audit or AuditLog()
    approvals = approvals or InlineApprovals()
    gateway = ToolGateway(registry, policy, verifier, directory, approvals, audit, store,
                          agent_registry=agent_registry,
                          facts=backend.facts, clock=clock, txn_tokens=txn_tokens)
    return Environment(backend, registry, policy, keys, tokens, verifier, directory, store, gateway, audit, approvals)

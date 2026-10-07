"""Self-test against a running Keycloak: does the real server behave the way this build assumes?

Runs the real flows (browser-style sign-in with PKCE, RFC 8693 token exchange) and pushes the
resulting tokens through an in-process gateway configured exactly as `serve --oidc-issuer` would be.
Writes a plain-text report with decoded claims (never raw tokens) for troubleshooting.
"""

from __future__ import annotations

import json
import time
import traceback
from pathlib import Path
from typing import Any, Callable

import httpx
import jwt

from . import AGENT_ID
from .app import PRINCIPALS, OidcIdp, build_environment
from .approvals import QueueApprovals
from .identity import AGENT_SCOPES, DEFAULT_AUDIENCE, ROLE_SCOPES, JwksKeySource, TokenError

REDIRECT = "http://localhost:8000/auth/callback"
SHOW = ("iss", "aud", "azp", "sub", "preferred_username", "act", "scope", "typ", "exp", "iat", "jti")


def _claims(token: str) -> tuple[dict[str, Any], dict[str, Any]]:
    return jwt.get_unverified_header(token), jwt.decode(token, options={"verify_signature": False})


def run_checks(issuer: str, report_path: Path, http: httpx.Client | None = None) -> int:
    from .demo.oidc import OidcConfig, OidcIdentity, password_login

    http = http or httpx.Client(timeout=10)
    lines: list[str] = [f"keycloak-check  {time.strftime('%Y-%m-%d %H:%M:%S')}  issuer={issuer}", ""]
    results: list[tuple[bool, str]] = []
    tokens: dict[str, dict[str, Any]] = {}

    def check(name: str, fn: Callable[[], str | None]) -> None:
        try:
            detail = fn() or ""
            results.append((True, name))
            lines.append(f"PASS  {name}" + (f"  ({detail})" if detail else ""))
        except Exception as exc:  # noqa: BLE001 - report every failure, keep going
            results.append((False, name))
            lines.append(f"FAIL  {name}: {type(exc).__name__}: {exc}")
            lines.extend("      " + ln for ln in traceback.format_exc().strip().splitlines()[-3:])

    state: dict[str, Any] = {}

    def discovery():
        state["cfg"] = OidcConfig.discover(issuer, http=http)
        meta = http.get(issuer + "/.well-known/openid-configuration").json()
        te = "urn:ietf:params:oauth:grant-type:token-exchange" in meta.get("grant_types_supported", [])
        return f"token exchange advertised: {te}"

    def jwks():
        keys = http.get(state["cfg"].jwks_uri).json()["keys"]
        okp = [k for k in keys if k.get("kty") == "OKP" and k.get("crv") == "Ed25519"]
        assert okp, f"no Ed25519 key in JWKS (found {[k.get('alg') for k in keys]})"
        return f"{len(okp)} Ed25519 key(s), {len(keys)} keys total"

    def login(who: str) -> Callable[[], str]:
        def _run():
            body = password_login(state["cfg"], PRINCIPALS[who].user_id, "demo", REDIRECT, http=http)
            state[f"login:{who}"] = body
            hdr, c = _claims(body["access_token"])
            tokens[f"{who} console token"] = {"header": hdr, **{k: c.get(k) for k in SHOW}}
            assert hdr.get("typ") == "at+jwt", f"header typ is {hdr.get('typ')!r}, expected 'at+jwt'"
            assert hdr.get("alg") == "EdDSA", f"alg is {hdr.get('alg')!r}, expected EdDSA"
            assert c.get("typ") == "Bearer", f"payload typ {c.get('typ')!r}"
            assert c.get("preferred_username") == PRINCIPALS[who].user_id
            got = set(str(c.get("scope", "")).split()) - {"openid"}
            want = set(ROLE_SCOPES[PRINCIPALS[who].role])
            assert got >= want, f"missing scopes {sorted(want - got)}"
            assert not (got - want), f"scopes beyond the role: {sorted(got - want)}"
            aud = c.get("aud") if isinstance(c.get("aud"), list) else [c.get("aud")]
            assert AGENT_ID in aud and DEFAULT_AUDIENCE in aud, f"aud is {aud}"
            return f"scopes = role scopes ({len(want)})"
        return _run

    def identity() -> OidcIdentity:
        ident = state.get("ident")
        if ident is None:
            ident = OidcIdentity(state["cfg"], {k: p.user_id for k, p in PRINCIPALS.items()}, http=http)
            for who in ("ana", "sam", "sup", "cmp"):
                body = state.get(f"login:{who}")
                if body:
                    ident._store(who, body, _claims(body["access_token"])[1])
            state["ident"] = ident
        return ident

    def exchange():
        token = identity().agent_token("ana")
        state["agent:ana"] = token
        hdr, c = _claims(token)
        tokens["ana agent token (after RFC 8693 exchange)"] = {"header": hdr, **{k: c.get(k) for k in SHOW}}
        assert hdr.get("typ") == "at+jwt" and hdr.get("alg") == "EdDSA", f"header {hdr}"
        assert c.get("azp") == AGENT_ID, f"azp {c.get('azp')!r}"
        assert c.get("act") == {"sub": AGENT_ID}, f"act {c.get('act')!r}"
        aud = c.get("aud") if isinstance(c.get("aud"), list) else [c.get("aud")]
        assert aud == [DEFAULT_AUDIENCE], f"aud should be only the gateway, got {aud}"
        scopes = set(str(c.get("scope", "")).split())
        assert scopes and scopes <= AGENT_SCOPES, f"scope {sorted(scopes)}"
        assert c.get("preferred_username") == "ana.ruiz" and c.get("sub"), "user claims missing"
        return f"scope: {' '.join(sorted(scopes))}"

    def no_upscope():
        resp = identity().exchange_raw(state["login:sam"]["access_token"], "payments:initiate")
        body = resp.json()
        assert resp.status_code == 400 and body.get("error") == "invalid_scope", f"HTTP {resp.status_code} {body}"
        return body.get("error_description", "")

    def agent_cannot_approve():
        token = identity().agent_token("sup")
        _, c = _claims(token)
        assert "approvals:decide" not in str(c.get("scope", "")).split(), c.get("scope")
        return f"supervisor's agent token scope: {c.get('scope')!r}"

    def no_password_grant():
        resp = http.post(state["cfg"].token_endpoint, auth=state["cfg"].console,
                         data={"grant_type": "password", "username": "ana.ruiz", "password": "demo"})
        assert resp.status_code in (400, 401) and "access_token" not in resp.text, resp.text[:200]
        return resp.json().get("error", "")

    def gateway():
        from fastapi.testclient import TestClient

        from .service import create_app

        cfg = state["cfg"]
        env = build_environment(approvals=QueueApprovals(), idp=OidcIdp(cfg.issuer, cfg.jwks_uri),
                                key_source=JwksKeySource(cfg.jwks_uri, fetch=lambda u: http.get(u).json()))
        r = env.gateway.invoke(state["agent:ana"], "get_positions", {"client_id": "C-1001"})
        assert r.status == "executed", f"agent token: {r.status} {r.reasons}"
        r = env.gateway.invoke(state["login:ana"]["access_token"], "get_positions", {"client_id": "C-1001"})
        assert r.status == "denied" and "act claim" in r.reasons[0], f"console token: {r.status} {r.reasons}"
        try:
            env.verifier.verify(state["login:ana"]["id_token"])
            raise AssertionError("ID token was accepted")
        except TokenError:
            pass
        svc = TestClient(create_app(env))
        wire = {"client_id": "C-1002", "from_account_id": "40055555555", "beneficiary_id": "B-2002", "amount_usd": 5000}
        pending = env.gateway.invoke(identity().agent_token("ana"), "initiate_wire_transfer", wire,
                                     idempotency_key=f"kc-check-{int(time.time())}")
        assert pending.status == "pending_approval", f"{pending.status} {pending.reasons}"
        ana = {"Authorization": f"Bearer {state['login:ana']['access_token']}"}
        casey = {"Authorization": f"Bearer {state['login:sup']['access_token']}"}
        own = svc.post(f"/v1/approvals/{pending.action_id}/decision", headers=ana, json={"approve": True})
        assert own.status_code == 403, f"advisor approving: HTTP {own.status_code}"
        done = svc.post(f"/v1/approvals/{pending.action_id}/decision", headers=casey, json={"approve": True})
        assert done.json().get("status") == "executed", done.text[:200]
        if "payments-token" in state:
            steps, grant = env.verifier.explain(state["payments-token"])
            assert grant is not None and grant.actor_chain == ("payments-agent", "orchestrator-agent"), steps
            assert env.gateway.agent_registry.check_chain(grant.actor_chain) is None
        return "agent token executes; console token and ID token refused; supervisor approval executes"

    def orchestrator_chain():
        ident = identity()
        orch = ident.exchange(state["login:ana"]["access_token"], "orchestrator-agent", AGENT_SCOPES)
        hdr, c = _claims(orch)
        tokens["orchestrator token"] = {"header": hdr, **{k: c.get(k) for k in SHOW}}
        aud = set(c.get("aud") if isinstance(c.get("aud"), list) else [c.get("aud")])
        want_aud = {DEFAULT_AUDIENCE, "accounts-agent", "payments-agent", "comms-agent"}
        assert aud == want_aud, f"orchestrator aud {sorted(aud)}"
        assert c.get("act") == {"sub": "orchestrator-agent"}, f"act {c.get('act')}"
        pay = ident.exchange(orch, "payments-agent", frozenset({"payments:initiate"}))
        hdr, c = _claims(pay)
        tokens["payments token (delegated by orchestrator)"] = {"header": hdr, **{k: c.get(k) for k in SHOW}}
        assert c.get("act") == {"sub": "payments-agent", "act": {"sub": "orchestrator-agent"}}, f"act {c.get('act')}"
        assert c.get("aud") in (DEFAULT_AUDIENCE, [DEFAULT_AUDIENCE]), f"aud {c.get('aud')}"
        assert str(c.get("scope")).split() == ["payments:initiate"], f"scope {c.get('scope')}"
        state["payments-token"] = pay
        return "person -> orchestrator -> payments; nested act; aud narrowed to the gateway"

    def no_skipping():
        from .demo.oidc import OidcError

        try:
            identity().exchange(state["login:ana"]["access_token"], "payments-agent", frozenset({"payments:initiate"}))
        except OidcError as exc:
            return f"refused: {exc}"
        raise AssertionError("payments-agent exchanged the person's token directly")

    check("discovery: issuer matches", discovery)
    if "cfg" in state:
        check("JWKS: Ed25519 signing key", jwks)
        for who in ("ana", "sam", "sup", "cmp"):
            check(f"sign-in (code + PKCE) as {PRINCIPALS[who].user_id}: at+jwt, EdDSA, scopes by role", login(who))
        if "login:ana" in state:
            check("RFC 8693 exchange: aud=gateway, act=agent, narrowed scopes", exchange)
        if "login:sam" in state:
            check("exchange cannot add scopes (downscope-only policy)", no_upscope)
        if "login:sup" in state:
            check("agent never receives approvals:decide", agent_cannot_approve)
        check("password grant is disabled", no_password_grant)
        if "login:ana" in state:
            check("multi-agent: orchestrator delegates to payments (nested act)", orchestrator_chain)
            check("multi-agent: a specialist cannot skip the orchestrator", no_skipping)
        if "agent:ana" in state and "login:sup" in state:
            check("gateway accepts Keycloak tokens end to end", gateway)

    passed = sum(ok for ok, _ in results)
    lines += ["", f"{passed}/{len(results)} checks passed", "", "Decoded claims (no raw tokens):",
              json.dumps(tokens, indent=2, default=str)]
    text = "\n".join(lines)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(text + "\n")
    print("\n".join(lines[: len(results) + 4]))
    print(f"report: {report_path}")
    return 0 if passed == len(results) and results else 1

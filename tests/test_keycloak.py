"""Keycloak mode: real OAuth 2.0 flows (authorization code + PKCE, RFC 8693 token exchange, JWKS)
against a Keycloak stand-in driven by the same realm file. The live server is checked separately by
`govagent keycloak-check`."""

import json
import re
import urllib.parse

import pytest

pytest.importorskip("fastapi")

from fake_keycloak import REALM_FILE, create_fake_keycloak  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from govagent import AGENT_ID  # noqa: E402
from govagent.app import PRINCIPALS, OidcIdp, build_environment  # noqa: E402
from govagent.approvals import QueueApprovals  # noqa: E402
from govagent.demo.app import create_demo_app  # noqa: E402
from govagent.demo.oidc import OidcConfig, OidcIdentity, password_login  # noqa: E402
from govagent.identity import AGENT_SCOPES, ROLE_SCOPES, JwksKeySource, TokenError  # noqa: E402
from govagent.service import create_app  # noqa: E402

KC = "http://localhost:8180"
REDIRECT = "http://localhost:8000/auth/callback"
USERNAMES = {k: p.user_id for k, p in PRINCIPALS.items()}


@pytest.fixture
def kc():
    return TestClient(create_fake_keycloak(KC), base_url=KC)


@pytest.fixture
def cfg(kc):
    return OidcConfig.discover(f"{KC}/realms/fsi-demo", http=kc)


@pytest.fixture
def env(kc, cfg):
    idp = OidcIdp(cfg.issuer, cfg.jwks_uri)
    return build_environment(approvals=QueueApprovals(), idp=idp,
                             key_source=JwksKeySource(cfg.jwks_uri, fetch=lambda u: kc.get(u).json()))


@pytest.fixture
def identity(kc, cfg):
    return OidcIdentity(cfg, USERNAMES, http=kc)


def login(identity, kc, who):
    """Sign a person in through the console's real authorization-code flow."""
    url = identity.authorize_url(who, REDIRECT)
    page = kc.get(url)
    action = re.search(r'action="([^"]+)"', page.text).group(1).replace("&amp;", "&")
    resp = kc.post(action, data={"username": USERNAMES[who], "password": "demo"}, follow_redirects=False)
    q = urllib.parse.parse_qs(urllib.parse.urlparse(resp.headers["location"]).query)
    return identity.complete_login(q["state"][0], q["code"][0])


def claims(token):
    import jwt

    return jwt.decode(token, options={"verify_signature": False}), jwt.get_unverified_header(token)


# ------------------------------------------------------------------ realm file stays in step with the code

def test_realm_matches_role_scopes_and_clients():
    realm = json.loads(REALM_FILE.read_text())
    by_scope = {m["clientScope"]: set(m["roles"]) for m in realm["scopeMappings"]}
    for role, scopes in ROLE_SCOPES.items():
        assert {s for s, roles in by_scope.items() if role in roles} == set(scopes), role
    clients = {c["clientId"]: c for c in realm["clients"]}
    agent, console = clients[AGENT_ID], clients["advisor-console"]
    assert set(agent["optionalClientScopes"]) == set(AGENT_SCOPES)
    # client-level mappers are dropped during a downscope-only exchange; claims must come from default scopes
    assert "protocolMappers" not in agent and "agent-actor" in agent["defaultClientScopes"]
    assert agent["attributes"]["standard.token.exchange.enabled"] == "true" and not agent["standardFlowEnabled"]
    assert console["attributes"]["pkce.code.challenge.method"] == "S256"
    for c in clients.values():
        assert not c["directAccessGrantsEnabled"] and not c["publicClient"]
        assert c["attributes"]["access.token.header.type.rfc9068"] == "true"
        assert c["attributes"]["access.token.signed.response.alg"] == "EdDSA"
    assert {u["username"]: u["realmRoles"] for u in realm["users"]} == {p.user_id: [p.role] for p in PRINCIPALS.values()}
    policy = realm["clientPolicies"]["policies"][0]
    assert policy["enabled"] and policy["profiles"] == ["exchange-downscope-only"]
    assert realm["clientProfiles"]["profiles"][0]["executors"][0]["executor"] == "downscope-assertion-grant-enforcer"


# ------------------------------------------------------------------ the flows

def test_login_scopes_follow_roles(identity, kc):
    login(identity, kc, "ana")
    login(identity, kc, "sam")
    ana, hdr = claims(identity.console_token("ana"))
    sam, _ = claims(identity.console_token("sam"))
    assert hdr["typ"] == "at+jwt" and hdr["alg"] == "EdDSA"
    assert "payments:initiate" in ana["scope"].split()
    assert "payments:initiate" not in sam["scope"].split()  # the IdP never issues it to a service associate


def test_agent_token_via_token_exchange_is_accepted(identity, kc, env):
    login(identity, kc, "ana")
    token = identity.agent_token("ana")
    c, hdr = claims(token)
    assert hdr["typ"] == "at+jwt" and c["act"] == {"sub": AGENT_ID} and c["azp"] == AGENT_ID
    assert c["aud"] == env.verifier.audience  # only the gateway, not the console
    assert set(c["scope"].split()) <= AGENT_SCOPES
    grant = env.verifier.verify(token)
    assert grant.principal_id == "ana.ruiz" and grant.agent_id == AGENT_ID and grant.role == "advisor"
    assert grant.clients == PRINCIPALS["ana"].entitled_clients  # from the directory, not the token
    r = env.gateway.invoke(token, "get_positions", {"client_id": "C-1001"})
    assert r.status == "executed"


def test_each_exchange_is_a_new_run(identity, kc, env):
    login(identity, kc, "ana")
    a, b = identity.agent_token("ana"), identity.agent_token("ana")
    assert env.verifier.verify(a).run_id != env.verifier.verify(b).run_id
    env.gateway.invoke(a, "get_positions", {"client_id": "C-1001"})
    env.gateway.close_run(a)
    r = env.gateway.invoke(a, "get_positions", {"client_id": "C-1001"})
    assert r.status == "denied" and "closed" in r.reasons[0]


def test_console_token_cannot_call_tools(identity, kc, env):
    login(identity, kc, "ana")
    r = env.gateway.invoke(identity.console_token("ana"), "get_positions", {"client_id": "C-1001"})
    assert r.status == "denied" and "act claim" in r.reasons[0]


def test_token_exchange_cannot_add_scopes(identity, kc):
    login(identity, kc, "sam")
    resp = identity.exchange_raw(identity.console_token("sam"), "payments:initiate")
    assert resp.status_code == 400 and resp.json()["error"] == "invalid_scope"


def test_agent_never_gets_approval_or_audit_scopes(identity, kc):
    login(identity, kc, "sup")
    c, _ = claims(identity.agent_token("sup"))
    assert "approvals:decide" not in c["scope"].split()
    resp = identity.exchange_raw(identity.console_token("sup"), "approvals:decide")
    got = set(resp.json().get("scope", "").split()) if resp.status_code == 200 else set()
    assert "approvals:decide" not in got  # not one of the agent client's scopes


def test_supervisor_approves_with_own_token(identity, kc, env):
    svc = TestClient(create_app(env))
    login(identity, kc, "ana")
    login(identity, kc, "sup")
    wire = {"client_id": "C-1002", "from_account_id": "40055555555", "beneficiary_id": "B-2002", "amount_usd": 5000}
    r = env.gateway.invoke(identity.agent_token("ana"), "initiate_wire_transfer", wire, idempotency_key="kc-1")
    assert r.status == "pending_approval"
    ana = {"Authorization": f"Bearer {identity.console_token('ana')}"}
    casey = {"Authorization": f"Bearer {identity.console_token('sup')}"}
    assert svc.post(f"/v1/approvals/{r.action_id}/decision", headers=ana, json={"approve": True}).status_code == 403
    done = svc.post(f"/v1/approvals/{r.action_id}/decision", headers=casey, json={"approve": True, "note": "called"})
    assert done.json()["status"] == "executed"


def test_gateway_rejects_id_tokens_and_foreign_tokens(identity, kc, cfg, env):
    body = password_login(cfg, "ana.ruiz", "demo", REDIRECT, http=kc)
    with pytest.raises(TokenError, match="wrong token type"):
        env.verifier.verify(body["id_token"])
    dev_token = env.token_for("ana")  # signed by the dev IdP, not Keycloak
    with pytest.raises(TokenError):
        env.verifier.verify(dev_token)


def test_jwks_refresh_on_unknown_kid():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from jwt.algorithms import OKPAlgorithm

    k1, k2 = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    docs = [{"keys": [{**json.loads(OKPAlgorithm.to_jwk(k1.public_key())), "kid": "a"}]},
            {"keys": [{**json.loads(OKPAlgorithm.to_jwk(k2.public_key())), "kid": "b"}]}]
    now = [0.0]
    src = JwksKeySource("x", fetch=lambda u: docs.pop(0), clock=lambda: now[0])
    assert set(src()) == {"a"}
    assert "b" not in src.refresh()  # rate-limited
    now[0] = 60
    assert set(src.refresh()) == {"b"}


# ------------------------------------------------------------------ the demo app in Keycloak mode

def test_demo_app_sign_in_and_scenarios(kc, cfg, env):
    gw = TestClient(create_app(env, base_url="http://testserver", dev_mode=True))
    identity = OidcIdentity(cfg, USERNAMES, http=kc)
    demo = TestClient(create_demo_app("http://testserver", gateway_client=gw, identity=identity),
                      base_url="http://localhost:8000")

    first = demo.post("/api/scenario/holdings")
    assert first.status_code == 401 and first.json()["error"] == "login_required" and first.json()["who"] == "ana"

    def sign_in(who):
        to_kc = demo.get(f"/auth/login?as={who}", follow_redirects=False).headers["location"]
        assert "code_challenge_method=S256" in to_kc and "prompt=login" in to_kc
        page = kc.get(to_kc)
        action = re.search(r'action="([^"]+)"', page.text).group(1).replace("&amp;", "&")
        back = kc.post(action, data={"username": USERNAMES[who], "password": "demo"}, follow_redirects=False)
        path = back.headers["location"].replace("http://localhost:8000", "")
        page = demo.get(path)
        assert "signed-in" in page.text

    sign_in("ana")
    assert demo.get("/api/config").json()["idp"]["signed_in"] == ["ana"]
    runs = demo.post("/api/scenario/holdings").json()["runs"]
    assert runs[0]["calls"][0]["outcome"] == "executed"
    assert demo.post("/api/scenario/wrong-role").json()["who"] == "sam"
    sign_in("sam")
    call = demo.post("/api/scenario/wrong-role").json()["runs"][0]["calls"][0]
    assert call["outcome"] == "denied" and call["reasons"][0].startswith("scope")
    demo.post("/api/scenario/wire-approval")
    assert demo.get("/api/approvals").json()["who"] == "sup"  # supervisor must sign in
    sign_in("sup")
    [pending] = demo.get("/api/approvals").json()["pending"]
    refused = demo.post(f"/api/approvals/{pending['action_id']}", json={"approve": True, "as": "ana"}).json()
    assert refused["status"] == "approval_denied" and "approvals:decide" in refused["reasons"][0]
    done = demo.post(f"/api/approvals/{pending['action_id']}", json={"approve": True, "as": "sup"}).json()
    assert done["status"] == "executed"
    assert demo.post("/api/scenario/token-replay").json()["runs"][-1]["calls"][0]["outcome"] == "denied"
    assert demo.get("/api/audit").status_code == 401  # compliance not signed in
    sign_in("cmp")
    assert demo.get("/api/audit").json()["intact"]


def test_keycloak_check_passes_against_stand_in(kc, tmp_path):
    from govagent.keycloak_check import run_checks

    report = tmp_path / "kc.txt"
    assert run_checks(f"{KC}/realms/fsi-demo", report, http=kc) == 0, report.read_text()
    text = report.read_text()
    assert "13/13 checks passed" in text and "eyJ" not in text  # decoded claims only, never raw tokens


def test_multi_agent_with_keycloak(kc, cfg, env):
    """Orchestrator and specialists each exchange tokens at Keycloak; the realm's audiences fix who may
    delegate to whom, and a hardcoded nested act records the chain."""
    gw = TestClient(create_app(env, base_url="http://testserver", dev_mode=True))
    identity = OidcIdentity(cfg, USERNAMES, http=kc)
    demo = TestClient(create_demo_app("http://testserver", gateway_client=gw, identity=identity),
                      base_url="http://localhost:8000")
    login(identity, kc, "ana")
    run = demo.post("/api/scenario/multi-review-email").json()["runs"][0]
    assert [(c["agent"], c["outcome"]) for c in run["calls"]] == [("accounts-agent", "executed"),
                                                                  ("comms-agent", "executed")]
    events = demo.get("/api/tokens", params={"trace_id": run["trace_id"]}).json()["events"]
    assert [e["kind"] for e in events] == ["sign-in", "token-exchange", "token-exchange", "token-exchange"]
    signin, orch, accounts, _ = events
    assert orch["parent"] == signin["id"] and accounts["parent"] == orch["id"]
    assert accounts["claims"]["act"] == {"sub": "accounts-agent", "act": {"sub": "orchestrator-agent"}}
    assert accounts["claims"]["aud"] == env.verifier.audience and accounts["header"]["typ"] == "at+jwt"
    assert set(accounts["claims"]["scope"].split()) <= {"client:read", "positions:read", "profile:write"}
    assert demo.post(f"/api/tokens/{accounts['id']}/validate").json()["valid"]

    skip = demo.post("/api/scenario/multi-skip-orchestrator").json()["runs"][0]
    assert skip["calls"] == [] and "Keycloak refused" in skip["final_text"]  # IdP stops it first

    hijack = demo.post("/api/scenario/multi-comms-hijack").json()["runs"][0]
    wire = next(c for c in hijack["calls"] if c["tool"] == "initiate_wire_transfer")
    assert wire["outcome"] == "denied" and wire["reasons"][0].startswith("agent:")

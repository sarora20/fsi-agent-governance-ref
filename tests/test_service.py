"""Gap 4: the gateway as a separate service. The agent runtime holds only a token and a URL."""

import pytest

pytest.importorskip("fastapi")

from conftest import WIRE_OK  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from govagent.adapters.scripted import ScriptedAdapter  # noqa: E402
from govagent.agent.runner import AgentRunner  # noqa: E402
from govagent.agents import AgentRegistry  # noqa: E402
from govagent.app import PRINCIPALS  # noqa: E402
from govagent.audit import AuditLog  # noqa: E402
from govagent.remote import RemoteGateway  # noqa: E402
from govagent.service import METADATA_PATH, create_app  # noqa: E402


@pytest.fixture
def svc(make_env):
    env = make_env(queue=True)
    return env, TestClient(create_app(env))


def auth(token, key=None):
    h = {"Authorization": f"Bearer {token}"}
    if key:
        h["Idempotency-Key"] = key
    return h


def test_protected_resource_metadata(svc):
    env, tc = svc
    meta = tc.get(METADATA_PATH).json()
    assert meta["resource"] == env.verifier.audience and meta["authorization_servers"] == [env.verifier.issuer]
    assert "header" in meta["bearer_methods_supported"]


def test_401_with_resource_metadata_pointer(svc):
    env, tc = svc
    r = tc.post("/v1/tools/get_positions/invoke", json={"arguments": {"client_id": "C-1001"}})
    assert r.status_code == 401 and "resource_metadata=" in r.headers["www-authenticate"]
    bad = env.token_for("ana", audience="https://other.example")
    assert tc.post("/v1/tools/get_positions/invoke", json={"arguments": {"client_id": "C-1001"}},
                   headers=auth(bad)).status_code == 401


def test_status_codes(svc):
    env, tc = svc
    t = env.token_for("ana")
    email = {"arguments": {"client_id": "C-1001", "subject": "s", "body": "b"}}
    assert tc.post("/v1/tools/get_positions/invoke", json={"arguments": {"client_id": "C-1003"}},
                   headers=auth(t)).status_code == 403
    assert tc.post("/v1/tools/draft_client_email/invoke", json=email, headers=auth(t)).status_code == 400
    assert tc.post("/v1/tools/draft_client_email/invoke", json=email, headers=auth(t, "k")).status_code == 200
    replay = tc.post("/v1/tools/draft_client_email/invoke", json=email, headers=auth(t, "k"))
    assert replay.status_code == 200 and replay.json()["replayed"]
    changed = {"arguments": {"client_id": "C-1001", "subject": "s", "body": "other"}}
    assert tc.post("/v1/tools/draft_client_email/invoke", json=changed, headers=auth(t, "k")).status_code == 422
    assert tc.post("/v1/tools/initiate_wire_transfer/invoke", json={"arguments": WIRE_OK},
                   headers=auth(t, "w")).status_code == 202


def test_remote_agent_run_and_supervisor_approval(svc):
    env, tc = svc
    remote = RemoteGateway(client=tc)
    token = env.token_for("ana")
    runner = AgentRunner(ScriptedAdapter([
        {"tool_calls": [{"name": "initiate_wire_transfer", "args": WIRE_OK}]},
        {"text": "Submitted for approval."},
    ]), remote, remote.tools(token), audit=AuditLog())
    run = runner.run("wire", token)
    assert [c.outcome for c in run.calls] == ["pending_approval"]
    action_id = run.calls[0].action_id

    # the agent runtime cannot approve (no approvals:decide scope), nor can the requester
    assert tc.post(f"/v1/approvals/{action_id}/decision", json={"approve": True},
                   headers=auth(env.token_for("ana"))).status_code == 403
    sup = env.person_token("sup")
    listed = tc.get("/v1/approvals", headers=auth(sup)).json()["pending"]
    assert [a["action_id"] for a in listed] == [action_id]
    # the approver identity comes from the token, not the body
    r = tc.post(f"/v1/approvals/{action_id}/decision", json={"approve": True, "approver": "ana.ruiz"},
                headers=auth(sup))
    assert r.status_code == 200 and r.json()["status"] == "executed" and env.backend.wires
    assert tc.get("/v1/audit/verify").json()["intact"]


def test_run_calls_are_private_to_the_run(svc):
    env, tc = svc
    t1, t2 = env.token_for("ana"), env.token_for("ana")
    tc.post("/v1/tools/get_positions/invoke", json={"arguments": {"client_id": "C-1001"}}, headers=auth(t1))
    from govagent.identity import peek_run_id

    assert tc.get(f"/v1/runs/{peek_run_id(t1)}/calls", headers=auth(t2)).status_code == 403
    assert len(tc.get(f"/v1/runs/{peek_run_id(t1)}/calls", headers=auth(t1)).json()["calls"]) == 1


def test_remote_retries_reuse_the_idempotency_key(make_env):
    import httpx

    env = make_env(initiate_wire_transfer=True)
    app_client = TestClient(create_app(env))
    attempts = {"n": 0}

    class Flaky(httpx.BaseTransport):
        def handle_request(self, request):
            attempts["n"] += 1
            resp = app_client.post(request.url.path, content=request.content, headers=dict(request.headers))
            if attempts["n"] == 1:  # the gateway acted, but the response was lost on the way back
                raise httpx.ReadTimeout("lost response", request=request)
            return httpx.Response(resp.status_code, json=resp.json())

    remote = RemoteGateway(client=httpx.Client(base_url="http://gw", transport=Flaky()))
    r = remote.invoke(env.token_for("ana"), "initiate_wire_transfer", WIRE_OK, idempotency_key="k-retry")
    assert r.ok and r.replayed and len(env.backend.wires) == 1


def test_authority_reports_whether_agent_registry_is_enforced(make_env):
    """/v1/authority never reports `agents: null`: an AgentRegistry is required to build a gateway, so
    the field is always present, and `unconstrained` says plainly whether stage 4 is actually enforcing
    rather than leaving that to be inferred from the field's absence."""
    env = make_env()
    tc = TestClient(create_app(env))
    agents = tc.get("/v1/authority", headers=auth(env.token_for("ana"))).json()["agents"]
    assert agents is not None and agents["unconstrained"] is False
    assert any(a["id"] == "payments-agent" for a in agents["list"])

    open_env = make_env(agent_registry=AgentRegistry.unconstrained())
    open_tc = TestClient(create_app(open_env))
    open_agents = open_tc.get("/v1/authority", headers=auth(open_env.token_for("ana"))).json()["agents"]
    assert open_agents["unconstrained"] is True and open_agents["list"] == []


def test_kill_switch_is_never_delegated_to_an_agent(make_env):
    """controls:admin is never issued to an agent token (identity.py AGENT_SCOPES); the endpoint also
    refuses an agent token explicitly, the same defence-in-depth pattern as approvals and audit."""
    env = make_env()
    tc = TestClient(create_app(env))
    body = {"scope": "global", "key": "", "reason": "incident"}

    agent_attempt = tc.post("/v1/controls/stop", json=body, headers=auth(env.token_for("ana")))
    assert agent_attempt.status_code == 403 and agent_attempt.json()["error"] == "agents_cannot_administer_controls"

    no_scope_attempt = tc.post("/v1/controls/stop", json=body, headers=auth(env.person_token("lee")))
    assert no_scope_attempt.status_code == 403 and no_scope_attempt.json()["error"] == "insufficient_scope"

    supervisor = tc.post("/v1/controls/stop", json=body, headers=auth(env.person_token("sup")))
    assert supervisor.status_code == 200 and supervisor.json()["global"]["reason"] == "incident"
    assert env.gateway.invoke(env.token_for("ana"), "get_positions", {"client_id": "C-1001"}).status == "denied"

    released = tc.post("/v1/controls/release", json=body, headers=auth(env.person_token("sup")))
    assert released.status_code == 200 and released.json()["global"] is None
    assert env.gateway.invoke(env.token_for("ana"), "get_positions", {"client_id": "C-1001"}).ok


def test_metrics_is_public_and_reports_stop_and_breaker_state(make_env):
    env = make_env()
    tc = TestClient(create_app(env))
    env.gateway.invoke(env.token_for("ana"), "get_positions", {"client_id": "C-1003"})  # one entitlement denial
    env.store.engage_stop("tool", "draft_client_email", "maintenance", "casey.morgan", env.gateway.clock())

    metrics = tc.get("/v1/metrics").json()  # no Authorization header at all
    assert metrics["decisions"]["by_stage"].get("entitlement", 0) >= 1
    assert metrics["stop"]["tools"]["draft_client_email"]["reason"] == "maintenance"
    assert metrics["breakers"] == {}


def test_dpop_bound_token_over_real_http_end_to_end(make_env):
    """item 7: a stolen delegation token is useless without the private key -- proven over the
    actual HTTP path (RemoteGateway -> service.py -> ToolGateway -> TokenVerifier), not just the
    in-process identity layer test_identity.py already covers."""
    import govagent.dpop as dpop
    from govagent.remote import RemoteGateway

    env = make_env()
    tc = TestClient(create_app(env))
    client_key = dpop.DPoPKey.generate()
    bound_token = env.tokens.issue(PRINCIPALS["ana"], "advisor-assist-agent", dpop_jkt=client_key.thumbprint)

    legitimate = RemoteGateway(client=tc, dpop_key=client_key)
    assert legitimate.invoke(bound_token, "get_positions", {"client_id": "C-1001"}).ok

    thief = RemoteGateway(client=tc, dpop_key=dpop.DPoPKey.generate())
    stolen = thief.invoke(bound_token, "get_positions", {"client_id": "C-1001"})
    assert stolen.status == "denied" and "different key" in stolen.reasons[0]

    bare = RemoteGateway(client=tc)  # the classic bearer-token-theft shape: no DPoP header at all
    bare_result = bare.invoke(bound_token, "get_positions", {"client_id": "C-1001"})
    assert bare_result.status == "denied" and "no proof/method/url" in bare_result.reasons[0]

    # unaffected: an ordinary (never-bound) token, over the exact same HTTP path
    plain_token = env.tokens.issue(PRINCIPALS["ana"], "advisor-assist-agent")
    assert bare.invoke(plain_token, "get_positions", {"client_id": "C-1001"}).ok


def test_dpop_missing_proof_gets_the_rfc9449_challenge(make_env):
    import govagent.dpop as dpop

    env = make_env()
    tc = TestClient(create_app(env, base_url="http://testserver"))
    client_key = dpop.DPoPKey.generate()
    bound_token = env.tokens.issue(PRINCIPALS["ana"], "advisor-assist-agent", dpop_jkt=client_key.thumbprint)

    r = tc.post("/v1/tools/get_positions/invoke", json={"arguments": {"client_id": "C-1001"}},
               headers=auth(bound_token))
    assert r.status_code == 401
    assert 'DPoP error="invalid_dpop_proof"' in r.headers["www-authenticate"]


def test_dpop_proof_cannot_be_replayed_over_http(make_env):
    import govagent.dpop as dpop

    env = make_env()
    tc = TestClient(create_app(env, base_url="http://testserver"))
    key = dpop.DPoPKey.generate()
    token = env.tokens.issue(PRINCIPALS["ana"], "advisor-assist-agent", dpop_jkt=key.thumbprint)
    url = "http://testserver/v1/tools/get_positions/invoke"
    proof = key.proof("POST", url, access_token=token)
    headers = {**auth(token), "DPoP": proof}
    body = {"arguments": {"client_id": "C-1001"}}

    assert tc.post("/v1/tools/get_positions/invoke", json=body, headers=headers).status_code == 200
    replayed = tc.post("/v1/tools/get_positions/invoke", json=body, headers=headers)
    assert replayed.status_code == 401 and "replay" in replayed.json()["reasons"][0]

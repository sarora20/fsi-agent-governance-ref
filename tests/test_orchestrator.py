"""Multi-agent: agent registry, delegation chains (nested act), orchestrated scenarios, traces and tokens."""

import json

import jwt
import pytest

from govagent.agents import AgentRegistry
from govagent.app import PRINCIPALS, build_environment
from govagent.approvals import QueueApprovals
from govagent.audit import AuditLog
from govagent.gateway import ToolGateway
from govagent.identity import DEFAULT_AUDIENCE, ROLE_SCOPES, TokenError, TokenService
from govagent.orchestrator import SPECIALISTS

WIRE = {"client_id": "C-1001", "from_account_id": "40012345678", "beneficiary_id": "B-2001", "amount_usd": 1000}


@pytest.fixture
def env():
    return build_environment(approvals=QueueApprovals())


def claims(token):
    return jwt.decode(token, options={"verify_signature": False})


# ------------------------------------------------------------------ registry and realm agree

def test_registry_specialists_and_realm_agree():
    reg = AgentRegistry.from_file()
    realm = json.load(open("keycloak/realm-fsi-demo.json"))
    clients = {c["clientId"]: c for c in realm["clients"]}
    assert set(reg.agents) <= set(clients)
    for agent_id, spec in SPECIALISTS.items():
        assert reg.get(agent_id).delegated_by == {"orchestrator-agent"}
        assert set(clients[agent_id]["optionalClientScopes"]) == set(spec.scopes)
        assert spec.scopes <= ROLE_SCOPES["advisor"]
    assert reg.get("orchestrator-agent").tools == frozenset()


# ------------------------------------------------------------------ delegation chains at the gateway

def test_dev_exchange_nests_act_and_only_narrows(env):
    orch = env.tokens.issue(PRINCIPALS["ana"], "orchestrator-agent")
    pay = env.tokens.exchange(orch, "payments-agent", {"payments:initiate"})
    c = claims(pay)
    assert c["act"] == {"sub": "payments-agent", "act": {"sub": "orchestrator-agent"}}
    assert c["scope"] == "payments:initiate" and c["client_id"] == "payments-agent"
    assert env.verifier.verify(pay).actor_chain == ("payments-agent", "orchestrator-agent")
    sam_orch = env.tokens.issue(PRINCIPALS["sam"], "orchestrator-agent")
    with pytest.raises(TokenError, match="invalid_scope"):
        env.tokens.exchange(sam_orch, "payments-agent", {"payments:initiate"})


def test_gateway_enforces_agent_registry(env):
    orch = env.tokens.issue(PRINCIPALS["ana"], "orchestrator-agent")
    r = env.gateway.invoke(orch, "initiate_wire_transfer", WIRE, idempotency_key="k1")
    assert r.status == "denied" and "orchestrator-agent' is not allowed" in r.reasons[0]

    comms = env.tokens.exchange(orch, "comms-agent", {"comms:draft", "client:read"})
    r = env.gateway.invoke(comms, "initiate_wire_transfer", WIRE, idempotency_key="k2")
    assert r.status == "denied" and r.reasons[0].startswith("agent:")  # before scope or policy

    direct = env.tokens.issue(PRINCIPALS["ana"], "payments-agent", ["payments:initiate"])
    r = env.gateway.invoke(direct, "initiate_wire_transfer", WIRE, idempotency_key="k3")
    assert r.status == "denied" and "cannot act for a person directly" in r.reasons[0]

    pay = env.tokens.exchange(orch, "payments-agent", {"payments:initiate"})
    deeper = env.tokens.exchange(pay, "comms-agent", {"payments:initiate"})
    r = env.gateway.invoke(deeper, "get_client_profile", {"client_id": "C-1001"})
    assert r.status == "denied" and "deeper than" in r.reasons[0]

    accounts = env.tokens.exchange(orch, "accounts-agent", {"client:read", "positions:read"})
    assert env.gateway.invoke(accounts, "get_positions", {"client_id": "C-1001"}).status == "executed"


def test_agent_registry_is_required_to_build_a_gateway(env):
    """Stage 4 has no "not configured" path: an AgentRegistry is a required constructor argument,
    not an optional one that happens to always be supplied. Leaving it out is a TypeError, not a
    silently permissive gateway."""
    with pytest.raises(TypeError):
        ToolGateway(env.registry, env.policy, env.verifier, env.directory, env.approvals, env.audit, env.store)


def test_unconstrained_agent_registry_is_explicit_and_audited():
    """AgentRegistry.unconstrained() is the only way to get the old "no registry" behavior back, and
    choosing it is recorded in the audit log at construction -- visible in the evidence pack rather
    than inferred from a missing argument."""
    audit = AuditLog()
    unconstrained_env = build_environment(approvals=QueueApprovals(), audit=audit,
                                          agent_registry=AgentRegistry.unconstrained())
    assert any(e["event"] == "agent_registry_unconstrained" for e in audit.entries())

    orch = unconstrained_env.tokens.issue(PRINCIPALS["ana"], "orchestrator-agent")
    # orchestrator-agent has no tools of its own (test_gateway_enforces_agent_registry shows this
    # denied, "orchestrator-agent' is not allowed", under the real registry); unconstrained, nothing
    # at stage 4 stops it, and the read-only policy and scope checks both allow it through.
    r = unconstrained_env.gateway.invoke(orch, "get_client_profile", {"client_id": "C-1001"})
    assert r.status == "executed"


def test_exchanged_token_audience_is_narrowed_to_its_actor(env):
    """Every issued or exchanged token for a known agent carries that agent's own id as a second
    audience value alongside the gateway's own -- RFC 8707 resource narrowing, so a comms-agent
    token and a payments-agent token are no longer identical by audience alone. This is checked at
    identity (verify()), independent of the agent-registry stage at the gateway (stage 4): a token
    minted without it -- here, deliberately, by a TokenService that bypasses the shared registry --
    is refused before run binding, registry lookup or stage 4 even run."""
    orch = env.tokens.issue(PRINCIPALS["ana"], "orchestrator-agent")
    pay = env.tokens.exchange(orch, "payments-agent", {"payments:initiate"})
    assert set(claims(pay)["aud"]) == {DEFAULT_AUDIENCE, "payments-agent"}
    comms = env.tokens.exchange(orch, "comms-agent", {"comms:draft", "client:read"})
    assert set(claims(comms)["aud"]) == {DEFAULT_AUDIENCE, "comms-agent"}  # distinct from payments-agent's

    bare = TokenService(env.keys, env.tokens.issuer)  # no agent_registry: narrowing skipped at mint
    bare_orch = bare.issue(PRINCIPALS["ana"], "orchestrator-agent")
    bare_pay = bare.exchange(bare_orch, "payments-agent", {"payments:initiate"})
    with pytest.raises(TokenError, match="does not name its own actor"):
        env.verifier.verify(bare_pay)


def test_explain_token_lists_every_check(env):
    from fastapi.testclient import TestClient

    from govagent.service import create_app

    svc = TestClient(create_app(env, dev_mode=True))
    orch = env.tokens.issue(PRINCIPALS["ana"], "orchestrator-agent")
    pay = env.tokens.exchange(orch, "payments-agent", {"payments:initiate"})
    body = svc.post("/v1/dev/explain-token", json={"token": pay}).json()
    names = [c["check"] for c in body["checks"]]
    assert body["valid"] and {"algorithm pinned", "signature", "audience", "delegation chain", "agent registry"} <= set(names)
    assert body["grant"]["chain"] == ["payments-agent", "orchestrator-agent"]
    bad = svc.post("/v1/dev/explain-token", json={"token": pay[:-4] + "AAAA"}).json()
    assert not bad["valid"] and bad["checks"][-1] == {"check": "signature", "ok": False, "detail": "invalid signature"}


# ------------------------------------------------------------------ the demo app, dev mode

@pytest.fixture
def demo(tmp_path):
    from fastapi.testclient import TestClient

    from govagent.app import dev_keyring
    from govagent.audit import AuditLog
    from govagent.demo.app import create_demo_app
    from govagent.service import create_app
    from govagent.state import StateStore

    e = build_environment(approvals=QueueApprovals(), audit=AuditLog(tmp_path / "a.jsonl"),
                          store=StateStore(tmp_path / "s.db"), keys=dev_keyring(shared=True))
    gw = TestClient(create_app(e, base_url="http://testserver", dev_mode=True))
    return TestClient(create_demo_app("http://testserver", gateway_client=gw))


def outcomes(run):
    return [(c["agent"], c["tool"], c["outcome"]) for c in run["calls"]]


def test_multi_scenarios(demo):
    demo.post("/api/reset")
    run = demo.post("/api/scenario/multi-review-email").json()["runs"][0]
    assert outcomes(run) == [("accounts-agent", "get_positions", "executed"),
                             ("comms-agent", "draft_client_email", "executed")]
    assert [d["agent_id"] for d in run["delegations"]] == ["accounts-agent", "comms-agent"]

    run = demo.post("/api/scenario/multi-wire").json()["runs"][0]
    assert ("payments-agent", "initiate_wire_transfer", "pending_approval") in outcomes(run)

    run = demo.post("/api/scenario/multi-comms-hijack").json()["runs"][0]
    wire_call = next(c for c in run["calls"] if c["tool"] == "initiate_wire_transfer")
    assert wire_call["agent"] == "comms-agent" and wire_call["outcome"] == "denied"
    assert wire_call["reasons"][0].startswith("agent:")
    assert {p["stage"]: p["state"] for p in wire_call["pipeline"]}["agent"] == "fail"
    comms = next(d for d in run["delegations"] if d["agent_id"] == "comms-agent")
    assert "unsupported_success_claim" in comms["guardrail_flags"]  # "Done: I sent the wire" corrected

    run = demo.post("/api/scenario/multi-orchestrator-direct").json()["runs"][0]
    assert outcomes(run) == [("orchestrator-agent", "initiate_wire_transfer", "denied")]

    run = demo.post("/api/scenario/multi-skip-orchestrator").json()["runs"][0]
    assert run["calls"][0]["outcome"] == "denied" and "person directly" in run["calls"][0]["reasons"][0]


def test_trace_covers_every_hop(demo):
    demo.post("/api/reset")
    run = demo.post("/api/scenario/multi-comms-hijack").json()["runs"][0]
    spans = demo.get(f"/api/trace/{run['trace_id']}").json()["spans"]
    names = {s["name"] for s in spans}
    assert {"scenario multi-comms-hijack", "invoke_agent orchestrator", "invoke_agent comms",
            "execute_tool ask_comms_agent", "idp token_exchange", "gateway initiate_wire_transfer",
            "check agent", "backend get_client_profile", "guardrail final_answer"} <= names
    assert any(n.startswith("chat ") for n in names)
    failed = [s for s in spans if s["name"] == "check agent" and s["status"] == "ERROR"]
    assert failed and "comms-agent" in failed[0]["status_message"]
    ids = {s["span_id"] for s in spans}
    assert all(s["parent_id"] in ids for s in spans if s["parent_id"])  # one connected tree
    gw = next(s for s in spans if s["name"] == "gateway initiate_wire_transfer")
    assert gw["attributes"]["govagent.delegation_chain"] == "comms-agent <- orchestrator-agent"


def test_token_ledger_and_validation(demo):
    demo.post("/api/reset")
    run = demo.post("/api/scenario/multi-wire").json()["runs"][0]
    events = demo.get("/api/tokens", params={"trace_id": run["trace_id"]}).json()["events"]
    agents = [e["agent"] for e in events]
    assert agents == ["orchestrator-agent", "payments-agent", "comms-agent"]
    orch, pay = events[0], events[1]
    assert pay["parent"] == orch["id"] and pay["claims"]["act"]["act"]["sub"] == "orchestrator-agent"
    checks = demo.post(f"/api/tokens/{pay['id']}/validate").json()
    assert checks["valid"] and checks["grant"]["scopes"] == ["payments:initiate"]


def test_compare_pair(demo):
    demo.post("/api/reset")
    out = demo.post("/api/compare/multi").json()
    assert all(c["outcome"] == "executed" for c in out["allowed"]["run"]["calls"])
    assert any(c["outcome"] == "denied" for c in out["denied"]["run"]["calls"])
    assert out["allowed"]["run"]["trace_id"] != out["denied"]["run"]["trace_id"]


def test_scores_endpoints_run_the_suite(tmp_path, monkeypatch):
    import time as _time

    from fastapi.testclient import TestClient

    from govagent.demo.app import create_demo_app

    monkeypatch.setenv("GOVAGENT_REPORTS", str(tmp_path))
    demo = TestClient(create_demo_app("http://testserver"))
    assert demo.get("/api/evals").json()["latest"] == []
    job = demo.post("/api/evals/run", json={"adapter": "scripted", "trials": 2}).json()
    assert job["state"] == "running" and job["total"] >= 40
    for _ in range(600):
        state = demo.get("/api/evals").json()["job"]
        if state["state"] != "running":
            break
        _time.sleep(0.1)
    assert state["state"] == "done" and state["gate_passed"]
    latest = demo.get("/api/evals").json()["latest"][0]
    assert latest["trials"] == 2 and latest["scores"]["behavior_pass_hat_2"] == 1.0
    report = demo.get("/api/evals/report/scripted").json()
    multi = [r for r in report["results"] if r["mode"] == "multi"]
    assert len(multi) >= 5 and all(r["passed"] for r in multi)
    assert demo.post("/api/evals/run", json={"adapter": "claude"}).status_code in (400, 409)


def test_review_fixes_answer_guardrail_and_chains():
    """From the independent v0.6 review: hedges judged per sentence, dollar amounts not masked,
    orchestrator answers checked, malformed act chains refused."""
    import pytest as _pytest

    from govagent.guardrails import check_final_answer
    from govagent.identity import TokenError, actor_chain

    denied = [{"tool": "initiate_wire_transfer", "outcome": "denied"}]
    for ok in ("The wire wasn't sent.", "It hasn't been sent yet.", "It was never sent; policy refused it."):
        assert check_final_answer(ok, denied)[1] == [], ok
    assert "unsupported_success_claim" in check_final_answer("Wire sent! I cannot share the SSN.", denied)[1]
    assert "$12500000" in check_final_answer("A $12500000 wire is over the limit.", [])[0]
    with _pytest.raises(TokenError):
        actor_chain({"sub": "payments-agent", "act": {"id": "x"}})
    with _pytest.raises(TokenError):
        actor_chain({"sub": "a", "act": {"sub": "b"}}, limit=1)

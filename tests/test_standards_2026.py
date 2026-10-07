"""Alignment with standards current as of September 2026:
MCP authorization 2026-07-28 scope challenges, task-style polling, W3C trace context,
OpenID AuthZEN Authorization API 1.0 (Final, Jan 2026), IETF Transaction Tokens (draft-08)."""

import uuid

import jwt
import pytest

pytest.importorskip("fastapi")

from conftest import WIRE_OK  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from govagent import pdp  # noqa: E402
from govagent.service import create_app  # noqa: E402

TRACEPARENT = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"


def auth(token, key=None):
    h = {"Authorization": f"Bearer {token}"}
    if key:
        h["Idempotency-Key"] = key
    return h


@pytest.fixture
def svc(make_env):
    env = make_env(queue=True)
    return env, TestClient(create_app(env))


def test_insufficient_scope_challenge(svc):
    env, tc = svc
    narrowed = env.token_for("ana", scopes=["client:read"])
    r = tc.post("/v1/tools/get_positions/invoke", json={"arguments": {"client_id": "C-1001"}}, headers=auth(narrowed))
    assert r.status_code == 403
    challenge = r.headers["www-authenticate"]
    assert 'error="insufficient_scope"' in challenge and 'scope="positions:read"' in challenge
    assert "resource_metadata=" in challenge


def test_401_names_the_scope_needed(svc):
    _, tc = svc
    r = tc.post("/v1/tools/initiate_wire_transfer/invoke", json={"arguments": WIRE_OK})
    assert r.status_code == 401 and 'scope="payments:initiate"' in r.headers["www-authenticate"]


def test_pending_action_can_be_polled_like_a_task(svc):
    env, tc = svc
    token = env.token_for("ana")
    action_id = tc.post("/v1/tools/initiate_wire_transfer/invoke", json={"arguments": WIRE_OK},
                        headers=auth(token, "k1")).json()["action_id"]
    assert tc.get(f"/v1/actions/{action_id}", headers=auth(token)).json()["status"] == "pending"
    # another user cannot even learn it exists
    assert tc.get(f"/v1/actions/{action_id}", headers=auth(env.token_for("sam"))).status_code == 404
    tc.post(f"/v1/approvals/{action_id}/decision", json={"approve": True}, headers=auth(env.person_token("sup")))
    assert tc.get(f"/v1/actions/{action_id}", headers=auth(token)).json()["status"] == "executed"


def test_trace_context_flows_to_audit_and_backend(make_env):
    env = make_env(initiate_wire_transfer=True)
    seen = {}
    original = env.registry.get("initiate_wire_transfer").handler
    object.__setattr__(env.registry.get("initiate_wire_transfer"), "handler",
                       lambda a, m: seen.setdefault("meta", m) and original(a, m))
    tc = TestClient(create_app(env))
    headers = {**auth(env.token_for("ana"), "k-trace"), "traceparent": TRACEPARENT}
    assert tc.post("/v1/tools/initiate_wire_transfer/invoke", json={"arguments": WIRE_OK}, headers=headers).status_code == 200
    assert any(e.get("traceparent") == TRACEPARENT for e in env.audit.entries())
    claims = jwt.decode(seen["meta"].txn_token, options={"verify_signature": False})
    assert claims["rctx"]["trace_id"] == "4bf92f3577b34da6a3ce929d0e0e4736"


def test_authzen_pdp(svc):
    env, tc = svc
    cfg = tc.get(pdp.WELL_KNOWN).json()
    assert cfg["access_evaluation_endpoint"].endswith("/access/v1/evaluation")
    h = auth(env.token_for("ana"))

    def ask(subject, tool, props):
        return tc.post(pdp.EVALUATION_PATH, headers=h, json={
            "subject": {"type": "user", "id": subject}, "resource": {"type": "tool", "id": tool, "properties": props},
            "action": {"name": "invoke"}}).json()

    assert ask("ana.ruiz", "get_positions", {"client_id": "C-1001"})["decision"] is True
    wire = ask("ana.ruiz", "initiate_wire_transfer", WIRE_OK)
    assert wire["decision"] is False and wire["context"]["outcome"] == "require_approval"
    big = ask("ana.ruiz", "initiate_wire_transfer", dict(WIRE_OK, amount_usd=75000))
    assert big["context"]["outcome"] == "deny"
    assert ask("sam.okafor", "initiate_wire_transfer", WIRE_OK)["context"]["outcome"] == "deny"
    batch = tc.post(pdp.EVALUATIONS_PATH, headers=h, json={
        "subject": {"type": "user", "id": "ana.ruiz"}, "action": {"name": "invoke"},
        "evaluations": [{"resource": {"type": "tool", "id": "get_positions", "properties": {"client_id": "C-1001"}}},
                        {"resource": {"type": "tool", "id": "get_positions", "properties": {"client_id": "C-1003"}}}]})
    assert [e["decision"] for e in batch.json()["evaluations"]] == [True, False]
    assert tc.post(pdp.EVALUATION_PATH, json={}).status_code == 401


def test_gateway_can_use_a_remote_authzen_pdp(make_env):
    """PEP/PDP split: the gateway asks an AuthZEN PDP (here our own service) for the policy decision."""
    from govagent.pdp import AuthZenPolicyClient

    pdp_env = make_env()
    pdp_client = TestClient(create_app(pdp_env))
    env = make_env(initiate_wire_transfer=True)
    env.gateway.policy = AuthZenPolicyClient(pdp_client, env.policy, token=pdp_env.token_for("ana"))
    assert env.gateway.invoke(env.token_for("ana"), "initiate_wire_transfer", WIRE_OK, uuid.uuid4().hex).ok
    denied = env.gateway.invoke(env.token_for("ana"), "initiate_wire_transfer", dict(WIRE_OK, amount_usd=75000),
                                uuid.uuid4().hex)
    assert denied.status == "denied" and "$50,000" in denied.reasons[0]


def test_unreachable_pdp_fails_closed(make_env):
    from govagent.pdp import AuthZenPolicyClient

    class Down:
        def post(self, *a, **k):
            raise ConnectionError("pdp down")

    env = make_env()
    env.gateway.policy = AuthZenPolicyClient(Down(), env.policy)
    r = env.gateway.invoke(env.token_for("ana"), "get_positions", {"client_id": "C-1001"})
    assert r.status == "denied" and "fail closed" in r.reasons[0]

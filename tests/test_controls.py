"""Gaps closed in v0.2: cross-run velocity, async approvals with re-validation, idempotency."""

import threading
import uuid

from conftest import ADDR, WIRE_OK, Clock

from govagent.app import build_environment
from govagent.approvals import QueueApprovals
from govagent.identity import Principal


def wire(env, amount, who="ana", key=None, **extra):
    return env.gateway.invoke(env.token_for(who), "initiate_wire_transfer", dict(WIRE_OK, amount_usd=amount, **extra),
                              idempotency_key=key or uuid.uuid4().hex)


# ---------------------------------------------------------------- velocity (gap 1)

def test_split_wires_across_runs_are_aggregated(make_env):
    env = make_env(initiate_wire_transfer=True)
    assert wire(env, 20000).ok and wire(env, 20000).ok
    r = wire(env, 15000)
    assert r.status == "denied" and "payments.client-daily" in r.reasons[0]
    assert wire(env, 9000).ok  # 49,000 total is still within 50,000


def test_rolling_window_expires():
    clock = Clock()
    env = build_environment(approvals=__import__("govagent.approvals", fromlist=["x"]).InlineApprovals(
        {"initiate_wire_transfer": True}), clock=clock)
    assert wire(env, 45000).ok
    assert wire(env, 10000).status == "denied"
    clock.now += 86401
    assert wire(env, 10000).ok


def test_rejected_and_expired_approvals_release_reservations():
    clock = Clock()
    env = build_environment(approvals=QueueApprovals(), clock=clock)
    p = wire(env, 40000)
    assert p.status == "pending_approval"
    assert wire(env, 20000).status == "denied"  # the pending 40k is reserved
    env.gateway.decide(p.action_id, "casey.morgan", False)
    q = wire(env, 45000)
    assert q.status == "pending_approval"  # released
    clock.now += 4 * 3600 + 1
    assert wire(env, 45000).status == "pending_approval"  # the stale reservation expired and was released
    assert env.gateway.get_action(q.action_id).status == "expired"


def test_concurrent_requests_cannot_both_pass_the_limit():
    env = build_environment(approvals=QueueApprovals())
    results = []
    barrier = threading.Barrier(8)

    def go():
        barrier.wait()
        results.append(wire(env, 20000).status)

    threads = [threading.Thread(target=go) for _ in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert results.count("pending_approval") == 2  # 2 x 20k fit under 50k; the rest are denied
    assert results.count("denied") == 6


def test_principal_limit_spans_clients(make_env):
    env = make_env(initiate_wire_transfer=True)
    # add two more clients to Ana's book with accounts and beneficiaries
    for i, cid in enumerate(["C-2001", "C-2002", "C-2003"]):
        env.backend.clients[cid] = {**env.backend.clients["C-1001"],
                                    "accounts": {f"5000000000{i}": {"type": "Brokerage", "cash_usd": 1e6}}}
    book = frozenset({"C-1001", "C-1002", "C-2001", "C-2002", "C-2003"})
    env.directory.put(Principal("ana.ruiz", "Ana Ruiz", "advisor", book))
    env.directory.put(Principal("casey.morgan", "Casey Morgan", "supervisor", book))
    from govagent.app import PRINCIPALS
    PRINCIPALS["ana2"] = env.directory.get("ana.ruiz")
    try:
        for i, cid in enumerate(["C-2001", "C-2002", "C-2003"]):
            args = dict(WIRE_OK, client_id=cid, from_account_id=f"5000000000{i}", amount_usd=50000)
            r = env.gateway.invoke(env.token_for("ana2"), "initiate_wire_transfer", args, uuid.uuid4().hex)
            assert r.ok, r.reasons
        r = env.gateway.invoke(env.token_for("ana2"), "initiate_wire_transfer",
                               dict(WIRE_OK, amount_usd=1000), uuid.uuid4().hex)
        assert r.status == "denied" and "payments.principal-daily" in r.reasons[0]
    finally:
        PRINCIPALS.pop("ana2")


# ---------------------------------------------------------------- async approvals (gap 2)

def test_async_approval_executes_only_after_supervisor(make_env):
    env = make_env(queue=True)
    p = wire(env, 12000)
    assert p.status == "pending_approval" and not env.backend.wires
    assert [a.action_id for a in env.gateway.pending_actions()] == [p.action_id]
    r = env.gateway.decide(p.action_id, "casey.morgan", True, "verified by phone")
    assert r.ok and env.backend.wires
    assert env.gateway.get_action(p.action_id).status == "executed"
    assert env.gateway.decide(p.action_id, "casey.morgan", True).status == "rejected"  # no double execution


def test_approver_authority(make_env):
    env = make_env(queue=True)
    p = wire(env, 12000)
    assert "four-eyes" in env.gateway.decide(p.action_id, "ana.ruiz", True).reasons[0]
    assert "not authorized" in env.gateway.decide(p.action_id, "sam.okafor", True).reasons[0]
    env.directory.put(Principal("supervisor-02", "Other", "supervisor", frozenset({"C-9999"})))
    assert "does not supervise" in env.gateway.decide(p.action_id, "supervisor-02", True).reasons[0]
    assert env.gateway.get_action(p.action_id).status == "pending"  # refusals do not consume the action


def test_expired_approval_never_executes():
    clock = Clock()
    env = build_environment(approvals=QueueApprovals(), clock=clock)
    p = wire(env, 12000)
    clock.now += 4 * 3600 + 1
    r = env.gateway.decide(p.action_id, "casey.morgan", True)
    assert r.status == "expired" and not env.backend.wires


def test_revalidation_catches_changes_between_request_and_approval(make_env):
    # beneficiary removed from the approved list
    env = make_env(queue=True)
    p = wire(env, 12000)
    env.backend.clients["C-1001"]["approved_beneficiaries"].pop("B-2001")
    r = env.gateway.decide(p.action_id, "casey.morgan", True)
    assert r.status == "denied" and "revalidation: policy" in r.reasons[0] and not env.backend.wires

    # requester moved to a role without payments scope
    env = make_env(queue=True)
    p = wire(env, 12000)
    env.directory.put(Principal("ana.ruiz", "Ana Ruiz", "analyst", frozenset({"C-1001"})))
    assert "no longer grants" in env.gateway.decide(p.action_id, "casey.morgan", True).reasons[0]

    # requester's access revoked
    env = make_env(queue=True)
    p = wire(env, 12000)
    env.revoke_subject("ana.ruiz")
    assert "revoked" in env.gateway.decide(p.action_id, "casey.morgan", True).reasons[0]
    assert not env.backend.wires


def test_address_change_async(make_env):
    env = make_env(queue=True)
    p = env.gateway.invoke(env.token_for("ana"), "update_mailing_address", ADDR, "k-addr")
    assert p.status == "pending_approval"
    assert env.gateway.decide(p.action_id, "casey.morgan", True).ok
    assert env.backend.clients["C-1001"]["mailing_address"]["street"] == "1 Main St"


# ---------------------------------------------------------------- idempotency (gap 3)

def test_side_effects_require_a_key(make_env):
    env = make_env()
    r = env.gateway.invoke(env.token_for("ana"), "draft_client_email",
                           {"client_id": "C-1001", "subject": "s", "body": "b"})
    assert r.status == "rejected" and "key required" in r.reasons[0]
    assert env.gateway.invoke(env.token_for("ana"), "get_positions", {"client_id": "C-1001"}).ok  # reads don't


def test_retry_replays_without_repeating_the_side_effect(make_env):
    env = make_env(initiate_wire_transfer=True)
    token = env.token_for("ana")
    first = env.gateway.invoke(token, "initiate_wire_transfer", WIRE_OK, "retry-me")
    again = env.gateway.invoke(token, "initiate_wire_transfer", WIRE_OK, "retry-me")
    assert first.ok and again.ok and again.replayed and again.data == first.data
    assert len(env.backend.wires) == 1 and len(env.approvals.requests) == 1


def test_key_reuse_with_different_payload_is_rejected(make_env):
    env = make_env(initiate_wire_transfer=True)
    token = env.token_for("ana")
    env.gateway.invoke(token, "initiate_wire_transfer", WIRE_OK, "k1")
    r = env.gateway.invoke(token, "initiate_wire_transfer", dict(WIRE_OK, amount_usd=13000), "k1")
    assert r.status == "rejected" and "different payload" in r.reasons[0]


def test_pending_result_is_replayed_not_duplicated(make_env):
    env = make_env(queue=True)
    token = env.token_for("ana")
    a = env.gateway.invoke(token, "initiate_wire_transfer", WIRE_OK, "k-pend")
    b = env.gateway.invoke(token, "initiate_wire_transfer", WIRE_OK, "k-pend")
    assert a.action_id == b.action_id and len(env.gateway.pending_actions()) == 1


def test_keys_are_scoped_per_principal(make_env):
    env = make_env()
    body = {"client_id": "C-1001", "subject": "s", "body": "b"}
    assert env.gateway.invoke(env.token_for("ana"), "draft_client_email", body, "same").ok
    r = env.gateway.invoke(env.token_for("sam"), "draft_client_email", body, "same")
    assert r.ok and not r.replayed and len(env.backend.drafts) == 2


def test_backend_dedupes_on_key_too(make_env):
    env = make_env()
    from govagent.gateway import ExecutionMeta

    meta = ExecutionMeta("ana.ruiz", "run-x", "k-backend", agent_id="advisor-assist-agent")
    meta.txn_token = env.gateway.txn_tokens.mint(principal="ana.ruiz", tool="initiate_wire_transfer", args=WIRE_OK,
                                                 run_id="run-x", agent_id="advisor-assist-agent")
    a = env.backend.initiate_wire_transfer(WIRE_OK, meta)
    b = env.backend.initiate_wire_transfer(WIRE_OK, meta)
    assert a["wire_id"] == b["wire_id"] and b["deduplicated"] and len(env.backend.wires) == 1


# ---------------------------------------------------------------- transaction tokens (gateway -> backend)

def test_backend_refuses_calls_that_bypass_the_gateway(make_env):
    import pytest

    from govagent.gateway import ExecutionMeta

    env = make_env()
    with pytest.raises(PermissionError, match="missing transaction token"):
        env.backend.get_positions({"client_id": "C-1001"}, ExecutionMeta("ana.ruiz", "r", None))


def test_transaction_token_is_bound_to_the_operation(make_env):
    import jwt
    import pytest

    from govagent.txn import TxnTokenError

    env = make_env()
    token = env.gateway.txn_tokens.mint(principal="ana.ruiz", tool="initiate_wire_transfer", args=WIRE_OK,
                                        run_id="r", agent_id="a")
    header = jwt.get_unverified_header(token)
    claims = jwt.decode(token, options={"verify_signature": False})
    assert header["typ"] == "txntoken+jwt"
    assert {"aud", "txn", "sub", "scope", "req_wl", "iat", "exp"} <= set(claims)
    assert claims["exp"] - claims["iat"] <= 60
    verifier = env.backend.txn_verifier
    verifier.verify(token, "initiate_wire_transfer", WIRE_OK)
    with pytest.raises(TxnTokenError, match="different operation"):
        verifier.verify(token, "update_mailing_address", WIRE_OK)
    with pytest.raises(TxnTokenError, match="does not match"):  # amount changed in flight
        verifier.verify(token, "initiate_wire_transfer", dict(WIRE_OK, amount_usd=99999))


def test_gateway_never_forwards_the_users_token(make_env):
    env = make_env(initiate_wire_transfer=True)
    seen = {}
    original = env.registry.get("initiate_wire_transfer").handler

    def spy(args, meta):
        seen["meta"] = meta
        return original(args, meta)

    object.__setattr__(env.registry.get("initiate_wire_transfer"), "handler", spy)
    user_token = env.token_for("ana")
    assert env.gateway.invoke(user_token, "initiate_wire_transfer", WIRE_OK, "k-txn").ok
    assert seen["meta"].txn_token and seen["meta"].txn_token != user_token
    assert user_token not in str(seen["meta"].__dict__)

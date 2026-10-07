import uuid

from conftest import ADDR, WIRE_OK


def invoke(env, who_or_token, tool, args, key="auto", **token_kw):
    token = who_or_token if "." in who_or_token else env.token_for(who_or_token, **token_kw)
    return env.gateway.invoke(token, tool, args, idempotency_key=uuid.uuid4().hex if key == "auto" else key)


def test_read_executes(make_env):
    r = invoke(make_env(), "ana", "get_positions", {"client_id": "C-1001"})
    assert r.ok and r.data["total_market_value_usd"] == 217880.0


def test_compliant_wire_with_inline_approval(make_env):
    env = make_env(initiate_wire_transfer=True)
    r = invoke(env, "ana", "initiate_wire_transfer", WIRE_OK)
    assert r.ok and r.data["status"] == "pending_release_by_operations" and r.action_id
    assert len(env.approvals.requests) == 1 and env.backend.wires


def test_declined_approval_creates_nothing(make_env):
    env = make_env(initiate_wire_transfer=False)
    assert invoke(env, "ana", "initiate_wire_transfer", WIRE_OK).status == "approval_denied"
    assert not env.backend.wires


def test_denials_never_reach_approval_or_backend(make_env):
    env = make_env(initiate_wire_transfer=True)
    for args in (dict(WIRE_OK, amount_usd=75000), dict(WIRE_OK, beneficiary_id="B-9999"),
                 dict(WIRE_OK, from_account_id="40055555555")):
        assert invoke(env, "ana", "initiate_wire_transfer", args).status == "denied"
    assert not env.approvals.requests and not env.backend.wires


def test_scope_entitlement_expiry_unknown_schema(make_env):
    env = make_env(initiate_wire_transfer=True)
    assert "scope" in invoke(env, "sam", "initiate_wire_transfer", WIRE_OK).reasons[0]
    assert "entitlement" in invoke(env, "ana", "get_positions", {"client_id": "C-1003"}).reasons[0]
    assert "expired" in invoke(env, "ana", "get_positions", {"client_id": "C-1001"}, expired=True).reasons[0]
    assert invoke(env, "ana", "drop_tables", {}).status == "denied"
    assert invoke(env, "ana", "initiate_wire_transfer", dict(WIRE_OK, amount_usd=-1)).status == "rejected"
    assert invoke(env, "ana", "get_positions", {"client_id": "C-1001", "extra": 1}).status == "rejected"


def test_run_binding(make_env):
    env = make_env()
    token = env.token_for("ana")
    assert invoke(env, token, "get_positions", {"client_id": "C-1001"}).ok
    env.gateway.close_run(token)
    r = invoke(env, token, "get_positions", {"client_id": "C-1001"})
    assert r.status == "denied" and "closed" in r.reasons[0]
    # a second principal cannot join someone else's run, even with a valid token
    run_id = "run-shared"
    assert invoke(env, env.token_for("ana", run_id=run_id), "get_positions", {"client_id": "C-1001"}).ok
    r = invoke(env, env.token_for("sam", run_id=run_id), "get_positions", {"client_id": "C-1001"})
    assert "different principal" in r.reasons[0]


def test_budgets_are_held_by_the_gateway_per_run(make_env):
    env = make_env(initiate_wire_transfer=True)
    token = env.token_for("ana")
    outcomes = [invoke(env, token, "get_positions", {"client_id": "C-1001"}).status for _ in range(10)]
    assert outcomes.count("executed") == 8 and outcomes[-1] == "denied"
    token2 = env.token_for("ana")
    assert invoke(env, token2, "initiate_wire_transfer", dict(WIRE_OK, amount_usd=100)).ok
    second = invoke(env, token2, "initiate_wire_transfer", dict(WIRE_OK, amount_usd=100))
    assert second.status == "denied" and "high-risk" in second.reasons[0]


def test_injection_is_flagged_and_wrapped(make_env):
    env = make_env()
    r = invoke(env, "ana", "get_client_profile", {"client_id": "C-1002"})
    assert r.ok and "_warning" in r.data
    assert any(e["event"] == "untrusted_content" for e in env.audit.entries())


def test_domain_error_is_returned_internal_error_is_masked(make_env):
    env = make_env(initiate_wire_transfer=True)
    r = invoke(env, "ana", "initiate_wire_transfer", dict(WIRE_OK, from_account_id="40087654321", amount_usd=9000))
    assert r.status == "error" and "insufficient" in r.reasons[0]

    def boom(args, meta=None):
        raise RuntimeError("db password is hunter2")

    object.__setattr__(env.registry.get("get_positions"), "handler", boom)
    r = invoke(env, "ana", "get_positions", {"client_id": "C-1001"})
    assert r.status == "error" and "hunter2" not in str(r.to_model())


def test_model_view_has_guidance(make_env):
    env = make_env(queue=True)
    denied = invoke(env, "ana", "get_positions", {"client_id": "C-1003"}).to_model()
    assert denied["status"] == "denied" and "Do not retry" in denied["guidance"]
    pending = invoke(env, "ana", "initiate_wire_transfer", WIRE_OK).to_model()
    assert pending["status"] == "pending_approval" and pending["action_id"] and "NOT happened" in pending["guidance"]


def test_audit_redacts_account_numbers(make_env):
    env = make_env(initiate_wire_transfer=True)
    invoke(env, "ana", "initiate_wire_transfer", WIRE_OK)
    dump = str(env.audit.entries())
    assert "40012345678" not in dump and "****5678" in dump


def test_address_velocity_fact_needs_approval(make_env):
    env = make_env(queue=True)
    assert invoke(env, "ana", "update_mailing_address", ADDR).status == "pending_approval"
    other = dict(ADDR, client_id="C-1002")
    assert invoke(env, "ana", "update_mailing_address", other).ok


def test_account_ids_are_masked_in_results(make_env):
    """get_client_profile and get_positions mask account_id wherever it appears (a scalar in
    accounts, nested inside each entry of positions); nothing the model receives carries a raw
    account number, only the last 4 digits."""
    env = make_env()
    profile = invoke(env, "ana", "get_client_profile", {"client_id": "C-1001"}).data
    assert {a["account_id"] for a in profile["accounts"]} == {"****5678", "****4321"}
    positions = invoke(env, "ana", "get_positions", {"client_id": "C-1001"}).data
    assert {p["account_id"] for p in positions["positions"]} == {"****5678", "****4321"}


def test_masked_account_id_resolves_through_a_wire(make_env):
    """A masked value echoed back into initiate_wire_transfer's from_account_id -- exactly what a
    live model would supply, having only ever seen the masked form -- resolves to the real account
    before policy or the backend handler see it, and the wire succeeds normally."""
    env = make_env(initiate_wire_transfer=True)
    r = invoke(env, "ana", "initiate_wire_transfer",
              dict(WIRE_OK, from_account_id="****5678"))
    assert r.ok and r.data["status"] == "pending_release_by_operations"
    assert env.backend.wires[-1]["from_account_id"] == "40012345678"  # resolved to the real id


def test_unresolvable_masked_account_id_is_denied_at_minimise_stage(make_env):
    """A masked value that matches no account on this client's record is refused -- never guessed,
    and never silently passed through to policy or the backend as a literal '****0000'."""
    from govagent.pipeline import stage_for_reason

    env = make_env(initiate_wire_transfer=True)
    r = invoke(env, "ana", "initiate_wire_transfer",
              dict(WIRE_OK, from_account_id="****0000"))
    assert r.status == "rejected" and "does not resolve" in r.reasons[0]
    assert stage_for_reason(r.reasons[0]) == "minimise"
    assert not env.backend.wires


def test_returns_allowlist_drops_unlisted_fields(make_env):
    """ToolSpec.returns is an allowlist, not a denylist: a field the handler returns that is not in
    it never reaches the model, regardless of what the handler does -- defence in depth against a
    future handler change leaking a new field by accident."""
    env = make_env()
    spec = env.registry.get("get_positions")
    original = spec.handler

    def leaky(args, meta=None):
        return {**original(args, meta), "ssn": "123-45-6789"}

    object.__setattr__(spec, "handler", leaky)  # frozen dataclass; patch for this one call
    try:
        r = invoke(env, "ana", "get_positions", {"client_id": "C-1001"})
        assert "ssn" not in r.data
    finally:
        object.__setattr__(spec, "handler", original)


# ---------------------------------------------------------------- kill switch (item 5)

def test_global_stop_denies_ahead_of_identity(make_env):
    from govagent.pipeline import stage_for_reason

    env = make_env()
    env.store.engage_stop("global", "", "incident #1", "casey.morgan", env.gateway.clock())
    r = invoke(env, "ana", "get_positions", {"client_id": "C-1001"})
    assert r.status == "denied" and r.reasons[0].startswith("stop:") and "incident #1" in r.reasons[0]
    assert stage_for_reason(r.reasons[0]) == "stop"


def test_per_tool_stop_is_scoped_to_that_tool(make_env):
    env = make_env()
    env.store.engage_stop("tool", "draft_client_email", "maintenance", "casey.morgan", env.gateway.clock())
    blocked = invoke(env, "ana", "draft_client_email", {"client_id": "C-1001", "subject": "s", "body": "b"})
    assert blocked.status == "denied" and "maintenance" in blocked.reasons[0]
    unaffected = invoke(env, "ana", "get_positions", {"client_id": "C-1001"})
    assert unaffected.ok


def test_per_agent_stop_uses_the_tokens_own_claimed_actor(make_env):
    """The per-agent check runs ahead of identity verification, reading only the token's own
    unverified act claim -- which it cannot be exploited via, since the check can only ADD a
    restriction, never remove one, and a genuine token's act claim is signed."""
    env = make_env()
    env.store.engage_stop("agent", "advisor-assist-agent", "runtime compromised", "casey.morgan",
                          env.gateway.clock())
    r = invoke(env, "ana", "get_positions", {"client_id": "C-1001"})
    assert r.status == "denied" and "runtime compromised" in r.reasons[0]


def test_releasing_a_stop_restores_normal_operation(make_env):
    env = make_env()
    env.store.engage_stop("global", "", "x", "casey.morgan", env.gateway.clock())
    assert invoke(env, "ana", "get_positions", {"client_id": "C-1001"}).status == "denied"
    assert env.store.release_stop("global", "") is True
    assert invoke(env, "ana", "get_positions", {"client_id": "C-1001"}).ok
    assert env.store.release_stop("global", "") is False  # nothing left to release


# ---------------------------------------------------------------- circuit breaker (item 5)

def test_breaker_opens_after_repeated_backend_errors_and_blocks_other_clients_too(make_env):
    """The breaker is per tool, not per client: once open, a different, perfectly healthy client on
    the same tool is also refused, without the backend being reached."""
    env = make_env()
    del env.backend.clients["C-1001"]  # make every call to it raise DomainError
    for _ in range(3):  # policy's circuit_breaker.max_errors
        assert invoke(env, "ana", "get_positions", {"client_id": "C-1001"}).status == "error"
    tripped = invoke(env, "ana", "get_positions", {"client_id": "C-1001"})
    assert tripped.status == "denied" and tripped.reasons[0].startswith("breaker:")
    other_client = invoke(env, "ana", "get_positions", {"client_id": "C-1002"})
    assert other_client.status == "denied" and other_client.reasons[0].startswith("breaker:")


def test_breaker_half_opens_after_cooldown_and_closes_on_a_successful_probe(make_env):
    from conftest import Clock

    clock = Clock()
    env = make_env(clock=clock)  # build_environment() now threads clock into token issuance too
    env.store.breaker_record_error("get_positions", max_errors=3, window_seconds=60, now=clock.now)
    env.store.breaker_record_error("get_positions", max_errors=3, window_seconds=60, now=clock.now)
    env.store.breaker_record_error("get_positions", max_errors=3, window_seconds=60, now=clock.now)
    assert invoke(env, "ana", "get_positions", {"client_id": "C-1001"}).status == "denied"
    clock.now += 31  # past policy's circuit_breaker.cooldown_seconds
    probe = invoke(env, "ana", "get_positions", {"client_id": "C-1001"})
    assert probe.ok  # the probe itself is a real call, and this client is healthy
    assert env.store.breaker_state()["get_positions"]["state"] == "closed"
    assert invoke(env, "ana", "get_positions", {"client_id": "C-1001"}).ok  # back to normal

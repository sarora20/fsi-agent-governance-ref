import pytest

from govagent.policy import PolicyEngine, PolicyError


def engine(**tools):
    return PolicyEngine({"default_decision": "deny", "tools": tools})


def test_unknown_tool_denied_by_default():
    assert engine().evaluate("anything", {}).outcome == "deny"


def test_rules_only_tighten():
    e = engine(t={"decision": "require_approval",
                  "rules": [{"when": {"field": "x", "op": "gt", "value": 1}, "decision": "allow"}]})
    assert e.evaluate("t", {"x": 5}).outcome == "require_approval"


def test_deny_rule_wins_and_replaces_reason():
    e = engine(t={"decision": "require_approval", "reason": "base",
                  "rules": [{"when": {"field": "x", "op": "gt", "value": 1}, "decision": "deny", "reason": "big"}]})
    d = e.evaluate("t", {"x": 5})
    assert d.outcome == "deny" and d.reasons == ["big"]


def test_fact_comparison_and_missing_fact_fails_closed():
    e = engine(t={"decision": "allow",
                  "rules": [{"when": {"field": "b", "op": "not_in", "fact": "ok"}, "decision": "deny"}]})
    assert e.evaluate("t", {"b": "B-1"}, {"ok": ["B-1"]}).outcome == "allow"
    assert e.evaluate("t", {"b": "B-2"}, {"ok": ["B-1"]}).outcome == "deny"
    assert e.evaluate("t", {"b": "B-1"}, {}).outcome == "deny"


def test_fact_field_on_left_side():
    e = engine(t={"decision": "allow",
                  "rules": [{"when": {"fact_field": "age", "op": "lt", "value": 30}, "decision": "require_approval"}]})
    assert e.evaluate("t", {}, {"age": 12}).outcome == "require_approval"
    assert e.evaluate("t", {}, {"age": 400}).outcome == "allow"


def test_type_confusion_fails_closed():
    e = engine(t={"decision": "allow",
                  "rules": [{"when": {"field": "amt", "op": "gt", "value": 100}, "decision": "deny"}]})
    assert e.evaluate("t", {"amt": "lots"}).outcome == "deny"


def test_malformed_policy_rejected():
    with pytest.raises(PolicyError):
        engine(t={"decision": "maybe"})
    with pytest.raises(PolicyError):
        engine(t={"decision": "allow", "rules": [{"when": {"field": "x", "op": "regex"}, "decision": "deny"}]})


def test_shipped_policy_loads(make_env):
    env = make_env()
    assert env.policy.default == "deny"
    assert set(env.policy.tools) == set(env.registry.names())

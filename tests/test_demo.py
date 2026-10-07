"""The live demo, wired end to end in-process: demo app -> HTTP -> gateway service -> backend."""

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402

from govagent.app import build_environment, dev_keyring  # noqa: E402
from govagent.approvals import QueueApprovals  # noqa: E402
from govagent.audit import AuditLog  # noqa: E402
from govagent.demo.app import create_demo_app  # noqa: E402
from govagent.demo.scenarios import SCENARIOS  # noqa: E402
from govagent.pipeline import STAGES, pipeline  # noqa: E402
from govagent.service import create_app  # noqa: E402
from govagent.state import StateStore  # noqa: E402


@pytest.fixture
def stack(tmp_path):
    env = build_environment(approvals=QueueApprovals(), audit=AuditLog(tmp_path / "audit.jsonl"),
                            store=StateStore(tmp_path / "state.db"), keys=dev_keyring(shared=True))
    gw = TestClient(create_app(env, base_url="http://testserver", dev_mode=True))
    return env, gw, TestClient(create_demo_app("http://testserver", gateway_client=gw))


def outcomes(result):
    return [c["outcome"] for run in result["runs"] for c in run["calls"]]


EXPECTED = {
    "holdings": ["executed"],
    "wire-approval": ["pending_approval"],
    "injection": ["executed", "denied"],
    "split-wire": ["pending_approval", "pending_approval", "denied"],
    "over-limit": ["denied"],
    "not-entitled": ["denied"],
    "wrong-role": ["denied"],
    "no-guarantees": ["denied"],
}


def test_every_scenario_has_the_expected_outcome(stack):
    _, _, demo = stack
    assert set(EXPECTED) == {s["id"] for s in SCENARIOS}
    for sid, want in EXPECTED.items():
        demo.post("/api/reset")
        assert outcomes(demo.post(f"/api/scenario/{sid}").json()) == want, sid


def test_split_wire_is_denied_by_cross_run_velocity(stack):
    _, _, demo = stack
    demo.post("/api/reset")
    last = demo.post("/api/scenario/split-wire").json()["runs"][-1]["calls"][0]
    assert last["reasons"][0].startswith("velocity")
    states = {p["stage"]: p["state"] for p in last["pipeline"]}
    assert states["velocity"] == "fail" and states["execute"] == "skip"


def test_advisor_cannot_approve_and_supervisor_can(stack):
    _, _, demo = stack
    demo.post("/api/reset")
    demo.post("/api/scenario/wire-approval")
    [pending] = demo.get("/api/approvals").json()["pending"]
    aid = pending["action_id"]

    refused = demo.post(f"/api/approvals/{aid}", json={"approve": True, "as": "ana"}).json()
    assert refused["status"] == "approval_denied" and "approvals:decide" in refused["reasons"][0]
    assert refused["pipeline"] is None

    done = demo.post(f"/api/approvals/{aid}", json={"approve": True, "as": "sup", "note": "called client"}).json()
    assert done["status"] == "executed" and done["data"]["wire_id"].startswith("W-")
    assert all(p["state"] == "pass" for p in done["pipeline"])


def test_extra_demos(stack):
    _, _, demo = stack
    demo.post("/api/reset")
    retry = demo.post("/api/scenario/retry").json()
    assert any(c.get("replayed") for run in retry["runs"] for c in run["calls"])
    replay = demo.post("/api/scenario/token-replay").json()
    assert outcomes(replay)[-1] == "denied"
    four = demo.post("/api/scenario/four-eyes").json()
    assert "approval_denied" in four["runs"][0]["final_text"]


def test_audit_viewer_needs_audit_scope_and_chain_is_intact(stack):
    env, gw, demo = stack
    demo.post("/api/scenario/holdings")
    audit = demo.get("/api/audit").json()
    assert audit["intact"] and audit["entries"]
    assert gw.get("/v1/audit/entries").status_code == 401
    advisor = env.person_token("ana")
    r = gw.get("/v1/audit/entries", headers={"Authorization": f"Bearer {advisor}"})
    assert r.status_code == 403 and "audit:read" in r.headers["www-authenticate"]
    # an agent never reads the audit log or approves, even with a token carrying the scope
    from govagent.app import PRINCIPALS

    agent = env.tokens.issue(PRINCIPALS["cmp"], "advisor-assist-agent")
    r = gw.get("/v1/audit/entries", headers={"Authorization": f"Bearer {agent}"})
    assert r.status_code == 403 and r.json()["error"] == "agents_cannot_read_audit"


def test_demo_audit_view_names_the_identity_and_can_be_pointed_at_a_refused_one(stack):
    """item 6: the console's /api/audit names whose token it read with, defaults to compliance
    (back-compat for the existing test above), and can be switched to any of the five people --
    including one the gateway will refuse, which is the whole demonstration."""
    _, _, demo = stack
    demo.post("/api/scenario/holdings")

    default = demo.get("/api/audit").json()
    assert default["read_as"] == {"key": "cmp", "name": "Riley Brooks", "role": "compliance"}

    compliance = demo.get("/api/audit?who=cmp").json()
    assert compliance["read_as"]["key"] == "cmp" and compliance["entries"]

    refused = demo.get("/api/audit?who=ana").json()
    assert refused["read_as"] == {"key": "ana", "name": "Ana Ruiz", "role": "advisor"}
    assert refused["error"] == "insufficient_scope"

    bad = demo.get("/api/audit?who=nobody")
    assert bad.status_code == 400


def test_dev_reset_clears_state_and_is_audited(stack):
    _, gw, demo = stack
    demo.post("/api/scenario/wire-approval")
    assert demo.get("/api/approvals").json()["pending"]
    demo.post("/api/reset")
    assert demo.get("/api/approvals").json()["pending"] == []
    events = [e.get("event") for e in demo.get("/api/audit").json()["entries"]]
    assert "dev_reset" in events


def test_dev_reset_absent_without_dev_mode(make_env):
    tc = TestClient(create_app(make_env(queue=True)))
    assert tc.post("/v1/dev/reset").status_code in (404, 405)


def test_demo_header_surfaces_kill_switch_and_breaker_state(stack):
    """item 5's last box: the demo's /api/controls (what the header indicator polls) reflects a
    stop or an open breaker engaged directly at the gateway, and a reset clears both."""
    env, gw, demo = stack
    quiet = demo.get("/api/controls").json()
    assert quiet["reachable"] and not quiet["stop"]["global"] and quiet["breakers"] == {}

    env.store.engage_stop("tool", "draft_client_email", "maintenance", "casey.morgan", env.gateway.clock())
    del env.backend.clients["C-1001"]
    for _ in range(3):
        env.gateway.invoke(env.token_for("ana"), "get_positions", {"client_id": "C-1001"})

    busy = demo.get("/api/controls").json()
    assert busy["stop"]["tools"]["draft_client_email"]["reason"] == "maintenance"
    assert busy["breakers"]["get_positions"]["state"] == "open"

    demo.post("/api/reset")
    cleared = demo.get("/api/controls").json()
    assert cleared["stop"]["tools"] == {} and cleared["breakers"] == {}


def test_pipeline_states():
    # "stop" (item 5) then "identity"; 18 stages total: +1 "minimise" (item 3), +1 "stop" (item 5)
    assert [s[0] for s in STAGES][:2] == ["stop", "identity"] and len(STAGES) == 18
    denied = pipeline({"outcome": "denied", "reasons": ["entitlement: not entitled to C-1003"]})
    states = {p["stage"]: p["state"] for p in denied}
    assert states["scope"] == "pass" and states["entitlement"] == "fail" and states["execute"] == "skip"
    ok = pipeline({"outcome": "executed", "reasons": [], "risk_tier": "LOW"})
    assert {p["state"] for p in ok} <= {"pass", "skip"}

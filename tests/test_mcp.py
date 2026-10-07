"""MCP (2026-07-28) JSON-RPC surface: one endpoint, translating to the exact same gateway/verifier
every REST route uses -- not a second enforcement path that could drift from the first."""

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402

from govagent.app import PRINCIPALS, build_environment  # noqa: E402
from govagent.service import create_app  # noqa: E402


@pytest.fixture
def mcp(make_env):
    env = make_env(initiate_wire_transfer=True)
    return env, TestClient(create_app(env))


def rpc(tc, method, params=None, token=None, rid=1, extra_headers=None):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    headers.update(extra_headers or {})
    return tc.post("/mcp", json={"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}},
                   headers=headers)


def test_initialize(mcp):
    _, tc = mcp
    r = rpc(tc, "initialize").json()
    assert r["id"] == 1 and r["result"]["protocolVersion"] and r["result"]["serverInfo"]["name"] == "govagent"


def test_notifications_initialized_gets_no_body(mcp):
    _, tc = mcp
    r = tc.post("/mcp", json={"jsonrpc": "2.0", "method": "notifications/initialized"})
    assert r.status_code == 202


def test_tools_list_requires_auth_and_matches_the_registry(mcp):
    env, tc = mcp
    assert rpc(tc, "tools/list").status_code == 401
    r = rpc(tc, "tools/list", token=env.token_for("ana")).json()
    names = {t["name"] for t in r["result"]["tools"]}
    assert names == set(env.registry.names())


def test_tools_call_read_executes(mcp):
    import json as _json

    env, tc = mcp
    r = rpc(tc, "tools/call", {"name": "get_positions", "arguments": {"client_id": "C-1001"}},
           token=env.token_for("ana")).json()
    assert r["result"]["isError"] is False
    assert _json.loads(r["result"]["content"][0]["text"])["total_market_value_usd"] == 217880.0


def test_tools_call_denial_is_an_http_level_challenge_not_a_200(mcp):
    """MCP's own authorization spec expects a resource-server auth failure as plain HTTP 401/403
    with a challenge header -- not a 200 response body carrying a JSON-RPC error."""
    env = build_environment()
    tc = TestClient(create_app(env))
    token = env.tokens.issue(PRINCIPALS["cmp"], "advisor-assist-agent", [])
    r = rpc(tc, "tools/call", {"name": "get_client_profile", "arguments": {"client_id": "C-1001"}}, token=token)
    assert r.status_code == 403
    assert "insufficient_scope" in r.headers["www-authenticate"]
    assert r.json()["error"]["code"] == -32002


def test_tools_call_pending_approval_becomes_a_task_and_tasks_get_polls_it(make_env):
    env = make_env(queue=True)
    tc = TestClient(create_app(env))
    token = env.token_for("ana")
    wire = {"name": "initiate_wire_transfer",
           "arguments": {"client_id": "C-1001", "from_account_id": "40012345678",
                         "beneficiary_id": "B-2001", "amount_usd": 1000}}
    r = rpc(tc, "tools/call", wire, token=token, extra_headers={"Idempotency-Key": "k-mcp"}).json()
    task_id = r["result"]["task"]["taskId"]
    assert r["result"]["task"]["status"] == "working"

    polled = rpc(tc, "tasks/get", {"taskId": task_id}, token=token).json()
    assert polled["result"]["task"]["status"] == "working"

    env.gateway.decide(task_id, "casey.morgan", True, "approved")
    done = rpc(tc, "tasks/get", {"taskId": task_id}, token=token).json()
    assert done["result"]["task"]["status"] == "completed"


def test_tasks_get_refuses_someone_elses_task(make_env):
    env = make_env(queue=True)
    tc = TestClient(create_app(env))
    wire = {"name": "initiate_wire_transfer",
           "arguments": {"client_id": "C-1001", "from_account_id": "40012345678",
                         "beneficiary_id": "B-2001", "amount_usd": 1000}}
    r = rpc(tc, "tools/call", wire, token=env.token_for("ana"),
           extra_headers={"Idempotency-Key": "k-mcp-2"}).json()
    task_id = r["result"]["task"]["taskId"]

    other_token = env.tokens.issue(PRINCIPALS["lee"], "advisor-assist-agent", [])
    denied = rpc(tc, "tasks/get", {"taskId": task_id}, token=other_token)
    assert denied.status_code == 404


def test_unknown_method_is_a_clean_jsonrpc_error(mcp):
    env, tc = mcp
    r = rpc(tc, "nonexistent", token=env.token_for("ana"))
    assert r.status_code == 404 and r.json()["error"]["code"] == -32601


def test_missing_method_is_invalid_request(mcp):
    _, tc = mcp
    r = tc.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "params": {}})
    assert r.status_code == 400 and r.json()["error"]["code"] == -32600

"""Google ADK integration, offline: a scripted BaseLlm drives a real ADK LlmAgent + InMemoryRunner."""

import pytest

pytest.importorskip("google.adk")

from conftest import WIRE_OK  # noqa: E402
from google.adk.tools import FunctionTool  # noqa: E402

from govagent.adapters.adk import GovernedAdkAgent  # noqa: E402
from govagent.adapters.adk_scripted import ScriptedAdkLlm  # noqa: E402


def raw_delete_client(client_id: str) -> dict:
    """An ungoverned tool someone bolted on later."""
    raise AssertionError("must never run")


def test_adk_tools_route_through_gateway_and_raw_tools_are_blocked(make_env):
    env = make_env(initiate_wire_transfer=True)
    llm = ScriptedAdkLlm(turns=[
        {"tool_calls": [{"name": "get_positions", "args": {"client_id": "C-1001"}}]},
        {"tool_calls": [{"name": "initiate_wire_transfer", "args": dict(WIRE_OK, amount_usd=95000)}]},
        {"tool_calls": [{"name": "raw_delete_client", "args": {"client_id": "C-1001"}}]},
        {"text": "Holdings shown; the wire and the delete were blocked."},
    ])
    agent = GovernedAdkAgent(env.gateway, env.registry, model=llm, extra_tools=[FunctionTool(raw_delete_client)])
    run = agent.run("do things", env.token_for("ana"))
    assert [(c.tool, c.outcome) for c in run.calls] == [
        ("get_positions", "executed"), ("initiate_wire_transfer", "denied"), ("raw_delete_client", "denied")]
    assert run.final_text.startswith("Holdings shown")
    assert env.audit.verify()[0] and not env.backend.wires


def test_adk_uses_session_token(make_env):
    env = make_env()
    llm = ScriptedAdkLlm(turns=[{"tool_calls": [{"name": "get_positions", "args": {"client_id": "C-1001"}}]},
                                {"text": "done"}])
    run = GovernedAdkAgent(env.gateway, env.registry, model=llm).run("x", env.token_for("ana", expired=True))
    assert run.calls[0].outcome == "denied" and "expired" in run.calls[0].reasons[0]

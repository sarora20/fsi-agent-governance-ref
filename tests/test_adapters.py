"""Adapter wire-format tests, offline. Claude responses are parsed with the real SDK types and
Bedrock calls go through a real botocore client with a Stubber, which validates request and
response shapes against the service model."""

import pytest

from govagent.agent.runner import AgentRunner
from govagent.agent.types import AssistantTurn, ToolCall, ToolResult, ToolResults, UserMessage


class FakeMessages:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return self.responses.pop(0)


class FakeAnthropic:
    def __init__(self, responses):
        self.messages = FakeMessages(responses)


def anthropic_message(content, stop_reason):
    anthropic = pytest.importorskip("anthropic")
    return anthropic.types.Message.model_validate({
        "id": "msg_test", "type": "message", "role": "assistant", "model": "claude-test",
        "content": content, "stop_reason": stop_reason, "stop_sequence": None,
        "usage": {"input_tokens": 10, "output_tokens": 5},
    })


def test_claude_message_conversion():
    from govagent.adapters.claude import to_anthropic_messages

    history = [
        UserMessage("hi"),
        AssistantTurn("checking", [ToolCall("toolu_1", "get_positions", {"client_id": "C-1001"})]),
        ToolResults([ToolResult("toolu_1", "get_positions", {"status": "ok"}, False)]),
    ]
    msgs = to_anthropic_messages(history)
    assert msgs[0] == {"role": "user", "content": "hi"}
    assert msgs[1]["content"][1] == {"type": "tool_use", "id": "toolu_1", "name": "get_positions",
                                     "input": {"client_id": "C-1001"}}
    assert msgs[2]["content"][0]["type"] == "tool_result" and msgs[2]["content"][0]["tool_use_id"] == "toolu_1"


def test_claude_adapter_end_to_end_with_gateway(make_env):
    from govagent.adapters.claude import ClaudeAdapter

    env = make_env()
    fake = FakeAnthropic([
        anthropic_message([{"type": "text", "text": "Let me look."},
                           {"type": "tool_use", "id": "toolu_1", "name": "get_positions",
                            "input": {"client_id": "C-1001"}}], "tool_use"),
        anthropic_message([{"type": "text", "text": "C-1001 holds VTI, BND and VXUS."}], "end_turn"),
    ])
    adapter = ClaudeAdapter(model="claude-test", client=fake)
    run = AgentRunner(adapter, env.gateway, env.registry).run("What does C-1001 hold?", env.token_for("ana"))
    assert run.stop_reason == "completed" and run.final_text.startswith("C-1001 holds")
    assert [c.outcome for c in run.calls] == ["executed"]
    first = fake.messages.calls[0]
    assert first["model"] == "claude-test" and {t["name"] for t in first["tools"]} == set(env.registry.names())
    second = fake.messages.calls[1]["messages"]
    assert second[-1]["content"][0]["type"] == "tool_result"
    assert run.usage == {"input_tokens": 20, "output_tokens": 10}


def _bedrock_stub():
    boto3 = pytest.importorskip("boto3")
    from botocore.stub import Stubber

    client = boto3.client("bedrock-runtime", region_name="us-east-1",
                          aws_access_key_id="test", aws_secret_access_key="test")
    return client, Stubber(client)


def _converse_response(content, stop):
    return {"output": {"message": {"role": "assistant", "content": content}}, "stopReason": stop,
            "usage": {"inputTokens": 10, "outputTokens": 5, "totalTokens": 15}, "metrics": {"latencyMs": 1}}


def test_bedrock_adapter_end_to_end_with_gateway(make_env):
    from govagent.adapters.bedrock import BedrockAdapter

    env = make_env()
    client, stub = _bedrock_stub()
    stub.add_response("converse", _converse_response(
        [{"toolUse": {"toolUseId": "tu_1", "name": "get_positions", "input": {"client_id": "C-1003"}}}], "tool_use"))
    stub.add_response("converse", _converse_response([{"text": "You are not entitled to C-1003."}], "end_turn"))
    with stub:
        adapter = BedrockAdapter(model_id="test-model", client=client)
        run = AgentRunner(adapter, env.gateway, env.registry).run("Show C-1003", env.token_for("ana"))
    stub.assert_no_pending_responses()
    assert [c.outcome for c in run.calls] == ["denied"]
    assert run.final_text == "You are not entitled to C-1003."


def test_bedrock_requires_model_id(monkeypatch):
    from govagent.adapters.bedrock import BedrockAdapter

    monkeypatch.delenv("BEDROCK_MODEL_ID", raising=False)
    with pytest.raises(ValueError):
        BedrockAdapter(client=object())


def test_model_outage_is_handled(make_env):
    class Down:
        name, model_id = "down", "none"

        def complete(self, *a):
            raise ConnectionError("503")

    env = make_env()
    run = AgentRunner(Down(), env.gateway, env.registry).run("hi", env.token_for("ana"))
    assert run.stop_reason == "model_error" and not run.calls


def test_registry_wire_formats(make_env):
    reg = make_env().registry
    mcp = reg.to_mcp()["tools"]
    wire = next(t for t in mcp if t["name"] == "initiate_wire_transfer")
    assert wire["annotations"]["destructiveHint"] is True and wire["_meta"]["govagent/riskTier"] == "HIGH"
    assert reg.to_bedrock()["tools"][0]["toolSpec"]["inputSchema"]["json"]["type"] == "object"
    assert len(reg.fingerprint()) == 64

"""Kept for compatibility: the agent loop now lives in govagent.harness (AgentHarness)."""

from __future__ import annotations

from ..harness.runtime import AgentHarness, GatewayClient, HarnessConfig, LocalTool, RunResult

AgentRunner = AgentHarness

__all__ = ["AgentRunner", "AgentHarness", "GatewayClient", "HarnessConfig", "LocalTool", "RunResult"]

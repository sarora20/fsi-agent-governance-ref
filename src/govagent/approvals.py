"""Human-in-the-loop approvals as durable, asynchronous actions.

When policy returns `require_approval`, the gateway persists a PendingAction and stops. The
agent tells the user the action is pending. A supervisor decides later (minutes or hours), through
the gateway, with their own token. Only then does the gateway execute, after re-validating
everything that could have changed in between (see gateway.ToolGateway.decide).

A broker is notified of each new pending action. It may:
  * return None       leave it pending (queue, ticket, chat approval card)   -> production shape
  * return a Decision decide immediately                                      -> tests, evals, demos
Either way the same decide-and-revalidate code path runs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol


@dataclass
class PendingAction:
    action_id: str
    run_id: str
    tool: str
    args: dict[str, Any]
    principal: str
    client_id: str | None
    created_at: float
    expires_at: float
    status: str  # pending | approved | rejected | expired | executed | failed
    reasons: list[str]
    idempotency_key: str | None = None
    approver: str | None = None
    note: str = ""


@dataclass
class Decision:
    approved: bool
    approver_id: str
    note: str = ""


class ApprovalBroker(Protocol):
    def on_request(self, action: PendingAction) -> Decision | None: ...


class InlineApprovals:
    """Decides immediately with scripted per-tool answers. For tests, evals and demos."""

    def __init__(self, decisions: dict[str, bool] | None = None, default: bool = False,
                 approver_id: str = "casey.morgan"):
        self.decisions = decisions or {}
        self.default = default
        self.approver_id = approver_id
        self.requests: list[PendingAction] = []

    def on_request(self, action: PendingAction) -> Decision:
        self.requests.append(action)
        return Decision(self.decisions.get(action.tool, self.default), self.approver_id, "inline")


# backwards-compatible name used in earlier versions
ScriptedApprovals = InlineApprovals


class QueueApprovals:
    """Leaves actions pending for a supervisor to decide later through the gateway API."""

    def __init__(self) -> None:
        self.queued: list[str] = []

    def on_request(self, action: PendingAction) -> None:
        self.queued.append(action.action_id)
        return None


class ConsoleApprovals:
    """Interactive approvals for a local demo."""

    def __init__(self, approver_id: str = "casey.morgan"):
        self.approver_id = approver_id

    def on_request(self, action: PendingAction) -> Decision:
        print("\n=== APPROVAL REQUIRED ===")
        print(f"action: {action.action_id}  tool: {action.tool}  requested by: {action.principal}")
        print(f"args: {action.args}\nwhy: {'; '.join(action.reasons)}")
        answer = input(f"Approve as {self.approver_id}? [y/N] ").strip().lower()
        return Decision(answer == "y", self.approver_id, "console")

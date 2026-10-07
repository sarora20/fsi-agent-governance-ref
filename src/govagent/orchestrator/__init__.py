"""Multi-agent orchestration under the same governance.

    person ──sign-in──► orchestrator-agent ──RFC 8693 exchange──► accounts / payments / comms agent
                          (plans; no tools)                          (each: own token, own tools)

Every hop is a token exchange that can only narrow scopes, and each exchanged token carries a nested
`act` claim recording who delegated to whom. The gateway checks every tool call against the token AND
the agent registry (agents.yaml): which agent is acting, through which chain, with which tool.
The orchestrator cannot call business tools itself; a specialist cannot use another specialist's tools.
"""

from .runtime import SPECIALISTS, DevTokenBroker, Orchestrator, TokenBroker, TokenLedger

__all__ = ["SPECIALISTS", "DevTokenBroker", "Orchestrator", "TokenBroker", "TokenLedger"]

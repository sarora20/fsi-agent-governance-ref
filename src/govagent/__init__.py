"""govagent — a governed, model-agnostic agent reference for regulated financial services.

Every tool call an agent makes passes through one enforcement point (the ToolGateway), ideally
deployed as its own service: token -> run binding -> registry -> schema -> idempotency -> scope ->
entitlement -> risk ceiling -> run budgets -> policy -> cross-run velocity -> durable approval
(re-validated at execution) -> execute -> output scan -> tamper-evident audit.
"""

__version__ = "0.6.0"
AGENT_ID = "advisor-assist-agent"
AGENT_VERSION = __version__

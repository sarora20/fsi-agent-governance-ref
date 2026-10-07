"""Agent registry: the gateway's record of which agents exist, what each may do, and who may delegate
to whom. Scopes in a token say what the person allowed; the registry says what this particular agent
is for. Both must allow a call (OWASP ASI02 tool misuse, ASI03 privilege abuse, ASI07 inter-agent trust).

A delegation chain comes from nested RFC 8693 `act` claims, outermost first:
    ("payments-agent", "orchestrator-agent")  = payments-agent acting for orchestrator-agent for the person
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

DEFAULT_AGENTS = Path(__file__).resolve().parent / "policies" / "agents.yaml"
PERSON = "person"


@dataclass(frozen=True)
class AgentSpec:
    id: str
    name: str
    description: str
    tools: frozenset[str]
    delegated_by: frozenset[str]
    may_delegate_to: frozenset[str]


class AgentRegistry:
    def __init__(self, agents: dict[str, AgentSpec], max_depth: int = 2, *, is_unconstrained: bool = False):
        self.agents = agents
        self.max_depth = max_depth
        # True only for the explicit opt-out below: every delegated call then passes stage 4
        # unexamined, same as the old "no registry configured" behavior. A gateway built with an
        # unconstrained registry records that choice in the audit log at construction (see
        # ToolGateway.__init__), so it is visible in the evidence pack rather than inferred from a
        # missing constructor argument.
        self.is_unconstrained = is_unconstrained

    @classmethod
    def from_file(cls, path: str | Path = DEFAULT_AGENTS) -> "AgentRegistry":
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        agents = {
            aid: AgentSpec(aid, a.get("name", aid), a.get("description", ""), frozenset(a.get("tools", [])),
                           frozenset(a.get("delegated_by", [PERSON])), frozenset(a.get("may_delegate_to", [])))
            for aid, a in raw["agents"].items()
        }
        for a in agents.values():  # the two directions must agree
            for d in a.delegated_by - {PERSON}:
                if d not in agents or a.id not in agents[d].may_delegate_to:
                    raise ValueError(f"agents.yaml: {a.id} lists {d} as delegator, but {d} may not delegate to it")
        return cls(agents, int(raw.get("max_delegation_depth", 2)))

    @classmethod
    def unconstrained(cls) -> "AgentRegistry":
        """Opts out of agent-registry enforcement entirely: every delegated call passes stage 4
        unexamined and only token scopes bound what an agent may do. Use this only when something
        else enforces which agent may call which tool (e.g. a single trusted agent runtime with its
        own allowlist) -- a gateway built with it is otherwise identical to the pre-registry gateway,
        and OWASP ASI02/ASI03/ASI07 (tool misuse, privilege abuse, inter-agent trust) are then
        unmitigated at this layer."""
        return cls({}, max_depth=0, is_unconstrained=True)

    def get(self, agent_id: str) -> AgentSpec | None:
        return self.agents.get(agent_id)

    def check_chain(self, chain: tuple[str, ...]) -> str | None:
        """None if every link is allowed; otherwise the reason (prefixed 'agent:')."""
        if self.is_unconstrained:
            return None
        if not chain:
            return "agent: no acting agent in the token"
        if len(chain) > self.max_depth:
            return f"agent: delegation chain {' <- '.join(chain)} is deeper than {self.max_depth}"
        for i, agent_id in enumerate(chain):
            spec = self.get(agent_id)
            if spec is None:
                return f"agent: '{agent_id}' is not a registered agent"
            delegator = chain[i + 1] if i + 1 < len(chain) else PERSON
            if delegator not in spec.delegated_by:
                who = "a person directly" if delegator == PERSON else f"'{delegator}'"
                return f"agent: '{agent_id}' cannot act for {who} (allowed: {', '.join(sorted(spec.delegated_by))})"
        return None

    def check_tool(self, chain: tuple[str, ...], tool: str) -> str | None:
        if self.is_unconstrained:
            return None
        problem = self.check_chain(chain)
        if problem:
            return problem
        spec = self.agents[chain[0]]
        if tool not in spec.tools:
            allowed = ", ".join(sorted(spec.tools)) or "none; it only delegates"
            return f"agent: '{spec.id}' is not allowed to use {tool} (its tools: {allowed})"
        return None

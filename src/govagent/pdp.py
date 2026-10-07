"""Policy decision point (PDP) over the OpenID AuthZEN Authorization API 1.0.

AuthZEN 1.0 became an OpenID Foundation Final Specification on 12 January 2026. It standardises
the PEP -> PDP call: an evaluation request of {subject, resource, action, context} returns
{"decision": bool, "context": {...}}. Using it means the gateway (PEP) can ask any conformant PDP,
e.g. one backed by Cedar or OPA, without custom glue, and this repo's YAML engine can be swapped out.

Mapping used here:
  subject   {"type": "user", "id": <principal>}           (the human the agent acts for)
  resource  {"type": "tool", "id": <tool>, "properties": <arguments>}
  action    {"name": "invoke"}
  context   {"agent": <agent id>}                          (optional)
  response  decision=true only for "allow"; for "require_approval" decision=false with
            context.outcome="require_approval" so the PEP routes it to a human instead of refusing.
"""

from __future__ import annotations

from typing import Any, Callable

from .identity import ROLE_SCOPES, Directory
from .policy import Decision, PolicyEngine
from .registry import ToolRegistry

WELL_KNOWN = "/.well-known/authzen-configuration"
EVALUATION_PATH = "/access/v1/evaluation"
EVALUATIONS_PATH = "/access/v1/evaluations"


def evaluate(request: dict[str, Any], policy: PolicyEngine, registry: ToolRegistry, directory: Directory,
             facts: Callable[[str, dict[str, Any]], dict[str, Any]]) -> dict[str, Any]:
    subject = request.get("subject") or {}
    resource = request.get("resource") or {}
    action = request.get("action") or {}
    if resource.get("type") != "tool" or action.get("name") != "invoke":
        return {"decision": False, "context": {"outcome": "deny", "reasons": ["unsupported resource or action"]}}
    tool = resource.get("id", "")
    args = resource.get("properties") or {}
    spec = registry.get(tool)
    person = directory.get(subject.get("id", ""))
    reasons: list[str] = []
    if spec is None:
        reasons.append(f"unknown tool '{tool}'")
    elif person is None:
        reasons.append("unknown subject")
    else:
        if spec.required_scope not in ROLE_SCOPES.get(person.role, frozenset()):
            reasons.append(f"role lacks '{spec.required_scope}'")
        if spec.client_arg and args.get(spec.client_arg) not in person.entitled_clients:
            reasons.append("subject is not entitled to this client")
    if reasons:
        return {"decision": False, "context": {"outcome": "deny", "reasons": reasons}}
    d = policy.evaluate(tool, args, facts(tool, args))
    return {"decision": d.outcome == "allow",
            "context": {"outcome": d.outcome, "reasons": [r for r in d.reasons if r], "rules": d.rule_ids}}


def configuration(base_url: str) -> dict[str, Any]:
    return {"policy_decision_point": base_url,
            "access_evaluation_endpoint": base_url + EVALUATION_PATH,
            "access_evaluations_endpoint": base_url + EVALUATIONS_PATH}


class AuthZenPolicyClient:
    """Lets the gateway use a remote AuthZEN PDP for the policy step, while keeping local limits.

    Drop-in for PolicyEngine: exposes evaluate(tool, args, facts) plus the limits the gateway reads.
    """

    def __init__(self, http_client: Any, local: PolicyEngine, token: str | None = None):
        self.http = http_client
        self.local = local
        self.token = token

    def __getattr__(self, name: str) -> Any:  # limits, velocity, approval TTL come from local config
        return getattr(self.local, name)

    def evaluate(self, tool: str, args: dict[str, Any], facts: dict[str, Any] | None = None,
                 subject: str | None = None) -> Decision:
        body = {"subject": {"type": "user", "id": subject or ""},
                "resource": {"type": "tool", "id": tool, "properties": args},
                "action": {"name": "invoke"}}
        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
        try:
            resp = self.http.post(EVALUATION_PATH, json=body, headers=headers)
            data = resp.json()
        except Exception:
            return Decision("deny", ["pdp: unreachable (fail closed)"], ["pdp.unavailable"])
        ctx = data.get("context") or {}
        outcome = "allow" if data.get("decision") else ctx.get("outcome", "deny")
        if outcome not in ("allow", "require_approval", "deny"):
            outcome = "deny"
        return Decision(outcome, list(ctx.get("reasons", [])), list(ctx.get("rules", [])))

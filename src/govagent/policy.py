"""Declarative policy engine.

Design rules:
  * Deny by default: a tool with no policy entry is denied.
  * Monotonic: conditional rules can only make a decision stricter
    (allow -> require_approval -> deny), never looser. A bad rule cannot open a hole.
  * Facts: rules can compare arguments with facts the gateway looks up from systems of
    record (e.g. the client's approved beneficiaries), never with anything the model says.
    A condition's left side is a tool argument (`field`) or a fact (`fact_field`); its right
    side is a literal (`value`) or a fact (`fact`).
  * Fail closed: a missing fact, or a type mismatch, makes the (tightening) rule match.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .velocity import VelocityRule

OUTCOMES = ("allow", "require_approval", "deny")
_RANK = {o: i for i, o in enumerate(OUTCOMES)}
_OPS = {
    "gt", "gte", "lt", "lte", "eq", "ne", "in", "not_in", "exists", "not_exists", "contains_any",
}


class PolicyError(ValueError):
    pass


@dataclass
class Decision:
    outcome: str
    reasons: list[str] = field(default_factory=list)
    rule_ids: list[str] = field(default_factory=list)

    def stricter(self, other: "Decision") -> "Decision":
        if _RANK[other.outcome] > _RANK[self.outcome]:
            # the stricter decision replaces the explanation of the weaker one
            return Decision(other.outcome, list(other.reasons), list(other.rule_ids))
        if _RANK[other.outcome] == _RANK[self.outcome]:
            return Decision(self.outcome, self.reasons + other.reasons, self.rule_ids + other.rule_ids)
        return self


class PolicyEngine:
    def __init__(self, doc: dict[str, Any]):
        self._doc = doc
        self.version = str(doc.get("version", "0"))
        self.default = doc.get("default_decision", "deny")
        self.tools: dict[str, dict[str, Any]] = doc.get("tools", {}) or {}
        limits = doc.get("limits", {}) or {}
        self.max_tool_calls_per_run = int(limits.get("max_tool_calls_per_run", 8))
        self.max_high_risk_calls_per_run = int(limits.get("max_high_risk_calls_per_run", 1))
        self.max_risk_tier = str(limits.get("max_risk_tier", "HIGH"))
        self.velocity = [VelocityRule.parse(r) for r in doc.get("velocity", []) or []]
        self.approval_ttl_seconds = int((doc.get("approvals") or {}).get("ttl_seconds", 4 * 3600))
        breaker = doc.get("circuit_breaker") or {}
        self.breaker_max_errors = int(breaker.get("max_errors", 3))
        self.breaker_window_seconds = int(breaker.get("window_seconds", 60))
        self.breaker_cooldown_seconds = int(breaker.get("cooldown_seconds", 30))
        self._validate()

    @classmethod
    def from_file(cls, path: str | Path) -> "PolicyEngine":
        with open(path, encoding="utf-8") as fh:
            return cls(yaml.safe_load(fh))

    def fingerprint(self) -> str:
        canonical = json.dumps(self._doc, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(canonical.encode()).hexdigest()

    def evaluate(self, tool: str, args: dict[str, Any], facts: dict[str, Any] | None = None,
                 subject: str | None = None) -> Decision:
        facts = facts or {}
        cfg = self.tools.get(tool)
        if cfg is None:
            return Decision(self.default, [f"no policy entry for '{tool}' (default: {self.default})"], ["default"])
        decision = Decision(
            cfg.get("decision", "deny"),
            [cfg.get("reason", f"baseline for '{tool}'")],
            [f"{tool}.baseline"],
        )
        for i, rule in enumerate(cfg.get("rules", []) or []):
            if self._matches(rule["when"], args, facts):
                decision = decision.stricter(
                    Decision(rule["decision"], [rule.get("reason", "")], [rule.get("id", f"{tool}.rule{i}")])
                )
        return decision

    # --- internals --------------------------------------------------------------------

    def _validate(self) -> None:
        if self.default not in OUTCOMES:
            raise PolicyError(f"default_decision must be one of {OUTCOMES}")
        for tool, cfg in self.tools.items():
            if cfg.get("decision", "deny") not in OUTCOMES:
                raise PolicyError(f"{tool}: invalid decision")
            for rule in cfg.get("rules", []) or []:
                if rule.get("decision") not in OUTCOMES:
                    raise PolicyError(f"{tool}: rule has invalid decision")
                conds = rule.get("when")
                for cond in conds if isinstance(conds, list) else [conds]:
                    if (not isinstance(cond, dict) or cond.get("op") not in _OPS
                            or ("field" in cond) == ("fact_field" in cond)):
                        raise PolicyError(f"{tool}: malformed condition {cond!r}")

    def _matches(self, when: Any, args: dict[str, Any], facts: dict[str, Any]) -> bool:
        conds = when if isinstance(when, list) else [when]
        return all(self._cond(c, args, facts) for c in conds)

    @staticmethod
    def _cond(cond: dict[str, Any], args: dict[str, Any], facts: dict[str, Any]) -> bool:
        op = cond["op"]
        # the left-hand side is either a tool argument (`field`) or a system-of-record fact (`fact_field`)
        source, key = (args, cond["field"]) if "field" in cond else (facts, cond["fact_field"])
        present = key in source
        if op == "exists":
            return present
        if op == "not_exists":
            return not present
        if not present:
            # an argument that is absent cannot match; a fact that is absent fails closed
            return source is facts
        actual = source[key]
        expected = facts.get(cond["fact"]) if "fact" in cond else cond.get("value")
        if expected is None and op not in ("eq", "ne"):
            # a fact the policy needs is missing: fail closed by matching the rule
            return True
        try:
            if op == "gt":
                return actual > expected
            if op == "gte":
                return actual >= expected
            if op == "lt":
                return actual < expected
            if op == "lte":
                return actual <= expected
            if op == "eq":
                return actual == expected
            if op == "ne":
                return actual != expected
            if op == "in":
                return actual in expected
            if op == "not_in":
                return actual not in expected
            if op == "contains_any":
                text = str(actual).lower()
                return any(str(term).lower() in text for term in expected)
        except TypeError:
            return True  # type confusion fails closed
        return False

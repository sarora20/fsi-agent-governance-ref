"""Cross-run velocity limits.

Per-run budgets stop a looping agent. They do not stop the same request split across many runs,
e.g. 20 runs x $49,000 when the agent limit is $50,000. That splitting pattern is the same evasion
behind structuring (31 U.S.C. 5324), so limits must aggregate across runs, per client and per
principal, over rolling windows (OWASP LLM06 Excessive Agency lists rate limiting as a mitigation).

Pending approvals count as reservations, so parallel requests cannot all slip under a limit while
waiting for a supervisor. Check-and-reserve runs inside one store transaction.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .state import StateStore

ACTIVE_STATES = ("reserved", "committed")


@dataclass(frozen=True)
class VelocityRule:
    id: str
    tool: str
    per: str  # "client" | "principal"
    window_seconds: int
    max_count: int | None = None
    sum_field: str | None = None
    max_sum: float | None = None
    reason: str = ""

    @classmethod
    def parse(cls, raw: dict[str, Any]) -> "VelocityRule":
        if raw.get("per") not in ("client", "principal"):
            raise ValueError(f"velocity rule {raw.get('id')}: per must be client or principal")
        total = raw.get("max_total") or {}
        rule = cls(
            id=raw["id"], tool=raw["tool"], per=raw["per"], window_seconds=int(raw["window_seconds"]),
            max_count=raw.get("max_count"), sum_field=total.get("field"),
            max_sum=float(total["limit"]) if "limit" in total else None, reason=raw.get("reason", ""),
        )
        if rule.max_count is None and rule.max_sum is None:
            raise ValueError(f"velocity rule {rule.id}: needs max_count or max_total")
        return rule


def check(store: StateStore, rules: list[VelocityRule], tool: str, principal: str, client_id: str | None,
          args: dict[str, Any], now: float, exclude_action: str | None = None) -> list[str]:
    """Returns the reasons of every rule this request would breach (empty list = within limits)."""
    breaches: list[str] = []
    for rule in rules:
        if rule.tool != tool:
            continue
        key_col, key_val = ("client_id", client_id) if rule.per == "client" else ("principal", principal)
        row = store.one(
            f"SELECT COUNT(*) AS n, COALESCE(SUM(amount), 0) AS total FROM velocity "
            f"WHERE tool = ? AND {key_col} = ? AND ts > ? AND state IN (?, ?) AND COALESCE(action_id, '') != ?",
            (tool, key_val, now - rule.window_seconds, *ACTIVE_STATES, exclude_action or ""),
        )
        amount = float(args.get(rule.sum_field, 0) or 0) if rule.sum_field else 0.0
        if rule.max_count is not None and row["n"] + 1 > rule.max_count:
            breaches.append(f"velocity [{rule.id}]: {rule.reason or 'count limit'} "
                            f"({row['n']} already in window, limit {rule.max_count})")
        if rule.max_sum is not None and row["total"] + amount > rule.max_sum:
            breaches.append(f"velocity [{rule.id}]: {rule.reason or 'amount limit'} "
                            f"(${row['total']:,.0f} already in window + ${amount:,.0f} > ${rule.max_sum:,.0f})")
    return breaches


def reserve(store: StateStore, rules: list[VelocityRule], tool: str, principal: str, client_id: str | None,
            args: dict[str, Any], now: float, action_id: str, state: str = "reserved") -> None:
    if not any(r.tool == tool for r in rules):
        return
    amount = next((float(args.get(r.sum_field, 0) or 0) for r in rules if r.tool == tool and r.sum_field), 0.0)
    store.execute(
        "INSERT INTO velocity (tool, principal, client_id, amount, ts, state, action_id) VALUES (?,?,?,?,?,?,?)",
        (tool, principal, client_id, amount, now, state, action_id),
    )


def commit(store: StateStore, action_id: str) -> None:
    store.execute("UPDATE velocity SET state = 'committed' WHERE action_id = ?", (action_id,))


def release(store: StateStore, action_id: str) -> None:
    store.execute("UPDATE velocity SET state = 'released' WHERE action_id = ?", (action_id,))

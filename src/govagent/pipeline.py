"""Turn a tool-call record into the gateway's check pipeline, stage by stage, for display.

Each stage is "pass", "fail", "wait" (pending a human) or "skip" (not reached or not applicable).
Derived only from the outcome and the first reason's prefix, which the gateway sets per check.
"""

from __future__ import annotations

from typing import Any

STAGES = [
    ("stop", "Kill switch"),
    ("identity", "Token valid"),
    ("run", "Run binding"),
    ("registry", "Tool registered"),
    ("agent", "Agent allowed"),
    ("schema", "Arguments valid"),
    ("minimise", "Masked fields resolved"),
    ("idempotency", "Idempotency key"),
    ("scope", "Scope"),
    ("entitlement", "Client entitlement"),
    ("risk", "Risk ceiling"),
    ("budget", "Run budget"),
    ("policy", "Policy + facts"),
    ("velocity", "Cross-run limits"),
    ("approval", "Human approval"),
    ("revalidation", "Re-validated"),
    ("execute", "Executed (Txn-Token)"),
    ("output", "Output scan"),
]
_KEYS = [k for k, _ in STAGES]


def _failed_stage(reason: str) -> str:
    prefix = reason.split(":", 1)[0].strip().lower()
    if prefix == "identity":
        return "run" if "run" in reason.lower() else "identity"
    if prefix.startswith("velocity"):
        return "velocity"
    if prefix in ("four-eyes",):
        return "approval"
    if prefix == "domain" or prefix == "internal" or prefix == "breaker":
        return "execute"
    return prefix if prefix in _KEYS else "policy"


def stage_for_reason(reason: str) -> str:
    """The gateway stage a denial reason belongs to. Public so callers can tally denials by
    stage without re-deriving the prefix rules."""
    return _failed_stage(reason)


def pipeline(call: dict[str, Any]) -> list[dict[str, str]]:
    outcome = call.get("outcome", "")
    reasons = call.get("reasons") or []
    approval = call.get("approval") or {}
    needed_approval = bool(call.get("action_id")) and (approval or outcome in ("pending_approval", "approval_denied"))
    states: dict[str, str] = {}

    def upto(stage: str, final: str) -> None:
        for key in _KEYS:
            if key == stage:
                states[key] = final
                break
            states[key] = "pass"

    if outcome == "executed":
        for key in _KEYS:
            states[key] = "pass"
        if not needed_approval:
            states["approval"] = states["revalidation"] = "skip"
        if call.get("flags"):
            states["output"] = "flag"
    elif outcome == "pending_approval":
        upto("approval", "wait")
    elif outcome == "approval_denied":
        upto("approval", "fail")
    elif outcome == "expired":
        upto("approval", "fail")
    elif outcome in ("denied", "rejected", "conflict", "error"):
        first = reasons[0] if reasons else ""
        stage = "revalidation" if first.startswith("revalidation") else _failed_stage(first)
        if call.get("replayed"):
            stage = "idempotency"
        upto(stage, "fail")
    for key in _KEYS:
        states.setdefault(key, "skip")
    return [{"stage": k, "label": label, "state": states[k]} for k, label in STAGES]

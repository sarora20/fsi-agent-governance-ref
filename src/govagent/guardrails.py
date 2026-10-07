"""Guardrails on data flowing through the gateway.

redact()              masks account numbers, SSNs and emails before anything is logged.
scan_for_injection()  flags instruction-like text inside tool results (indirect prompt
                      injection). Flagged results are wrapped with a warning so the model
                      treats them as data, and an audit event is written.

These are deliberately simple pattern checks. They are a layer, not the defence: the real
protection is that a hijacked model still cannot get past scope, entitlement and policy.
"""

from __future__ import annotations

import re
from typing import Any

_ACCOUNT = re.compile(r"\b\d{8,17}\b")
_SSN = re.compile(r"\b\d{3}-\d{2}-(\d{4})\b")
_EMAIL = re.compile(r"\b([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")

INJECTION_PATTERNS: dict[str, re.Pattern[str]] = {
    "ignore_instructions": re.compile(r"\b(ignore|disregard|forget)\b.{0,20}\b(previous|prior|above|all|earlier)\b.{0,20}\binstructions?\b", re.I),
    "role_override": re.compile(r"\byou are now\b|\bact as (an? )?(admin|administrator|developer|system)\b", re.I),
    "system_prompt_probe": re.compile(r"\b(system prompt|developer message|hidden instructions)\b", re.I),
    "embedded_directive": re.compile(r"\b(new|updated) instructions?\s*:", re.I),
}


def _redact_str(text: str) -> str:
    text = _SSN.sub(lambda m: f"***-**-{m.group(1)}", text)
    text = _ACCOUNT.sub(lambda m: f"****{m.group(0)[-4:]}", text)
    text = _EMAIL.sub(lambda m: f"{m.group(1)}***@{m.group(2)}", text)
    return text


def redact(obj: Any) -> Any:
    if isinstance(obj, str):
        return _redact_str(obj)
    if isinstance(obj, dict):
        return {k: redact(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [redact(v) for v in obj]
    return obj


def _strings(obj: Any):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _strings(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _strings(v)


def scan_for_injection(obj: Any) -> list[str]:
    hits: list[str] = []
    for text in _strings(obj):
        for name, pattern in INJECTION_PATTERNS.items():
            if name not in hits and pattern.search(text):
                hits.append(name)
    return hits


# ---------------------------------------------------------------- final-answer guardrail (harness)

_CLAIMS = {
    "initiate_wire_transfer": re.compile(r"\b(sent|wired|transferred|initiated|completed|done|processed)\b", re.I),
    "update_mailing_address": re.compile(r"\b(updated|changed|done|completed)\b", re.I),
}
# Negations and hedges are judged per sentence, next to the claim, not anywhere in the answer.
_HEDGE = re.compile(r"(\bnot\b|n't\b|\bnever\b|\bno\b|\bpending\b|\bawaiting\b|\bsubmitted for\b|"
                    r"\bneeds? (supervisor )?approval\b|\bcannot\b|\bblocked\b|\bdenied\b|\bdeclined\b|"
                    r"\brefused\b|\brejected\b|\bunable\b|\bstopped\b)", re.I)
_SENTENCES = re.compile(r"[^.!?\n]+[.!?]?")
_ADVICE = re.compile(r"\bguarantee[ds]?\b.{0,40}\breturns?\b|\brisk[- ]free\b|\byou should (buy|sell)\b", re.I)
_ACCOUNT_IN_ANSWER = re.compile(r"(?<![$\d,.])\b\d{8,17}\b")  # not dollar amounts like $12500000
_NAMES = {"initiate_wire_transfer": "the wire", "update_mailing_address": "the address change"}


def _unhedged_claim(text: str, claim: re.Pattern) -> bool:
    return any(claim.search(s) and not _HEDGE.search(s) for s in _SENTENCES.findall(text))


def check_final_answer(text: str, calls: list[Any]) -> tuple[str, list[str]]:
    """Checks the agent's final answer against what actually happened at the gateway.

    - account-number-like strings are masked here too, as a last line of defence: account ids in
      get_client_profile's and get_positions's results are already masked before the model ever sees
      them (ToolSpec.mask, gateway.py stage "output"; minimisation.py), so this mainly catches a
      number the model invented, copied from elsewhere in its context, or a tool result this
      masking does not yet cover
    - a sentence claiming an action happened, when the gateway did not execute that action, gets a
      correction appended (a hijacked model will happily say "done"; the person must not believe it)
    - return guarantees and buy/sell advice are flagged
    `calls` are objects or dicts with `tool` and `outcome`. Returns (text shown to the person, flags).
    """
    flags: list[str] = []
    shown = _ACCOUNT_IN_ANSWER.sub(lambda m: f"****{m.group(0)[-4:]}", text or "")
    if shown != (text or ""):
        flags.append("account_number_masked")

    def field(c: Any, name: str) -> Any:
        return c.get(name) if isinstance(c, dict) else getattr(c, name, None)

    for tool, claim in _CLAIMS.items():
        attempts = [c for c in calls if field(c, "tool") == tool]
        if attempts and not any(field(c, "outcome") == "executed" for c in attempts) and _unhedged_claim(shown, claim):
            outcome = str(field(attempts[-1], "outcome") or "unknown").replace("_", " ")
            shown += (f"\n\n[Checked by the agent harness: the gateway did not complete {_NAMES[tool]} "
                      f"({tool}, outcome: {outcome}). It has not happened.]")
            flags.append("unsupported_success_claim")
    if _ADVICE.search(shown):
        flags.append("advice_language")
    return shown, flags

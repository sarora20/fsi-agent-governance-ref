"""Field-level minimisation of what tool results hand back to the model, and -- for a field the
model must later echo back as an argument -- resolving a masked value against the system of record.

Independent of guardrails.redact(): that protects what the audit log writes (payloads are masked
there, always, regardless of this module); this protects what the model itself is ever shown or
asked to repeat, which is a separate surface (an account number the model never saw cannot appear
in its output, be reasoned about by a hijacked model, or leak through a prompt-injected summary).

Two directions, one convention (mask = "****" + last 4 characters, same as a bank statement):
  mask_fields()        outbound: ToolSpec.mask names result fields masked wherever they appear.
  resolve_masked_args()  inbound: ToolSpec.resolve names args that may arrive masked; a value that
                        is not masked (every scripted eval case and behavior script passes real
                        account ids directly) is left exactly as given -- this only activates for a
                        value a live model echoed back after seeing a masked result earlier in the
                        same run.
"""

from __future__ import annotations

import re
from typing import Any, Callable

_MASKED = re.compile(r"^\*{4}(\d{4})$")


def _mask_one(value: Any) -> Any:
    if isinstance(value, str) and len(value) > 4:
        return f"****{value[-4:]}"
    return "****"


def mask_fields(data: Any, field_names: frozenset[str]) -> Any:
    """Recursively replace the value of any dict key in field_names with a masked form, wherever it
    appears -- a scalar field or nested inside lists/dicts (e.g. a positions list, one entry per
    account). Anything else in the structure is returned unchanged."""
    if not field_names:
        return data
    if isinstance(data, dict):
        return {k: (_mask_one(v) if k in field_names else mask_fields(v, field_names)) for k, v in data.items()}
    if isinstance(data, (list, tuple)):
        return [mask_fields(v, field_names) for v in data]
    return data


def resolve_masked_args(args: dict[str, Any], field_names: frozenset[str],
                        facts: Callable[[str, dict], dict], tool: str) -> str | None:
    """Resolve every named arg that looks masked to the real id it stands for, in place. Returns None
    on success (including when nothing needed resolving), or a reason string to deny the call with.

    Matched by last 4 characters against `client_account_ids` from the system of record (never from
    anything the model said) -- ambiguous (two accounts sharing a last 4, not possible in this
    reference build's seed data but a real constraint worth documenting) or unresolvable is a denial,
    not a guess."""
    if not field_names:
        return None
    for field in field_names:
        value = args.get(field)
        m = _MASKED.match(value) if isinstance(value, str) else None
        if m is None:
            continue  # already a real id (or absent/malformed in some other way schema already judges)
        suffix = m.group(1)
        real_ids = facts(tool, args).get("client_account_ids", [])
        matches = [rid for rid in real_ids if str(rid).endswith(suffix)]
        if len(matches) != 1:
            return (f"masked value for '{field}' does not resolve to exactly one account on this "
                    f"client's record ({len(matches)} matches)")
        args[field] = matches[0]
    return None

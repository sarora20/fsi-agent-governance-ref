"""Evidence pack for an independent agent assessment (e.g. the Agentic Stability Framework).

Produces, from the running configuration rather than from documentation:
  abom.json        agent bill of materials: model, prompt hash, tools, tiers, scopes, policy hash
  authority.json   effective operating authority per role and tool (what the agent can really do)
  traces.jsonl     audit-log traces (redacted), including denial and approval paths
  summary.json     counts and completeness checks (e.g. at least one denied-action trace)

Scoring is deliberately NOT done here. Assign the evidence tier and score with the assessment
framework itself, by an assessor independent of the team that built the agent.

Freshness: `summary.json["provenance"]` binds the pack to a specific audit-log head -- signed, when
`keys` is given, with a checkpoint taken over exactly the entries this pack ships (audit.py's
checkpoint_entries()) -- plus the window of seq/timestamps covered and the policy/abom fingerprints,
so an assessor can tell this pack apart from one taken at a different, possibly healthier, time.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from . import AGENT_ID, AGENT_VERSION
from .agent.prompts import SYSTEM_PROMPT
from .app import Environment
from .audit import checkpoint_entries, verify_entries

if TYPE_CHECKING:
    from .identity import KeyRing
from .identity import MAX_TTL_SECONDS, ROLE_SCOPES
from .registry import RiskTier


def build_abom(env: Environment, adapter: str, model_id: str) -> dict[str, Any]:
    p = env.policy
    return {
        "agent_id": AGENT_ID,
        "agent_version": AGENT_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "model": {"adapter": adapter, "model_id": model_id},
        "system_prompt_sha256": hashlib.sha256(SYSTEM_PROMPT.encode()).hexdigest(),
        "tool_registry_sha256": env.registry.fingerprint(),
        "tools": [
            {"name": s.name, "risk_tier": s.risk_tier.name, "required_scope": s.required_scope,
             "side_effect": s.side_effect, "data_classes": list(s.data_classes),
             "client_scoped": s.client_arg is not None,
             # Field-level minimisation of what reaches the model (gateway.py stage "output"/
             # "minimise"; minimisation.py): None = no restriction beyond the handler's own return.
             "returns": sorted(s.returns) if s.returns is not None else None,
             "mask": sorted(s.mask), "resolve": sorted(s.resolve)}
            for s in env.registry.specs()
        ],
        "policy": {"version": p.version, "sha256": p.fingerprint(), "default_decision": p.default,
                   "limits": {"max_tool_calls_per_run": p.max_tool_calls_per_run,
                              "max_high_risk_calls_per_run": p.max_high_risk_calls_per_run,
                              "max_risk_tier": p.max_risk_tier}},
        "identity": {"mechanism": "JWT access token (RFC 9068 profile), EdDSA, delegation via act claim (RFC 8693)",
                     "validated": ["typ", "alg pinned", "kid", "iss", "aud", "exp/nbf", "jti/subject revocation",
                                   "run binding"],
                     "max_ttl_seconds": MAX_TTL_SECONDS, "signing_keys_active": sorted(env.keys.public_keys()),
                     "entitlement_check": "client book of the human principal",
                     "sender_constraining": "DPoP (RFC 9449): opt-in per token via cnf.jkt -- a token minted "
                                            "with no DPoP key stays a bearer credential, unaffected. A bound "
                                            "token's proof is checked for signature, key binding, freshness, "
                                            "method/URL match and jti replay before any other stage runs."},
        "velocity_rules": [{"id": r.id, "tool": r.tool, "per": r.per, "window_seconds": r.window_seconds,
                            "max_count": r.max_count, "max_sum": r.max_sum} for r in p.velocity],
        "approvals": {"mode": "durable pending actions", "ttl_seconds": p.approval_ttl_seconds,
                      "four_eyes": True, "revalidation_at_execution": True},
        "idempotency": {"required_for": "side-effecting tools", "ttl_seconds": 86400,
                        "scope": "per principal"},
        "controls": ["token verification", "run binding", "schema validation", "idempotency keys", "scope",
                     "entitlement", "risk ceiling", "per-run budgets", "cross-run velocity limits",
                     "declarative policy (deny by default, monotonic rules)",
                     "durable approvals with four-eyes, expiry and re-validation",
                     "output injection scan", "PII redaction in logs", "hash-chained audit log",
                     "Transaction Tokens on every backend call (draft-ietf-oauth-transaction-tokens-08)",
                     "W3C trace context", "AuthZEN 1.0 compatible policy decision point",
                     "DPoP sender-constrained tokens, opt-in (RFC 9449)"],
        "standards_checked_on": "2026-09-26",
    }


def build_authority(env: Environment) -> dict[str, Any]:
    matrix: dict[str, dict[str, Any]] = {}
    for role, scopes in ROLE_SCOPES.items():
        row: dict[str, Any] = {}
        for s in env.registry.specs():
            if s.required_scope not in scopes:
                row[s.name] = {"authority": "none", "why": f"role lacks scope {s.required_scope}"}
                continue
            cfg = env.policy.tools.get(s.name)
            baseline = cfg.get("decision", "deny") if cfg else env.policy.default
            row[s.name] = {
                "authority": {"allow": "autonomous", "require_approval": "with human approval",
                              "deny": "none"}[baseline],
                "risk_tier": s.risk_tier.name,
                "conditional_rules": [{"id": r.get("id"), "decision": r["decision"], "reason": r.get("reason", "")}
                                      for r in (cfg or {}).get("rules", []) or []],
            }
        matrix[role] = row
    return {"agent_id": AGENT_ID, "roles": matrix,
            "note": "Authority is also bounded per run by entitlement to the principal's clients and by budgets."}


def summarize_traces(entries: list[dict[str, Any]]) -> dict[str, Any]:
    events = Counter(e["event"] for e in entries)
    runs = {e["run_id"] for e in entries if e.get("run_id")}
    ok, bad = verify_entries(entries)
    high_risk_executed = sum(1 for e in entries if e["event"] == "tool_executed"
                             and e.get("risk_tier") == RiskTier.HIGH.name)
    return {
        "runs": len(runs),
        "events": dict(events),
        "executed": events.get("tool_executed", 0),
        "denied": events.get("tool_denied", 0),
        "approval_denied": events.get("tool_approval_denied", 0),
        "errors": events.get("tool_error", 0),
        "high_risk_executed": high_risk_executed,
        "untrusted_content_flags": events.get("untrusted_content", 0),
        "pending_approval": events.get("tool_pending_approval", 0),
        "approvals_expired": events.get("approval_expired", 0),
        "revalidation_failures": events.get("revalidation_failed", 0),
        "idempotent_replays": events.get("tool_replayed", 0),
        "completeness": {
            "denied_action_trace_present": events.get("tool_denied", 0) > 0,
            "approval_path_trace_present": events.get("approval_decided", 0) > 0,
            "audit_chain_intact": ok,
            "first_broken_seq": bad,
        },
    }


def _git_commit() -> str | None:
    """Best effort: None when this isn't a git checkout, git isn't installed, or there is no commit
    yet -- a pack should still be produced, with the gap visible in provenance rather than guessed at."""
    try:
        out = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.strip() if out.returncode == 0 else None


def build_provenance(entries: list[dict[str, Any]], abom: dict[str, Any], policy_fingerprint: str,
                     adapter: str, model_id: str, keys: "KeyRing | None" = None) -> dict[str, Any]:
    """Binds the pack to a specific audit-log head: which entries it covers, their fingerprints, and
    -- when `keys` is given -- a fresh signed checkpoint over exactly the entries being shipped
    (appended to `entries` in place, so it ships inside traces.jsonl too). Without `keys`, the window
    and fingerprints are still recorded; `checkpointed` says plainly that this pack carries no
    signature, rather than a verifier having to infer that from its absence."""
    prov: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "adapter": adapter, "model_id": model_id,
        "abom_sha256": hashlib.sha256(json.dumps(abom, sort_keys=True, default=str).encode()).hexdigest(),
        "policy_sha256": policy_fingerprint,
        "git_commit": _git_commit(),
        "entries_covered": len(entries),
        "seq_range": [entries[0]["seq"], entries[-1]["seq"]] if entries else None,
        "ts_range": [entries[0]["ts"], entries[-1]["ts"]] if entries else None,
        "checkpointed": False,
    }
    if entries and keys is not None:
        checkpoint = checkpoint_entries(entries, keys)
        entries.append(checkpoint)
        # audit_head/audit_head_seq always name the actual last entry now shipped in traces.jsonl --
        # the checkpoint itself, once appended -- so a re-check can compare it directly against
        # entries[-1] without needing to know whether a checkpoint is present. What the checkpoint's
        # signature attests to (the entry just before it) is named separately.
        prov.update(checkpointed=True, audit_head=checkpoint["hash"], audit_head_seq=checkpoint["seq"],
                   checkpoint_attests_seq=checkpoint["checkpoint_of_seq"],
                   checkpoint_attests_hash=checkpoint["checkpoint_of_hash"],
                   checkpoint_kid=checkpoint["kid"], checkpoint_signature=checkpoint["signature"])
    elif entries:
        prov["audit_head"], prov["audit_head_seq"] = entries[-1]["hash"], entries[-1]["seq"]
    return prov


def write_evidence(env: Environment, out_dir: str | Path, adapter: str, model_id: str,
                   audit_file: str | Path | None = None, eval_report: str | Path | None = None,
                   keys: "KeyRing | None" = None) -> Path:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    if audit_file:
        with open(audit_file, encoding="utf-8") as fh:
            entries = [json.loads(line) for line in fh if line.strip()]
    else:
        entries = env.audit.entries()
    abom = build_abom(env, adapter, model_id)
    (out / "abom.json").write_text(json.dumps(abom, indent=2), encoding="utf-8")
    (out / "authority.json").write_text(json.dumps(build_authority(env), indent=2), encoding="utf-8")
    provenance = build_provenance(entries, abom, env.policy.fingerprint(), adapter, model_id, keys)
    with (out / "traces.jsonl").open("w", encoding="utf-8") as fh:  # entries may now include a checkpoint
        for e in entries:
            fh.write(json.dumps(e, default=str) + "\n")
    summary = summarize_traces(entries)
    summary["provenance"] = provenance
    if eval_report:
        summary["eval_report"] = str(eval_report)
    (out / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return out


def verify_evidence_pack(out_dir: str | Path, public_keys: dict[str, Any] | None = None
                         ) -> tuple[bool, str]:
    """Re-checks a pack already on disk: the chain (and, with public_keys, its checkpoint signature)
    verifies, and summary.json's provenance actually describes the traces.jsonl shipped beside it --
    the second check is what catches a pack assembled from a different run's files (summary.json
    from a healthy run, traces.jsonl swapped for an unhealthy one, or the reverse)."""
    out = Path(out_dir)
    with (out / "traces.jsonl").open(encoding="utf-8") as fh:
        entries = [json.loads(line) for line in fh if line.strip()]
    ok, bad = verify_entries(entries, public_keys)
    if not ok:
        return False, f"audit chain broken at seq {bad}"
    summary = json.loads((out / "summary.json").read_text())
    prov = summary.get("provenance") or {}
    head = entries[-1] if entries else None
    if prov.get("audit_head") != (head["hash"] if head else None):
        return False, (f"summary.json's provenance names a different audit head ({prov.get('audit_head')}) "
                       f"than traces.jsonl actually ends with ({head['hash'] if head else None}) -- "
                       "these files were not shipped together")
    if prov.get("checkpointed") and public_keys is None:
        return True, "chain intact; provenance matches; checkpoint signature NOT checked (no public keys given)"
    return True, "chain intact; provenance matches traces.jsonl" + (
        "; checkpoint signature verified" if prov.get("checkpointed") else "; pack carries no checkpoint")

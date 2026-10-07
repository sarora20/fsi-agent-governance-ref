"""Tamper-evident audit log.

Each entry carries the hash of the previous entry, so editing or deleting any line breaks
the chain. Payloads are redacted before they are written. Writes to JSONL when a path is given.

The chain alone proves internal consistency, not that nothing was removed from one end or that a
pack handed to an assessor is the log they think it is: checkpoint() signs the current head with the
issuer's own EdDSA signing key (the same kid machinery that signs delegation tokens), so a later
re-check -- by anyone holding the public key, not the log's own writer -- can confirm the chain up to
that point has not been edited, truncated, or swapped for a different run's.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .guardrails import redact

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    from .identity import KeyRing

GENESIS = "0" * 64
# identifiers that must stay intact so the log can be filtered and joined
_UNREDACTED = {"run_id", "call_id", "tool", "outcome", "principal", "agent", "adapter", "token_id",
              "kid", "signature", "checkpoint_of_seq", "checkpoint_of_hash"}


def _hash(entry: dict[str, Any]) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path | None = None):
        self._entries: list[dict[str, Any]] = []
        self._path = Path(path) if path else None
        if self._path:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text("", encoding="utf-8")

    @property
    def path(self) -> Path | None:
        return self._path

    def record(self, event: str, **fields: Any) -> dict[str, Any]:
        keep = {k: fields.pop(k) for k in list(fields) if k in _UNREDACTED}
        entry: dict[str, Any] = {
            "seq": len(self._entries) + 1,
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "event": event,
            **keep,
            **redact(fields),
            "prev": self._entries[-1]["hash"] if self._entries else GENESIS,
        }
        entry["hash"] = _hash(entry)
        self._entries.append(entry)
        if self._path:
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, default=str) + "\n")
        return entry

    def entries(self, run_id: str | None = None) -> list[dict[str, Any]]:
        if run_id is None:
            return list(self._entries)
        return [e for e in self._entries if e.get("run_id") == run_id]

    def checkpoint(self, keys: "KeyRing") -> dict[str, Any]:
        """Sign the current head with the issuer's active signing key. Appends its own entry,
        chained like any other -- a checkpoint is itself part of the log it attests to."""
        if not self._entries:
            raise ValueError("cannot checkpoint an empty audit log")
        return self.record("audit_checkpoint", **sign_checkpoint(self._entries[-1], keys))

    def verify(self, public_keys: dict[str, "Ed25519PublicKey"] | None = None) -> tuple[bool, int | None]:
        return verify_entries(self._entries, public_keys)

    @staticmethod
    def verify_file(path: str | Path, public_keys: dict[str, "Ed25519PublicKey"] | None = None
                    ) -> tuple[bool, int | None]:
        with open(path, encoding="utf-8") as fh:
            entries = [json.loads(line) for line in fh if line.strip()]
        return verify_entries(entries, public_keys)


def sign_checkpoint(head: dict[str, Any], keys: "KeyRing") -> dict[str, Any]:
    """The fields a checkpoint of `head` (an audit entry: its seq and hash) carries, signed with the
    issuer's active key. Shared by AuditLog.checkpoint() (a live log) and checkpoint_entries() below
    (an arbitrary entries list, e.g. read from a file) so both produce the identical shape."""
    canonical = json.dumps({"seq": head["seq"], "hash": head["hash"]},
                           sort_keys=True, separators=(",", ":")).encode()
    kid, key = keys.signing_key()
    signature = key.sign(canonical)
    return {"checkpoint_of_seq": head["seq"], "checkpoint_of_hash": head["hash"], "kid": kid,
            "signature": base64.b64encode(signature).decode()}


def checkpoint_entries(entries: list[dict[str, Any]], keys: "KeyRing") -> dict[str, Any]:
    """Build a properly chained audit_checkpoint entry over the current last entry of `entries`,
    without needing a live AuditLog -- used by write_evidence() so a pack is checkpointed over
    exactly the entries it ships, even when they were read from a file rather than a running log.
    The caller decides whether to append the result to `entries`."""
    if not entries:
        raise ValueError("cannot checkpoint an empty entries list")
    head = entries[-1]
    entry: dict[str, Any] = {
        "seq": head["seq"] + 1,
        "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "event": "audit_checkpoint",
        **sign_checkpoint(head, keys),
        "prev": head["hash"],
    }
    entry["hash"] = _hash(entry)
    return entry


def _checkpoint_signature_ok(entry: dict[str, Any], actual_hash_at_seq: dict[int, str],
                             public_keys: dict[str, "Ed25519PublicKey"]) -> bool:
    key = public_keys.get(entry.get("kid", ""))
    if key is None:
        return False
    seq, claimed_hash = entry.get("checkpoint_of_seq"), entry.get("checkpoint_of_hash")
    if actual_hash_at_seq.get(seq) != claimed_hash:  # attests to a hash that was never actually at that seq
        return False
    canonical = json.dumps({"seq": seq, "hash": claimed_hash}, sort_keys=True, separators=(",", ":")).encode()
    try:
        key.verify(base64.b64decode(entry.get("signature", "")), canonical)
    except Exception:  # noqa: BLE001 - any failure (bad signature, bad base64) means "not verified"
        return False
    return True


def verify_entries(entries: list[dict[str, Any]], public_keys: dict[str, "Ed25519PublicKey"] | None = None
                   ) -> tuple[bool, int | None]:
    """Returns (ok, first_bad_seq). With public_keys, also checks any audit_checkpoint entry's
    signature -- a checkpoint that does not verify is treated exactly like a broken hash link."""
    prev = GENESIS
    hash_at_seq: dict[int, str] = {}
    for entry in entries:
        if entry.get("prev") != prev or _hash(entry) != entry.get("hash"):
            return False, entry.get("seq")
        hash_at_seq[entry.get("seq")] = entry["hash"]
        if (public_keys is not None and entry.get("event") == "audit_checkpoint"
                and not _checkpoint_signature_ok(entry, hash_at_seq, public_keys)):
            return False, entry.get("seq")
        prev = entry["hash"]
    return True, None

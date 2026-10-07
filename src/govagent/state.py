"""Shared, durable governance state (SQLite).

Everything that must hold *across* runs and processes lives here, not in the agent:
  runs          per-run budgets and closed flag (the run id comes from the token, not the agent)
  calls         per-run tool-call records
  velocity      rolling-window reservations and commits for cross-run limits
  idempotency   request keys, payload fingerprints, stored responses
  actions       durable pending actions awaiting human approval
  revocations   revoked token ids and subjects

`transaction()` serialises check-and-write sequences (BEGIN IMMEDIATE), so two concurrent runs
cannot both pass a limit check before either records its reservation (CWE-367, TOCTOU).
Production: the same interface over Postgres or Redis with the same atomicity guarantees.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
  run_id TEXT PRIMARY KEY, principal TEXT, created_at REAL, closed INTEGER DEFAULT 0,
  calls INTEGER DEFAULT 0, high_risk INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS calls (
  run_id TEXT, seq INTEGER, record TEXT, PRIMARY KEY (run_id, seq));
CREATE TABLE IF NOT EXISTS velocity (
  id INTEGER PRIMARY KEY AUTOINCREMENT, tool TEXT, principal TEXT, client_id TEXT,
  amount REAL, ts REAL, state TEXT, action_id TEXT);
CREATE INDEX IF NOT EXISTS velocity_lookup ON velocity (tool, ts);
CREATE TABLE IF NOT EXISTS idempotency (
  principal TEXT, key TEXT, fingerprint TEXT, status TEXT, response TEXT, created_at REAL,
  PRIMARY KEY (principal, key));
CREATE TABLE IF NOT EXISTS actions (
  action_id TEXT PRIMARY KEY, run_id TEXT, tool TEXT, args TEXT, fingerprint TEXT, principal TEXT,
  client_id TEXT, token_id TEXT, agent TEXT, traceparent TEXT, created_at REAL, expires_at REAL, status TEXT, approver TEXT,
  decided_at REAL, note TEXT, idempotency_key TEXT, reasons TEXT, result TEXT);
CREATE TABLE IF NOT EXISTS revocations (
  kind TEXT, value TEXT, revoked_at REAL, PRIMARY KEY (kind, value));
CREATE TABLE IF NOT EXISTS controls (
  scope TEXT, key TEXT, reason TEXT, by TEXT, at REAL, PRIMARY KEY (scope, key));
CREATE TABLE IF NOT EXISTS backend_errors (
  tool TEXT, ts REAL);
CREATE INDEX IF NOT EXISTS backend_errors_lookup ON backend_errors (tool, ts);
CREATE TABLE IF NOT EXISTS breakers (
  tool TEXT PRIMARY KEY, state TEXT, opened_at REAL, half_open_inflight INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS dpop_jti (
  jti TEXT PRIMARY KEY, ts REAL);
"""


class StateStore:
    def __init__(self, path: str | Path = ":memory:"):
        self._lock = threading.RLock()
        self._db = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._db.executescript(SCHEMA)
        self._depth = 0

    @contextmanager
    def transaction(self) -> Iterator["StateStore"]:
        with self._lock:
            outer = self._depth == 0
            if outer:
                self._db.execute("BEGIN IMMEDIATE")
            self._depth += 1
            try:
                yield self
            except BaseException:
                self._depth -= 1
                if outer:
                    self._db.execute("ROLLBACK")
                raise
            self._depth -= 1
            if outer:
                self._db.execute("COMMIT")

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> sqlite3.Cursor:
        with self._lock:
            return self._db.execute(sql, params)

    def one(self, sql: str, params: tuple[Any, ...] = ()) -> sqlite3.Row | None:
        # Fetch inside the lock: threads share one connection (check_same_thread=False),
        # so another statement on it can reset this cursor before the rows are read.
        with self._lock:
            return self._db.execute(sql, params).fetchone()

    def all(self, sql: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._db.execute(sql, params).fetchall()

    # --- runs ------------------------------------------------------------------------------

    def ensure_run(self, run_id: str, principal: str, now: float) -> sqlite3.Row:
        # One transaction: a concurrent writer's ROLLBACK would otherwise discard the
        # INSERT before the SELECT reads it back, returning None to the caller.
        with self.transaction():
            self.execute("INSERT OR IGNORE INTO runs (run_id, principal, created_at) VALUES (?, ?, ?)",
                         (run_id, principal, now))
            return self.one("SELECT * FROM runs WHERE run_id = ?", (run_id,))

    def add_call(self, run_id: str, record: dict[str, Any], high_risk_executed: bool) -> int:
        with self.transaction():
            seq = self.one("SELECT COUNT(*) AS n FROM calls WHERE run_id = ?", (run_id,))["n"] + 1
            self.execute("INSERT INTO calls (run_id, seq, record) VALUES (?, ?, ?)",
                         (run_id, seq, json.dumps(record, default=str)))
            self.execute("UPDATE runs SET calls = calls + 1, high_risk = high_risk + ? WHERE run_id = ?",
                         (1 if high_risk_executed else 0, run_id))
            return seq

    def run_calls(self, run_id: str) -> list[dict[str, Any]]:
        rows = self.all("SELECT record FROM calls WHERE run_id = ? ORDER BY seq", (run_id,))
        return [json.loads(r["record"]) for r in rows]

    def close_run(self, run_id: str) -> None:
        self.execute("UPDATE runs SET closed = 1 WHERE run_id = ?", (run_id,))

    def reset(self) -> None:
        """Dev/demo only: clear runs, limits, idempotency keys, actions, revocations, kill switches,
        breaker state and DPoP replay history."""
        with self.transaction():
            for table in ("runs", "calls", "velocity", "idempotency", "actions", "revocations",
                          "controls", "backend_errors", "breakers", "dpop_jti"):
                self.execute(f"DELETE FROM {table}")

    # --- DPoP replay (RFC 9449: a proof's jti must never be accepted twice) ------------------

    def dpop_replay_check(self, jti: str, now: float) -> bool:
        """True if this proof jti was already used (a replay, which must be refused); records it
        as seen on first use. A real deployment would also prune rows older than the proof
        freshness window; left for an operator to schedule, same as any other append-only table
        here -- it does not affect correctness within a demo's lifetime."""
        with self.transaction():
            if self.one("SELECT 1 FROM dpop_jti WHERE jti = ?", (jti,)):
                return True
            self.execute("INSERT INTO dpop_jti (jti, ts) VALUES (?, ?)", (jti, now))
            return False

    # --- kill switch (scope: "global" key "" | "tool" key=<tool> | "agent" key=<agent id>) ----

    def engage_stop(self, scope: str, key: str, reason: str, by: str, now: float) -> None:
        self.execute("INSERT OR REPLACE INTO controls (scope, key, reason, by, at) VALUES (?,?,?,?,?)",
                     (scope, key, reason, by, now))

    def release_stop(self, scope: str, key: str) -> bool:
        cur = self.execute("DELETE FROM controls WHERE scope = ? AND key = ?", (scope, key))
        return cur.rowcount > 0

    def active_stop(self, tool: str | None, agent: str | None) -> dict[str, Any] | None:
        """The first applicable stop, global first, then per-tool, then per-agent -- or None."""
        row = self.one("SELECT * FROM controls WHERE scope = 'global' AND key = ''")
        if row is None and tool:
            row = self.one("SELECT * FROM controls WHERE scope = 'tool' AND key = ?", (tool,))
        if row is None and agent:
            row = self.one("SELECT * FROM controls WHERE scope = 'agent' AND key = ?", (agent,))
        return dict(row) if row else None

    def stop_state(self) -> dict[str, Any]:
        rows = self.all("SELECT * FROM controls")
        state: dict[str, Any] = {"global": None, "tools": {}, "agents": {}}
        for r in rows:
            entry = {"reason": r["reason"], "by": r["by"], "at": r["at"]}
            if r["scope"] == "global":
                state["global"] = entry
            elif r["scope"] == "tool":
                state["tools"][r["key"]] = entry
            elif r["scope"] == "agent":
                state["agents"][r["key"]] = entry
        return state

    # --- circuit breaker (per tool) -----------------------------------------------------------

    def breaker_check(self, tool: str, cooldown_seconds: float, now: float) -> str | None:
        """None if the call may proceed; else a denial reason. A breaker that has been open for at
        least cooldown_seconds lets exactly one probe through (half-open) rather than staying shut
        forever or snapping fully closed on a guess."""
        row = self.one("SELECT * FROM breakers WHERE tool = ?", (tool,))
        if row is None or row["state"] == "closed":
            return None
        if row["state"] == "open":
            if now - row["opened_at"] < cooldown_seconds:
                return f"breaker open for '{tool}'; retry after the cooldown"
            self.execute("UPDATE breakers SET state = 'half_open' WHERE tool = ?", (tool,))
            return None
        if row["half_open_inflight"]:
            return f"breaker half-open for '{tool}'; a probe is already in flight"
        self.execute("UPDATE breakers SET half_open_inflight = 1 WHERE tool = ?", (tool,))
        return None

    def breaker_record_error(self, tool: str, max_errors: int, window_seconds: float, now: float) -> None:
        with self.transaction():
            self.execute("INSERT INTO backend_errors (tool, ts) VALUES (?, ?)", (tool, now))
            recent = self.one("SELECT COUNT(*) AS n FROM backend_errors WHERE tool = ? AND ts > ?",
                              (tool, now - window_seconds))["n"]
            cur = self.one("SELECT state FROM breakers WHERE tool = ?", (tool,))
            if cur is None:
                self.execute("INSERT INTO breakers (tool, state, opened_at) VALUES (?, 'closed', 0)", (tool,))
                cur = {"state": "closed"}
            if recent >= max_errors or cur["state"] == "half_open":
                # threshold crossed, or the half-open probe itself failed: (re)open for a fresh cooldown
                self.execute("UPDATE breakers SET state = 'open', opened_at = ?, half_open_inflight = 0 "
                            "WHERE tool = ?", (now, tool))

    def breaker_record_success(self, tool: str) -> None:
        self.execute("UPDATE breakers SET state = 'closed', half_open_inflight = 0 WHERE tool = ?", (tool,))

    def breaker_state(self) -> dict[str, Any]:
        return {r["tool"]: {"state": r["state"], "opened_at": r["opened_at"]} for r in self.all("SELECT * FROM breakers")}

    # --- revocations -------------------------------------------------------------------------

    def revoke(self, kind: str, value: str, now: float) -> None:
        self.execute("INSERT OR REPLACE INTO revocations (kind, value, revoked_at) VALUES (?, ?, ?)",
                     (kind, value, now))

    def revoked_at(self, kind: str, value: str) -> float | None:
        row = self.one("SELECT revoked_at FROM revocations WHERE kind = ? AND value = ?", (kind, value))
        return row["revoked_at"] if row else None

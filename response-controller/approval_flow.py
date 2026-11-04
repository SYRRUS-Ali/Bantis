"""Persistent, host-local review queue. No HTTP or model-output entry point.

SQLite records survive CLI invocations; a host lock serializes decisions through
execution. The executing marker is committed *before* any external effect, so a
crash cannot roll it back and make an action eligible again. This local journal
does not replace the externally anchored action log required by gate G2.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from executor import Executor
from models import HASH_PREFIX_LENGTH, Approval, Outcome, Proposal, Status
from registry import ActionRegistry


class ReviewError(ValueError):
    pass


class ReviewStore:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock_path = path.with_suffix(path.suffix + ".lock")
        fd = os.open(path, os.O_CREAT | os.O_WRONLY, 0o600)
        os.close(fd)
        self.db = sqlite3.connect(path, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS proposals (
                action_id TEXT PRIMARY KEY, payload TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending'
            );
            CREATE TABLE IF NOT EXISTS approvals (
                action_id TEXT NOT NULL, approver TEXT NOT NULL, payload TEXT NOT NULL,
                PRIMARY KEY (action_id, approver)
            );
            CREATE TABLE IF NOT EXISTS events (
                sequence INTEGER PRIMARY KEY, payload TEXT NOT NULL
            );
        """)

        # Only the original schema is migrated. Missing hashes in an upgraded
        # journal are corruption, never an invitation to silently rehash it.
        with self.transaction():
            columns = {row["name"] for row in self.db.execute("PRAGMA table_info(events)")}
            if "entry_hash" not in columns:
                self.db.execute("ALTER TABLE events ADD COLUMN previous_hash TEXT")
                self.db.execute("ALTER TABLE events ADD COLUMN entry_hash TEXT")
                previous = "0" * 64
                for row in self.db.execute("SELECT sequence, payload FROM events ORDER BY sequence").fetchall():
                    digest = self._digest(row["sequence"], previous, row["payload"])
                    self.db.execute("UPDATE events SET previous_hash = ?, entry_hash = ? WHERE sequence = ?",
                                    (previous, digest, row["sequence"]))
                    previous = digest

    @staticmethod
    def _digest(sequence: int, previous: str, payload: str) -> str:
        return hashlib.sha256(f"{sequence}\n{previous}\n{payload}".encode()).hexdigest()

    def verify(self, expected_head: str | None = None) -> dict:
        previous = "0" * 64
        count = 0
        for row in self.db.execute("SELECT * FROM events ORDER BY sequence"):
            count += 1
            if (row["sequence"] != count or row["previous_hash"] != previous
                    or row["entry_hash"] != self._digest(row["sequence"], previous, row["payload"])):
                raise ReviewError(f"audit integrity check failed at sequence {row['sequence']}")
            previous = row["entry_hash"]
        if expected_head is not None and previous != expected_head:
            raise ReviewError("audit head does not match the trusted checkpoint")
        return {"count": count, "head": previous}

    def audit(self, *, action_id: str | None = None, actor: str | None = None) -> list[dict]:
        self.verify()
        entries = []
        for row in self.db.execute("SELECT * FROM events ORDER BY sequence"):
            entry = json.loads(row["payload"])
            if action_id is not None and entry["action_id"] != action_id:
                continue
            if actor is not None and actor not in {entry.get("actor"), entry.get("initiated_by")}:
                continue
            entries.append({**entry, "sequence": row["sequence"], "previous_hash": row["previous_hash"],
                            "entry_hash": row["entry_hash"]})
        return entries

    def close(self) -> None:
        self.db.close()

    @contextmanager
    def locked(self):
        fd = os.open(self._lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        with os.fdopen(fd, "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)

    @contextmanager
    def transaction(self):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield
            self.db.execute("COMMIT")
        except BaseException:
            self.db.execute("ROLLBACK")
            raise

    def get(self, action_id: str) -> tuple[Proposal, str]:
        row = self.db.execute("SELECT payload, status FROM proposals WHERE action_id = ?", (action_id,)).fetchone()
        if row is None:
            raise ReviewError(f"unknown action: {action_id}")
        return Proposal.model_validate_json(row["payload"]), row["status"]

    def pending(self, now: datetime | None = None) -> list[Proposal]:
        now = now or datetime.now(UTC)
        return [
            p for row in self.db.execute("SELECT payload FROM proposals WHERE status = 'pending' ORDER BY rowid")
            if not (p := Proposal.model_validate_json(row["payload"])).is_expired(now)
            and not self.already_executed(p.action_id)
        ]

    def history(self, action_id: str) -> list[dict]:
        return self.audit(action_id=action_id)

    def record(self, entry: dict) -> None:
        if not self.db.in_transaction:
            with self.transaction():
                self._record(entry)
        else:
            self._record(entry)

    def _record(self, entry: dict) -> None:
        head = self.verify()
        payload = json.dumps(entry, sort_keys=True, separators=(",", ":"), allow_nan=False)
        sequence = head["count"] + 1
        self.db.execute("INSERT INTO events(sequence, payload, previous_hash, entry_hash) VALUES (?, ?, ?, ?)",
                        (sequence, payload, head["head"], self._digest(sequence, head["head"], payload)))
        if entry["event"] == "executing":
            self._status(entry["action_id"], "executing")
        elif entry["event"] == "outcome":
            status = "pending" if entry["status"] == Status.AWAITING_APPROVAL else entry["status"]
            self.db.execute("UPDATE proposals SET status = ? WHERE action_id = ? AND status IN ('pending', 'executing')",
                            (status, entry["action_id"]))

    def already_executed(self, action_id: str) -> bool:
        return any(e["event"] in {"executing", "dismissed", "modified"} for e in self.history(action_id))

    def _insert(self, proposal: Proposal) -> None:
        self.db.execute("INSERT INTO proposals(action_id, payload) VALUES (?, ?)",
                        (proposal.action_id, proposal.model_dump_json()))

    def _status(self, action_id: str, status: str) -> None:
        self.db.execute("UPDATE proposals SET status = ? WHERE action_id = ?", (status, action_id))


class ApprovalFlow:
    def __init__(self, store: ReviewStore, executor: Executor, registry: ActionRegistry) -> None:
        self.store, self.executor, self.registry = store, executor, registry

    def _validate(self, proposal: Proposal) -> None:
        action = self.registry.get(proposal.type)
        if action is None:
            raise ReviewError(f"{proposal.type!r} has no implementation")
        action.parse_params(proposal)

    def _event(self, subject: Proposal, event: str, actor: str, now: datetime, **detail) -> None:
        self.store.record({"action_id": subject.action_id, "event": event, "actor": actor,
                           "at": now.astimezone(UTC).isoformat(), "proposal_hash": subject.proposal_hash,
                           "incident_id": subject.incident_id, "type": subject.type, **detail})

    def submit(self, proposal: Proposal, *, actor: str = "policy", now: datetime | None = None) -> Proposal:
        if not actor.strip():
            raise ReviewError("proposer is required")
        self._validate(proposal)
        with self.store.locked(), self.store.transaction():
            now = now or datetime.now(UTC)
            if not proposal.created_at <= now < proposal.expires_at:
                raise ReviewError("proposal is outside its review window")
            if self.store.db.execute("SELECT 1 FROM proposals WHERE action_id = ?", (proposal.action_id,)).fetchone():
                raise ReviewError("action_id already exists")
            self.store._insert(proposal)
            self._event(proposal, "proposed", actor, now, proposal=proposal.model_dump(mode="json"))
        return proposal

    def _pending(self, action_id: str, prefix: str, now: datetime) -> Proposal:
        proposal, status = self.store.get(action_id)
        if status != "pending" or self.store.already_executed(action_id):
            raise ReviewError(f"action is closed ({status})")
        if not proposal.created_at <= now < proposal.expires_at:
            raise ReviewError("proposal is outside its review window")
        if not HASH_PREFIX_LENGTH <= len(prefix) <= 64 or not proposal.proposal_hash.startswith(prefix):
            raise ReviewError("proposal hash does not match; review the current proposal")
        return proposal

    def approve(self, action_id: str, prefix: str, actor: str, *, now: datetime | None = None) -> Outcome:
        if not actor.strip():
            raise ReviewError("approver is required")
        with self.store.locked():
            now = now or datetime.now(UTC)
            proposal = self._pending(action_id, prefix, now)
            approval = Approval(action_id=action_id, approver=actor, hash_prefix=prefix, approved_at=now)
            with self.store.transaction():
                if self.store.db.execute("SELECT 1 FROM approvals WHERE action_id = ? AND approver = ?",
                                         (action_id, actor)).fetchone():
                    raise ReviewError("this operator has already approved the proposal")
                self.store.db.execute("INSERT INTO approvals VALUES (?, ?, ?)",
                                      (action_id, actor, approval.model_dump_json()))
                self._event(proposal, "approved", actor, now)
            approvals = [Approval.model_validate_json(row["payload"]) for row in self.store.db.execute(
                "SELECT payload FROM approvals WHERE action_id = ?", (action_id,))]
            if len(approvals) < proposal.required_approvals:
                outcome = Outcome(action_id=action_id, type=proposal.type, status=Status.AWAITING_APPROVAL,
                                  reasons=[f"approval required: {len(approvals)} of {proposal.required_approvals}"])
                self._event(proposal, "outcome", actor, now, **outcome.model_dump(mode="json"))
                return outcome
            # Each executor record autocommits. Never wrap execution in a DB transaction.
            return self.executor.run(proposal, approvals, now=now, actor=actor)

    def modify(self, action_id: str, prefix: str, actor: str, params: dict, reason: str,
               *, now: datetime | None = None) -> Proposal:
        self._reason(actor, reason)
        with self.store.locked(), self.store.transaction():
            now = now or datetime.now(UTC)
            original = self._pending(action_id, prefix, now)
            fields = original.model_dump(exclude={"action_id", "params", "created_at"})
            replacement = Proposal(**fields, params=params, created_at=now)
            self._validate(replacement)
            self.store._insert(replacement)
            self.store._status(action_id, "modified")
            self._event(original, "modified", actor, now, reason=reason, replacement_id=replacement.action_id)
            self._event(replacement, "proposed", actor, now, replaces_id=action_id,
                        proposal=replacement.model_dump(mode="json"))
            return replacement

    def dismiss(self, action_id: str, prefix: str, actor: str, reason: str,
                *, now: datetime | None = None) -> None:
        self._reason(actor, reason)
        with self.store.locked(), self.store.transaction():
            now = now or datetime.now(UTC)
            proposal = self._pending(action_id, prefix, now)
            self.store._status(action_id, "dismissed")
            self._event(proposal, "dismissed", actor, now, reason=reason)

    @staticmethod
    def _reason(actor: str, reason: str) -> None:
        if not actor.strip() or not reason.strip():
            raise ReviewError("operator and reason are required")
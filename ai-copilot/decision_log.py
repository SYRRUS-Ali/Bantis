from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import sys
import uuid
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, Field

from models import AnalysisTrace, AttemptRecord, CopilotRequest, CopilotResponse

DEFAULT_PATH = os.environ.get("BANTIS_DECISION_LOG", str(Path(__file__).resolve().parent / "decision_log.db"))
GENESIS_HASH = "0" * 64

_SCHEMA = """
CREATE TABLE IF NOT EXISTS decisions (
    seq          INTEGER PRIMARY KEY AUTOINCREMENT,
    record_id    TEXT NOT NULL UNIQUE,
    incident_id  TEXT NOT NULL,
    recorded_at  TEXT NOT NULL,
    record_json  TEXT NOT NULL,
    prev_hash    TEXT NOT NULL,
    record_hash  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS decisions_incident ON decisions (incident_id);
"""


class DecisionRecord(BaseModel):
    record_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str
    recorded_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    outcome: str
    model: str
    system_prompt: str | None = None
    request: CopilotRequest | None = None
    attempts: list[AttemptRecord] = Field(default_factory=list)
    response: CopilotResponse
    note: str | None = None

    @classmethod
    def from_trace(cls, incident_id: str, request: CopilotRequest | None, trace: AnalysisTrace) -> DecisionRecord:
        return cls(
            incident_id=incident_id,
            outcome=trace.response.proposed_action.type,
            model=trace.response.model,
            system_prompt=trace.system_prompt,
            request=request,
            attempts=trace.attempts,
            response=trace.response,
        )

    @classmethod
    def without_provider_call(cls, incident_id: str, request: CopilotRequest | None, response: CopilotResponse, note: str) -> DecisionRecord:
        return cls(
            incident_id=incident_id,
            outcome=response.proposed_action.type,
            model=response.model,
            request=request,
            response=response,
            note=note,
        )


class StoredDecision(BaseModel):
    seq: int
    prev_hash: str
    record_hash: str
    record: DecisionRecord


def _hash(prev_hash: str, record_json: str) -> str:
    return hashlib.sha256(f"{prev_hash}\n{record_json}".encode("utf-8")).hexdigest()


class DecisionLog:
    def __init__(self, path: str | os.PathLike = DEFAULT_PATH) -> None:
        self._path = str(path)
        with closing(self._connect()) as connection:
            connection.executescript(_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        # isolation_level=None: transactions are managed explicitly below.
        return sqlite3.connect(self._path, isolation_level=None, timeout=30)

    def append(self, record: DecisionRecord) -> StoredDecision:
        record_json = record.model_dump_json()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT record_hash FROM decisions ORDER BY seq DESC LIMIT 1").fetchone()
            prev_hash = row[0] if row else GENESIS_HASH
            record_hash = _hash(prev_hash, record_json)
            cursor = connection.execute(
                "INSERT INTO decisions (record_id, incident_id, recorded_at, record_json, prev_hash, record_hash) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (record.record_id, record.incident_id, record.recorded_at.isoformat(), record_json, prev_hash, record_hash),
            )
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()
        return StoredDecision(seq=cursor.lastrowid, prev_hash=prev_hash, record_hash=record_hash, record=record)

    def _rows(self, where: str = "", params: tuple = ()) -> list[StoredDecision]:
        with closing(self._connect()) as connection:
            rows = connection.execute(
                f"SELECT seq, prev_hash, record_hash, record_json FROM decisions {where} ORDER BY seq", params
            ).fetchall()
        return [
            StoredDecision(seq=seq, prev_hash=prev, record_hash=digest, record=DecisionRecord.model_validate_json(body))
            for seq, prev, digest, body in rows
        ]

    def for_incident(self, incident_id: str) -> list[StoredDecision]:
        return self._rows("WHERE incident_id = ?", (incident_id,))

    def has_incident(self, incident_id: str) -> bool:
        with closing(self._connect()) as connection:
            return connection.execute(
                "SELECT 1 FROM decisions WHERE incident_id = ? LIMIT 1", (incident_id,)
            ).fetchone() is not None

    def verify(self) -> list[str]:
        problems = []
        expected_prev = GENESIS_HASH
        with closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT seq, record_json, prev_hash, record_hash FROM decisions ORDER BY seq"
            ).fetchall()
        for seq, record_json, prev_hash, record_hash in rows:
            if prev_hash != expected_prev:
                problems.append(f"seq {seq}: prev_hash doesn't match the record before it (a record was removed or reordered)")
            if _hash(prev_hash, record_json) != record_hash:
                problems.append(f"seq {seq}: content doesn't match its hash (the record was modified)")
            expected_prev = record_hash
        return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Inspect the AI Copilot's decision log.")
    parser.add_argument("--path", default=DEFAULT_PATH)
    commands = parser.add_subparsers(dest="command", required=True)
    show = commands.add_parser("show", help="Print every decision recorded for one incident.")
    show.add_argument("incident_id")
    commands.add_parser("verify", help="Check the hash chain; exits 1 if anything was altered.")
    args = parser.parse_args(argv)

    log = DecisionLog(args.path)
    if args.command == "show":
        decisions = log.for_incident(args.incident_id)
        if not decisions:
            print(f"no decisions recorded for {args.incident_id!r}", file=sys.stderr)
            return 1
        for decision in decisions:
            print(json.dumps(json.loads(decision.model_dump_json()), indent=2))
        return 0

    problems = log.verify()
    for problem in problems:
        print(problem)
    print("decision log intact" if not problems else f"{len(problems)} problem(s) found", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
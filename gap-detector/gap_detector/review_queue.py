"""Persistent human review of rule proposals. Approval never activates a rule."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import sys
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from pathlib import Path


def queue_path(output: Path, explicit: Path | None = None) -> Path:
    return explicit if explicit is not None else output.with_name(output.name + ".review.sqlite3")


class ReviewQueue:
    def __init__(self, path: Path):
        self.path = Path(path)

    @contextmanager
    def _connect(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Restrict newly created queues; no raw event messages are stored here.
        descriptor = os.open(self.path, os.O_CREAT | os.O_WRONLY, 0o600)
        os.close(descriptor)
        with closing(sqlite3.connect(self.path, timeout=10)) as connection:
            connection.row_factory = sqlite3.Row
            with connection:
                connection.execute("""CREATE TABLE IF NOT EXISTS proposals (
                    proposal_id TEXT PRIMARY KEY,
                    draft_id TEXT NOT NULL,
                    draft_json TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending_review'
                        CHECK (status IN ('pending_review', 'approved', 'rejected')),
                    created_at TEXT NOT NULL,
                    reviewed_at TEXT,
                    reviewer TEXT,
                    reason TEXT,
                    CHECK ((status = 'pending_review' AND reviewed_at IS NULL
                            AND reviewer IS NULL AND reason IS NULL)
                        OR (status != 'pending_review' AND reviewed_at IS NOT NULL
                            AND reviewer IS NOT NULL AND reason IS NOT NULL))
                )""")
            with connection:
                yield connection

    def enqueue(self, suggestions: dict) -> None:
        """Idempotent per exact proposal; changed content needs its own review."""
        if (suggestions.get("schema_version") != 1
                or not isinstance(suggestions.get("drafts"), list)):
            raise ValueError("unsupported suggestions")
        rows = []
        for draft in suggestions["drafts"]:
            if (not isinstance(draft, dict) or not isinstance(draft.get("draft_id"), str)
                    or not draft["draft_id"].strip() or draft.get("enabled") is not False
                    or draft.get("status") != "pending_review"):
                raise ValueError("only inactive pending proposals may enter review")
            payload = json.dumps(draft, sort_keys=True, separators=(",", ":"), allow_nan=False)
            proposal_id = hashlib.sha256(payload.encode()).hexdigest()
            rows.append((proposal_id, draft["draft_id"], payload,
                         datetime.now(timezone.utc).isoformat()))
        with self._connect() as connection:
            connection.executemany("""INSERT INTO proposals
                (proposal_id, draft_id, draft_json, created_at) VALUES (?, ?, ?, ?)
                ON CONFLICT(proposal_id) DO NOTHING""", rows)

    @staticmethod
    def _record(row) -> dict:
        result = dict(row)
        result["draft"] = json.loads(result.pop("draft_json"))
        return result

    def list(self, status: str | None = "pending_review") -> list[dict]:
        with self._connect() as connection:
            rows = connection.execute("""SELECT * FROM proposals
                WHERE (? IS NULL OR status = ?) ORDER BY created_at, proposal_id""", (status, status))
            return [self._record(row) for row in rows]

    def show(self, proposal_id: str) -> dict:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM proposals WHERE proposal_id = ?", (proposal_id,)).fetchone()
            if row is None:
                raise ValueError("unknown proposal")
            return self._record(row)

    def decide(self, proposal_id: str, decision: str, *, reviewer: str, reason: str) -> dict:
        if decision not in {"approved", "rejected"}:
            raise ValueError("unsupported review decision")
        if not isinstance(reviewer, str) or not reviewer.strip() or not isinstance(reason, str) or not reason.strip():
            raise ValueError("reviewer and reason are required")
        with self._connect() as connection:
            # The conditional update serializes competing decisions; no last-writer wins.
            cursor = connection.execute("""UPDATE proposals
                SET status = ?, reviewed_at = ?, reviewer = ?, reason = ?
                WHERE proposal_id = ? AND status = 'pending_review'""",
                (decision, datetime.now(timezone.utc).isoformat(), reviewer.strip(), reason.strip(), proposal_id))
            if cursor.rowcount != 1:
                raise ValueError("proposal is unknown or already reviewed")
            row = connection.execute("SELECT * FROM proposals WHERE proposal_id = ?", (proposal_id,)).fetchone()
            return self._record(row)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Review rule proposals without activating them.")
    parser.add_argument("--queue", required=True, type=Path)
    commands = parser.add_subparsers(dest="command", required=True)
    listing = commands.add_parser("list")
    listing.add_argument("--status", choices=("pending_review", "approved", "rejected", "all"),
                         default="pending_review")
    show = commands.add_parser("show")
    show.add_argument("proposal_id")
    for name in ("approve", "reject"):
        decision = commands.add_parser(name)
        decision.add_argument("proposal_id", help="Full content hash from list/show")
        decision.add_argument("--reviewer", required=True)
        decision.add_argument("--reason", required=True)
    args = parser.parse_args(argv)
    try:
        queue = ReviewQueue(args.queue)
        if args.command == "list":
            result = queue.list(None if args.status == "all" else args.status)
        elif args.command == "show":
            result = queue.show(args.proposal_id)
        else:
            result = queue.decide(args.proposal_id,
                                  "approved" if args.command == "approve" else "rejected",
                                  reviewer=args.reviewer, reason=args.reason)
    except (OSError, ValueError, sqlite3.Error) as exc:
        print(json.dumps({"status": "error", "error_type": type(exc).__name__,
                          "message": "Review queue operation failed; no rule activated."}), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
import hashlib
import json
import sqlite3
import time
from collections import deque
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, Field, ValidationError, field_validator

from .detection import Incident, UpstreamError

MAX_ENTRIES = 100_000
MAX_PAYLOAD_BYTES = 1_000_000
MAX_JOURNAL_BYTES = 64_000_000
GENESIS = "0" * 64
DETAIL_FIELDS = {
    "reason",
    "reasons",
    "verified",
    "level",
    "ai_off",
    "replacement_id",
    "replaces_id",
    "rollback_id",
    "rollback_of",
    "policy_rule",
    "maximum_per_hour",
}


class AuditEntry(BaseModel):
    sequence: int = Field(ge=1)
    event: str = Field(min_length=1, max_length=200)
    at: datetime
    action_id: str = Field(min_length=1, max_length=512)
    actor: str = Field(min_length=1, max_length=512)
    initiated_by: str | None = Field(default=None, max_length=512)
    incident_id: str | None = Field(default=None, max_length=512)
    type: str | None = Field(default=None, max_length=200)
    status: str | None = Field(default=None, max_length=200)
    attempt_id: str | None = Field(default=None, max_length=512)
    proposal_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    previous_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    entry_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    details: dict = Field(default_factory=dict)

    @field_validator("at")
    @classmethod
    def utc_time(cls, value):
        return Incident.utc_time(value)


class AuditPage(BaseModel):
    total: int
    limit: int
    offset: int
    through_sequence: int
    journal_total: int
    head: str
    integrity: str = "consistent"
    observed_at: datetime
    items: list[AuditEntry]


def _details(raw):
    selected = {}
    for key in DETAIL_FIELDS:
        value = raw.get(key)
        if isinstance(value, (str, bool, int, float)) or value is None:
            if key in raw:
                selected[key] = value[:4096] if isinstance(value, str) else value
        elif key == "reasons" and isinstance(value, list):
            selected[key] = [
                reason[:4096] for reason in value[:20] if isinstance(reason, str)
            ]
    return selected


def _invalid_number(_value):
    raise ValueError("Invalid number")


def _project(sequence, payload, previous_hash, entry_hash):
    raw = json.loads(payload, parse_constant=_invalid_number)
    if not isinstance(raw, dict):
        raise TypeError("Invalid event")
    # Full proposals, parameters, AI context and rollback snapshots stay on disk.
    fields = {
        key: raw[key]
        for key in AuditEntry.model_fields
        if key in raw
        and key not in {"sequence", "previous_hash", "entry_hash", "details"}
    }
    return AuditEntry.model_validate(
        {
            **fields,
            "sequence": sequence,
            "previous_hash": previous_hash,
            "entry_hash": entry_hash,
            "details": _details(raw),
        }
    )


class AuditReader:
    def __init__(self, path: Path | None):
        self.path = path

    def page(
        self,
        *,
        limit=20,
        offset=0,
        through_sequence=None,
        since=None,
        until=None,
        **filters,
    ):
        if self.path is None:
            raise UpstreamError(
                503, "Audit journal is not configured on this dashboard"
            )
        deadline = time.monotonic() + 3
        try:
            # mode=ro prevents creation and writes; query_only is a second boundary.
            uri = self.path.resolve().as_uri() + "?mode=ro"
            with closing(sqlite3.connect(uri, uri=True, timeout=1)) as db:
                db.execute("PRAGMA query_only = ON")
                db.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
                db.execute("BEGIN")
                count, size, largest = db.execute(
                    "SELECT COUNT(*), COALESCE(SUM(LENGTH(CAST(payload AS BLOB))), 0), "
                    "COALESCE(MAX(LENGTH(CAST(payload AS BLOB))), 0) FROM events"
                ).fetchone()
                if (
                    count > MAX_ENTRIES
                    or size > MAX_JOURNAL_BYTES
                    or largest > MAX_PAYLOAD_BYTES
                ):
                    raise UpstreamError(
                        503,
                        "Audit journal exceeds the dashboard read limit; use the controller CLI",
                    )
                previous = GENESIS
                matched = 0
                seen = 0
                # Retain sequence IDs only; payloads are projected again for the selected page.
                entries = deque(maxlen=offset + limit)
                boundary = (
                    count if through_sequence is None else min(through_sequence, count)
                )
                for sequence, payload, previous_hash, entry_hash in db.execute(
                    "SELECT sequence, payload, previous_hash, entry_hash FROM events ORDER BY sequence"
                ):
                    if time.monotonic() > deadline:
                        raise UpstreamError(
                            503, "Audit journal read timed out; try again"
                        )
                    expected = hashlib.sha256(
                        f"{sequence}\n{previous}\n{payload}".encode()
                    ).hexdigest()
                    seen += 1
                    if sequence != seen:
                        raise UpstreamError(
                            502,
                            "Audit integrity check failed; inspect the controller journal",
                        )
                    if previous_hash != previous or entry_hash != expected:
                        raise UpstreamError(
                            502,
                            "Audit integrity check failed; inspect the controller journal",
                        )
                    previous = entry_hash
                    entry = _project(sequence, payload, previous_hash, entry_hash)
                    if (
                        sequence > boundary
                        or (since and entry.at < since)
                        or (until and entry.at > until)
                    ):
                        continue
                    if any(
                        value
                        and (
                            value not in {entry.actor, entry.initiated_by}
                            if key == "actor"
                            else getattr(entry, key) != value
                        )
                        for key, value in filters.items()
                    ):
                        continue
                    matched += 1
                    entries.append(sequence)
                sequence_ids = list(reversed(entries))[offset : offset + limit]
                selected = [
                    _project(
                        *db.execute(
                            "SELECT sequence, payload, previous_hash, entry_hash FROM events WHERE sequence = ?",
                            (sequence,),
                        ).fetchone()
                    )
                    for sequence in sequence_ids
                ]
                return AuditPage(
                    total=matched,
                    limit=limit,
                    offset=offset,
                    through_sequence=boundary,
                    journal_total=count,
                    head=previous,
                    observed_at=datetime.now(timezone.utc),
                    items=selected,
                )
        except UpstreamError:
            raise
        except (sqlite3.Error, OSError) as exc:
            raise UpstreamError(
                503, "Audit journal is unavailable or its schema is unsupported"
            ) from exc
        except (
            ValidationError,
            ValueError,
            TypeError,
            UnicodeError,
            RecursionError,
        ) as exc:
            raise UpstreamError(502, "Audit journal contains invalid records") from exc
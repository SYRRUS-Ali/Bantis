# detection-engine

M3's Detection Engine — ingests structured events from `range/` and
`attack-sim/` (the shared envelope in
[`docs/event-schema.md`](../docs/event-schema.md)) and correlates them
into incidents, per the rules designed in
[`docs/correlation-design.md`](../docs/correlation-design.md).

This is a separate, independently-deployable component, same
relationship to `range/` and `attack-sim/` that those two already have
to each other.

## Structure

```
detection-engine/
├── app/
│   ├── main.py             # FastAPI app: /health, includes routers/
│   ├── db.py                # SQLAlchemy engine/session, Base, init_db()
│   ├── event_models.py       # EventORM table definition
│   ├── incident_models.py    # IncidentORM table definition
│   ├── correlation.py         # correlate() + run_correlation() — docs/correlation-design.md's two patterns
│   ├── models.py               # Pydantic schemas for the API (EventIn/EventOut)
│   └── routers/
│       └── events.py            # POST /events — the ingestion endpoint
├── tests/
│   ├── test_events_endpoint.py
│   ├── test_correlation.py
│   ├── test_init_db.py
│   └── requirements.txt
└── requirements.txt
```

## Status

Ingestion, plus correlation as a callable function. `app/correlation.py`
implements both patterns from
[`docs/correlation-design.md`](../docs/correlation-design.md) —
`correlate(events)` is the pure grouping logic (fed a list of `EventORM`,
returns `IncidentORM` instances, no database involved); `run_correlation(session)`
wires it to real stored data: loads every event not already claimed by a
past incident, correlates them, and persists any new incidents.

**Nothing calls `run_correlation()` automatically yet** — no scheduler,
no endpoint triggers it on ingestion. It's a function ready to be wired
in, same staged approach as every other piece of M3 so far (the
ingestion endpoint existed for a day before either producer was
connected to it). Run it manually for now:

```python
from app.db import SessionLocal
from app.correlation import run_correlation

with SessionLocal() as session:
    new_incidents = run_correlation(session)
```

**Both real producers are wired up.** `range/api` and `attack-sim` each
carry a `DetectionEngineHandler` logging handler (in their own
`logging_config.py` — duplicated, not shared, same reasoning as
attack-sim's existing standalone copy of the JSON formatter) that
forwards every event to `POST /events` here. It's opt-in per producer:
set `DETECTION_ENGINE_URL` and it activates; leave it unset and nothing
changes. See [`range/.env.example`](../range/.env.example) and
[`attack-sim/README.md`](../attack-sim/README.md#detection-engine-forwarding).

Only **envelope-shaped** log records are forwarded — anything without an
`event_id` (uvicorn's own startup lines, a scenario's
`logger.warning()` on a cleanup failure) is silently skipped, never
POSTed, matching `docs/event-schema.md`'s own distinction between a
security-relevant event and "a routine operational log line."

Forwarding is **synchronous and best-effort**: each `emit()` call blocks
on the HTTP POST (short timeout, 2s) and swallows any failure, writing it
to stderr instead of raising — logging must never crash or block the app
it's instrumenting. Known limitation, not an oversight: a slow or
unreachable detection-engine adds up to that 2s to every event-emitting
call in the producer (a scenario's `run()`, an API request) rather than
being decoupled via a background queue. Acceptable for v1 given
forwarding is opt-in and detection-engine is expected to be running
locally alongside its producers; revisit if this ever needs to tolerate
a genuinely unreliable or remote detection-engine.

**Ingestion validates the envelope, not just its shape.** `EventIn`
(`app/models.py`) rejects an empty `level`/`logger`/`source`/`event_type`/
`event_id` and an unrecognized `level` with a 422, rather than storing
malformed data that would only surface later as a confusing, silent
problem — e.g. every empty-`source` event quietly forming its own
same-source-burst incident. `level` accepts any of Python's actual
logging levels (`DEBUG`/`INFO`/`WARNING`/`ERROR`/`CRITICAL`), not just
the `INFO`/`WARNING`/`ERROR` examples in `docs/event-schema.md`.

## Database

No `docker-compose`/`.env` setup exists for this service yet (unlike
`range/`), so `DATABASE_URL` defaults to a local SQLite file
(`detection_engine.db`, gitignored) rather than failing loudly the way
`range/api` does — this keeps the service runnable today without
inventing that infrastructure just to start it. Set `DATABASE_URL`
explicitly to point at a real Postgres instance instead:

```bash
export DATABASE_URL=postgresql://user:pass@host:5432/dbname
```

## Running it

```bash
cd detection-engine
pip install -r requirements.txt
uvicorn app.main:app --reload
curl http://localhost:8000/health
```

## Known issues

**A real app startup never created the `incidents` table.** Found while
wiring up `app/correlation.py` on 2026-09-25 — `run_correlation()`
immediately hit `sqlite3.OperationalError: no such table: incidents`
against a freshly-started real app. Root cause: SQLAlchemy only registers
a table with `Base.metadata` once its ORM model's module is actually
imported, and nothing in the app's real startup path (`main.py` →
`routers/events.py`) ever imported `incident_models` — only
`event_models`, via the events router. `init_db()`'s
`Base.metadata.create_all()` genuinely only ever knew about one table.
**Fix:** `init_db()` now imports every model module itself before calling
`create_all()`, so the metadata is guaranteed complete regardless of
which routers happen to be wired up. Verified with a regression test
that runs in a real subprocess (`tests/test_init_db.py`) — an in-process
test would have silently passed either way, since every other test file
in this suite eventually imports `incident_models` too and registers it
for the rest of that pytest process.

**An `ERROR`-status scenario run was being correlated as if it were a
real attack outcome.** Found on 2026-09-26 while actually running the
real `malicious-dependency` and `leaked-secret` scenarios end-to-end
against a live detection-engine (`../tests/test_e2e_composite_incident.py`)
instead of only synthetic events — nothing constructs a synthetic
`"error"` event by habit, so a unit test alone never surfaced this. A
`leaked-secret` run that failed to even initialize its scratch git repo
(`status: "error"`, per `docs/scenarios.md`'s distinction between "the
scenario itself couldn't run" and a real success/failure verdict) was
still getting composited with a real `malicious-dependency` failure,
reporting a "high severity" incident that was only half real. **Fix:**
`correlate()` now filters out every `status: "error"` event before
either pattern in `docs/correlation-design.md` ever sees it. Verified
with both synthetic regression tests (`tests/test_correlation.py`) and
the real end-to-end scenario run.

## Running the tests

```bash
cd detection-engine
pip install -r requirements.txt -r tests/requirements.txt
python -m pytest tests -v
```

Tests never touch the default SQLite file or a real database — each
test gets an isolated `sqlite:///:memory:` database via `DATABASE_URL`
overridden per test, with all tables dropped and recreated before every
test to guarantee isolation even though the underlying engine object is
cached and shared across the whole test run (a Python module-import
quirk, not a design choice — see the comment at the top of
`tests/test_events_endpoint.py`).
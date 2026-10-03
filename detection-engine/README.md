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
│   ├── correlation.py         # correlate() + run_correlation() — docs/correlation-design.md's three patterns
│   ├── scorecard.py            # generate_scorecard() — detection rate, false positives, MTTD
│   ├── models.py               # Pydantic schemas for the API (EventIn/EventOut, IncidentOut/IncidentListOut)
│   └── routers/
│       ├── events.py            # POST /events — the ingestion endpoint
│       └── incidents.py          # GET /incidents, GET /incidents/{id} — query API
├── tests/
│   ├── test_events_endpoint.py
│   ├── test_incidents_endpoint.py
│   ├── test_correlation.py
│   ├── test_scorecard.py
│   ├── test_events_concurrency.py
│   ├── test_init_db.py
│   ├── evaluate_correlation_rules.py  # standalone script, not pytest — see docs/detection-rate-baseline.md
│   └── requirements.txt
└── requirements.txt
```

## Status

Ingestion, plus correlation as a callable function. `app/correlation.py`
implements all three patterns from
[`docs/correlation-design.md`](../docs/correlation-design.md) —
`correlate(events)` is the pure grouping logic (fed a list of `EventORM`,
returns `IncidentORM` instances, no database involved); `run_correlation(session)`
wires it to real stored data: loads every event not already claimed by a
past incident, correlates them, and persists any new incidents.

Pattern 3 (untrusted registry pull) is single-event, not a time-windowed
grouping like the other two: a `container_image_pull` event is flagged
immediately if its `registry` isn't in the `TRUSTED_REGISTRIES`
whitelist (currently `docker.io` and `ghcr.io`). It runs before Pattern 1
in `correlate()` so its event is claimed and never also swept into a
generic same-source burst. No producer emits `container_image_pull` yet
— the rule is defined and tested ahead of that, same staged approach the
rest of M3 has followed throughout.

**Confidence scoring goes through one shared formula.** `_confidence()`
computes every pattern's `confidence` as `base + per_success_bonus ×
min(successes, max_counted_successes)`, with per-pattern constants
instead of three separate hand-rolled calculations — see
[`docs/correlation-design.md`](../docs/correlation-design.md#confidence-score-formula-v1)
for the constants table and the reasoning behind each one, including why
Pattern 1's success bonus is capped at 1 event even though its burst can
contain more than that.

**`app/scorecard.py` turns a run's events and incidents into the three
numbers `docs/threat-model.md` names as what "success" looks like:**
detection rate, false positives, and MTTD (mean time to detect).
`generate_scorecard(events, incidents, expected_patterns)` needs a known
set of expected incident patterns to score detection rate and false
positives against — those two numbers aren't well-defined without first
knowing what should have happened, the same ground truth
`tests/evaluate_correlation_rules.py` and `tests/run_m2_baseline.py`
already rely on. MTTD needs no such ground truth: it's the gap between
each incident's earliest correlated event and the moment
`run_correlation()` actually formed it, averaged across the run.
`tests/run_m2_baseline.py` prints a scorecard after every real run — see
[`docs/m2-detection-baseline.md`](../docs/m2-detection-baseline.md) for
recorded numbers.

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

**A read-only incidents API exists, as the foundation for the planned
dashboard.** `GET /incidents` lists incidents newest-first with optional
exact-match filters (`severity`, `pattern`), a `since` cutoff (ISO 8601;
only incidents created at or after it), and pagination (`limit`,
default 50, max 200; `offset`), returning `{total, limit, offset,
items}` so a UI can build page controls without a second request.
`GET /incidents/{incident_id}` returns one incident's full record, or
404. `severity` is validated against the closed four-value enum from
`docs/correlation-design.md` (422 on anything else); `pattern` is
deliberately **not** validated against today's three values — the design
doc already treats extending that enum as how a v2 rule gets added, so
hard-validating it here would mean every new correlation rule also needs
an API change just to be filterable. No write endpoints: incidents are
only ever created by `run_correlation()`, never directly by a client.

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

**Adding Pattern 3 conflicted with the documented `correlated_event_ids`
invariant.** Found on 2026-09-27 while writing the untrusted-registry-pull
rule: `docs/correlation-design.md` documented `correlated_event_ids` as
"always ≥ 2" for every incident, which is only true for Patterns 1 and 2
— Pattern 3 is single-event by design, since one pull from outside the
whitelist is already the complete signal, not partial evidence awaiting
a second event. **Fix:** the doc's field table now calls out Pattern 3 as
the one exception, and `correlate()` runs Pattern 3 before Pattern 1 so
an untrusted pull's event is claimed and never *also* reported as a
vague same-source burst — verified by deliberately reordering them and
confirming `tests/test_correlation.py`'s ordering test fails, then
restoring the correct order.

**The persistence test only ever compared an object to itself.** Found
on 2026-09-28 while confirming every incident field is genuinely stored:
`test_run_correlation_persists_new_incidents` queried
`IncidentORM` on the *same* session `run_correlation()` had just used —
SQLAlchemy's identity map returns the same Python object for a given
primary key within one session, so the assertion was comparing an
object to itself, not to a row actually read back from the database.
Proven by deliberately removing `session.commit()` from
`run_correlation()`: the old test still passed (a query on the same
session sees its own uncommitted pending writes), while nothing had
actually reached SQLite. **Fix:** added
`test_run_correlation_stores_every_incident_field_completely`, which
opens a *separate* `Session` on the same engine and compares every
column against the incident `correlate()` built — this one genuinely
fails without the commit.

**The confidence formula was three independent, hand-rolled
calculations that happened to look similar.** Unified into one
`_confidence()` function (`base + per_success_bonus × min(successes,
max_counted_successes)`) shared by all three patterns — see
[`docs/correlation-design.md`](../docs/correlation-design.md#confidence-score-formula-v1).
Calibration check while unifying: a naive generalization of Pattern 2's
"bonus per successful event" to Pattern 1 (whose burst can have more
than 2 events) would silently let confidence exceed the documented
`0.5` cap for that pattern once more than one event in a larger burst
succeeded. `max_counted_successes` exists specifically to prevent that;
`test_same_source_confidence_stays_capped_with_more_than_one_success_in_a_larger_burst`
proves it holds, and fails without the cap.

**Ordinary API/nginx traffic was a 25% false-positive rate.** Found on
2026-09-30 by a labeled true-positive/true-negative evaluation
(`tests/evaluate_correlation_rules.py`) built specifically to put a
number on detection rate and false positives, rather than trusting that
the existing hand-picked unit tests were representative. Three plain,
successful `/health` requests to `api`, seconds apart, formed a
`"medium"` severity `same-source-burst` incident — Pattern 1 is
type-agnostic by design, but nothing had ever scoped which event types
it should even consider, so ordinary per-request telemetry got treated
like a discrete attacker action. **Fix:** `_SAME_SOURCE_EXCLUDED_EVENT_TYPES
= {"http_request"}` excludes it from Pattern 1 entirely — see
[`docs/detection-rate-baseline.md`](../docs/detection-rate-baseline.md)
for the full before/after numbers (25.0% → 0.0% false positive rate,
100.0% detection rate unchanged).

**Two race conditions in event handling, found on 2026-10-03 by firing
genuinely concurrent requests at a live server** (`tests/test_events_concurrency.py`,
`tests/test_correlation.py`'s "Event ordering" section) rather than
reasoning about concurrency in the abstract:

1. **`POST /events` could 500 on a duplicate `event_id` under real
   concurrency.** `ingest_event()` checks whether an event already
   exists, then inserts if not — classic TOCTOU: two concurrent requests
   for the same `event_id` (a producer retrying a POST after a timeout,
   per `DetectionEngineHandler`'s best-effort, 2s-timeout forwarding)
   could both pass the check before either commits, and the second
   commit then hit `UNIQUE constraint failed` as an unhandled 500
   instead of the intended idempotent 200. Reproduced with 20 genuinely
   concurrent requests against a live server: 5/20 got a 500. **Fix:**
   catch the `IntegrityError` on commit, roll back, and return the
   now-committed row from the request that won the race — the same
   outcome the existence check above would have given it.
2. **`StaticPool` was forcing every sqlite connection — file-based or
   not — onto one shared raw connection, process-wide.** `StaticPool` is
   only actually *needed* for `sqlite:///:memory:` (a new connection to
   `:memory:` is a separate, empty database, so every session has to
   share one). Applying it to file-based sqlite too meant concurrent
   requests shared one raw connection across threads regardless, which
   can corrupt that connection's cursor state outright rather than
   raising a clean, catchable error — confirmed by the fact that fix #1
   alone still left the reproduction flaky (~40% failure rate) until
   this was scoped to `:memory:` specifically. Production (Postgres) was
   never affected — this only ever applied to the sqlite fallback.
3. **Correlation's event ordering wasn't deterministic under timestamp
   ties.** `correlate()` and `run_correlation()` sorted strictly by
   `timestamp`; two events sharing an identical one (coarse producer
   clocks, or two events racing into the table per #1 above) had their
   relative order left to whatever a database's `ORDER BY` happens to do
   with ties — unspecified by SQL, not guaranteed to match across
   backends. Which specific event a pairing or burst claimed was
   effectively a coin flip. **Fix:** `event_id` as a secondary sort key
   everywhere events are ordered for correlation, making the outcome a
   reproducible rule instead.

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

`tests/evaluate_correlation_rules.py` is not a pytest file (no `test_`
prefix, so `pytest tests -v` above skips it) — a standalone script that
runs a labeled true-positive/true-negative case battery and prints the
detection-rate and false-positive numbers directly, without needing a
database or live server. See
[`docs/detection-rate-baseline.md`](../docs/detection-rate-baseline.md)
for the recorded baseline and how to reproduce it.
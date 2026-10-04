# Detection Engine Architecture

M3's Detection Engine is a separate, independently-deployable component
— the same relationship `range/` and `attack-sim/` already have to each
other. It ingests the structured event envelope both of them emit
([`docs/event-schema.md`](event-schema.md)), correlates it into
incidents using the rule-based patterns below, and surfaces the result
through a read-only query API: the foundation M4 (AI-assisted analysis)
and the eventual dashboard build on, not a dashboard itself.

## Components

| File | Role |
|---|---|
| `app/main.py` | FastAPI app factory; `/health`; wires up both routers; runs `init_db()` on startup via the app's `lifespan`. |
| `app/db.py` | SQLAlchemy `engine`/`SessionLocal`/`Base`, `init_db()`, `get_session()` (the FastAPI dependency every route uses). |
| `app/event_models.py` | `EventORM` — the `events` table. |
| `app/incident_models.py` | `IncidentORM` — the `incidents` table. |
| `app/models.py` | Pydantic schemas for the API: `EventIn`/`EventOut`, `IncidentOut`/`IncidentListOut`. |
| `app/correlation.py` | `correlate()` (pure function) and `run_correlation()` (wires it to the database) — the three rules below. |
| `app/scorecard.py` | `generate_scorecard()` — detection rate, false positives, and MTTD for one run, given a known-good expectation. |
| `app/routers/events.py` | `POST /events` — ingestion. |
| `app/routers/incidents.py` | `GET /incidents`, `GET /incidents/{incident_id}` — the query API. |

## Runtime data flow

```
range/api, nginx, attack-sim
        │  (DetectionEngineHandler, opt-in via DETECTION_ENGINE_URL)
        ▼
  POST /events  ──validates envelope (app/models.py)──▶  events table
                                                               │
                                                        run_correlation()
                                                      (manual/script-triggered
                                                       today — see below)
                                                               │
                                                        incidents table
                                                               │
                      GET /incidents, GET /incidents/{id}  ◀───┘
                               │
                         (dashboard — M4+, not built yet)
```

**Nothing calls `run_correlation()` automatically today** — no scheduler,
no trigger on ingestion. It's invoked manually, by
[`tests/run_m2_baseline.py`](../tests/run_m2_baseline.py), or by a future
scheduler/webhook; the ingestion and correlation stages are intentionally
decoupled so a slow correlation pass never blocks an event POST.

Ingestion and correlation run as two logically separate stages even
though they share one database: an event can be ingested and sit
unclaimed for an arbitrary amount of time before anything correlates it,
and `run_correlation()` is safe to call repeatedly — it only ever looks
at events not already claimed by a past incident
(`already_correlated` in `run_correlation()`), so re-running it is a
no-op once nothing new has arrived.

## Database

SQLite (a local file, gitignored) is the default when `DATABASE_URL`
isn't set — this keeps the service runnable without inventing
docker-compose/`.env` infrastructure for it yet (unlike `range/`). Set
`DATABASE_URL` to a real Postgres instance for anything beyond local
dev. `StaticPool` is scoped specifically to `sqlite:///:memory:` (the one
case that actually needs a single shared connection); file-based sqlite
and Postgres both get a normal connection pool — see
[`detection-engine/README.md`](../detection-engine/README.md#known-issues)
for the concurrency bug this scoping fixed.

## Correlation rules

Three rules, applied in this order inside `correlate()` — most specific
first, so a more specific pattern's events are claimed before the
generic burst rule gets a chance to also report them:

| Claim order | Pattern (design doc name) | Trigger | Window | Severity | Confidence |
|---|---|---|---|---|---|
| 1st | `composite-dependency-secret` (Pattern 2) | A `malicious-dependency` + a `leaked-secret` `attack_scenario_run` event (by `details.scenario`) | 300s, either order | `high`, `critical` if both succeeded | `0.6`–`0.9` |
| 2nd | `untrusted-registry-pull` (Pattern 3) | A single `container_image_pull` event whose `registry` isn't in `TRUSTED_REGISTRIES` (`docker.io`, `ghcr.io`) | none — single-event | `high`, fixed | `0.7`, fixed |
| 3rd | `same-source-burst` (Pattern 1) | 2+ events from the same `source`, excluding `http_request` (ordinary traffic — see below) | 60s | `medium`, `high` if any succeeded | `0.3`–`0.5` |

Every rule that has a success/failure signal to weigh computes
confidence through one shared formula (`_confidence()` in
`app/correlation.py`): `base + per_success_bonus × min(successes,
max_counted_successes)`. `ERROR`-status `attack_scenario_run` events
(the scenario itself didn't run meaningfully — a missing tool, a bad
environment) are filtered out before any rule sees them, since they're
not a real attack outcome. `http_request` is excluded from rule 3
specifically — it's continuous per-request telemetry, not a discrete
attacker action, and traffic-volume detection is out of scope for v1
([`docs/threat-model.md`](threat-model.md)). Events are sorted by
`(timestamp, event_id)` everywhere correlation reads them, so which
specific event a pairing or burst claims is a reproducible rule even
when two events share an identical timestamp, not an artifact of
database ordering.

Full rationale for each rule, the complete severity/confidence scoring
tables, and explicit non-goals: [`docs/correlation-design.md`](correlation-design.md).

## API surface

- `GET /health` — liveness.
- `POST /events` — ingestion; idempotent on `event_id` (a duplicate
  returns the existing record, 200, rather than erroring).
- `GET /incidents` — list, newest first; filters (`severity` exact-match
  and validated, `pattern` exact-match and intentionally *not*
  validated against a closed set, `since`), pagination (`limit`,
  `offset`), returns `{total, limit, offset, items}`.
- `GET /incidents/{incident_id}` — single incident, 404 if missing.

No write endpoint for incidents — they're only ever created by
`run_correlation()`. No authentication on any route yet: the current
trust model assumes a single operator running this locally alongside
its producers, same as `range/`'s own setup-wizard-gated admin account
is still ahead of it; this is a known gap, not an oversight, to revisit
before anything here is reachable beyond localhost.

## Observability and evaluation tooling

Built specifically because "the correlation rules work" needs to be a
measured claim, not an assumption:

- [`app/scorecard.py`](../detection-engine/app/scorecard.py) — detection
  rate, false positives, and MTTD for one run, scored against a known
  expectation.
- [`tests/evaluate_correlation_rules.py`](../detection-engine/tests/evaluate_correlation_rules.py) —
  a labeled True-Positive/True-Negative case battery; recorded result in
  [`docs/detection-rate-baseline.md`](detection-rate-baseline.md).
- [`tests/run_m2_baseline.py`](../tests/run_m2_baseline.py) — runs all
  four real M2 scenarios against a live detection-engine and prints a
  scorecard; recorded result in [`docs/m2-detection-baseline.md`](m2-detection-baseline.md).

## Known limitations

- `run_correlation()` isn't scheduled or triggered automatically (see
  "Runtime data flow" above).
- No authentication on the API (see "API surface" above).
- `container_image_pull` (Pattern 2) has no real producer yet — the rule
  is defined and tested ahead of that, same staged approach
  `attack_scenario_run` itself followed.
- Full, dated account of every bug found and fixed while building this
  (the incidents-table-never-created bug, the ERROR-status correlation
  bug, the `http_request` false positive, the two race conditions, the
  persistence-test that only ever compared an object to itself) is in
  [`detection-engine/README.md`](../detection-engine/README.md#known-issues)
  — worth reading before assuming any of these edges are untested.
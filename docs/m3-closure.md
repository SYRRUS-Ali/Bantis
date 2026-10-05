# M3 Closure: Detection Engine (Sprint 3)

Sprint 3 of the DevSecOps roadmap is M3 in this repo: the Detection
Engine. This document closes it — what was delivered, how it was
verified, and what it does not do yet. It is written to be read cold:
a reader should be able to decide from this page alone whether M3 is
safe to build on, and what must be fixed before anything depends on it.

## What was delivered

Mapped to the roadmap's Sprint 3 task list (rows 76–89):

| Roadmap task | Delivered | Where |
|---|---|---|
| Define a reasonable time window; design the same-source, composite, and incident shape | `correlation-design.md` (three patterns, windows, incident schema, scoring) | [`correlation-design.md`](correlation-design.md) |
| Build `detection-engine/` with `events` and `incidents` tables and an initial ingestion endpoint | `POST /events`, `EventORM`, `IncidentORM`, `init_db()` | `detection-engine/app/` |
| Connect ingestion to real range and attack-sim events; unify the two sources' shape | `DetectionEngineHandler` in `range/api` and `attack-sim`, opt-in via `DETECTION_ENGINE_URL`; shared envelope in `event-schema.md` | `range/api/app/logging_config.py`, `attack-sim/logging_config.py` |
| Time-window grouping over real data; incident creation; single-event edge | `correlate()`, `run_correlation()` | `detection-engine/app/correlation.py` |
| Composite dependency+secret rule, wired and verified against real M2 scenarios | Pattern 2, plus `test_e2e_composite_incident.py` | `correlation.py`, `tests/` |
| Untrusted-registry-pull rule with a trusted-registry whitelist | Pattern 3, `TRUSTED_REGISTRIES = {docker.io, ghcr.io}` | `correlation.py` |
| Every incident stored in full; simple confidence formula applied to the rules; calibrated; documented | `_confidence()` shared formula; persistence test that reads back from a separate session | `correlation.py`, `correlation-design.md` |
| Script that runs all four M2 scenarios in sequence and checks each event arrives and each expected incident forms | `tests/run_m2_baseline.py`; recorded in `m2-detection-baseline.md` | `tests/run_m2_baseline.py` |
| Measure detection rate and false positives; adjust thresholds; record the baseline | Labeled evaluation; `http_request` excluded from same-source bursts (25% → 0% false positives) | `evaluate_correlation_rules.py`, `detection-rate-baseline.md` |
| Scorecard after every run (detection rate, false positives, MTTD) | `app/scorecard.py`, printed by `run_m2_baseline.py` | `detection-engine/app/scorecard.py` |
| Fix race conditions in event ordering | Duplicate-ID ingestion TOCTOU fixed; `StaticPool` scoped to `:memory:`; `event_id` tiebreaker in correlation ordering | `routers/events.py`, `db.py`, `correlation.py` |
| Read-only REST API to query incidents | `GET /incidents` (filters, pagination), `GET /incidents/{id}` | `detection-engine/app/routers/incidents.py` |
| Document the Detection Engine architecture and correlation rules | `detection-engine-architecture.md`; M3 section in the root README | `docs/detection-engine-architecture.md` |

Bugs found and fixed while building it (root cause and fix for each are
in [`detection-engine/README.md`](../detection-engine/README.md#known-issues)):

- The incidents table was never created on a real app startup.
- An `ERROR`-status scenario run was correlated as if it were a real attack outcome.
- Ordinary `http_request` traffic formed "security incidents" (25% false-positive rate).
- A duplicate event ID under concurrent POSTs returned HTTP 500 (5 of 20 requests in the reproduction).
- `StaticPool` forced every SQLite connection onto one shared raw connection.
- Correlation order was undefined when two events shared a timestamp.
- A persistence test compared an ORM object to itself, so it could not catch a missing commit.
- The confidence formula would have let a larger burst exceed its documented cap.

## Verification at closure

Full suites, all passing at closure:

| Component | Tests |
|---|---|
| `detection-engine/tests` | 66 |
| `attack-sim/tests` (with `BANTIS_ENV=range-local`) | 111 |
| root `tests/` (cross-component E2E) | 3 |

Plus two standalone scripts, not pytest:

- `tests/run_m2_baseline.py`: runs all four real M2 scenarios against a
  live detection-engine. Result: 4/4 events arrive, 2/2 expected
  incidents form, 100% detection, 0% false positives.
- `detection-engine/tests/evaluate_correlation_rules.py`: 5/5 true
  positives, 0/8 false positives on a labeled synthetic battery.

Several fixes were confirmed by reverting them and checking that a test
fails, then restoring the fix. The concurrency fixes were confirmed the
same way with a live server and 20 concurrent requests.

## Known limitations

These are the gaps a reader must know before relying on M3.

### Security

- **No authentication on any route.** `POST /events` and both
  `GET /incidents` routes are open to anyone who can reach port 8000.
  An unauthenticated client can inject events, which can then form
  incidents. This is the most important gap in M3. It is acceptable
  only while the service stays on localhost, which is the only
  deployment that exists today. It must be fixed before any network
  exposure, and the threat model's operator-authentication assumption
  does not yet hold for this service.
- **Incidents are not tamper-evident.** Rows can be edited directly in
  the database. There is no audit trail or integrity check.

### Detection quality and evidence

- **The 100% detection rate is measured on a small, self-selected
  set.** The labeled battery has 5 true positives and 8 true negatives,
  all synthetic. The M2 run uses the four scenarios the rules were
  designed around. The numbers show the rules fire on the cases they
  were written for. They do not show performance on unseen attacks, and
  they must not be read as a general detection rate.
- **Only three rules exist, and two attack classes have no dedicated
  rule.** `compromised-ci-step` and `typosquatting` are detected only as
  part of a generic same-source burst, which fires on any two
  attack-sim events close together. This includes a legitimate operator
  re-running a scenario, which the design doc accepts as noise.
- **Confidence and severity values are hand-set constants.** They are
  documented as a naive v1 baseline. They have not been calibrated
  against real labeled incidents, because none exist yet.
- **Pattern 3 (untrusted registry) has no real producer.** No code emits
  `container_image_pull`. The rule is tested only on synthetic events,
  so it has never seen real traffic.
- **The 1:1 pairing rule for the composite pattern is a scope limit.**
  One dependency event can pair with only one secret event, so a second
  real attack in the same window is not reported as its own incident.

### Measurement

- **MTTD is not an operational detection latency.** `run_m2_baseline.py`
  calls `run_correlation()` once, after all four scenarios finish. Its
  MTTD therefore measures roughly the scenario runtime, not how long a
  real attack would take to surface. A real MTTD needs a scheduler or
  an ingestion-triggered correlation pass, which does not exist yet.
- **Nothing measures a real producer end to end.** `range/api` forwards
  events through `DetectionEngineHandler`, but no test under `range/`
  covers this, and the real docker-compose range was never run against
  the detection engine in this sprint. The end-to-end tests exercise
  attack-sim only.

### Operations

- **Correlation is not automatic.** `run_correlation()` runs only when a
  script or test calls it. Incidents do not appear on their own.
- **Concurrent correlation passes are not proven safe.** Two passes
  running at once could both claim the same unclaimed events. I observed
  this under a test harness, but the harness was confounded by SQLite's
  shared in-memory connection, so the result is inconclusive. It is not
  fixed and not ruled out.
- **Postgres is never exercised in tests.** The production database
  target from the README is only ever tested as SQLite. Postgres-specific
  behavior (locking, `ORDER BY` semantics under ties) is unverified.
- **Concurrency is tested at 20 requests.** This shows the duplicate-ID
  race is fixed for that load. It is not a load test.
- **No dashboard.** The query API is the foundation. Nothing renders it.

### Process

- **The roadmap tracker is out of date.** All Sprint 3 rows in
  `private-local-folder/DevSecOps.xlsx` still read "لم يبدأ" (not
  started), although every row above is delivered. The workbook is
  private and gitignored, so I did not edit it. Its status column needs
  updating by hand.
- **No Sprint 3 git tag exists.** Sprint 1 and Sprint 2 were tagged
  (`v0.1.0-range`, `v0.2.0-attacksim`). A tag for this sprint has not
  been created.

## Carried into the next sprint

Sprint 4 is the AI Copilot, which will read these incidents. Before it
starts, the following should be addressed or consciously accepted:

1. Authentication on the ingestion POST and the incidents API.
2. A scheduled or ingestion-triggered correlation pass, so MTTD can be
   measured as a real latency.
3. A test covering `range/api` forwarding, and one real run of the
   docker-compose range against the detection engine.
4. A Postgres run of the test suite.
5. Calibration of confidence values against real incidents, once there
   are enough of them to be meaningful.
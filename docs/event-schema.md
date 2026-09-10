# Event Schema (v1)

This defines the canonical JSON event shape that Bantis's Detection Engine
(M3) will ingest and correlate. Every structured log line intended to be
treated as a *security-relevant event* (as opposed to a routine operational
log line) follows this envelope.

## Envelope

| Field        | Type    | Description                                                        |
|--------------|---------|----------------------------------------------------------------------|
| `timestamp`  | string  | ISO 8601, UTC.                                                       |
| `level`      | string  | Log level (`INFO`, `WARNING`, `ERROR`).                              |
| `logger`     | string  | Fine-grained origin (e.g. `app.access`, `nginx.access`).             |
| `source`     | string  | Coarse origin category: `api`, `nginx`, `ci`, `attack-sim`.          |
| `event_type` | string  | What kind of event this is (see below).                              |
| `event_id`   | string  | UUID4, unique per event. Used for dedup and correlation.              |
| `message`    | string  | Short human-readable summary.                                        |
| `details`    | object  | `event_type`-specific fields. Shape varies by type (see below).      |

## Event types (v1)

Two event types are emitted today. More are added as later milestones
(Attack Simulation, Detection Engine) need them — this list is expected to
grow, not to be redesigned.

### `http_request`
Emitted once per HTTP request, by both `api` and `nginx`.

`details`:
| Field               | Type   | Notes                                                     |
|---------------------|--------|------------------------------------------------------------|
| `method`            | string | HTTP method.                                                |
| `path`              | string | Request path.                                               |
| `status_code`       | int    | HTTP response status.                                       |
| `client_ip`         | string | Client address as seen by this source.                      |
| `user_agent`        | string | Only present on `nginx`-sourced events.                     |
| `duration_ms`       | float  | Only present on `api`-sourced events.                        |
| `duration_seconds`  | float  | Only present on `nginx`-sourced events (nginx's native unit).|

### `attack_scenario_run`
Emitted once per scenario execution by `attack-sim`
(`scenarios/base.py`'s `Scenario.log_result()`), regardless of which
scenario ran or whether it succeeded.

`details`:
| Field             | Type   | Notes                                                          |
|-------------------|--------|------------------------------------------------------------------|
| `scenario`        | string | The scenario's `name` (e.g. `noop`).                             |
| `mitre_technique` | string | The scenario's primary MITRE technique ID, or `"N/A"` for non-attack scenarios like `noop`. |
| `status`          | string | `success`, `failure`, or `error` — see `ScenarioStatus`.          |

Individual scenarios may add further fields to `details` beyond these
three (via `ScenarioResult.details`) — this table lists only what every
scenario is guaranteed to include.

## Known limitation
`api` and `nginx` report request duration in different units
(`duration_ms` vs `duration_seconds`) because nginx's `$request_time`
variable is natively seconds, and converting it inside `nginx.conf` would
require an extra module (njs) not worth adding at this stage. The
Detection Engine's ingestion pipeline (M3) is responsible for normalizing
this when correlating events across sources.

Additionally, `event_id` is not uniform in format across sources: `api`
generates a standard UUID4 (`f1ea5acc-7873-4d21-944f-db2d6d5ed140`), while
`nginx` uses its native `$request_id` variable — a 32-character random hex
string without dashes (`6d7e02db12d03fa18ba5996927fd714a`), not a
standards-compliant UUID string. Both are unique and suitable for
deduplication today, but any future validation logic in the Detection
Engine must not assume strict UUID formatting on this field.
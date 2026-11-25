# Gap Detector

A read-only comparison service for the [Purple Team loop](../docs/purple-team-loop.md).
It reads the producer-side attack-sim log and every page of the Detection
Engine incidents API, then writes a JSON report identifying valid M2 runs
without a referencing incident. It requires Python 3.10+ and the standard
library only. It does not run attacks, create incidents, or execute responses.

## Capture the attack history

Keep the structured stdout from your existing lab exercise. From the repository
root, this is an example capture command for an explicitly selected scenario:

```bash
mkdir -p /tmp/bantis-purple
chmod 700 /tmp/bantis-purple
(cd attack-sim && BANTIS_ENV=range-local DETECTION_ENGINE_URL=http://127.0.0.1:8000 python cli.py run compromised-ci-step) >> /tmp/bantis-purple/attack.log
```

Only run this in the disposable lab described in the [scenario
reference](../docs/scenarios.md). Capture stdout for every run under review;
keep stderr separately for forwarding and cleanup diagnostics. Structured JSON
lines and the CLI's ordinary result lines can coexist. The detector ignores
unrelated log records and `noop`, excludes `error` outcomes from coverage
decisions, and deduplicates identical event IDs. A conflicting duplicate,
malformed scenario record, empty history, or incomplete final line makes the
check inconclusive. In polling mode an unfinished line is retried on the next
pass. It never silently substitutes the Detection Engine's limited recent-event
feed for the producer history, so a lost forwarded event can still be flagged.

## Run once or as a service

With the Detection Engine running, from the repository root:

```bash
cd gap-detector
python -m gap_detector --history /tmp/bantis-purple/attack.log --output /tmp/bantis-purple/gaps.json
```

Add `--interval 10` to keep checking in the foreground, suitable for a local
process supervisor. Ctrl+C stops it. `--detection-url` defaults to
`http://127.0.0.1:8000`; `--timeout` sets the positive HTTP timeout in seconds
(default 5). No additional listener or database is needed. Keep the history
and output paths distinct and use a single writer per report file.

The default deadline for each run is its producer timestamp plus 330 seconds:
5 seconds ingestion allowance + 300 seconds settling + two default 10-second
scheduler intervals + 5 seconds processing allowance. This assumes an isolated,
finite exercise, synchronized clocks, and no continuing same-source traffic
extending a burst. Set `--wait-seconds` before execution to match your actual
scheduler, ingestion, and hold configuration; ongoing traffic can require the
600-second maximum burst hold plus ingestion and scheduling allowances.
The detector does not inspect or enable the scheduler. Disabled or failing
correlation can cause a gap that needs operator triage.

For a grouped exercise or batch pass, prefer one fixed deadline declared by
the exercise plan. Replace the timestamp with your exercise's UTC cutoff:

```bash
python -m gap_detector --history /tmp/bantis-purple/attack.log --output /tmp/bantis-purple/gaps.json --deadline 2026-11-25T12:10:00Z
```

`--deadline` and `--wait-seconds` are mutually exclusive. For a batch exercise,
explicitly complete correlation and use its completion time as the deadline.
The service never triggers correlation itself. It rejects future producer
events and deadlines preceding a run. Do not change the timing configuration
after seeing a miss: retain the original report and use fresh event IDs for
retests. The timing settings are included in every report.

## Report contract

Each `runs` entry includes `event_id`, scenario, attacker status, producer
timestamp, deadline, state, matching incident IDs, and first detection time.
Raw messages, artifacts, credentials, and tool output are excluded.

| State | Meaning |
| --- | --- |
| `pending` | Valid run, no referencing incident, observation deadline not reached. |
| `detected` | A persisted incident references the exact event ID and was created at or before the deadline. |
| `gap` | Valid `success` or defended `failure`, deadline reached, no referencing incident found. |
| `late_detection` | A referencing incident exists, but its earliest creation time missed the deadline. The gap remains visible. |
| `invalid` | Scenario returned `error`; repair the exercise before judging coverage. |

The same composite incident may cover several runs. Unrelated incidents never
count, even if their scenario or pattern names match. Gaps and late detections
use the stable identifier `gap:<event_id>`. Repeated checks replace the report
without adding duplicate gap entries. This is a current-state report, not an
append-only audit log or a remediation tracker; archive reports with the
exercise evidence. It relies on incident history remaining retained and
immutable. A database reset/deletion or changing the captured history can
change later results.

The report includes `schema_version`, `observed_at`, `complete`, source
configuration, and counts for all five states. `complete: true` means the
comparison succeeded; pending and invalid runs are not evidence of coverage.
The service performs two full, agreeing incident scans with stable totals and
no repeated IDs. API failures, malformed responses, or pagination changes make
the check fail and preserve the previous report. Offset pagination is not a
transactional snapshot; frequent incident arrivals can prevent a successful
comparison until a quiet interval. Scans are limited to one million incidents.

One-shot exit codes: `0` means a completed comparison with no gaps or late
detections (inspect pending/invalid counts), `1` means gaps or late detections,
and `2` means an incomplete check or invalid configuration. Polling emits a
JSON status line on success and an error status on stderr on failure, retaining
the previous report. Consumers must check `observed_at` and process health;
a retained report is not proof that the latest check succeeded.

The service reports unmatched evidence, not its root cause. Use the Purple Team
workflow to distinguish telemetry loss, failed correlation, and rule coverage
limitations, assign an owner, and verify a repair. Isolated M2 scenarios lack
dedicated rules today and can correctly appear as gaps while current rule
tests pass. No automatic ticket creation, notifications, or containment is added.

## Validation

Install pytest and the Detection Engine dependencies in your test environment.
From the repository root with the shared environment:

```bash
(cd gap-detector && ../range/.venv/bin/python -m pytest tests -q)
git diff --check
```

Unit tests cover deadline boundaries, both attacker outcomes, exact membership,
multiple runs per incident, late detection, pagination, malformed input,
deduplication, polling recovery, exit codes, and atomic report preservation.
The integration test starts a temporary Detection Engine with SQLite and its
real scheduler, formats producer records with attack-sim's actual formatter,
ingests events over HTTP, and invokes the real gap-detector CLI. It verifies
both a stored isolated miss and an event lost before ingestion, and preserves
the report when the API stops. It needs loopback listeners; it runs no attack
scenarios, creates no commits, and uses no external services.

The existing `security-e2e` CI job runs this suite, and changes under
`gap-detector/` trigger that workflow for pushes and pull requests.
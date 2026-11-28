# Gap Detector

A read-only comparison service for the [Purple Team loop](../docs/purple-team-loop.md).
It reads the producer-side attack-sim log and every page of the Detection
Engine incidents API, then writes a JSON report identifying valid M2 runs
without a referencing incident. It requires Python 3.10+ and the standard
library only. It does not run attacks, create incidents, or execute responses.
Outstanding gaps also produce inactive correlation-rule drafts through the
[scenario-to-rule suggester](#scenario-to-rule-suggester).

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

The full [M2 baseline runner](../docs/m2-detection-baseline.md#automatic-post-run-gap-check)
automatically runs a one-shot comparison after its batch correlation pass,
using that pass's completion time as a fixed deadline. It captures producer
history and retains the report and review queue in a unique evidence directory.
Gaps or incomplete comparisons fail the baseline. Individual scenario CLI
replays continue to use the manual capture and comparison commands below.

With the Detection Engine running, from the repository root:

```bash
cd gap-detector
python -m gap_detector --history /tmp/bantis-purple/attack.log --output /tmp/bantis-purple/gaps.json
```

Add `--interval 10` to keep checking in the foreground, suitable for a local
process supervisor. Ctrl+C stops it. `--detection-url` defaults to
`http://127.0.0.1:8000`; `--timeout` sets the positive HTTP timeout in seconds
(default 5). No additional listener or database service is needed. A local
SQLite review queue is created beside the report (see below). Keep the history,
output, and queue paths distinct and use a single writer per report file.

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

## Scenario-to-rule suggester

Every successful comparison now includes `rule_suggestions`, generated locally
from the canonical [event schema](../docs/event-schema.md#attack_scenario_run).
No provider, network call, or additional dependency is needed for drafting.
The existing incident queries still run as part of the gap check.

Only outstanding `gap` entries produce drafts. `pending`, `invalid`, and
`detected` runs produce none. `late_detection` remains a timing finding, rather
than prompting a redundant coverage rule. Multiple gaps for the same scenario
produce one draft containing sorted gap IDs, event IDs, and observed outcomes.
If another valid run of the same scenario is `detected` or `late_detection` in
the same report, no new rule is suggested for that scenario. This partial
coverage needs pipeline or rule-condition investigation. Missed runs remain
`gap` entries with their exact event IDs, counts, and failing exit code; a
detected run never establishes full coverage of the scenario. Coverage of a
different scenario does not suppress suggestions. Suppression uses only the
current report; it does not remove proposals already retained in the queue.
The draft ID is stable across replays; the report continues to represent the
current exercise rather than accumulated review history.

To generate a separate draft file from an existing complete report, run from
`gap-detector/`:

```bash
python -m gap_detector.suggester --report /tmp/bantis-purple/gaps.json --output /tmp/bantis-purple/rule-drafts.json
```

The offline command accepts a complete version 1 gap report, including reports
created before automatic drafting was added. It validates timestamps, counts,
scenario names, gap IDs, and gap evidence. Unsupported, incomplete, or
contradictory evidence leaves the previous output intact. Exit `0` means a
successful generation, including an empty draft list; exit `2` means invalid
input, configuration, or a write failure. Input and output must be different
files. The service's existing gap exit codes are unchanged.

Each suggestion contains:

- A stable `draft_id`, `status: pending_review`, and `enabled: false`.
- Schema fields and a selector for `source=attack-sim`,
  `event_type=attack_scenario_run`, the scenario name, and status in
  `success` or `failure`. `error` outcomes never match.
- A proposed single-event correlation: one event, grouped by `event_id`, with
  `window_seconds=0`. A fresh run can match without an unrelated burst partner.
- An incident blueprint with a scenario-specific pattern, the contributing
  event ID, technique field, summary, and proposed severity for each outcome.
  `confidence` is unset until a reviewer chooses and evaluates scoring.
- References to the observed gaps, a rationale, integration review steps, and
  complete positive and negative event examples with expected match results.

For example, an isolated `compromised-ci-step` gap proposes this selector:

```json
{
  "source": "attack-sim",
  "event_type": "attack_scenario_run",
  "details.scenario": "compromised-ci-step",
  "details.status": ["success", "failure"]
}
```

Selector keys use event-schema paths; array values mean membership. The
`matches_draft(draft, event)` function previews that fixed selector format and
checks for an event ID and a timezone-aware event timestamp. It does not execute
rule text or create incidents. Drafts use documented common fields rather than
requiring optional artifacts, scanner return codes, tool output, exact event
IDs, or a second scenario. Technique IDs are taken from the scenario contract.
Raw log messages, credentials, and tool output are omitted from the drafts.

These JSON objects are review blueprints, not a configuration format loaded by
the Detection Engine. `$event...` values describe field bindings for a future
implementation. Drafts remain inactive, and the current correlation rules and
incident storage are untouched. They cover instrumented lab scenario results;
they do not establish detection of equivalent activity outside attack-sim.

Before implementing a draft, confirm ingestion and scheduling worked. A missing
forwarded event or failed correlation pass needs a pipeline repair rather than
a new rule. Review noise from legitimate lab replays and preserve current
grouped coverage. In particular, a dependency or secret fallback must respect
the 300-second composite partner hold and composite priority before claiming
its event. Decide ordering relative to `same-source-burst`, reuse event-claim
deduplication, calibrate scoring, and test both isolated and grouped cases.
Close the gap only after the original conditions pass with fresh event IDs.

## Human review queue

Both the comparison service and the offline suggester enqueue every proposal
before publishing their JSON output. New proposals stop at `pending_review`
(pending review), with `enabled: false`, following M4's human-in-the-loop
principle. The default queue path is the full output filename followed by
`.review.sqlite3`, for example `/tmp/bantis-purple/gaps.json.review.sqlite3`.
Pass `--review-queue /tmp/bantis-purple/review.sqlite3` to either generator to
share a queue across output files. New queue files use owner-only permissions.

From `gap-detector/`, inspect the pending queue and a specific proposal:

```bash
python -m gap_detector.review_queue --queue /tmp/bantis-purple/gaps.json.review.sqlite3 list
python -m gap_detector.review_queue --queue /tmp/bantis-purple/gaps.json.review.sqlite3 show <proposal_id>
```

Use the full `proposal_id` printed by `list` or `show`. It is a SHA-256 hash of
the exact draft, including its evidence, selector, and integration checklist.
Review the complete draft, examples, and original gap evidence before deciding:

```bash
python -m gap_detector.review_queue --queue /tmp/bantis-purple/gaps.json.review.sqlite3 approve <proposal_id> --reviewer ali --reason "Reviewed positive and benign replay cases; integration still required"
python -m gap_detector.review_queue --queue /tmp/bantis-purple/gaps.json.review.sqlite3 reject <another_proposal_id> --reviewer ali --reason "Missing telemetry needs repair before adding coverage"
python -m gap_detector.review_queue --queue /tmp/bantis-purple/gaps.json.review.sqlite3 list --status all
```

Only `pending_review → approved` and `pending_review → rejected` are allowed.
Reviewer, reason, and UTC decision time are persisted with the original draft.
Blank identities/reasons, unknown IDs, and repeat decisions fail; concurrent
decisions allow one winner. Exit codes are `0` for success and `2` for failure.
The CLI relies on local filesystem access; reviewer names are operator-supplied,
not authenticated identities, and this SQLite history is not tamper-evident.

Repeated polling or regeneration of an identical draft preserves its decision
and creates no duplicate. Changed draft content, including changed gap evidence,
gets a new proposal ID and starts pending again; approval never transfers to a
changed rule. Old proposals remain visible even if a later report has no gaps.
Use `list --status approved` or `--status rejected` to filter decisions.

Generated reports always describe fresh recommendations as `pending_review`;
the queue's outer `status` is the authoritative review decision, while its
nested `draft` preserves the original proposal snapshot. **Approval does not
enable, install, or execute a rule.** Even an approved proposal retains
`enabled: false`. Detection Engine integration, scoring, regression tests,
and deployment remain separate reviewed work. Neither generation nor review
changes correlation rules, creates incidents, or invokes the Response Controller.

A failed queue write prevents publishing a new report and retains the previous
output. Queue insertion and report replacement are separate commits: a failed
report write may leave a pending proposal in the queue. A retry is safe and
idempotent; it does not activate anything. Existing pre-queue reports can be
imported by rerunning the offline suggester against their complete gap report.

### Pending proposals endpoint

Serve the same queue over a local HTTP endpoint, using only the standard library.
From the repository root:

```bash
cd gap-detector
python -m gap_detector.api --queue /tmp/bantis-purple/gaps.json.review.sqlite3 --port 8200
```

In another terminal:

```bash
curl --fail http://127.0.0.1:8200/rules/suggestions/pending
```

The response is `{"items": [...]}`, containing full queue records in creation
order, filtered by the authoritative outer `pending_review` status. An empty
queue returns `{"items": []}`. Approved and rejected records are excluded,
even though their nested draft snapshots retain their original status.
Each request reads current persisted decisions and returns `Cache-Control:
no-store`. A missing queue is initialized empty, as with the review CLI; use
the exact `--review-queue` path passed to the generator when overriding defaults.
Queue failures return HTTP 503 with a generic JSON error. Unknown routes return
404 and methods other than GET return 405. The server binds only to
`127.0.0.1`, has no authentication, and is intended for local inspection.
Use the existing CLI for review decisions; this endpoint never activates rules.

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

Suggester checks cover all four scenario schemas, successful and defended
outcomes, grouping and stable IDs, rejected or excluded evidence, selector
previews, and offline generation. The integration test verifies that the live
gap-detector CLI embeds drafts, offline regeneration produces identical output,
example envelopes validate against the Detection Engine schema, and drafting
does not change stored incidents.

Queue checks cover restart persistence, deduplication, content-bound decisions,
changed proposals requiring fresh review, concurrent decisions, required reviewer
and reason, inactive proposals, CLI operations, and retaining reports on queue
failure. The live integration check also approves queued proposals and verifies
that incident storage remains unchanged.

The existing `security-e2e` CI job runs this suite, and changes under
`gap-detector/` trigger that workflow for pushes and pull requests.
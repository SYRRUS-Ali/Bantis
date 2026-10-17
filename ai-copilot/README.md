# ai-copilot

M4's AI Copilot — analyzes a correlated incident from
[`detection-engine/`](../detection-engine/) and returns reasoning plus a
proposed next step, always subject to human approval. The exact
input/output shape and the security constraints this component must
honor are fixed in
[`docs/ai-copilot-contract.md`](../docs/ai-copilot-contract.md) — this
directory implements that contract, not a different one.

This is a separate, independently-deployable component, same
relationship `range/`, `attack-sim/`, and `detection-engine/` already
have to each other.

## Structure

```
ai-copilot/
├── models.py              # CopilotRequest/CopilotResponse — docs/ai-copilot-contract.md's shape
├── converter.py           # build_copilot_request() — detection-engine incident + events → CopilotRequest
├── parser.py              # parse_model_output() — model text → validated CopilotResponse (provider-agnostic)
├── detection_client.py    # read-only HTTP client for detection-engine's incidents API
├── worker.py              # polls for new incidents and analyzes each one automatically
├── decision_log.py        # append-only, hash-chained record of every analysis and follow-up (+ show/verify CLI)
├── api.py                 # authenticated HTTP API for follow-up questions ("Ask the Copilot") and /usage
├── budget.py              # daily token budget shared by the worker and the API
├── prompts.py             # versioned analysis prompts + the shared untrusted-data fence
├── eval/
│   ├── sprint3_incidents.json  # real Sprint 3 incidents (tests/export_sprint3_incidents.py)
│   ├── evaluate_prompt.py      # runs prompt versions side by side -> a manual scoring report
│   └── README.md               # the prompt review, rubric, and how to run it
├── providers/
│   ├── base.py              # AIProvider — the abstraction ADR 0003 asks for
│   └── claude.py             # ClaudeProvider — the only implementation in v1
├── examples/
│   └── send_test_request.py  # manual smoke test against the real API
├── tests/
│   ├── test_models.py
│   ├── test_converter.py
│   ├── test_parser.py
│   ├── test_worker.py
│   ├── test_decision_log.py
│   ├── test_followup_api.py
│   ├── test_budget.py
│   ├── test_prompts.py
│   └── test_claude_provider.py
└── requirements.txt
```

## Status

A basic, working connection to the Claude API exists behind an
abstraction (`AIProvider`), per [ADR 0003](../docs/adr/0003-single-ai-provider-first.md)
— adding a second provider later means writing a new class that
implements `AIProvider`, not touching anything that calls `analyze()`.

**The evidence-timeline converter** (`converter.py`) turns
detection-engine's own JSON — an `IncidentOut` as `GET /incidents/{id}`
returns it, plus `EventOut`-shaped event dicts — into a `CopilotRequest`.
It's where the contract's trust boundary is actually enforced:

- Only `artifact`, `tool_returncode`, `registry`, and `image` are copied
  from an event's `details` into `summary_fields`
  (`SUMMARY_FIELDS_ALLOWLIST`). `tool_output_tail` — which can carry the
  matched secret text from a real `gitleaks` scan — `message`, `logger`,
  and any field nobody has reviewed are dropped, by never being copied
  rather than by being filtered out.
- The timeline is ordered by `(timestamp, event_id)`, the same order
  detection-engine's `correlate()` uses.
- Timestamps are normalized to UTC: detection-engine's SQLite backend
  returns them without a timezone, and a mix of naive and aware values
  can't be sorted.
- If the incident references an event that wasn't provided, it raises
  `MissingEvidenceError` instead of sending a partial timeline the model
  would have no way to know was partial.

Verified against real output, not just hand-written dicts: events with a
fake AWS key in `tool_output_tail` were posted to a live detection-engine,
correlated into a real incident, read back through `GET /incidents`, and
converted — the key does not appear in the resulting request.

**Automatic analysis of new incidents** (`worker.py`): polls
detection-engine's `GET /incidents?since=` and, for each incident it
hasn't analyzed yet, fetches its evidence from `GET /incidents/{id}/events`,
converts it, and runs it through the provider. Each result goes to a
sink — by default one JSON line on stdout.

Polling rather than detection-engine pushing to the Copilot:
detection-engine stays unaware the Copilot exists (the dependency runs
one way, as the dashboard's will), and if the Copilot is down incidents
wait instead of a push being lost. How it avoids missing or repeating
an incident:

- **Only new ones.** Incidents created before the worker started are
  skipped (`--since` backfills older ones on purpose).
- **Late commits.** `correlate()` stamps `created_at` before
  `run_correlation()` commits, so an incident can appear after a newer
  one was already seen. Each poll re-reads 60s behind the newest
  incident seen, and skips ids it already analyzed.
- **Retries.** If an incident's events can't be fetched, it's retried
  next poll, and the cursor is held at it so newer incidents can't push
  it out of the query window. Without that hold, an outage longer than
  60s would drop it silently — found by a test, fixed, and covered by
  one now.
- **Never re-billed.** An incident is marked done once analyzed, even if
  the result is `analysis_failed` or the sink fails (the analysis then
  goes to stderr instead of being lost). The decision log is the durable
  memory: an incident already in it is never analyzed again, across
  restarts and even when `--since` reaches back over it.
- **Missing evidence** isn't sent to the AI at all — it's recorded as
  `analysis_failed` without a provider call.
- **Provider unavailable.** See "When the AI provider is unavailable"
  below: the incident is delivered without an analysis and nothing is
  recorded, so it's analyzed once the provider is back.
- **One worker per incident.** Before calling the model, a worker
  atomically claims the incident in the decision log (`try_claim`, under
  SQLite's write lock). Checking "not in the log yet" and then calling
  was a race: two workers on one incident made 2 paid calls and wrote 2
  decisions (reproduced, now a regression test with 4 workers). A
  claim expires after 15 minutes, so a worker that crashes mid-analysis
  doesn't block its incident forever. As a backstop, the log refuses a
  second decision for the same incident outright.

### When the AI provider is unavailable

An outage of the AI provider delays the AI's opinion, never the incident.
Incidents keep forming and being served by detection-engine, which
doesn't depend on ai-copilot at all; ai-copilot itself keeps running.

| Situation | Before | Now |
|---|---|---|
| `ANTHROPIC_API_KEY` not set | `worker.py` and `api.py` crashed at startup (`KeyError`) | both start, log an `ERROR`, and run without AI analysis |
| Provider unreachable, timing out, overloaded (5xx, 529), rate-limited (429), or rejecting the key (401/403) | recorded as the incident's final `analysis_failed`; it could never be analyzed again, even after recovery (reproduced) | incident delivered without analysis, nothing recorded, analyzed on recovery |
| Provider hangs | up to 600s per try, 3 tries, before the worker moved on | 60s per try (`REQUEST_TIMEOUT_SECONDS`) |
| A request the API rejects (400, 404, 413, 422) | `analysis_failed` | unchanged: the same request would fail again, so it's a real result |

What the worker does on an outage:

- **Delivers the incident without analysis**, once, as a stdout line with
  `"analysis": null` and an `"analysis_pending"` reason. The analysis is
  delivered as a second line when it exists.
- **Decides nothing.** No decision is written and the claim is released,
  so the incident's one decision stays available and another worker can
  take it straight away. The incident is deferred like an over-budget
  one, holding the cursor so it can't fall out of the query window.
- **Stops calling the provider for a while.** After a failure, no
  incident is sent for 30s; each further failure doubles the wait, up to
  10 minutes; the first success resets it. A long outage costs one failed
  call per interval, not one per incident per poll.
- **Counts what was paid for.** An outage after a paid attempt (a reply
  that failed validation, then a dropped connection) is still recorded as
  `analysis_failed`, so its tokens count toward the daily budget.

Follow-up questions return `503` with `Retry-After: 60` while the provider
is unavailable; the incident and its recorded analysis are unaffected.
The response doesn't say why — a missing key is configuration a client
doesn't need to learn — but the server log does, and the failed question
is recorded in the `followups` table like any other failure.

### Throttling: what gets sent to the AI

Every incident costs up to three model calls, and `POST /events` is
unauthenticated — so without limits, anyone who can reach
detection-engine controls how much you spend. `ThrottlePolicy` decides
what's worth a call:

- **Only correlated incidents.** An incident built from fewer than 2
  events (`--min-correlated-events`) isn't a correlation — today that's
  Pattern 3, the single-event untrusted-registry pull. It's recorded in
  the decision log as `skipped`, with the reason, and never sent. That's
  a real trade-off: a high-severity registry pull no longer gets AI
  analysis by default. `--min-correlated-events 1` sends everything.
- **A rate limit.** At most 30 incidents sent per rolling hour
  (`--max-analyses-per-hour`, `--no-rate-limit` to disable). The count
  comes from the decision log, so it survives restarts and is shared by
  every worker using the same log. Incidents over the limit are
  **deferred**, not dropped — the cursor is held so they're analyzed once
  budget frees up. Skips and decisions made without a model call don't
  count against it.
- **Most severe first.** When the limit cuts a poll short, the incidents
  left waiting are the least severe ones. Without that, a flood of
  low-severity incidents (anyone can post events) could spend the hour's
  budget ahead of a critical one.

The limit is soft across workers: two workers checking at the same
moment can each take the last slot, so it can be exceeded by at most the
number of workers sharing the log.

Detection-engine is reached through `detection_client.py`, which uses
`http.client` with the URL scheme checked up front, the same as the
producers' `DetectionEngineHandler` — not `urllib.request.urlopen`,
which Semgrep flagged in this repo before.

**The decision log** (`decision_log.py`) is a durable record of every
analysis and how it was reached, one per incident, in a SQLite file
(`ai-copilot/decision_log.db` by default, `--decision-log` or
`$BANTIS_DECISION_LOG` to change it; gitignored). Each record holds:

- the request the provider saw — the allowlisted `CopilotRequest`, never
  detection-engine's raw events, so nothing is stored that didn't
  already cross the trust boundary;
- the exact system prompt;
- **every attempt**, including rejected ones: the model's raw output,
  why it was rejected, the stop reason, and token usage;
- the final response and its outcome;
- a note for decisions reached without a model call (missing evidence, a
  worker error), so the log has no gaps.

It's written before the stdout line, since it's the record and stdout
is a notification; if the write fails, the whole record goes to stderr
rather than being lost.

The log is **append-only and hash-chained**: each record's SHA-256
covers its content and the previous record's hash.
`python3 decision_log.py verify` recomputes the chain and exits 1 if a
record was edited or removed from the middle. What that does and
doesn't protect against:

- It **detects** a stored decision being changed after the fact (e.g.
  `flag_for_review` rewritten to `no_action_recommended`), and a record
  deleted from the middle.
- It does **not** detect deletion of the newest records (the shorter
  chain is still consistent), or a full rewrite by someone who can write
  the file and recompute every hash. Catching those needs the latest
  hash kept somewhere that attacker can't also write. A test pins this
  limitation so nobody assumes more protection than exists.

Writers take SQLite's write lock (`BEGIN IMMEDIATE`) before reading the
chain's tip, so two workers appending at once can't both chain from the
same record. Without it, a concurrency test with 8 writers fails every
run.

```bash
python3 decision_log.py show <incident_id>   # every decision for an incident, with all attempts
python3 decision_log.py verify               # integrity check; exit 1 if altered
```

### Ask the Copilot: follow-up questions (`api.py`)

An HTTP API for asking follow-up questions about an incident the
Copilot already analyzed:

| Route | |
|---|---|
| `POST /incidents/{id}/questions` | `{"question": "..."}` → `201` with the answer |
| `GET /incidents/{id}/questions` | every answered question for the incident, in order |
| `GET /health` | liveness, no token |

Every question is a paid model call, so this API is locked down from the
start, unlike detection-engine's:

- **Bearer token required** (`COPILOT_API_TOKEN`, at least 16
  characters; the server won't start without one), compared in constant
  time. It binds to `127.0.0.1` by default, and warns if told to listen
  elsewhere, since over plain HTTP the token travels in cleartext.
- **Grounded only in the decision log.** The model sees the incident's
  recorded, allowlisted request and its recorded analysis — never
  detection-engine's raw events — so asking can't widen what reaches the
  AI provider. A skipped incident (no recorded request) gets `409`
  rather than an answer invented from nothing.
- **Evidence is untrusted data.** Anyone can post events, so an evidence
  field is attacker-controlled text. It goes inside an
  `<incident_data>` block the model is told to treat as data, never
  instructions, with `<`/`>` escaped so a field can't close the block
  early. That escape was a real hole caught while writing the tests: a
  `</incident_data>` inside an `artifact` used to break out of the block.
  Delimiting reduces prompt injection; it doesn't make it impossible.
- **Answers explain, they don't act.** An answer is plain text with no
  action field, and asking never changes the recorded decision or its
  proposed action.
- **No credentials in questions.** A question that looks like it contains
  an AWS key, private key, GitHub token or Anthropic key is refused
  (`422`) before anything is sent — the threat model's "no secrets to the
  AI provider" applies to operator input too. Pattern-based and
  best-effort, not a guarantee.
- **Bounded cost.** Questions are capped at 2000 characters; only the last
  5 Q&A turns are sent as context; at most 60 questions per rolling hour
  (`--max-questions-per-hour`, `--no-rate-limit`), counted from the
  decision log, so the cap survives restarts.
- **Audited.** Every question and answer — failures included, with the
  exact prompt, raw output and token usage — goes into the decision log's
  `followups` table, its own append-only hash chain. `decision_log.py
  verify` checks it alongside the decisions, and `show` prints both.

```bash
export COPILOT_API_TOKEN=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')
export ANTHROPIC_API_KEY=sk-ant-...
python3 api.py                                   # http://127.0.0.1:8100
curl -X POST http://127.0.0.1:8100/incidents/<incident_id>/questions \
     -H "Authorization: Bearer $COPILOT_API_TOKEN" -H 'Content-Type: application/json' \
     -d '{"question": "Which event came first, and why does that matter?"}'
```

### Daily token budget (`budget.py`)

Every model call's token usage is recorded per attempt in the decision
log — including rejected attempts, because a rejected reply was still
billed. That record is what both tracking and the cap are built on:

- **Tracking.** `python3 decision_log.py usage --days 7` prints calls,
  input, output and total tokens per UTC day; the API's `GET /usage`
  (token required) returns today's numbers against the budget, for a
  dashboard.
- **One daily cap for everything.** At most 500,000 tokens per UTC day
  by default (`--max-tokens-per-day` on both `worker.py` and `api.py`,
  `--no-token-budget` to disable), counting worker analyses and follow-up
  questions together, since both bill the same account. It's read from
  the decision log, so it survives restarts and every process sharing
  the log draws on one allowance. Each process applies its own
  configured limit to that shared usage, so give them the same number.
- **Over budget means wait, not drop.** The worker defers incidents
  until the budget resets at UTC midnight, logging when it will; the API
  answers `429` with `Retry-After` set to the seconds left until midnight.
  Nothing is lost.
- **What it isn't: a hard cap.** A call's cost is only known once it
  returns, so the guard checks before each analysis or question starts.
  A process can overshoot by at most the one it already had in flight
  (an analysis is up to 3 model calls). A test pins that bound so nobody
  reads the limit as stricter than it is.

The rate limits above count requests; this counts tokens. They work
together: the rate limit stops a burst, and the budget stops slow,
steady spending from adding up.

**Still open:** a skipped incident stays skipped: lowering
`--min-correlated-events` later doesn't
re-evaluate incidents already recorded as skipped. The decision log's
analyses themselves aren't served over HTTP yet — only follow-ups are —
and the dashboard will need that.

### Prompts (`prompts.py`)

The analysis prompt is versioned. `v2` is current; `v1` is kept verbatim
so a change can be compared side by side on the same real incidents, and
every decision-log record stores which version produced it. `v2` came out
of reviewing `v1` against the real Sprint 3 incidents: it tells the model
what the data means (`status` is from the attacker's side, so `"failure"`
means the attack was blocked; exit codes differ per tool; `attack-sim` is
Bantis's own simulator, though a label anyone can forge), defines the four
actions, and fences the evidence as untrusted data the same way
follow-ups do. The analysis prompt used to be missing that fencing. Full
review, rubric and how to run the A/B comparison: [`eval/README.md`](eval/README.md).
**Model outputs haven't been scored yet** — that needs an API key; the
harness is ready for it.

### Validation and retries

`parser.py`'s `parse_model_output()` turns the model's raw text into a
validated `CopilotResponse`, or raises `OutputParseError` — the only
exception any parse failure produces, with a message written to be fed
back to the model. It lives outside `providers/` so a second provider
reuses the same definition of a valid answer. Extraction is lenient (a
```` ```json ```` fence or a line of prose around the JSON is fine);
content is strict (a boolean or string `confidence`, whitespace-only
`reasoning`, a top-level array, or a model-produced `analysis_failed`
are all rejected, not coerced). Full rule list:
[`docs/ai-copilot-contract.md#validation`](../docs/ai-copilot-contract.md#validation).

`ClaudeProvider.analyze()` retries a rejected reply up to twice (3
attempts total) as a continued conversation: the model sees its own
invalid reply, then exactly what was wrong with it. A reply cut off at
the token limit is told so specifically. A provider-level failure (the
connection itself failing, not a bad reply) is **not** retried —
retrying the same dead connection with "your response was invalid"
doesn't make sense, so it fails immediately instead. If the provider was
unavailable (see above), that's `ProviderUnavailableError`, not an
analysis.

Found and fixed while building this: two malformed shapes — a top-level
JSON array, and `proposed_action` sent as a string — used to raise an
uncaught `TypeError` straight out of `analyze()`, because the old retry
loop only caught `JSONDecodeError`/`KeyError`/`ValueError`. The caller
got an exception instead of the contract's `analysis_failed` result.
`confidence: true` was also silently accepted as `1.0` (`bool` is an
`int` subclass), and `"0.7"` and whitespace-only `reasoning` were
accepted too.

Any other failure, and running out of retries, produces the same
fallback: a stored, visible `CopilotResponse` with
`proposed_action.type = "analysis_failed"` and `confidence = 0.0` —
never nothing, and never the same value as a genuine "nothing's wrong"
finding (`no_action_recommended`). See
[`docs/ai-copilot-contract.md#error-cases-and-failure-semantics`](../docs/ai-copilot-contract.md#error-cases-and-failure-semantics).

### The recommend-only constraint is enforced in the schema, not by convention

`ProposedAction.requires_approval` is validated to be exactly `true` —
a response that tries to set it to `false` fails validation and falls
through to the same `analysis_failed` path as a malformed reply. This
is [ADR 0004](../docs/adr/0004-recommend-only-default.md)'s decision
made structurally impossible to bypass by a future caller forgetting to
check a flag: there is no code path in this component, today, that
executes a proposed action at all.

## How to use it

From detection-engine's JSON (the normal path):

```python
from converter import build_copilot_request
from providers.claude import ClaudeProvider

incident = ...  # dict: GET /incidents/{incident_id} response body
events = ...    # list of dicts in EventOut shape, covering incident["correlated_event_ids"]

request = build_copilot_request(incident, events)
response = ClaudeProvider().analyze(request)
```

Or building a `CopilotRequest` by hand:

```python
from datetime import datetime, timezone

from models import CopilotRequest, EvidenceEntry, IncidentPayload
from providers.claude import ClaudeProvider

request = CopilotRequest(
    incident=IncidentPayload(
        incident_id="...", created_at=datetime.now(timezone.utc),
        pattern="composite-dependency-secret", window_seconds=300,
        correlated_event_ids=["dep-1", "sec-1"],
        mitre_techniques=["T1195.001", "T1552.001"],
        severity="high", confidence=0.6,
        summary="malicious-dependency + leaked-secret within 300s",
    ),
    evidence_timeline=[
        EvidenceEntry(
            event_id="dep-1", timestamp=datetime.now(timezone.utc),
            source="attack-sim", event_type="attack_scenario_run",
            scenario="malicious-dependency", status="failure",
            mitre_technique="T1195.001",
            summary_fields={"artifact": "fake-package==0.0.0", "tool_returncode": 1},
        ),
    ],
)

provider = ClaudeProvider()  # reads ANTHROPIC_API_KEY from the environment
response = provider.analyze(request)
print(response.reasoning, response.proposed_action.type)
```

## Running it

The automatic worker, against a running detection-engine:

```bash
cd ai-copilot
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-...
python3 worker.py --detection-engine-url http://localhost:8000            # poll every 30s, new incidents only
python3 worker.py --detection-engine-url http://localhost:8000 --once     # a single poll, then exit
python3 worker.py --since 2026-10-10T00:00:00Z --once                     # also analyze older incidents
```

Each analysis is printed to stdout as one JSON line (`{"incident": ...,
"analysis": ...}`); logs go to stderr. While the AI provider is
unavailable, incidents are printed with `"analysis": null` and an
`"analysis_pending"` reason instead. Every analyzed incident is up to
three paid API calls to your Anthropic account — see Throttling above
for what's sent and how many per hour (`--min-correlated-events`,
`--max-analyses-per-hour`, `--no-rate-limit`), and Daily token budget for
the per-day cap (`--max-tokens-per-day`, `--no-token-budget`).

## Running the tests

```bash
cd ai-copilot
pip install -r requirements.txt -r tests/requirements.txt
python -m pytest tests -v
```

No test calls the real Claude API — `ClaudeProvider` accepts `client=`
for dependency injection, and every test passes a fake object with a
`.messages.create()` method instead, the same pattern `attack-sim`'s
tests use to fake out `docker`/`gitleaks` rather than needing them
installed.
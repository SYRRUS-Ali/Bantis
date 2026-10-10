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
  goes to stderr instead of being lost).
- **Missing evidence** isn't sent to the AI at all — it's recorded as
  `analysis_failed` without a provider call.

Detection-engine is reached through `detection_client.py`, which uses
`http.client` with the URL scheme checked up front, the same as the
producers' `DetectionEngineHandler` — not `urllib.request.urlopen`,
which Semgrep flagged in this repo before.

**Not built yet** (later Sprint 4 items): persistent storage for the
analyses (the decision log — today they're JSON lines on stdout, and the
worker's memory of what it analyzed doesn't survive a restart);
throttling; a token-budget guard; and the "ask a follow-up question"
endpoint. `run_correlation()` itself is still not automatic in
detection-engine, so an incident only exists for the worker to find once
something has called it.

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
doesn't make sense, so it fails immediately instead.

Found and fixed while building this: two malformed shapes — a top-level
JSON array, and `proposed_action` sent as a string — used to raise an
uncaught `TypeError` straight out of `analyze()`, because the old retry
loop only caught `JSONDecodeError`/`KeyError`/`ValueError`. The caller
got an exception instead of the contract's `analysis_failed` result.
`confidence: true` was also silently accepted as `1.0` (`bool` is an
`int` subclass), and `"0.7"` and whitespace-only `reasoning` were
accepted too.

Either kind of failure, and running out of retries, produces the same
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
"analysis": ...}`); logs go to stderr. Every new incident is one paid
API call to your Anthropic account.

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
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
├── providers/
│   ├── base.py              # AIProvider — the abstraction ADR 0003 asks for
│   └── claude.py             # ClaudeProvider — the only implementation in v1
├── examples/
│   └── send_test_request.py  # manual smoke test against the real API
├── tests/
│   ├── test_models.py
│   ├── test_converter.py
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

**Not built yet** (later Sprint 4 items): fetching the incident and its
events from detection-engine — there's no `GET /events` route yet, so a
caller passes the events in; the decision log; throttling; a
token-budget guard; the "ask a follow-up question" endpoint; and any
wiring into `detection-engine/` itself.

### Validation and retries

`ClaudeProvider.analyze()` sends the request, parses the model's reply
as the JSON shape `docs/ai-copilot-contract.md` defines, and validates
it through `models.py`'s Pydantic schema. On a malformed or
schema-invalid reply, it retries up to twice with the validation error
fed back to the model (3 attempts total) before giving up. A
provider-level failure (the connection itself failing, not a bad reply)
is **not** retried — retrying the same dead connection with "your
response was invalid" doesn't make sense, so it fails immediately
instead.

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

```bash
cd ai-copilot
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-...
python3 -c "..."   # see "How to use it" above
```

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
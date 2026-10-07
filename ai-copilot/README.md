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
├── providers/
│   ├── base.py              # AIProvider — the abstraction ADR 0003 asks for
│   └── claude.py             # ClaudeProvider — the only implementation in v1
├── tests/
│   ├── test_models.py
│   └── test_claude_provider.py
└── requirements.txt
```

## Status

A basic, working connection to the Claude API exists behind an
abstraction (`AIProvider`), per [ADR 0003](../docs/adr/0003-single-ai-provider-first.md)
— adding a second provider later means writing a new class that
implements `AIProvider`, not touching anything that calls `analyze()`.

**Not built yet** (later Sprint 4 items, intentionally out of scope
here): the incident-to-`CopilotRequest` converter that would actually
feed `detection-engine/`'s real incidents into this (today, a caller
builds a `CopilotRequest` by hand — see the tests for the shape); the
decision log; throttling; a token-budget guard; the "ask a follow-up
question" endpoint; and any wiring into `detection-engine/` itself. This
is the client and its contract, not the pipeline.

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
# AI Copilot Contract (M4, v1)

This fixes the AI Copilot's input/output shape and security constraints
before any `ai-copilot/` code exists — the same reasoning
[`docs/correlation-design.md`](correlation-design.md) used for M3: design
the contract first, so the implementation (Sprint 4) has a concrete
target instead of inventing the shape while also writing the client
code.

Scope: exactly the initial analysis call — an incident goes in,
reasoning plus a proposed action comes out. Follow-up questions ("Ask
the copilot"), the auto-execution whitelist, and token-budget
enforcement are named as explicit non-goals below; they're later
roadmap items, not this contract.

## Why a contract, not just "call the API"

Two reasons, one per side of the call:

- **Input side:** [`docs/threat-model.md`](threat-model.md) already
  commits to a specific trust boundary — "Bantis ⟷ AI provider:
  semi-trusted. Only correlated incident data is sent for analysis,
  never raw secrets or credentials." That has to be an enforced shape
  (an explicit allowlist of fields), not a hope that nothing sensitive
  happens to be in whatever gets forwarded.
- **Output side:** an LLM's response has to be parsed as data before
  anything can act on it — reasoning text alone isn't something a
  dashboard or an approval flow can render reliably. A validated shape
  with defined failure semantics (below) means a malformed or truncated
  response fails loudly, not silently as "the AI found nothing wrong."

## Input contract: `CopilotRequest`

```json
{
  "incident": {
    "incident_id": "1c9a3f2e-...",
    "created_at": "2026-10-06T14:03:11Z",
    "pattern": "composite-dependency-secret",
    "window_seconds": 300,
    "correlated_event_ids": ["dep-...", "sec-..."],
    "mitre_techniques": ["T1195.001", "T1552.001"],
    "severity": "high",
    "confidence": 0.6,
    "summary": "malicious-dependency + leaked-secret within 300s (0/2 succeeded)"
  },
  "evidence_timeline": [
    {
      "event_id": "dep-...",
      "timestamp": "2026-10-06T14:00:00Z",
      "source": "attack-sim",
      "event_type": "attack_scenario_run",
      "scenario": "malicious-dependency",
      "status": "failure",
      "mitre_technique": "T1195.001",
      "summary_fields": {"artifact": "bantis-attack-sim-simulated-malicious-dependency==0.0.0", "tool_returncode": 1}
    },
    {
      "event_id": "sec-...",
      "timestamp": "2026-10-06T14:00:50Z",
      "source": "attack-sim",
      "event_type": "attack_scenario_run",
      "scenario": "leaked-secret",
      "status": "failure",
      "mitre_technique": "T1552.001",
      "summary_fields": {"artifact": "config.py", "tool_returncode": 1}
    }
  ]
}
```

| Field | Rule |
|---|---|
| `incident` | Mirrors `IncidentOut` (`detection-engine/app/models.py`) exactly — the copilot reads the same shape the `/incidents` API already returns, not a second schema that can drift from it. |
| `evidence_timeline` | One entry per `incident.correlated_event_ids`, ordered by `(timestamp, event_id)` — the same tiebreak `app/correlation.py` uses, so the copilot sees a deterministic reconstruction of what happened, never an artifact of database ordering. |
| `evidence_timeline[].scenario`, `.status`, `.mitre_technique` | The three fields every `attack_scenario_run` event guarantees ([`docs/event-schema.md`](event-schema.md)) — always included at the top level, not allowlisted, because they're already enumerated classification values, never free text. |
| `evidence_timeline[].summary_fields` | **An explicit allowlist over the scenario-specific *extras* only, not the event's raw `details` dict.** This is the enforcement point for the trust boundary above. |

**The `summary_fields` allowlist (v1):** `artifact`, `tool_returncode`,
`registry`, `image`. Every one of these is an identifier, per its own
definition in [`docs/event-schema.md`](event-schema.md) — never a
secret's content.

**Explicitly excluded, always:** `tool_output_tail`. A real `gitleaks`
scan's output can contain the matched secret text itself, not just a
pointer to it — forwarding it verbatim would break the trust boundary
the moment a real leaked-secret incident (not attack-sim's synthetic
one) was analyzed. No other field from an event's `details` is ever
forwarded; a field reaches the AI provider only by being named on the
allowlist above, not by being present and not yet excluded. `message`
and `logger` are also never forwarded — free text from a producer is
exactly the kind of field nobody has reviewed for secret content.

## Output contract: `CopilotResponse`

```json
{
  "incident_id": "1c9a3f2e-...",
  "reasoning": "Both halves of a composite attack were defended (build rejected, secret caught by gitleaks), but their proximity in time suggests a single coordinated attempt rather than two unrelated events...",
  "confidence": 0.65,
  "proposed_action": {
    "type": "flag_for_review",
    "description": "Escalate to the operator — composite pattern with two independent supply-chain techniques from the same source.",
    "requires_approval": true
  },
  "model": "claude-...",
  "generated_at": "2026-10-06T14:03:14Z"
}
```

| Field | Rule |
|---|---|
| `confidence` | Float, `0.0`–`1.0`. **The AI's own confidence, distinct from `incident.confidence`** — the same `confidence`-not-`score` separation `docs/correlation-design.md` already uses for M3 vs. a future M4 value; M4's number must never overwrite M3's rule-based one. |
| `proposed_action.type` | One of the **closed v1 enum** below. Anything else is a validation failure, not a new action Bantis acts on. |
| `proposed_action.requires_approval` | **Always `true` in v1.** Not a field the AI chooses — see Security constraints. |
| `reasoning` | Non-empty. The human-readable basis for the proposed action; this is what an operator reads before approving or rejecting. |
| `model`, `generated_at` | Recorded for the decision log (a later Sprint 4 item) — which model produced this, and when. |

**`proposed_action.type` v1 enum:** `notify_operator`,
`flag_for_review`, `suggest_investigation`, `no_action_recommended`,
`analysis_failed`.

`analysis_failed` exists specifically so a failed call and a genuine
"nothing's wrong" conclusion are never the same value — see Error cases
below; a provider timeout must never be representable as
`no_action_recommended`, which is itself a real, positive finding.

All five are informational — none of them mutates anything in `range/`,
`attack-sim/`, or `detection-engine/`. An action like "roll back the
dependency" or "revoke the credential" is deliberately **not** a valid
v1 value: there is no code path in v1 that executes a proposed action at
all, so defining executable action types now would describe a
capability that doesn't exist. Adding them is exactly the kind of
"explicitly configured whitelist" ADR 0004 reserves for a later,
separately-reviewed decision.

### Validation (feeds the retry logic in a later Sprint 4 item)

A response is rejected, not accepted-with-a-shrug, if any of:
- `confidence` isn't a float in `[0.0, 1.0]`.
- `proposed_action.type` isn't one of the five values above.
- `proposed_action.requires_approval` isn't exactly `true`.
- `reasoning` is empty or missing.

On rejection: retry with the validation error fed back to the model, up
to 2 retries (3 attempts total). If every attempt still fails
validation, do not guess at a response — fall back to the error
semantics below instead.

## Security constraints

1. **Recommend-only, always (ADR 0004).** `requires_approval` is
   hard-coded `true` for every response in v1; it is not a value the AI
   returns, and validation rejects any response that tries to set it to
   `false`. No code in v1 calls back into `range/`, `attack-sim/`, or
   `detection-engine/` to execute a proposed action — there is nothing
   for an operator's future "approve" button to trigger beyond a status
   change, because no execution path exists yet.
2. **Never send raw secrets or credentials to the AI provider.**
   Enforced structurally by the `summary_fields` allowlist in the input
   contract — by what is never included in the request, not by trusting
   the model to disregard sensitive content it was never given.
3. **M4's confidence never overwrites M3's.** `IncidentORM.confidence`
   (the rule-based value) is immutable from the copilot's perspective;
   `CopilotResponse.confidence` is a separate value, stored separately.
4. **Idempotent per incident.** Calling the copilot twice on the same
   `incident_id` must be safe — a design constraint for the throttling
   work in a later Sprint 4 item, noted here as a dependency, not
   implemented by this contract.
5. **Token-budget enforcement is out of scope for this contract** — a
   separate Sprint 4 item. This contract defines the shape of one call;
   it does not decide whether that call should happen.

## Error cases and failure semantics

| Case | Response |
|---|---|
| Provider unreachable or times out | `proposed_action.type = "analysis_failed"`, `reasoning = "analysis unavailable: <reason>"`, `confidence = 0.0`. Stored, not discarded. |
| Output fails validation after all retries | Same fallback shape as above, with the validation failure (not the model's malformed text) as the reason. |

Both cases produce a stored, visible result rather than nothing. An
operator must be able to see "the copilot couldn't analyze this" as a
distinct, logged state — a silent gap would be indistinguishable from
"the copilot looked and found nothing," which is a materially different
and more dangerous claim.

## Open questions and explicit non-goals

- **Multi-turn follow-up questions** ("Ask the copilot" against an
  existing incident) are a separate later Sprint 4 item — this contract
  covers only the initial analysis call, not a conversation.
- **The auto-execution whitelist** is explicitly deferred to ADR 0004's
  own "later, separately-reviewed decision" — not designed here, and no
  v1 action type is executable in the first place.
- **Token-budget/cost enforcement** is a separate later Sprint 4 item;
  this contract assumes the call happens and defines what it looks like.
- **Retry count (2) is a starting point, not tuned** — revisit once
  real provider failure rates are observed, rather than guessing further
  now.
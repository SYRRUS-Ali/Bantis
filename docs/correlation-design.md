# Correlation Design (M3, v1)

This defines how the Detection Engine turns individual events (the
`http_request` / `attack_scenario_run` envelope in
[`docs/event-schema.md`](event-schema.md)) into **incidents** — a
correlated group of events worth a human's attention, not just a log
line. This is a design doc, not an implementation: no `detection-engine/`
code exists yet. It fixes the *rules* first so the storage/ingestion work
that follows has a concrete target to build against, rather than
inventing the schema while also writing the database layer.

Scope: exactly the two correlation patterns below, at whatever
confidence/severity a naive, rule-based first pass can honestly claim.
Neither pattern uses AI — that's M4's job, refining what this produces,
not replacing it. See [Open questions](#open-questions-and-explicit-non-goals)
for what this deliberately leaves out.

## Time window

"Close together" needs a number, not a feeling. Two windows, not one —
the two patterns below correlate fundamentally different things, and a
single global constant would be wrong for at least one of them:

| Constant | Value | Used by |
|---|---|---|
| `SAME_SOURCE_WINDOW_SECONDS` | `60` | Pattern 1 |
| `COMPOSITE_WINDOW_SECONDS` | `300` (5 minutes) | Pattern 2 |

**Why 60s for Pattern 1.** A burst of activity from the same `source`
within a minute is the shortest window that still tolerates normal
network jitter and event-emission timing (see
[`docs/event-schema.md#known-limitation`](event-schema.md#known-limitation)
— `api` and `nginx` don't even agree on a duration unit yet, so the
correlation layer can't assume sub-second precision means anything).
Longer than a minute and unrelated, coincidental activity starts looking
correlated for no good reason.

**Why 5 minutes for Pattern 2.** A composite attack (inject a bad
dependency, then leak a credential — or the reverse order) is a
multi-*step* action, not a single burst — an attacker plausibly pauses
between steps, or the two steps come from two different CI runs a few
minutes apart. Pattern 1's 60s window is too tight to ever catch this
realistically. 5 minutes is deliberately generous *because* this pattern
already requires two specific, named scenario types to co-occur (see
below) — that specificity is what keeps false positives down, not a
tight window.

Both constants live in one place in the eventual implementation, named
exactly as above, so they're never silently duplicated or drift apart —
same principle already applied to every attack-sim scenario's own
tunables (e.g. `_INSTALL_TIMEOUT_SECONDS`, `_SCAN_TIMEOUT_SECONDS`).

Windowing is computed off each event's `timestamp` field (ISO 8601, UTC
— already guaranteed by the envelope), sorted chronologically. An event
that would fall inside two different candidate incidents' windows joins
whichever one it's chronologically adjacent to first — first-come,
first-grouped; not re-litigated once assigned. Revisiting that
tie-breaking rule is explicitly out of scope for v1 (see below).

## Pattern 1: same-source burst

**Rule.** Two or more events sharing the same `source` value, both
falling within `SAME_SOURCE_WINDOW_SECONDS` of each other, form one
incident.

**Concrete example, grounded in what Bantis actually emits today.** The
`attack-sim` source is the clearest real case: an operator (or an
attacker who's gained the ability to trigger scenarios) runs
`malicious-dependency` and then, 40 seconds later, `typosquatting` — two
independent supply-chain attempts from the same actor in quick
succession is a meaningfully different situation than either alone,
regardless of which two scenario types they are. This pattern is
intentionally **type-agnostic** — it doesn't care *which* two events, only
that the same source produced two of them close together. Pattern 2
below is the type-*specific* complement to this.

**Why this pattern, not a smarter one, first.** It requires no schema
change and no cross-scenario knowledge — just grouping by `source` and
`timestamp`, both already guaranteed fields. It's the correlation
equivalent of `noop.py`: the simplest possible rule, built first so the
storage and incident-emission plumbing has something concrete to prove
itself against before a more specific rule is layered on.

## Pattern 2: composite dependency+secret

**Rule.** A `malicious-dependency` scenario event and a `leaked-secret`
scenario event (identified by `details.scenario`, not just `source` —
both share `source=attack-sim`, so `source` alone can't distinguish them)
occurring within `COMPOSITE_WINDOW_SECONDS` of each other, in either
order, form one **composite** incident — a distinct kind of incident from
Pattern 1's, not just a special case of it.

**Why these two specifically.** They're the two scenarios whose combined
narrative is genuinely more dangerous than the sum of their parts: a
malicious dependency getting into the build *and* a credential leaking
in the same short window is the shape of a real multi-stage supply-chain
compromise (plant persistence, then harvest credentials — or the
reverse: steal a credential, then use the resulting access to push a
poisoned dependency). Neither `compromised-ci-step` nor `typosquatting`
pairs with anything yet in v1 — not because they're less serious
individually (`compromised-ci-step` is documented as the *highest*
severity of the four in
[`docs/scenarios/compromised-ci-step.md`](scenarios/compromised-ci-step.md)),
but because this first composite rule is deliberately narrow rather than
guessing at every pairwise combination without evidence any of the
others are meaningful. Widening it is a v2 problem, made easier
specifically *because* v1 shipped one pattern that actually works.

## Incident data shape

```json
{
  "incident_id": "1c9a3f2e-...",
  "created_at": "2026-09-22T14:03:11Z",
  "pattern": "same-source-burst",
  "window_seconds": 60,
  "correlated_event_ids": ["...", "..."],
  "mitre_techniques": ["T1195.001", "T1195.001"],
  "severity": "medium",
  "confidence": 0.35,
  "summary": "2 attack-sim events within 60s: malicious-dependency (success), typosquatting (success)"
}
```

| Field | Type | Notes |
|---|---|---|
| `incident_id` | string (UUID4) | Same format convention as `event_id` in the envelope. |
| `created_at` | string (ISO 8601, UTC) | When the correlation engine formed the incident, not when the underlying events occurred. |
| `pattern` | string | `"same-source-burst"` or `"composite-dependency-secret"` — an enum of exactly the two patterns above; extending it is how a v2 pattern gets added later. |
| `window_seconds` | int | Whichever constant actually produced this incident — makes the incident self-describing without needing to cross-reference this doc. |
| `correlated_event_ids` | array of string | The `event_id`s that were grouped — always ≥ 2. The incident references events; it never duplicates their content. |
| `mitre_techniques` | array of string | The union of `details.mitre_technique` from every correlated event, in event order, **not deduplicated** — two techniques appearing twice is itself a signal (see confidence below), so collapsing it here would throw that away. |
| `severity` | enum: `low` \| `medium` \| `high` \| `critical` | See scoring below. |
| `confidence` | float, `0.0`–`1.0` | Explicitly a v1, rule-based, non-AI estimate — named `confidence` and not `score` on purpose, so M4's own AI-derived value has an obviously distinct field to land in later rather than overwriting this one. |
| `summary` | string | Human-readable, generated (not free text) from the pattern + the correlated events' `scenario`/`status` fields — deterministic, so the same inputs always produce the same summary. |

### Severity and confidence scoring (v1, naive baseline)

Deliberately simple, deliberately documented as naive — this is a
starting point for M3 to build against and for M4 to eventually improve
on, not a claim that rule-based scoring is sufficient long-term.

**Pattern 1 (same-source burst):**
- `severity = "medium"` by default; escalate to `"high"` if **any**
  correlated event has `details.status == "success"` (an attack that
  actually got through is more concerning than two defended attempts).
- `confidence = 0.3`, `+0.2` if escalated to `"high"` above (`0.5` cap in
  v1) — timing-and-source alone is a weak signal on purpose: legitimate
  repeated activity (an operator re-running a scenario after a fix) is
  common enough that this pattern is expected to be noisy, and the
  confidence value should say so honestly rather than overclaiming.

**Pattern 2 (composite dependency+secret):**
- `severity = "high"` by default; escalate to `"critical"` if **both**
  correlated events have `details.status == "success"` (both halves of
  the composite attack landed, not just one).
- `confidence = 0.6`, `+0.15` per event with `status == "success"` (so
  `0.6` / `0.75` / `0.9` depending on 0, 1, or 2 successes) — starts
  meaningfully higher than Pattern 1 because the *type-specific*
  pairing is a much less coincidental signal than shared timing alone.

Both scales stop short of `1.0` everywhere in v1: nothing rule-based
should ever claim total certainty — that ceiling is intentional, not an
oversight to raise later without also changing the underlying method.

## Open questions and explicit non-goals

- **The leaked-secret "misuse" pattern is not in scope here.**
  [`docs/scenarios/leaked-secret.md`](scenarios/leaked-secret.md) already
  describes a third correlation — a leaked credential later *used* to
  authenticate, tagged `T1078` and linked back to the leak event — as a
  goal for M3. That's a genuinely different shape of rule (it needs an
  `api`-sourced `http_request` event carrying evidence of the leaked
  credential, which nothing in today's event schema captures yet) and is
  deliberately deferred to a later design pass rather than bolted onto
  this one.
- **Overlapping/ambiguous window assignment** (an event equidistant
  between two candidate incidents) is resolved by the simple
  first-come-first-grouped rule above for v1. A more principled
  tie-breaker (e.g. nearest-timestamp) is left for whenever real data
  actually produces this case, rather than designed against a
  hypothetical.
- **Storage and ingestion are separate work.** This doc defines the
  rules only; the `events`/`incidents` database tables, the
  `detection-engine/` service structure, and the endpoint that actually
  populates them from real range and attack-sim events are later tasks
  in M3, not covered here.
- **Widening Pattern 2 beyond dependency+secret** to other scenario
  pairs (most plausibly `compromised-ci-step` paired with anything,
  given it's the highest-severity individual scenario) is intentionally
  deferred — see "Why these two specifically" above.
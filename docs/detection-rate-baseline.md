# Detection Rate / False Positive Baseline

A dated, numeric snapshot of how well the three correlation rules in
[`docs/correlation-design.md`](correlation-design.md) perform against a
labeled battery of True Positive (should form the named incident) and
True Negative (should form no incident at all) cases, produced by
[`detection-engine/tests/evaluate_correlation_rules.py`](../detection-engine/tests/evaluate_correlation_rules.py).
Kept for the same reason as
[`docs/m2-detection-baseline.md`](m2-detection-baseline.md): a later
regression (a rule threshold drifting, a new event type nobody scoped
correctly) shows up as a number moving against this baseline instead of
requiring someone to re-derive what "correct" looks like.

## How to reproduce

```bash
cd Bantis/detection-engine
pip install -r requirements.txt
python tests/evaluate_correlation_rules.py
```

Pure unit-level evaluation — synthetic `EventORM` cases, no live server,
no external tools, deterministic every run.

## Baseline: 2026-09-30

### Before: threshold gap found

| Metric | Result |
|---|---|
| Detection rate (5 True Positive cases) | 5/5 = **100.0%** |
| False positive rate (8 True Negative cases) | 2/8 = **25.0%** |

The two false positives: an ordinary 3-request burst to `api`, and a
2-request burst to `nginx` — both completely benign traffic, both
formed a `"same-source-burst"` incident. Root cause: Pattern 1 is
documented as type-agnostic among the events it correlates, but nothing
had ever scoped *which* event types it should consider in the first
place — `http_request` (continuous per-request telemetry) was being
treated the same as a discrete attacker action like
`attack_scenario_run`.

### Fix: scope Pattern 1 to discrete, attacker-relevant event types

`app/correlation.py`'s `_SAME_SOURCE_EXCLUDED_EVENT_TYPES = {"http_request"}`
excludes `http_request` from Pattern 1 eligibility entirely, before
clustering by source ever happens. See
[`docs/correlation-design.md#pattern-1-scope-which-event-types-are-eligible`](correlation-design.md#pattern-1-scope-which-event-types-are-eligible)
for the full reasoning, and
[`docs/threat-model.md`](threat-model.md) for why traffic-volume
detection is out of scope for v1 in the first place.

### After: fix verified

| Metric | Result |
|---|---|
| Detection rate (5 True Positive cases) | 5/5 = **100.0%** |
| False positive rate (8 True Negative cases) | 0/8 = **0.0%** |

Detection rate is unchanged — the fix only removes eligibility for one
event type Patterns 2 and 3 never considered anyway (they're already
scoped by `details.scenario` and `event_type == container_image_pull`
respectively), so no real attack case lost coverage.

## Case battery

**True Positives** (`detection-engine/tests/evaluate_correlation_rules.py::TRUE_POSITIVES`):
1. Composite pair, both defended → `composite-dependency-secret`
2. Composite pair, both succeeded → `composite-dependency-secret`
3. Same-source burst of two distinct attack-sim scenarios → `same-source-burst`
4. A single untrusted-registry image pull → `untrusted-registry-pull`
5. All four M2 scenarios back-to-back → both of the above, together (matches [`docs/m2-detection-baseline.md`](m2-detection-baseline.md))

**True Negatives** (`...::TRUE_NEGATIVES`):
1. Ordinary `api` traffic burst — the false positive fixed here
2. Ordinary `nginx` traffic burst — the false positive fixed here
3. A single isolated attack-sim event (no burst partner)
4. Two attack-sim events from different sources
5. Two attack-sim events outside the correlation window
6. A trusted-registry pull (`docker.io`)
7. A trusted-registry pull (`ghcr.io`)
8. Two `ERROR`-status attack-sim events

## What's intentionally *not* counted as a false positive here

An operator re-running the same attack-sim scenario twice while testing
a fix, close together, still forms a `"same-source-burst"` incident —
this is Pattern 1 working as documented, not a threshold to tighten
further. `docs/correlation-design.md` already prices this in: Pattern 1
is explicitly designed to be noisy for exactly this reason, which is why
its confidence tops out at `0.5` rather than being suppressed outright.
Silencing it would mean an actual two-scenario attack burst from the
same source goes undetected just to avoid a low-confidence, honestly-
labeled false alarm during normal testing — a worse trade than the one
this baseline documents.
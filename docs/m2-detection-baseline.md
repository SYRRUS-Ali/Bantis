# M2 Detection Baseline

A dated snapshot of what happens when all four M2 attack-sim scenarios
run in sequence against a live detection-engine, produced by
[`tests/run_m2_baseline.py`](../tests/run_m2_baseline.py). This is not a
design doc — it's a recorded result, kept so a later regression (a
scenario stops reaching the detection-engine, or a correlation rule
stops firing) shows up as a diff against a known-good run instead of
requiring someone to re-derive what "correct" looks like from scratch.

## How to reproduce

```bash
cd Bantis
BANTIS_ENV=range-local python tests/run_m2_baseline.py
```

Requires `pip install -r detection-engine/requirements.txt -r attack-sim/requirements.txt`
(or the shared `range/.venv`). No real `docker` or `gitleaks` needed —
the script fakes out only those two tools; every other call (`git`,
`pip`) is the real thing running against scratch temp directories, same
approach as `tests/test_e2e_composite_incident.py`.

## Baseline: 2026-09-29

Run three times consecutively; identical result every time (deterministic).

**Scenario outcomes:**

| Scenario | Status | Why |
|---|---|---|
| `malicious-dependency` | `failure` | Mocked `docker compose build` rejects the injected dependency (returncode 1) — the build defended itself. |
| `leaked-secret` | `failure` | Mocked `gitleaks` catches the committed fake AWS key (returncode 1) — the leak was caught. |
| `compromised-ci-step` | `success` | No tool in this environment checks CI workflow diffs for injected steps — the injection lands clean. |
| `typosquatting` | `success` | `pip install` has no package-name-similarity check — the fake `redsi` package (impersonating `redis`) installs without complaint. |

All four scenarios' events reached the detection-engine (4/4) — ingestion
has no gaps for any of the four M2 event shapes.

**Incidents formed (both existing rules fired as documented):**

1. **`composite-dependency-secret`** — `malicious-dependency` + `leaked-secret`,
   severity `high`, confidence `0.6` (0/2 succeeded). Matches
   [`docs/correlation-design.md`](correlation-design.md#pattern-2-composite-dependencysecret):
   both attack halves were defended, so this sits at Pattern 2's baseline,
   not its escalated confidence/severity.
2. **`same-source-burst`** — `compromised-ci-step` + `typosquatting`,
   severity `high`, confidence `0.5` (both succeeded). Matches
   [`docs/correlation-design.md`](correlation-design.md#pattern-1-same-source-burst)'s
   own worked example almost exactly — two independent supply-chain
   attempts from the same source, close together, escalated because at
   least one (here, both) got through undefended.

**Reading this baseline honestly:** the two scenarios that succeeded
(`compromised-ci-step`, `typosquatting`) succeeded because nothing in
this environment specifically defends against them yet — a CI
workflow-diff check and a package-name-similarity check are both gaps in
the *range*, not bugs in attack-sim or the detection engine. The
detection engine did its job regardless: it correctly escalated that
pairing to `"high"` severity via the same-source-burst rule precisely
because both attempts landed. No scenario or correlation-rule fix was
needed to reach this result — this run passed on the first attempt.

## Update: 2026-10-01 — scorecard added

`tests/run_m2_baseline.py` now scores every run through
[`detection-engine/app/scorecard.py`](../detection-engine/app/scorecard.py)
(`generate_scorecard()`) instead of a hand-rolled pattern comparison,
adding **MTTD** (mean time to detect) alongside detection rate and false
positives. Three consecutive runs:

| Run | Detection rate | False positives | MTTD |
|---|---|---|---|
| 1 | 2/2 = 100.0% | 0/2 = 0.0% | 1.87s |
| 2 | 2/2 = 100.0% | 0/2 = 0.0% | 1.53s |
| 3 | 2/2 = 100.0% | 0/2 = 0.0% | 1.55s |

Detection rate and false positives are exactly as stable as the
2026-09-29 baseline above (same underlying rules, same expected
patterns). MTTD varies run to run — it's a measurement of real wall-clock
time between the earliest correlated event's timestamp and the moment
`run_correlation()` forms the incident, in this script dominated by how
long the real `pip install` in `typosquatting` and the real `git`/scratch
I/O in `leaked-secret` take on the machine running it, not by anything
the correlation engine itself controls. ~1.5–2s is this machine's
baseline; a regression worth investigating looks like a large, sustained
jump, not minor run-to-run variance.

## What would fail this baseline

`tests/run_m2_baseline.py` exits non-zero (and prints exactly which
check failed) if any of:
- Fewer than 4 scenario events reach the detection-engine.
- The two incidents formed aren't exactly `composite-dependency-secret`
  and `same-source-burst` (e.g. a third, unexpected incident; one of the
  two missing; or a same-source-burst that also swallows the composite
  pair because ordering broke — see
  [`docs/correlation-design.md`](correlation-design.md)'s claiming rules).
- The scorecard's detection rate drops below 100% or its false-positive
  count rises above 0.

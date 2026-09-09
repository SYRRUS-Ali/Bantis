# M2 Scenarios Plan

This is the master index for the four supply-chain attack scenarios
planned for the attack simulation milestone (M2), first mapped in
[`docs/mitre-mapping.md`](mitre-mapping.md) and scoped by
[`docs/threat-model.md`](threat-model.md) and
[ADR 0005](adr/0005-single-attack-layer-v1.md). Each scenario has its own
detailed writeup in [`docs/scenarios/`](scenarios/); this file is the
overview and build order, not a duplicate of the detail.

## The four scenarios

| # | Scenario | MITRE Primary | MITRE Secondary | Caught by existing CI today? |
|---|---|---|---|---|
| 1 | [Malicious Dependency Injection](scenarios/malicious-dependency.md) | T1195.001 | T1059 | No — novel package, no CVE to match |
| 2 | [Leaked Secret Exploitation](scenarios/leaked-secret.md) | T1552.001 | T1078 | Partially — Gitleaks catches the leak, not later misuse |
| 3 | [Compromised CI Step](scenarios/compromised-ci-step.md) | T1195.002 | T1059 | No — the workflow file is the pipeline's own trust boundary |
| 4 | [Typosquatted Package](scenarios/typosquatting.md) | T1195.001 | T1027 | No — same gap as #1, plus no name-similarity check exists |

## Why these four
They cover the four attacker capabilities already listed as in-scope in
`docs/threat-model.md`: a malicious/unsigned dependency, a leaked
credential, a compromised CI workflow step, and (as a variant of the
dependency case worth testing separately, since the detection signal
differs) a typosquatted package name.

## What this plan deliberately leaves open
Three of the four scenarios (1, 3, 4) have **no existing automated
control** — that's intentional, not an oversight to fix before M2 starts.
Part of what M2 measures is exactly how much a behavioral/runtime
detection layer (M3) adds on top of the static CI scanners already
running (Semgrep, Gitleaks, pip-audit). Scenario 2 is the control case,
since it's the one scanner-covered scenario in the set.

## Suggested build order for M2
1. **Leaked secret** — lowest implementation cost (Gitleaks already runs;
   mainly need to turn its finding into a correlated Bantis incident) and
   gives an early end-to-end pipeline (scanner → event → incident) to
   build the rest against.
2. **Malicious dependency injection** — establishes the runtime-signal
   detection path (build-time payload execution) needed by scenarios 3
   and 4 too.
3. **Typosquatted package** — reuses #2's detection path; adds the
   name-similarity check as a distinct, separately testable control.
4. **Compromised CI step** — highest severity and highest implementation
   cost (needs runner-level anomaly detection, not just app-level
   events); tackled last once the event pipeline is proven on the other
   three.

## Prerequisites before implementation starts
- A safe, repeatable way to inject and then cleanly revert each scenario
  against the range (a script per scenario, not manual edits every time).
- Each scenario's payload must be inert by design (writes a local marker
  / calls a simulator-controlled endpoint) — never a real exfiltration
  target, even inside this self-hosted range.
- The event schema (`docs/event-schema.md`) may need new `event_type`
  values once M3 exists to ingest these — it currently only defines
  `http_request`.

## Open questions
- Where do simulator scripts for these four scenarios live — a new
  `range/attack-sim/` (colocated with the target) or a separate top-level
  `attack-sim/` (mirroring `range/`'s structure)? Not decided yet;
  revisit when M2 implementation actually starts.
- Time-to-detect targets per scenario are referenced in each detail doc
  as "to be set once M3 exists" — no Detection Engine exists yet to
  measure against.

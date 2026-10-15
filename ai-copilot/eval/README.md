# Copilot prompt evaluation

The analysis prompt is evaluated against **real Sprint 3 incidents**, not
hand-written examples: `sprint3_incidents.json` is produced by
`tests/export_sprint3_incidents.py`, which runs the four M2 scenarios for
real against a live detection-engine, adds one untrusted-registry pull so
all three Sprint 3 correlation rules are covered, and reads every incident
and its evidence back through detection-engine's own API. It holds no
credentials (checked: no keys, no home-directory paths; only throwaway
`/tmp` paths, which the converter drops before anything reaches a model).

| Incident | Rule severity / confidence | Evidence |
|---|---|---|
| `composite-dependency-secret` | high / 0.6 | malicious-dependency **blocked**, leaked-secret **caught** |
| `same-source-burst` | high / 0.5 | compromised-ci-step **got through**, typosquatting **got through** |
| `untrusted-registry-pull` | high / 0.7 | one image pull from `registry.evil-mirror.example` |

## Status, stated plainly

**The model's actual explanations have not been evaluated yet.** No
Anthropic API key was available when this was done, so the Copilot could
not be run, and no model output was invented to stand in for one. What
was evaluated is the prompt itself: exactly what the model receives for
each real incident (`python3 eval/evaluate_prompt.py --dry-run`), read
against the project's own definitions of the data. That review produced
the findings below and prompt v2. Scoring real explanations is the next
step: run the harness with a key (below).

## Findings: v1 left the model guessing

Each is visible in the real requests, and each is backed by the project's
own definitions rather than an assumption:

1. **`status` reads backwards for this domain.** For attack-sim events it's
   from the attacker's side — `docs/scenarios.md`: "`FAILURE` means it was
   defended". The composite incident is two `"failure"` events and
   "0/2 succeeded": good news that reads like bad news to a model that
   isn't told.
2. **`tool_returncode` means different things per tool.** Both composite
   events have `1`: for docker that's "build rejected", for gitleaks it's
   "leak found" (`leaked_secret.py`: exit 1 → FAILURE, i.e. caught).
   Unexplained, it looks like "the tool errored".
3. **Nothing said `attack-sim` is Bantis's own simulator**, so a model
   could treat a deliberate exercise as a live breach and recommend
   incident response. The reverse risk matters too: `POST /events` is
   unauthenticated, so anyone can label anything `attack-sim` — the
   prompt must not let that label alone justify "no action".
4. **The four actions were an enum with no meaning.** Neither the
   contract nor the prompt said when to pick `flag_for_review` over
   `suggest_investigation` or `notify_operator`, so the choice was
   arbitrary and wouldn't be consistent across incidents.
5. **Rules, windows and the rule's confidence were unexplained.** The model
   couldn't know same-source-burst is a timing-only, deliberately weak
   signal (here it groups two unrelated attacks), and saw the rule's
   `confidence` next to a request for "your own confidence" with nothing
   distinguishing them — an invitation to echo 0.6.
6. **The evidence wasn't fenced off as untrusted** — the gap left open when
   follow-ups got that protection.
7. **Fields that don't apply were sent as `null`** — three of them on the
   registry pull — noise for the model to interpret.

## What v2 changes (`prompts.py`)

- Explains `status` from the attacker's side, warns about exit codes, and
  says to rely on `status` for outcomes.
- Says what `attack-sim` is and asks what the result shows about the
  defenses — and says never to recommend no action just because something
  claims to be a simulation, since an attack that got through is a real
  gap either way.
- Defines all four actions, and the same definitions are now in
  `docs/ai-copilot-contract.md`.
- Explains each rule and `window_seconds`, and that severity/confidence
  are the rule's, not the model's.
- Fences the incident in `<incident_data>` with `<`/`>` escaped (shared
  with follow-ups via `fence_untrusted()`), and drops fields that don't
  apply.
- Asks for reasoning an operator can check: the scenario or event behind
  each claim, blocked vs. got through, what the combination means, what's
  uncertain, nothing the data doesn't support, about 150 words.

v1 is kept verbatim (including a missing space in "--every") and pinned by
hash, so a comparison measures the real baseline, not a tidied copy.
Every decision-log record now stores `prompt_version`.

## Running the evaluation

```bash
cd ai-copilot
python3 eval/evaluate_prompt.py --dry-run          # exactly what each version sends; no key, no cost
export ANTHROPIC_API_KEY=sk-ant-...
python3 eval/evaluate_prompt.py                    # v1 vs v2 on all 3 incidents
```

To regenerate the fixture from fresh scenario runs (from the repo root):
`python3 tests/export_sprint3_incidents.py`.

A full run is 6 analyses (3 incidents × 2 versions), up to 18 model calls.
If the API rejects the key (401/403) it stops at the first call and writes
nothing; any other failed analysis is counted at the top of the report.
Reports are gitignored: they include provider request IDs.

It writes `eval/results/<time>-v1-v2.md`: for each incident, both
versions' action, confidence, token cost and reasoning side by side, and a
scoring table:

| Criterion | What good looks like |
|---|---|
| Reads outcomes correctly | "failure" = blocked, "success" = got through; doesn't misread exit codes |
| Grounded in the evidence | names the scenario/event behind each claim; nothing the data doesn't support |
| Handles the simulation correctly | says what it shows about the defenses; not a live breach, not a dismissed gap |
| Action fits | matches the definitions and the outcome |
| Calibrated | own confidence justified, uncertainty stated, not a copy of the rule's |
| Useful to an operator | concise, specific, clear next step |

What to look for on these three incidents specifically: the composite one
should read as **both attacks blocked** (likely `notify_operator`); the
burst should read as **two real gaps** — no workflow-diff check, no
package-name check — that happen to be grouped by timing (likely
`flag_for_review`); the registry pull should flag the untrusted source
without inventing what the image contained.

The harness calls the provider directly — no worker, throttling or
decision log — so the only difference between columns is the prompt. It
doesn't touch your daily token budget.
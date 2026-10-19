# M4 Closure: AI Copilot (Sprint 4)

Sprint 4 is M4 in this repo: the AI Copilot. This document closes it —
what was delivered, how it was verified, and what it does not do yet.
Like [`m3-closure.md`](m3-closure.md), it is written to be read cold: a
reader should be able to decide from this page alone whether M4 is safe
to build on, and what must be fixed before anything depends on it.

Sprint 4 ran from 2026-10-06 to 2026-10-18: 53 commits, 36 of them in
`ai-copilot/`, the rest fixing what the Copilot exposed in
detection-engine, the range and CI.

## In one paragraph

Every new correlated incident is now analyzed automatically: the
Copilot reads it from detection-engine, sends an allowlisted summary to
the AI model, validates the reply, records the full reasoning trail in a
tamper-evident log, and answers follow-up questions about it. It **only
recommends** — no code in it can change anything, and every proposed
action requires human approval — and that is enforced in code and
guarded by a test, not left to the prompt. What is **not** established
yet is how good the explanations are: no analysis from the real model
has been reviewed, because no valid API key was available when the
evaluation ran.

## What was delivered

| Task | Delivered | Where |
|---|---|---|
| Design the Copilot's contract | Input allowlist, output schema, closed action vocabulary, failure semantics, security constraints | [`ai-copilot-contract.md`](ai-copilot-contract.md) |
| Build `ai-copilot/` and connect to the Claude API | `AIProvider` abstraction (ADR 0003), `ClaudeProvider`, a manual smoke-test script | `providers/`, `examples/send_test_request.py` |
| Convert an incident's evidence into a structured prompt | `build_copilot_request()`: allowlisted fields, deterministic timeline, UTC times, refuses partial evidence | `converter.py` |
| Parse the model's output with validation and retry | Strict parser; invalid replies retried as a conversation with the exact error, 3 attempts | `parser.py`, `providers/claude.py` |
| Analyze every new incident automatically | Polling worker with lookback, cursor hold and severity ordering; a read-only incident-events endpoint in detection-engine | `worker.py`, `detection_client.py` |
| Store the full reasoning trail per incident | Append-only, hash-chained decision log: request, prompt, every attempt, final response; `show`/`verify` CLI | `decision_log.py` |
| Call the AI only for correlated incidents; fix duplicate calls | `ThrottlePolicy` (≥2 events, 30/hour, most severe first); atomic claims and one decision per incident | `worker.py`, `decision_log.py` |
| Follow-up questions per incident | Authenticated `POST /incidents/{id}/questions`, grounded only in the recorded analysis | `api.py` |
| Token tracking and a daily cap | Per-UTC-day usage from the log, 500k-token budget shared by worker and API, `GET /usage` | `budget.py`, `api.py` |
| Run on Sprint 3 incidents, evaluate, adjust the prompt | Real-incident fixture, prompt review (7 findings), prompt v2, versioned prompts, side-by-side harness — **model outputs not yet scored** | `prompts.py`, `eval/` |
| Fallback when the AI provider is unavailable | Incidents delivered without analysis, nothing decided, retried with backoff; starts without a key | `providers/`, `worker.py`, `api.py` |
| Fix real integration problems | Scheduled correlation, UTC at detection-engine's boundary, range forwarding through compose | `detection-engine/`, `range/compose.yaml` |
| Document the architecture and the recommend-only principle | Architecture, enforcement layers, injection walkthrough, what it doesn't protect against | [`ai-copilot-architecture.md`](ai-copilot-architecture.md) |

## Problems found and fixed

Each was reproduced before it was fixed, and each fix has a test that
fails without it. Root cause and detail are in
[`ai-copilot/README.md`](../ai-copilot/README.md) and
[`detection-engine/README.md`](../detection-engine/README.md#known-issues).

**In the Copilot**

- Malformed model output (a top-level JSON array, `proposed_action` as a
  string) raised an uncaught `TypeError` instead of the contract's
  `analysis_failed`; `confidence: true` was accepted as `1.0`, and
  `"0.7"` and whitespace-only reasoning were accepted too.
- A `</incident_data>` inside an evidence field closed the untrusted-data
  block early in follow-up prompts — a prompt-injection hole.
- An outage longer than 60s while fetching an incident's events dropped
  that incident silently, because newer incidents moved the cursor past it.
- Two workers on one incident made two paid calls and wrote two
  decisions (reproduced with 4 workers).
- Concurrent writers forked the decision log's hash chain (fails every
  run with 8 writers without the write lock).
- A provider outage was recorded as the incident's final
  `analysis_failed`, so it could never be analyzed after recovery; both
  the worker and the API crashed at startup without a key; and the SDK's
  default 600s timeout could stall the worker for half an hour.
- The prompt evaluation harness wrote a report of six identical
  authentication failures that looked like an evaluation had happened.

**Exposed in other components**

- **Nothing correlated in a live deployment.** Only scripts and tests
  called `run_correlation()`: four scenario events arrived and zero
  incidents formed, so the Copilot had nothing to analyze. Every test had
  passed, because every test triggered correlation by hand. Now a
  scheduler runs it every 10s, with an end-to-end test in which nothing
  calls it.
- Scheduled correlation, done naively, lost composite incidents and split
  bursts; passes now wait for incomplete groups, timed by the server's
  `received_at` so a sender can't delay its own incident.
- Concurrent correlation passes created 2–4 copies of one incident, each
  of which would have been a separate paid analysis.
- Timestamps sent with a timezone offset were stored hours off on SQLite,
  so events 30s apart never correlated; `GET /incidents?since=` ignored
  the offset the same way.
- The range's compose file never passed `DETECTION_ENGINE_URL` to the API
  container, so following the documented setup forwarded nothing.
- detection-engine dropped its own INFO logs, including "incident formed".
- CI: an unpinned linter failed the build on unchanged code; new
  advisories against `pyjwt==2.13.0` (upgraded to 2.15.1); a step order
  that turned one lint failure into three misleading errors.

## Verification at closure

Full suites, all passing at closure:

| Component | Tests | At M3 closure |
|---|---|---|
| `ai-copilot/tests` | 241 | — |
| `detection-engine/tests` | 94 | 66 |
| `attack-sim/tests` (with `BANTIS_ENV=range-local`) | 111 | 111 |
| root `tests/` (cross-component end to end) | 5 | 3 |

Plus standalone scripts:

- `tests/run_m2_baseline.py`: 4/4 scenario events arrive, 2/2 expected
  incidents, 100% detection, 0% false positives.
- `detection-engine/tests/evaluate_correlation_rules.py`: 0/8 false
  positives on the labeled battery; passes.
- `ai-copilot/eval/evaluate_prompt.py --dry-run`: renders both prompt
  versions for all three real Sprint 3 incidents.

Beyond the suites, the whole chain was run as separate processes:
attack-sim's four scenarios → a live detection-engine with its scheduler
→ the Copilot worker → the decision log → the follow-up API. The
composite incident was analyzed within seconds and the burst formed 60s
later as one incident; the decision log verified intact; only
allowlisted fields reached the provider. The real range image, built
with compose, forwarded its requests to detection-engine.

**What those runs used:** the real Anthropic SDK and real HTTP, against
a local stand-in for the API that returns a fixed valid analysis. They
prove the plumbing, validation and security boundaries — not the
quality of the model's reasoning.

Fixes were confirmed by removing them and checking that a test fails,
then restoring them. The recommend-only guard
(`tests/test_recommend_only.py`) was confirmed the same way: adding a
`subprocess` call, `os.system`, a `POST` to detection-engine, or an
approve route each makes it fail.

## Known limitations

These are the gaps a reader must know before relying on M4.

### Explanation quality

- **No real model output has been reviewed.** The only recorded run
  against the real Anthropic API returned `401 invalid x-api-key` for all
  six analyses. The prompt itself was reviewed against the real
  incidents, and v2 addresses seven concrete gaps in v1, but whether v2's
  explanations are actually better — or good enough for an operator to
  act on — is unmeasured. The Sprint 4 task "evaluate the explanation
  quality manually" is therefore **only partly done**.
- **The model's confidence is uncalibrated.** It is the model's own
  number, kept separate from the rule's, with nothing yet to check it
  against.
- **Single-event incidents get no AI analysis by default.** The
  untrusted-registry rule produces one-event incidents, which the
  throttling policy skips; lowering `--min-correlated-events` later
  doesn't revisit incidents already recorded as skipped.

### Security

- **detection-engine still has no authentication** — carried from M3,
  and more consequential now: anyone who can reach `POST /events` can
  create incidents that trigger paid AI calls and carry text to the
  model. The Copilot's limits cap the cost; the fix belongs in
  detection-engine.
- **Prompt injection is reduced, not prevented.** Evidence is fenced and
  escaped, and recommend-only bounds a successful injection to a
  misleading recommendation a person reads — but that recommendation can
  still be wrong.
- **The decision log's tamper evidence has limits.** The chain is
  unkeyed: it detects edits and deletions from the middle, but not
  removal of the newest records or a full rewrite by someone who can
  write the file. A test pins this limitation.
- **The follow-up API speaks plain HTTP.** It binds to localhost by
  default and warns otherwise; anything beyond localhost needs TLS in
  front. Credential detection in questions is pattern-based and
  best-effort.

### Operations

- **No approval workflow and no dashboard.** Recommendations reach the
  operator as JSON lines and through `decision_log.py show`; analyses are
  not served over HTTP yet, only follow-ups are. "Approval" has nothing
  to trigger, by design, until a later decision adds an executor.
- **One host, one log file.** Worker and API share state through one
  SQLite decision log; the hourly limit is soft across workers (each
  can take the last slot).
- **Operational detection latency is not measured.** Correlation is now
  scheduled (a burst is reported about 60s after its last event), but
  the M2 baseline still runs one batch correlation, so its MTTD is not a
  live figure.
- **Postgres is still never exercised** in any test.
- **Range forwarding is verified by one manual compose run**, not an
  automated test.

### Process

- **No git tag for Sprint 3 or Sprint 4.** Sprint 1 and 2 were tagged
  (`v0.1.0-range`, `v0.2.0-attacksim`).

## What happened to M3's carried items

| Carried from M3 | Status at M4 closure |
|---|---|
| Authentication on ingestion and the incidents API | **Open** — unchanged |
| Scheduled or ingestion-triggered correlation, so MTTD can be real | **Done** (scheduler); a live MTTD measurement is still open |
| A test of `range/api` forwarding and a real compose run | **Half done** — a real compose run worked after a compose fix; no automated test |
| A Postgres run of the test suite | **Open** |
| Confidence calibration against real incidents | **Open** — still too few real incidents |
| Concurrent correlation passes (left "not proven safe") | **Fixed** — reproduced, then prevented by a database key |

## Carried into the next sprint

Before anything is built on the Copilot's output, the following should
be addressed or consciously accepted:

1. **Score real explanations.** Run `ai-copilot/eval/evaluate_prompt.py`
   with a valid key, score v1 against v2 with the rubric in
   `ai-copilot/eval/README.md`, and adjust the prompt from what the
   model actually wrote.
2. **Authenticate detection-engine** (ingestion and queries) — now the
   most important security gap in the system.
3. **Serve analyses over HTTP** for the dashboard, behind the same
   authentication as the follow-up API.
4. **Anchor the decision log**: keep the latest hash somewhere the log's
   writer can't change, so tail deletion and full rewrites become
   detectable.
5. A Postgres run of both suites, an automated range-forwarding test,
   and a live MTTD measurement with the scheduler on.
6. Tag Sprint 3 and Sprint 4.

Any move from recommend-only toward executing actions is **not** on
this list: per ADR 0004 it needs its own reviewed decision, and
[`ai-copilot-architecture.md`](ai-copilot-architecture.md#changing-the-principle)
lists what that decision must answer first.
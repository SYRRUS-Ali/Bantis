# Response Controller Design: Whitelist, Approval Flow, Kill Switch

**Status: design; skeleton built.** Bantis is recommend-only today
([ADR 0004](adr/0004-recommend-only-default.md)), and stays so until
[ADR 0006](adr/0006-response-actions-and-kill-switch.md) is accepted
**and** the gates below are met. This document is what that ADR decides
on. [`response-controller/`](../response-controller/README.md) has the
action interface, catalog, kill switch and executor rules, and the first
action: A3 `hold_promotion` with its undo B3, plus the CI change below.
Nothing is enabled by default, and nothing should be enabled live before
the gates are met.

It answers the five questions
[`ai-copilot-architecture.md`](ai-copilot-architecture.md#changing-the-principle)
sets for any move away from recommend-only:

| Question | Answered in |
|---|---|
| Which actions, exactly, and how are they undone? | [The action catalog](#the-action-catalog) |
| Where does execution run? | [Components and separation](#components-and-separation) |
| What is an approval? | [The approval flow](#the-approval-flow) |
| Is the input trustworthy enough? | [Gates before anything executes](#gates-before-anything-executes) |
| What stops a burst of approvals or actions? | [Limits](#limits) and [The kill switch](#the-kill-switch) |

## Principles

1. **The AI never causes an action.** Executable actions are proposed by
   a deterministic policy from detection-engine's rule-based incident
   facts. The AI Copilot's analysis is shown next to a proposal as
   context for a human; it cannot trigger, cancel, widen or parameterize
   an action. A prompt injection therefore gains nothing here — it can
   neither start containment nor suppress it.
2. **Nothing executes on free text.** An action's parameters are
   computed by the response controller from verified facts (a promotion
   history, a recorded image digest), never taken from model output or
   copied from an event's free-text fields.
3. **Auto-execution only in the safe direction.** An action on the
   whitelist adds evidence or friction — it preserves, notifies or holds.
   It never removes a running service, deletes data, or changes code.
4. **Every action has a tested undo**, or is purely additive.
5. **Stopping is easy; resuming is deliberate.** Anyone with host access
   can halt execution with one command and no approval; resuming needs
   an approver, a reason and a record.
6. **Fail closed.** If the controller can't read the kill switch, write
   its audit log, or verify an approval, it doesn't act.

## Components and separation

```
 detection-engine ──GET incidents──▶ response controller (new, separate process + OS user)
                                        │  policy: incident facts → proposals
                                        │  executor: approved/whitelisted → act
                                        │  reads kill switch before every action
                                        ▼
                                   action log (hash-chained, anchored)
                                        ▲                      │ scoped credentials
 operator ──approve / reject / kill──────┘                      ▼
                                              GitHub repo variable, workflow dispatch,
                                              range nginx config, Telegram, evidence store

 ai-copilot (unchanged: no capability; its analysis is read for display only)
```

Three roles, never combined in one component:

| Role | Who | Can |
|---|---|---|
| **Proposer** | the controller's policy | Turn incident facts into proposals from the catalog |
| **Approver** | a human operator | Approve or reject one exact proposal |
| **Executor** | the controller's executor | Carry out a proposal that is whitelisted or approved, once |

The AI Copilot holds none of them. It stays a component with no way to
act, and `ai-copilot/tests/test_recommend_only.py` stays in force
unchanged: execution lives in a different component, with different
credentials, so the process that reads attacker-influenced text never
holds the keys to act.

The controller runs as its own OS user. It can read the kill switch but
not write it, and each of its credentials covers exactly one action
type (a separate token per capability, below).

## The action catalog

### Eligibility for the whitelist

An action may be auto-executed only if **all** of these hold:

| Criterion | Why |
|---|---|
| Purely additive, or reversible by a documented, tested undo | A wrong action must be cheap to correct |
| Moves in the safe direction: preserves, notifies or holds; never stops a service or deletes anything | A false positive must not become an outage Bantis caused |
| One named target inside Bantis's own scope | Bounded blast radius |
| Idempotent | Retries and duplicate incidents are harmless |
| Parameters derived from verified facts, never free text | Injection can't choose the target |
| Triggered by the deterministic policy, not by AI output | See Principle 1 |
| Covered by limits and the kill switch, with a dry-run mode and tests | It can be stopped and checked |

### Tier A — auto-eligible (the whitelist)

| ID | Action | Trigger (policy) | Effect | Undo | Credential |
|---|---|---|---|---|---|
| A1 | `preserve_evidence` | Every incident with severity ≥ `high` | Write the incident and its **raw** events to a local, append-only evidence store with a content hash in the action log | None needed — additive. Retention policy deletes, never the controller | Local file write, evidence directory only |
| A2 | `notify_channel` | Every incident with severity ≥ `high`; at most one per incident | Send a fixed plain-text template to the operator's Telegram chat: pattern, severity, incident id, outcome counts | None needed — additive | Telegram bot token |
| A3 | `hold_promotion` | `composite-dependency-secret` with ≥1 attack that **got through**, or `untrusted-registry-pull` | Set repository variable `BANTIS_PROMOTION_HOLD` so CI's `promote-latest` job skips: a possibly-compromised build can't become `:latest`. Running services are untouched | B3 (`lift_promotion_hold`), approval required — a hold never lifts itself | Fine-grained GitHub token, this repository only, *Variables: write* |

Notes:

- **A1's raw events can contain secrets** (`tool_output_tail` from a real
  gitleaks run). The evidence store therefore stays inside Bantis's
  boundary: local disk, readable only by the operator, never sent to the
  AI provider or the notification channel.
- **A2's message is a fixed template filled from rule-based fields**
  (`pattern`, `severity`, `incident_id`, counts). No event text and no AI
  text goes into it: event fields can carry attacker-written content, and
  a notification is not a place to render it. Sent as plain text, not
  Markdown.
- **A3's CI change is in place:** `promote-latest` runs only while
  `vars.BANTIS_PROMOTION_HOLD` is empty; a `Promotion Held` job warns on
  the run instead, and the notification reports `held`.
- **A3 holds rather than reverts.** It stops the next promotion, which is
  reversible and leaves production as it is. Reverting what is already
  `:latest` is B1, a separate, approved decision. A hold that lifted
  itself after a timeout would re-open the path for the build it was
  protecting against, so lifting it is always a human's call.
- **A3 is also a denial-of-service lever** for anyone who can create
  incidents: forging one untrusted-registry event would freeze releases.
  That is why A3 requires authenticated ingestion (gate G1), at most one
  active hold, and why the hold is visible in every notification until
  lifted.

### Tier B — approval required

| ID | Action | Proposed when | Effect | Parameters | Undo | Credential |
|---|---|---|---|---|---|---|
| B1 | `rollback_latest` | An A3 hold is active, or a composite incident with an attack that got through | Dispatch CI's existing `rollback` workflow: `:latest` → a previously promoted image | Target SHA chosen **by the controller** as the last image promoted before the incident's first event; the approver may pick another SHA only from the recorded promotion history | B1 again, to the SHA it replaced | GitHub token, *Actions: write*, used only to dispatch `ci.yml` |
| B2 | `block_client_ip` | Range `http_request` events from one client IP correlated with an incident | Add a `deny` rule to the range's nginx config and reload | IP from the range's own nginx events — shown with a provenance warning while ingestion is unauthenticated | Remove the rule; every rule also carries an expiry (default 24h) | Write access to one generated include file in the range's nginx config, and a reload |
| B3 | `lift_promotion_hold` | An operator asks | Unset `BANTIS_PROMOTION_HOLD` | — | A3 | Same as A3 |

B2 needs one change to the range: nginx's config is mounted read-only
from `range/nginx/default.conf` today, so the deny rules would go in a
separate, generated include file that the controller alone writes, and
`default.conf` would include it. The controller never edits
`default.conf` itself.

Tier B is not "Tier A with a button". Each one can affect availability
(B1, B2) or reopen a path (B3), which is exactly where a human has to
decide.

### Tier C — never automated, not offered

| Action | Why not |
|---|---|
| Revoking or rotating credentials | Bantis holds no credentials for the range's systems, and shouldn't; rotation is the owner's process |
| Deleting images, data, branches or logs | Irreversible, and destroys evidence |
| Changing source code or CI workflow definitions | That is the supply chain under attack |
| Stopping the range, its database, or host services | An outage Bantis would cause itself |
| Firewall or host changes beyond the range's nginx | Outside Bantis's scope (ADR 0001) |
| Anything a model writes in free text | Principle 2 |

Adding to the catalog, or moving an action between tiers, needs its own
reviewed decision (an ADR amendment), not a configuration change.

## The approval flow

### A proposal

```json
{
  "action_id": "act_6f1c…",
  "incident_id": "1c9a3f2e-…",
  "type": "rollback_latest",
  "params": {"target_sha": "3d07256", "replaces_sha": "9a41e0b"},
  "policy_rule": "B1:composite-success",
  "created_at": "2026-10-20T09:12:00Z",
  "expires_at": "2026-10-20T10:12:00Z",
  "required_approvals": 1,
  "proposal_hash": "sha256 of the canonical JSON of every field above"
}
```

The approver is shown the proposal, its `proposal_hash`, the incident's
rule-based facts, the AI Copilot's recorded analysis (labeled as AI
output), the undo, and any provenance warning.

### States

```
              ┌──────────── expired (no execution; can be re-proposed)
              │
 proposed ──▶ pending ──▶ approved ──▶ executing ──▶ succeeded ──▶ (undone)
              │              │              │
              │              │              └──▶ failed  (post-check failed → tripwire)
              │              └──▶ invalidated (kill switch engaged, or preconditions changed)
              └──▶ rejected (reason required)

 Tier A skips "pending": proposed ──▶ executing, unless the kill switch is at auto-off.
```

### Rules

1. **An approval binds to one exact proposal.** The approver confirms by
   entering the first 12 characters of `proposal_hash`. The executor
   recomputes the hash at execution time; any change to type, params,
   incident or expiry means no execution. Approving X can only ever
   execute X.
2. **Approvals expire.** A proposal not approved within its window
   (default 60 minutes; 30 for B2) expires. A stale approval doesn't sit
   waiting for the moment it becomes wrong.
3. **Approvers authenticate separately.** v1 approval is a local CLI on
   the host (`responder approve <action_id> <hash-prefix>`), requiring
   the operator's host access plus an approver secret that is not the
   Copilot's API token and not any executor credential. An HTTP approval
   endpoint comes later, only behind the dashboard's authentication, TLS
   and CSRF protection.
4. **Rejections need a reason** and are recorded. They are the most
   useful signal for tuning the policy.
5. **Preconditions are re-checked at execution.** The incident still
   exists, the rollback target still exists in the promotion history,
   the hold is still active, and the kill switch is clear. Otherwise the
   proposal is `invalidated`.
6. **Execute once.** `action_id` is the idempotency key. A retry after a
   crash checks the action log and the target's actual state first.
7. **Verify the effect.** After acting, the controller checks the
   post-condition (the variable is set; `:latest` resolves to the target
   digest; nginx serves the deny rule). A failed check marks the action
   `failed` and trips the kill switch.
8. **Two-person rule, ready but off.** `required_approvals` is a field
   from day one. The threat model has a single operator in v1, so it's 1.
   With more operators it becomes 2 for B1, with approvers required to
   differ.
9. **Everything is recorded** in the action log: proposal, every state
   change, who approved or rejected and why, the executor's request and
   response, the post-check, the undo. It uses the decision log's
   hash-chain design, with the latest hash anchored outside the
   controller's write access (gate G2).

## Limits

| Limit | Default | When exceeded |
|---|---|---|
| Tier-A executions per hour, all types | 5 | Tripwire: kill switch to `auto-off` |
| Active promotion holds | 1 | No new A3; the existing hold is re-notified |
| A2 notifications per incident | 1 | Not sent |
| A2 notifications per hour | 10 | One summary message, then silence until the hour ends |
| Pending proposals | 20 | New proposals are recorded as `suppressed`, and the operator is notified once |
| B1 rollbacks per 24h | 2 | Not proposed; needs a manual workflow run |

The limits are counted from the action log, so they hold across
restarts. A burst is a signal in itself: the response to "too many
actions" is to stop, not to keep going more slowly.

## The kill switch

### Levels

| Level | Effect | Typical use |
|---|---|---|
| `clear` | Normal operation | — |
| `auto-off` | No Tier-A auto-execution. Tier-A actions become approval-required; approved actions still run | The policy is misfiring |
| `execution-off` | Nothing executes. Proposals are still recorded. **Approvals already granted are invalidated** and must be re-approved after resuming, so a backlog can't fire all at once | Something is wrong with the controller or its inputs |
| `ai-off` (independent) | The AI Copilot makes no model calls. Incidents are delivered without analysis, and follow-ups return `503` — its existing fallback path | Provider compromise, cost runaway, injection campaign |

`ai-off` can be combined with either execution level.

### Mechanism

- **State lives in two files** in `$BANTIS_STATE_DIR`. `kill-switch` is
  the operator's: the controller and the Copilot can read it, not write
  it. `kill-switch.tripped` is the only file the controller can write,
  for its tripwires, and it can only add restriction. The effective
  state is the more restrictive of the two. Each holds the level, who
  set it, when, and why.
- **Fail closed.** A missing state directory or operator file, a
  permission error, an unparseable file, or an unknown level are all
  treated as `execution-off` + `ai-off`. Only a readable file saying `clear` allows
  execution.
- **Checked at the last moment.** The executor reads the switch
  immediately before every external call, not once per poll. A
  multi-step action re-checks between steps. A step already in flight
  finishes (each step is single and idempotent); no new step starts.
- **The Copilot checks it** before every model call (`ai-off`).

### Engaging and resuming

| | Engage | Resume |
|---|---|---|
| Who | Anyone with host access, or an automatic tripwire | An approver |
| How | `responder kill --level execution-off --reason "…"` — or, if everything else is broken, writing the level into the file by hand (documented) | `responder resume --reason "…"` plus the approver secret |
| Approval | None — stopping must never wait | Required, and recorded |
| Works when | The controller is down, the network is down, the log is unreachable | The controller and its action log are healthy |

Resuming takes the switch to `clear`, removes `kill-switch.tripped`,
**and** invalidates every approval granted before or during the stop.

### Automatic tripwires

These can engage the switch, never clear it:

| Tripwire | Level |
|---|---|
| Tier-A executions over the hourly limit | `auto-off` |
| A post-condition check fails, or an undo fails | `execution-off` |
| `verify` fails on the action log or the decision log | `execution-off` |
| The action log can't be written ("can't record, so don't act") | `execution-off` |
| The AI token budget is exhausted twice in one day | `ai-off` |

Every engagement, manual or automatic, sends one A2-style notification
with the level and reason. That notification bypasses the A2 hourly
limit, but not the kill switch for anything else.

### Drills

A kill switch that has never been pulled is a hypothesis. The
controller's test suite must prove, at minimum, that:

- each level blocks what it should, with a pending action ready to run;
- an unreadable or garbled state file blocks everything;
- resuming invalidates earlier approvals;
- a tripwire engages the switch but can't clear it.

An operator drill (engage, confirm nothing runs, resume) is part of
enabling any action for the first time.

## Gates before anything executes

ADR 0006 can be accepted as a design before these exist. No action is
enabled until all of them do:

| Gate | Why |
|---|---|
| **G1 — authenticated ingestion in detection-engine** | Every trigger is an incident. While anyone can `POST /events`, anyone can trigger A3 (freezing releases) or flood A1/A2 |
| **G2 — anchored action log** | Execution needs an audit trail that the executor itself can't truncate or rewrite: the latest hash is kept where the controller can't write |
| **G3 — separate process, OS user and per-action credentials** | The component holding the keys must not be the one reading model output; each token covers one action type |
| **G4 — kill switch implemented and drilled** | It must exist before the first thing it is meant to stop |
| **G5 — every action ships disabled** | Each action is enabled individually, by configuration, after its own dry run |

## Rollout

| Phase | Enables | Exit criterion |
|---|---|---|
| 0 (now) | Nothing. This design | ADR 0006 reviewed |
| 1 | Kill switch, action log, approval flow; A1 and A2 auto | G1–G4 met; switch drills pass; two weeks without a false notification |
| 2 | A3 **approval-only**, then auto | A3 proposals in phase 2a approved as proposed with no rejections for false positives |
| 3 | B1, B2, B3 | Phase 2 stable; rollback rehearsed in staging |

Every phase starts in dry-run mode: the controller records what it
would have done, and nothing executes until an operator has compared
that record with what should have happened.

## What this design does not do

- **It doesn't make the AI more trusted.** The AI's role is unchanged;
  it explains, and is shown to the approver as AI output.
- **It doesn't remove the human from containment that costs
  availability.** Only additive or holding actions are ever automatic.
- **It doesn't defend against a compromised operator or host.** Someone
  with host access can approve, resume or edit configuration; the action
  log makes that visible, not impossible.
- **It doesn't cover the AI provider's own failures** beyond `ai-off`.

# ADR 0006: Response Action Whitelist, Manual Approval Flow, and Kill Switch

**Date:** 2026-10-20
**Status:** Proposed

## Context
[ADR 0004](0004-recommend-only-default.md) makes Bantis recommend-only
and allows "a narrow, explicitly configured whitelist of safe,
reversible actions" to be auto-executed later, as a separate, reviewed
decision. This is that decision. Detection is now automatic (scheduled
correlation) and every incident is analyzed (M4), so the remaining gap
between detecting a supply-chain attack and containing it is a human
noticing a JSON line. At the same time, the inputs that would trigger
any action are still attacker-influenced: detection-engine's ingestion
is unauthenticated, and the AI reads text attackers can write.

## Decision
Introduce a **response controller**, the component ADR 0001 already
names, separate from the AI Copilot, as designed in
[`docs/response-controller-design.md`](../response-controller-design.md):

- **Actions come from a deterministic policy over rule-based incident
  facts, never from AI output.** The AI cannot trigger, cancel, widen or
  parameterize an action; its analysis is shown to the approver as
  context.
- **A three-tier catalog.** Tier A, auto-eligible: `preserve_evidence`,
  `notify_channel`, `hold_promotion`. These are purely additive or
  hold-only, and reversible. Tier B, approval required:
  `rollback_latest`, `block_client_ip`, `lift_promotion_hold`,
  `rollback_action` (compensation of a recorded execution). Tier C is
  never offered: credentials, deletion, code, stopping services, host
  changes.
- **Approval binds to one exact proposal** (by hash), expires, is given
  through a separate approver credential, is re-checked at execution,
  executes once, and is verified afterwards. All of it is recorded in a
  hash-chained, externally anchored action log.
- **A fail-closed kill switch** with levels `auto-off`, `execution-off`
  and `ai-off`. Anyone with host access can engage it without approval;
  resuming requires an approver and invalidates earlier approvals.
  Automatic tripwires can engage it, never clear it.
- **Nothing is enabled until five gates are met**: authenticated
  ingestion (G1), an anchored action log (G2), a separate process with
  per-action credentials (G3), a drilled kill switch (G4), and every
  action shipping disabled (G5). Rollout is phased, starting in dry-run.

ADR 0004 remains the default and stays in force for the AI Copilot,
whose no-capability guard test is unchanged.

### Amendment: rollback of recorded executions

`rollback_action` is tier B and disabled by default. An authenticated operator
queues it against the hash of an executed proposal, supplies a reason, and then
approves the new proposal through the existing review flow. It retains the
original approval count and always requires fresh approval, even when undoing
an automatic hold. The snapshot is committed to the hash-chained journal before
the original effect; the new proposal binds to that snapshot's entry hash.

Each reversible implementation provides a read-only snapshot and a tested
compensation. The implemented promotion hold and release restore the exact
previous value or absence on the recorded repository API target. State drift
blocks compensation. Dry run, the kill switch, verification and audit failures
have the same behavior as other actions. A failed or interrupted attempt with a
saved snapshot can be reviewed for rollback; an execution without a snapshot
requires manual recovery. Purely additive actions remain irreversible.

This operation restores target state. It cannot cancel a deployment or other
downstream operation that already happened while promotions were allowed.

## Consequences
- Containment that preserves, notifies or holds can happen without
  waiting for a human; anything costing availability still waits for
  one.
- A successful prompt injection still gains nothing executable: the AI
  is outside the action path entirely.
- `hold_promotion` gives anyone able to create incidents a way to freeze
  releases. That is why G1 is a hard prerequisite, there is a single
  active hold, and lifting a hold is always manual.
- New operational surface: an action log to anchor, approver secrets to
  manage, a kill switch to drill.
- Adding an action or changing its tier needs an amendment to this ADR,
  not a configuration change.

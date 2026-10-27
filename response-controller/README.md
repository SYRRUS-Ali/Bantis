# response-controller

The skeleton of the response controller designed in
[`docs/response-controller-design.md`](../docs/response-controller-design.md)
under [ADR 0006](../docs/adr/0006-response-actions-and-kill-switch.md)
(**Proposed**). It is a separate component from `ai-copilot/`, which
keeps no capability to act.

**What exists:** the general interface every action implements, the
closed catalog, the proposal and approval model, the kill switch, and an
executor that enforces the design's rules in order.

**What doesn't:** any concrete action. No action is implemented, nothing
is enabled by default, and the default mode is dry run, so nothing in
this directory can affect anything outside its state directory. Each
real action, the hash-chained action log (G2), the policy that turns
incidents into proposals, and the approver-authenticated `resume` and
`approve` commands are separate, later steps.

## Structure

```
response-controller/
├── catalog.py          # the six catalog actions and their tiers (A: auto-eligible, B: approval), undo pairs
├── models.py           # Proposal (immutable, hashed), Approval (bound to a hash prefix), Outcome, Status
├── actions/base.py     # Action: the interface every action implements; ActionParams; StepGuard
├── registry.py         # catalog type → implementation; refuses anything outside the catalog
├── executor.py         # decides whether a proposal may run, and runs it; Recorder protocol
├── kill_switch.py      # read_state (fail closed), engage (operator), trip (tripwires)
├── config.py           # state directory, enabled actions, dry run — from the environment
├── cli.py              # `status`, `kill`
├── ruff.toml
└── tests/
```

## The action interface

Every action is a subclass of `actions.base.Action`:

| Member | Contract |
|---|---|
| `type` | A catalog name. The registry refuses anything else. |
| `params_model` | A subclass of `ActionParams`: unknown keys rejected, no type coercion, immutable. |
| `preconditions(proposal, params)` | Read-only. Why it can't run now; empty when it can. |
| `plan(proposal, params)` | Read-only. One line saying what `execute` would do — the dry-run record and what an approver reads. |
| `execute(proposal, params, guard)` | Does it. Idempotent per `action_id`. Calls `guard.check()` before every step with an external effect. |
| `verify(proposal, params, result)` | Read-only. Whether the effect is actually in place now. |

An action never decides *whether* to run. That's the executor's job,
before any effectful method is called:

1. The type is in the catalog and has an implementation.
2. The action is enabled in configuration (G5).
3. The parameters validate strictly against the action's model.
4. The `action_id` hasn't been executed before.
5. The proposal hasn't expired.
6. Every approval presented matches this exact proposal's hash. A
   mismatched approval is refused, never ignored.
7. The kill switch allows execution. It fails closed.
8. There are enough *distinct* approvers, when the tier — or `auto-off`
   — requires approval. Approvals only count if given inside the
   proposal's window.
9. The action's preconditions hold.
10. In dry run, the plan is recorded and nothing else happens.
11. `executing` is recorded first. If it can't be recorded, the action
    doesn't run, and the switch trips.
12. Execution, with the switch re-read right before the first step and
    before every step after it.
13. Verification. A failed or raising post-check, or an action that
    raises, trips the switch to `execution-off`.

## The kill switch

| File (in `$BANTIS_STATE_DIR`) | Written by | Can |
|---|---|---|
| `kill-switch` | The operator (`cli.py kill`), never the controller | Set any level; `kill` never lowers it |
| `kill-switch.tripped` | The controller's tripwires | Only add restriction; can never clear |

The effective state is the more restrictive of the two. A missing,
unreadable or malformed operator file, or an unreadable tripwire file,
means `execution-off` with AI calls off. Only a readable file saying
`clear` allows execution. Both files are replaced atomically.

This split resolves a conflict in the design: tripwires must be able to
engage the switch, but the controller must not be able to write the
operator's switch. Its own file can only make things stricter.

```bash
export BANTIS_STATE_DIR=/var/lib/bantis      # operator-owned; the controller's user gets read access
                                             # plus write access to kill-switch.tripped only
python3 cli.py status
python3 cli.py kill --reason "investigating" [--level auto-off] [--ai-off]
```

**Resuming is not built yet.** It needs the approver secret (design,
"Engaging and resuming"). Until it exists, clearing is a deliberate
manual step by the operator. Write the operator file with
`{"level": "clear", "ai_off": false, "reason": "...", "set_by": "..."}`
and delete `kill-switch.tripped`. Because no action is implemented, this
can't cause anything to run.

## Configuration

| Variable | Default | |
|---|---|---|
| `BANTIS_STATE_DIR` | none — required | Holds the kill switch |
| `RESPONSE_ENABLED_ACTIONS` | empty | Comma-separated catalog names; anything else fails at startup |
| `RESPONSE_DRY_RUN` | `true` | Only `false` makes execution live |

## Separation from the AI

`tests/test_separation.py` fails if anything here imports the Anthropic
SDK or an `ai-copilot` module, or reaches another component through
`sys.path`. Proposals come from incident facts, never from model output
(design, Principle 1).

## Running the tests

```bash
cd response-controller
pip install -r requirements.txt -r tests/requirements.txt
python3 -m pytest tests -q
```

Each rule above was checked by removing it and confirming a test fails.
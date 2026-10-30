# response-controller

The response controller designed in
[`docs/response-controller-design.md`](../docs/response-controller-design.md)
under [ADR 0006](../docs/adr/0006-response-actions-and-kill-switch.md)
(**Proposed**). It is a separate component from `ai-copilot/`, which
keeps no capability to act.

**What exists:** the general interface every action implements, the
closed catalog, the proposal and approval model, the kill switch, an
executor that enforces the design's rules in order, and the first real
action: the CI quarantine (`hold_promotion`) with its undo
(`lift_promotion_hold`).

**What doesn't:** the hash-chained action log (G2), the policy that
turns incidents into proposals, the approver-authenticated `resume` and
`approve` commands, and the other four actions. Nothing is enabled by
default and the default mode is dry run. **Don't enable anything live
until the gates in the design are met** — above all G1, authenticated
ingestion in detection-engine: until then, anyone who can post an event
could trigger a quarantine and freeze releases.

## Structure

```
response-controller/
├── catalog.py          # the six catalog actions and their tiers (A: auto-eligible, B: approval), undo pairs
├── models.py           # Proposal (immutable, hashed), Approval (bound to a hash prefix), Outcome, Status
├── actions/base.py     # Action: the interface every action implements; ActionParams; StepGuard
├── registry.py         # catalog type → implementation; refuses anything outside the catalog
├── executor.py         # decides whether a proposal may run, and runs it; Recorder protocol
├── actions/promotion_hold.py  # A3 hold_promotion (the CI quarantine) and B3 lift_promotion_hold
├── github_client.py    # repository-variables API only; https only; the token never reaches a message
├── wiring.py           # builds the registry, one credential per capability
├── kill_switch.py      # read_state (fail closed), engage (operator), trip (tripwires)
├── config.py           # state directory, enabled actions, dry run — from the environment
├── cli.py              # `status`, `kill`, `promotion-hold` (read-only)
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

## The CI quarantine (`hold_promotion`)

The first real action, tier A. It quarantines the CI pipeline's output:
it sets the repository variable `BANTIS_PROMOTION_HOLD`, and while that
is set, CI's `promote-latest` job skips, so **no build — including the
suspect one — becomes `:latest`**. Instead, a `Promotion Held` job puts
a warning on the run, and the Telegram notification says 🔒 `held`
instead of ✅ `success`.

Why it qualifies for auto-execution (design, "Eligibility"):

- **It holds, it doesn't remove.** Running services and published
  images are untouched. Reverting `:latest` is `rollback_latest`, a
  separate decision that needs approval.
- **One fixed target.** The repository comes from configuration and the
  variable name is a constant. A proposal can't carry parameters at all
  (`NoParams`), so nothing in an incident can choose what is written
  where. The only proposal data in the value, the incident and action
  ids, must be plain identifiers.
- **Idempotent, and never overwrites.** If a hold already exists —
  this one after a retry, or another one — it's left as is. The design
  allows at most one active hold, so a second quarantine is
  `invalidated` while one is active.
- **Verified.** After writing, the variable is read back. If it isn't
  there, the action fails and trips the kill switch.
- **A tested undo.** `lift_promotion_hold` deletes the variable. It is
  tier B: a hold never lifts itself, and lifting one always needs an
  approval.

Failure behavior:

| What happens | Outcome |
|---|---|
| GitHub unreachable or erroring while checking | `invalidated`; nothing written; switch not tripped |
| GitHub rejects the write (e.g. 403: wrong token scope) | `failed`; kill switch trips to `execution-off` |
| The write didn't stick (read-back fails) | `failed`; kill switch trips |
| Kill switch engaged | `invalidated` before any request to GitHub |

**The credential** is a fine-grained personal access token limited to
this one repository, with only **Variables: Read and write**. It needs no
contents, actions, secrets or admin access. If it leaks, the worst it
can do is set or remove repository variables.

```bash
export RESPONSE_GITHUB_REPO=owner/repo
export RESPONSE_GITHUB_TOKEN_PROMOTION=github_pat_...   # Variables: read and write, this repo only
python3 cli.py promotion-hold                           # read-only: is a quarantine active?
```

If a hold must be lifted while `approve` doesn't exist yet, the operator
can delete the variable in GitHub (Settings → Secrets and variables →
Actions → Variables). That is the same effect as `lift_promotion_hold`,
done by hand.

All of it is tested against a local stand-in for GitHub's API
(`tests/fake_github.py`), with the real HTTP client, so no test touches
a real repository.

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
| `RESPONSE_GITHUB_REPO` | none | `owner/name` the promotion hold applies to |
| `RESPONSE_GITHUB_TOKEN_PROMOTION` | none | Fine-grained token: this repo, *Variables: write* only |
| `RESPONSE_GITHUB_API_URL` | `https://api.github.com` | https only (plain http only to loopback, for tests) |

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
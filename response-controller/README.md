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
The local manual review queue now supports **Approve / Modify / Dismiss**,
with authenticated operator decisions and a persistent, hash-chained audit trail.

**What doesn't:** external anchoring of the action log (G2), the policy that
turns incidents into proposals, the approver-authenticated `resume`
command, and the other four actions. Nothing is enabled by
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
├── approval_flow.py    # persistent SQLite review queue and serialized Approve / Modify / Dismiss decisions
├── actions/promotion_hold.py  # A3 hold_promotion (the CI quarantine) and B3 lift_promotion_hold
├── github_client.py    # repository-variables API only; https only; the token never reaches a message
├── wiring.py           # builds the registry, one credential per capability
├── kill_switch.py      # read_state (fail closed), engage (operator), trip (tripwires)
├── config.py           # state directory, enabled actions, dry run — from the environment
├── cli.py              # review commands, `status`, `kill`, `promotion-hold` (read-only)
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

An operator can queue a `lift_promotion_hold` proposal and approve it
through the manual review flow below. The executor still checks the
enabled actions, dry-run mode, kill switch and current hold first.

All of it is tested against a local stand-in for GitHub's API
(`tests/fake_github.py`), with the real HTTP client, so no test touches
a real repository.

## Manual review: Approve / Modify / Dismiss

Review is a **local CLI**, as specified by the design; there is no HTTP
approval endpoint. Proposals come from trusted policy facts or deliberate
operator requests, never from AI output. The policy producer is not built
yet, so `propose` accepts a proposal JSON file using the fields documented
in the [design](../docs/response-controller-design.md#a-proposal).
Only implemented action types and valid action parameters are accepted.

The review database and lock file live at
`$BANTIS_STATE_DIR/reviews.sqlite3` and `reviews.sqlite3.lock`. The operator
needs write access there. These files are created with mode `0600`; keep
the state directory within the operator's access boundary. Each decision
is serialized through execution, and the execution marker is committed
before an action can have an external effect. A crash after that marker
requires investigation, rather than automatically replaying the action.

Configure `RESPONSE_APPROVER_SECRET_FILE` to an operator-owned, nonempty
secret file with mode `0600` or `0400`. Use a dedicated approval secret,
separate from provider tokens and executor credentials. Decision commands
prompt without echoing the secret; it is never a command-line argument or
an audit field. The recorded identity comes from the OS user ID, rather
than an operator-supplied name. Read commands and queuing a proposal rely
on trusted host access; approval, modification and dismissal additionally
require the secret.

```bash
cd response-controller
export BANTIS_STATE_DIR=/path/to/operator-state
export RESPONSE_APPROVER_SECRET_FILE=/path/to/private-approver-secret
export RESPONSE_ENABLED_ACTIONS=lift_promotion_hold
# RESPONSE_DRY_RUN defaults to true. Creating and reviewing proposals never enables live mode.

python3 cli.py propose proposal.json
python3 cli.py pending
python3 cli.py show act_example
python3 cli.py approve act_example 0123456789ab
python3 cli.py modify act_example 0123456789ab --params-file params.json --reason "Correct the target"
python3 cli.py dismiss act_example 0123456789ab --reason "False positive"
```

Replace the example ID and hash prefix with values from `show`. The
`approve` command confirms the exact displayed proposal with at least the
first 12 hash characters, then calls the existing executor. Required
approvals accumulate across CLI invocations and must come from distinct
OS identities. In dry run, the executor records the plan without acting;
that review is closed, so a later live run needs a new proposal.

`modify` accepts a JSON object replacing only the action parameters. It
validates them against the action's schema, requires a reason, closes the
old proposal and creates a linked replacement with a new ID and hash.
The action type, incident, policy, approval count and expiry stay fixed.
The replacement starts with **no approvals** and must be reviewed again;
modification never executes an action. The currently implemented hold
and lift actions accept only `{}`; parameterized actions can use the same
flow when their implementations are added.

`dismiss` requires a reason, records the decision and permanently closes
the proposal without execution. Closed proposals, expired proposals and
stale hashes cannot be approved, modified or dismissed again. `show`
includes the persisted decision and execution history; `pending` omits
closed and expired proposals.

**The SQLite journal is hash-chained, but external anchoring required by
G2 remains an operator deployment responsibility.** It supplies durable
local review and replay protection. ADR 0006 remains Proposed and all
deployment gates still apply. No dashboard, automated policy producer, authenticated
resume or new action implementation is introduced here.

## Audit trail

Every executor attempt records `requested` and a final `outcome`, including
refused, expired, invalidated, awaiting-approval and dry-run attempts. A live
execution additionally records `executing` before external effects,
`executed` with the action's structured result, `verification_started`, and
`verified` with the post-check result or error. If execution raises or the
switch interrupts it, the final outcome records the failure or halt;
verification events only exist if verification was reached. A crash can leave
an incomplete attempt, which must be investigated rather than replayed.

Executor events carry the OS executor identity (`actor`), the initiating
operator or policy (`initiated_by`), a unique `attempt_id`, a UTC `at`
timestamp captured at each event, the action and incident IDs, action type,
proposal and proposal hash. The request also preserves the presented
approvals. Review events retain their operator, timestamp and reason, and
modifications link both proposal IDs. Lifting a promotion hold uses the same
trail as any other action. Action results are structured summaries; approval
secrets, executor credentials and raw HTTP headers are never added as audit
fields.

Manual CLI kill-switch engagements and executor tripwires are also recorded
with identity, timestamp, restriction and reason. Emergency stopping happens
first and remains available when the journal is broken; the CLI returns a
nonzero status and explains when the stop succeeded but auditing failed.

Each journal row has an ordered sequence, previous hash and SHA-256 hash
covering the sequence, previous hash and exact stored payload. Appends verify
the existing chain inside a SQLite write transaction. Corruption prevents
further appends and execution. A failed pre-execution audit write prevents
the external effect and trips the switch. An audit failure after an effect
returns `failed` with an investigation reason and trips the switch; the
external effect may already have happened and is never reported as an
unaudited success.

```bash
cd response-controller
# Uses BANTIS_STATE_DIR, as do the review commands.
python3 cli.py audit                          # Ordered JSON lines, including hashes
python3 cli.py audit --action-id act_example
python3 cli.py audit --actor operator         # Reviewer, initiator or executor
python3 cli.py audit-verify                   # Prints count and current head hash
python3 cli.py audit-verify --expected-head <trusted-head-hash>
```

`show` also includes verified history for its proposal. Audit commands need
trusted host access but do not prompt for an approval secret. Verification
errors return exit code 2, and export verifies before emitting any records.
Exported lines may contain sensitive incident and proposal details; keep them
within the same access boundary as the private review database.

**Checkpoint handling:** retain the `audit-verify` head hash in an
operator-controlled location outside the controller's write access. Compare
it with `--expected-head` while the journal is unchanged. This comparison
catches tail truncation; ordinary chain verification detects edits and gaps
but cannot detect a complete rewrite or deletion of a valid suffix by someone
who can rewrite the database. A prior head will also differ after legitimate
new appends, so checkpoint comparisons require a known journal boundary.
Automatic publication to an external checkpoint store is not implemented.

Existing review databases are upgraded transactionally on first open. Their
original payloads are preserved and given an initial chain baseline; missing
historical actors or timestamps are not invented. This baseline does not
prove the authenticity of records written before the upgrade. Back up the
journal before upgrading. Once upgraded, missing or invalid row hashes are
reported as corruption and are never silently rebuilt.

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
and delete `kill-switch.tripped`. Review the enabled actions and dry-run
configuration before clearing the switch.

## Configuration

| Variable | Default | |
|---|---|---|
| `BANTIS_STATE_DIR` | none — required | Holds the kill switch |
| `RESPONSE_ENABLED_ACTIONS` | empty | Comma-separated catalog names; anything else fails at startup |
| `RESPONSE_DRY_RUN` | `true` | Only `false` makes execution live |
| `RESPONSE_APPROVER_SECRET_FILE` | none | Operator-owned private file; required by `approve`, `modify`, `dismiss` |
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

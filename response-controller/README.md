# response-controller

The response controller designed in
[`docs/response-controller-design.md`](../docs/response-controller-design.md)
under [ADR 0006](../docs/adr/0006-response-actions-and-kill-switch.md)
(**Proposed**). It is a separate component from `ai-copilot/`, which
keeps no capability to act.

Read the [current design](../docs/response-controller-design.md) for components,
state transitions, rollback, and deployment gates. The
[security guarantees](../docs/response-controller-security.md) map each control
to its implementation and tests, and describe the assumptions and remaining gaps.

**What exists:** the general interface every action implements, the
closed catalog, the proposal and approval model, the kill switch, an
executor that enforces the design's rules in order, and the first real
action: the CI quarantine (`hold_promotion`) with its undo
(`lift_promotion_hold`).
The local manual review queue now supports **Approve / Modify / Dismiss**,
with authenticated operator decisions and a persistent, hash-chained audit trail.
An opt-in automatic runner supports only `hold_promotion`, pinned to one
repository and policy rule, with durable attempt limits.
The `sync` bridge now builds proposals from detection incidents and joins
the matching Copilot decision-log recommendation as review context.
Executed holds and hold releases can be rolled back through a separate,
authenticated proposal that restores their saved prior state.

**What doesn't:** external anchoring of the action log (G2), the approver-authenticated `resume`
command, and the other four actions. Nothing is enabled by
default and the default mode is dry run. **Don't enable anything live
until the gates in the design are met** — above all G1, authenticated
ingestion in detection-engine: until then, anyone who can post an event
could trigger a quarantine and freeze releases.

## Structure

```
response-controller/
├── catalog.py          # catalog actions and their tiers (A: auto-eligible, B: approval), undo pairs
├── models.py           # Proposal (immutable, hashed), Approval (bound to a hash prefix), Outcome, Status
├── actions/base.py     # Action: the interface every action implements; ActionParams; StepGuard
├── registry.py         # catalog type → implementation; refuses anything outside the catalog
├── executor.py         # decides whether a proposal may run, and runs it; Recorder protocol
├── automatic.py        # automatic reservation checks: one attempt per incident, rolling hourly cap
├── incident_policy.py  # detection facts → fixed promotion-hold proposals
├── incident_client.py  # read-only, paginated detection-engine HTTP client
├── recommendations.py  # read-only, verified decision-log snapshot for review context
├── bridge.py           # idempotent proposal ingestion and optional guarded execution
├── approval_flow.py    # persistent SQLite review queue and serialized Approve / Modify / Dismiss decisions
├── rollback.py         # audited rollback snapshots and approval-only compensating actions
├── actions/promotion_hold.py  # A3 hold_promotion (the CI quarantine) and B3 lift_promotion_hold
├── github_client.py    # repository-variables API only; https only; the token never reaches a message
├── wiring.py           # builds the registry, one credential per capability
├── emergency_button.py # local Tk emergency stop button; shares the CLI stop path
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
| `automatic_scope` | The implementation's fixed target; defaults to no automatic support. |
| `prepare_rollback(proposal, params)` | Read-only prior state, persisted before execution; `None` for irreversible actions. |
| `reversal(proposal, state)` | Build a compensating action from the audited prior state; reject unsupported rollback. |
| `execute_prepared(proposal, params, guard, state)` | Execute with the durable snapshot; reversible implementations recheck the captured target state before acting. |
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
8. There are enough *distinct* approvers unless the proposal matches the
   explicit automatic scope and the switch is clear. Approvals only count
   if given inside the proposal's window. A partial manual approval never
   falls back to automatic execution.
9. The action's preconditions hold.
10. In dry run, the plan is recorded and nothing else happens.
11. Automatic attempts reserve a durable slot, then `executing` is
    recorded before any effect. A failed write prevents execution and
    trips the switch.
12. Persist rollback state for reversible actions, then execute, with the switch
    re-read before the first effectful step and before each subsequent effect.
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

## Rollback of an executed action

From `response-controller/`, enable `rollback_action` alongside the actions you
already use. It remains disabled by default:

```bash
export RESPONSE_ENABLED_ACTIONS=hold_promotion,lift_promotion_hold,rollback_action
python3 cli.py show ORIGINAL_ACTION_ID
python3 cli.py rollback ORIGINAL_ACTION_ID ORIGINAL_HASH_PREFIX --reason "False positive confirmed"
python3 cli.py show ROLLBACK_ACTION_ID
python3 cli.py approve ROLLBACK_ACTION_ID ROLLBACK_HASH_PREFIX
```

Use the IDs and hash prefixes printed by the commands; prefixes must contain
at least 12 characters. Requesting rollback and approving it both authenticate
with `RESPONSE_APPROVER_SECRET_FILE`. Requesting only queues the proposal and
never changes the target. Approval follows the configured dry-run mode and kill
switch. The rollback keeps the original approval count and cannot run automatically.

`show ROLLBACK_ACTION_ID` includes the captured state in its proposal history
so the operator can inspect the exact target and previous value before approval.
The journal saves the configured API target and exact previous hold value
before the original external effect. Rollback of `hold_promotion` removes that
hold; rollback of `lift_promotion_hold` restores the value it removed. A target
already in its prior state succeeds without writing. A changed repository API
target or an unrelated current hold blocks rollback. GitHub's variable API has
no conditional delete: the controller checks immediately before writing, but
cannot atomically exclude a concurrent external writer. Coordinate other writers
to this variable during rollback.

Repeated requests return the same pending rollback. An attempted rollback cannot
be replayed after a restart; inspect failures before manual recovery. A dismissed,
expired or dry-run proposal can be requested again. Rollback proposals cannot be
modified: dismiss and request a new review instead. A completed rollback can
itself be rolled back through the same flow.

The original proposal can have expired: rollback gets a fresh review window.
Failed or interrupted executions with a saved snapshot are also eligible, since
they may have changed the target. Legacy executions without snapshots and
irreversible actions require manual recovery. Future action implementations must
provide snapshot and compensation hooks to support this command. Restoring a
hold cannot undo releases already promoted while it was absent. The audit
history retains both executions, their linkage, reason, operators and results.

## Limited automatic execution

Automatic execution is disabled by default. Enabling an action with
`RESPONSE_ENABLED_ACTIONS` alone permits manual review; it no longer makes
Tier-A actions automatically executable. To opt in, configure the single
supported action, `hold_promotion`, and an exact repository allowlist entry.
The configured GitHub client's repository must match this entry exactly.
Proposals cannot supply a repository, variable name, or custom parameters.

The automatic scope is deliberately small:

| Boundary | Enforcement |
|---|---|
| Action | Only `hold_promotion`; every other action needs approval |
| Target | One repository; only its fixed `BANTIS_PROMOTION_HOLD` variable |
| Trigger | Exact `RESPONSE_AUTO_POLICY_RULE` match; default `A3:composite-success` |
| Approval count | Only proposals requiring one approval are auto-eligible; two-person proposals stay manual |
| Incident | At most one automatic attempt per incident for the lifetime of the journal |
| Rate | At most five automatic attempts per rolling hour; configurable down to one |
| Active holds | One; an existing hold is never overwritten |
| Undo | `lift_promotion_hold` still requires authenticated approval |
| Stop | `auto-off` requires approval; `execution-off` blocks everything |

`hold_promotion` pauses CI promotion without changing running services or
removing published images. IP blocking remains an approval-only catalog
action. The deployment gates in the design still apply; this runner does
not establish authenticated ingestion or external audit anchoring.

Start with the checked-in dry-run profile:

```bash
cd response-controller
# Edit the two repository placeholders in the example to the same approved repository.
source examples/limited-auto.env.example
export BANTIS_STATE_DIR=/path/to/existing-controller-state
# Supply RESPONSE_GITHUB_TOKEN_PROMOTION through your credential environment.
python3 cli.py status
```

Keep the operator kill switch clear only after reviewing the enabled
actions and target. Queue a trusted policy proposal with `params: {}` and
`policy_rule: "A3:composite-success"`, then pass its returned action ID to
the runner:

```bash
python3 cli.py propose proposal.json
python3 cli.py auto-run act_example
python3 cli.py show act_example
python3 cli.py audit-verify
```

`auto-run` executes one queued proposal without an approval prompt. A
trusted host-side policy process or scheduler can invoke it with the
queued action ID; incident-to-proposal generation remains separate.
It returns `0` for success or a dry run, `1` for a blocked or unsuccessful
attempt, and `2` for invalid input, a closed proposal, or a storage error.
Pending proposals with manual approvals must continue through `approve`.
Out-of-scope proposals remain awaiting approval and have no external effect.

The example caps attempts at one per rolling hour and keeps
`RESPONSE_DRY_RUN=true`. After inspecting the recorded plan and completing
the deployment gates, explicitly set `RESPONSE_DRY_RUN=false` and submit a
new proposal. A dry-run proposal is closed and cannot be replayed live.
No profile is loaded automatically and no live repository is enabled by
this change.

Automatic attempts use hash-chained `automatic_reserved` events in the
same SQLite journal as reviews. Each reservation records the action,
incident, proposal hash, actor, timestamp, repository and configured limit.
Counting and reserving happen in one write transaction, so concurrent
processes and restarts share the same budget. Reservations consume a slot
even if the process crashes or the switch stops the action before its first
effect; uncertain attempts are never automatically replayed. Dry runs and
precondition failures do not consume slots. Manual approved execution does
not consume the automatic budget.

Exceeding the hourly budget trips `auto-off` and leaves the proposal
awaiting manual approval. The tripwire stays engaged after the hour ends;
resuming requires deliberate operator intervention as documented below.
Failed execution, verification or audit writes still trip `execution-off`.

## Copilot-to-controller bridge

The controller joins two independent inputs by `incident_id`: detection-engine
facts determine executable proposals, and Copilot recommendations provide
labeled review context. The Copilot keeps its existing recommend-only
contract and receives no controller credentials or execution endpoint.

```text
Detection incidents + evidence ── deterministic policy ── proposal ── executor
                                                        │
Copilot worker ── verified decision log ── review context ┘
```

The implemented policy is limited to the existing `hold_promotion` action:

| Incident | Required evidence | Policy rule |
|---|---|---|
| `composite-dependency-secret` | Exactly the incident's dependency and secret scenario events from `attack-sim`, with at least one `success` | `A3:composite-success` |
| `untrusted-registry-pull` | The incident's single container-pull event with an explicit registry outside `docker.io` and `ghcr.io` | `A3:untrusted-registry` |

Missing, duplicate or malformed evidence prevents ingestion. Summaries,
model confidence, recommendation types and free-text descriptions never
select action types, targets or parameters. Every generated proposal has
empty parameters and a deterministic action ID. Its expiry is one hour
after the incident was created, so rescanning old incidents cannot give
them a fresh execution window. Other incident patterns receive no action
from this policy.

Run the Copilot worker normally with its durable decision log, then point
the controller at the same database using a path readable by its OS user.
The controller opens that database read-only and never imports Copilot
code or the provider SDK.

```bash
cd response-controller
export BANTIS_STATE_DIR=/path/to/existing-controller-state
export DETECTION_ENGINE_URL=http://127.0.0.1:8001
export BANTIS_DECISION_LOG=/path/to/copilot/decision_log.db

# Explicit backlog boundary; fetch all pages and queue eligible proposals.
python3 cli.py sync --since 2026-11-07T00:00:00Z
python3 cli.py pending
python3 cli.py show act_example

# Optionally attempt execution through the existing bounded automatic mode.
python3 cli.py sync --since 2026-11-07T00:00:00Z --execute
python3 cli.py audit-verify
```

Replace `act_example` with an action ID returned by `sync`. A host scheduler
can repeat `sync` with the same boundary: existing proposals, approvals and
closed actions are preserved. There is no new network listener or callback
from the model process. `--execute` does not enable an action, bypass
approval, disable dry-run, or clear the kill switch. Without the explicit
automatic configuration above, proposals remain awaiting manual approval.
The default automatic policy rule permits the composite-success case only;
the registry-pull rule needs its own explicit rule selection or approval.

`show` includes the incident facts, allowlisted evidence outcomes and a
Copilot context block labeled **untrusted review context**. Validated
recommendations include their record ID and source hash for cross-reference.
Raw model attempts, prompts and the Copilot request are not copied into
the controller journal. Copilot's `requires_approval` field describes its
informational recommendation; executable approvals remain bound to the
controller proposal's hash.

Source facts and context are journaled with proposal creation in one
transaction. Concurrent bridge runs create one proposal. Identical scans
add no duplicate context records. Late analysis updates the context of
the existing proposal and any modified replacement, including closed
proposals, without changing their hashes, inheriting approvals or replaying
execution. An expired incident is never newly queued.

A missing decision log, skipped analysis or failed analysis is displayed
explicitly and does not suppress a qualifying incident policy action.
Unsupported recommendation fields or executable recommendation types are
marked invalid context. A hash-chain failure, inconsistent incident identity,
or unreadable existing decision database trips `execution-off` and `ai-off`
before ingestion or execution. Local hash verification does not replace
the external anchoring required by the deployment design.

`sync` returns `0` after a successful scan, including approval-pending
proposals; `1` if an attempted execution was refused, invalidated or failed;
and `2` for invalid configuration, source or storage errors. Detection API
failures can be retried without creating another proposal. Scans are
committed per incident, so a failed scan can have already processed earlier
incidents; deterministic IDs make the retry safe.

## Manual review: Approve / Modify / Dismiss

Review is a **local CLI**, as specified by the design; there is no HTTP
approval endpoint. Proposals come from trusted policy facts or deliberate
operator requests, never from AI output. The bridge supplies the promotion-hold
policy; `propose` also accepts a proposal JSON file using the fields documented
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
than an operator-supplied name. Read commands and ordinary proposal submission
rely on trusted host access; approval, modification, dismissal, and rollback
requests additionally require the secret.

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
deployment gates still apply. A dashboard, authenticated resume and the
remaining catalog action implementations are still pending.

## Audit trail

Every executor attempt records `requested` and a final `outcome`, including
refused, expired, invalidated, awaiting-approval and dry-run attempts. A live
execution additionally records `executing` before external effects,
`executed` with the action's structured result, `verification_started`, and
`verified` with the post-check result or error. If execution raises or the
switch interrupts it, the final outcome records the failure or halt;
verification events only exist if verification was reached. A crash can leave
an incomplete attempt, which must be investigated rather than replayed.
Automatic live attempts also record `automatic_reserved` before `executing`.

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

### Emergency stop

Set `BANTIS_STATE_DIR` to the same existing state directory used by the
controller and Copilot, then open the local operator button:

```bash
cd response-controller
export BANTIS_STATE_DIR=/path/to/operator-state
python3 cli.py emergency-button
```

Click **EMERGENCY STOP** once. There is no approval or confirmation prompt.
The button engages `execution-off` and `ai-off`, blocking approved actions
as well as automatic actions and new AI model calls. The window requires
Python's Tk support and a graphical display. On a server or without Tk,
use the equivalent command:

```bash
python3 cli.py emergency-stop
python3 cli.py status
```

An optional `--reason "Incident investigation"` replaces the default
operator emergency reason. `kill` remains available for a narrower stop.
Both stop commands work even if `RESPONSE_ENABLED_ACTIONS` or
`RESPONSE_DRY_RUN` is invalid. They require local write access to the state
directory; no network connection or approval secret is needed.

The stop is persisted **before** attempting audit logging. The command
prints confirmation immediately after persisting it. Exit code `0` means
stopped and audited, `1` means stopped but audit logging failed, and `2`
means the stop could not be written or its configuration was invalid.
The button displays these outcomes and permits retrying a failed stop.

The executor re-reads the switch before execution and between action
steps. An external request already in flight can finish; stopping cannot
undo an effect already sent. No subsequent guarded step starts after the
stop is observed. New AI model calls are disabled; in-flight calls are not
cancelled. Monitoring and incident ingestion continue.

Concurrent operator and tripwire writers serialize their read/merge/write
operations using a local directory lock, preserving the strongest level
and any existing AI stop. Readers remain independent of this lock. Use a
local filesystem with advisory locking support. A malformed operator
switch remains fully stopped when an operator requests a milder stop.


| File (in `$BANTIS_STATE_DIR`) | Written by | Can |
|---|---|---|
| `kill-switch` | The operator (`cli.py kill`), never the controller | Set any level; `kill` never lowers it |
| `kill-switch.tripped` | The controller's tripwires | Only add restriction; can never clear |

The effective state is the more restrictive of the two. A missing,
unreadable or malformed operator file, or an unreadable tripwire file,
means `execution-off` with AI calls off. A valid operator file is required;
`auto-off` still permits approved execution. Both files are replaced atomically.

The two writers are logical roles. Deployment must enforce their OS permissions;
the Python modules do not provision separate accounts or prevent a privileged
writer from replacing either file. Provisioning must also account for the
directory access needed by atomic replacement, journal creation, and lock files.
The stop-writing APIs themselves only add restriction.

```bash
export BANTIS_STATE_DIR=/path/to/operator-state  # provision and verify deployment permissions separately
python3 cli.py status
python3 cli.py kill --reason "investigating" [--level auto-off] [--ai-off]
```

**Resuming is not built yet.** The planned command requires the approver secret
and approval invalidation (see the design's "Kill switch and recovery").
Until it exists, clearing is a deliberate
manual step by the operator. Write the operator file with
`{"level": "clear", "ai_off": false, "reason": "...", "set_by": "..."}`
and delete `kill-switch.tripped`. Review the enabled actions and dry-run
configuration before clearing the switch.

Stopping does not globally revoke stored approvals. Review pending partial
approvals and incomplete execution attempts before restoring permission; dismiss
and re-propose when a fresh review is needed. The planned authenticated `resume`
command will need to enforce approval invalidation explicitly.

## Configuration

| Variable | Default | |
|---|---|---|
| `BANTIS_STATE_DIR` | none — required | Holds the kill switch |
| `RESPONSE_ENABLED_ACTIONS` | empty | Comma-separated catalog names; anything else fails at startup |
| `RESPONSE_DRY_RUN` | `true` | Only `false` makes execution live |
| `RESPONSE_AUTO_ACTION` | empty | Only `hold_promotion` is accepted; empty means all actions require approval |
| `RESPONSE_AUTO_REPO` | empty | Required for automatic mode; exact `owner/name`, matching `RESPONSE_GITHUB_REPO` |
| `RESPONSE_AUTO_POLICY_RULE` | `A3:composite-success` | Exact policy rule eligible for automatic execution |
| `RESPONSE_AUTO_MAX_PER_HOUR` | `5` | Automatic attempt cap per rolling hour; integer from 1 to 5 |
| `RESPONSE_APPROVER_SECRET_FILE` | none | Operator-owned private file; required by `approve`, `modify`, `dismiss`, `rollback` |
| `RESPONSE_GITHUB_REPO` | none | `owner/name` the promotion hold applies to |
| `RESPONSE_GITHUB_TOKEN_PROMOTION` | none | Fine-grained token: this repo, *Variables: write* only |
| `RESPONSE_GITHUB_API_URL` | `https://api.github.com` | https only (plain http only to loopback, for tests) |
| `DETECTION_ENGINE_URL` | `http://127.0.0.1:8001` | Detection incidents API used by `sync`; `--detection-url` overrides |
| `BANTIS_DECISION_LOG` | none | Optional read-only Copilot decision database for `sync`; `--decision-log` overrides |

## Separation from the AI

`tests/test_separation.py` fails if anything here imports the Anthropic
SDK or an `ai-copilot` module, or reaches another component through
`sys.path`. Proposals come from incident facts, never from model output
(design, Principle 1). The recommendation reader only supplies context;
the deterministic policy does not accept recommendations as an input.

## Running the tests

```bash
cd response-controller
pip install -r requirements.txt -r tests/requirements.txt
python3 -m pytest tests -q
```

Each rule above was checked by removing it and confirming a test fails.

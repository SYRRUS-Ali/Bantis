# Response Controller Security Guarantees

## Scope and assumptions

This document describes controls enforced by the current controller, their test
evidence, and their limits. The [design](response-controller-design.md) explains
the execution path; the [component guide](../response-controller/README.md)
documents commands. [ADR 0006](adr/0006-response-actions-and-kill-switch.md)
remains Proposed, and its live-deployment gates remain in force.

The trusted boundary includes controller code, host configuration, OS identities,
the state directory, approver secret files, and scoped executor credentials.
An attacker controlling these can bypass local controls. Dedicated OS accounts,
filesystem ownership, backups, and credential scopes must be provisioned by the
operator. Tests do not prove those properties for a running deployment.

The CLI and optional dashboard process bridge authenticate the operator using
the host's OS identity and private secret file. Dashboard review additionally
requires a dashboard session and rejects foreign browser origins. Every browser
session shares the dashboard host identity, so multiple sessions cannot provide
distinct approvals. The bridge exposes only incident-scoped pending proposals
and Approve/Modify/Dismiss; it never accepts an actor or configuration from the
browser. See [dashboard review tests](../dashboard/tests/test_response.py) and
[bridge tests](../response-controller/tests/test_dashboard_review.py).
The review flow supplies serialization. Python library methods accept
actor and approval objects from their caller; they are not a separate remote
authentication boundary. Guarantees about concurrent review apply to cooperating
processes using the same journal and lock file, not independent hosts or a caller
bypassing the review flow.

## Trust boundaries and threats

| Input or boundary | Treatment | Remaining risk |
|---|---|---|
| Detection incidents and evidence | Validate structure, exact event membership, and deterministic trigger conditions | Ingestion is unauthenticated; fabricated events can satisfy the policy and freeze promotions |
| Copilot recommendations | Verify the decision chain, restrict the display schema, label as untrusted, exclude from policy inputs | Prose can mislead a human; corrupt local context intentionally causes a fail-stop |
| Host operator | OS identity plus a separate prompted secret for approval, modification, dismissal, and rollback requests | A compromised account or secret is inside the trusted boundary |
| Proposal file and parameters | Catalog, implementation, enablement, strict parameter schema, expiry, and hash-bound review | Submission relies on trusted host access; hashing does not authenticate the proposer |
| GitHub repository API | Configured target, scoped Variables credential, HTTPS except loopback tests, post-checks | Remote availability and concurrent external writers remain outside the local transaction |
| Local SQLite journal and stop files | Chain verification, transactional appends, host locks, durable pre-effect markers, fail-closed reads | No protection against a privileged host writer replacing state or rebuilding a chain |

## Enforced invariants and evidence

The linked tests are executable examples of these claims. They use local
stand-ins, not production credentials or repositories.

| Guarantee | Implementation | Representative evidence |
|---|---|---|
| Nothing is enabled or automatic by default; dry run is the default | [config.py](../response-controller/config.py) | [test_automatic.py](../response-controller/tests/test_automatic.py): `test_automatic_execution_is_disabled_by_default` |
| Unknown, unimplemented, disabled, or malformed actions cannot reach their external effect | [registry.py](../response-controller/registry.py), [executor.py](../response-controller/executor.py) | [test_executor.py](../response-controller/tests/test_executor.py): `test_a_catalog_type_without_an_implementation_is_refused`, `test_parameters_that_dont_fit_the_action_exactly_are_refused` |
| Approval of one proposal cannot authorize changed fields or a different action | [models.py](../response-controller/models.py), [approval_flow.py](../response-controller/approval_flow.py) | [test_executor.py](../response-controller/tests/test_executor.py): `test_approving_x_can_never_execute_a_changed_x`; [test_approval_flow.py](../response-controller/tests/test_approval_flow.py): `test_modifying_invalidates_old_approvals_and_preserves_scope` |
| CLI review requires a private operator-owned secret; duplicate identities do not provide extra approvals | [cli.py](../response-controller/cli.py), [executor.py](../response-controller/executor.py) | [test_cli.py](../response-controller/tests/test_cli.py): `test_cli_missing_or_public_secret_is_refused`; [test_executor.py](../response-controller/tests/test_executor.py): `test_two_person_rule_needs_two_different_approvers` |
| Automatic execution is restricted to the configured hold, repository, rule, approval count, and rolling attempt budget | [automatic.py](../response-controller/automatic.py), [executor.py](../response-controller/executor.py) | [test_automatic.py](../response-controller/tests/test_automatic.py): `test_out_of_scope_proposals_require_approval`, `test_concurrent_connections_cannot_overbook_the_budget_or_incident` |
| A committed execution marker blocks replay after restart or a crash, even if success was never recorded | [approval_flow.py](../response-controller/approval_flow.py) | [test_approval_flow.py](../response-controller/tests/test_approval_flow.py): `test_crash_after_executing_marker_cannot_replay` |
| Missing or corrupt stop state blocks execution; engaging a stop blocks subsequent effectful steps | [kill_switch.py](../response-controller/kill_switch.py), [executor.py](../response-controller/executor.py) | [test_kill_switch.py](../response-controller/tests/test_kill_switch.py): `test_a_garbled_tripwire_file_halts_everything`; [test_executor.py](../response-controller/tests/test_executor.py): `test_engaging_mid_action_stops_the_next_step` |
| A pre-effect audit failure blocks the effect; a later failure reports uncertainty and trips the stop | [executor.py](../response-controller/executor.py) | [test_audit.py](../response-controller/tests/test_audit.py): `test_audit_write_failure_stops_or_reports_uncertain_effect` |
| Chain mutation is detected; tail deletion is detected when compared with a trusted checkpoint | [approval_flow.py](../response-controller/approval_flow.py) | [test_audit.py](../response-controller/tests/test_audit.py): `test_corruption_is_detected_and_cannot_be_extended`, `test_trusted_checkpoint_detects_tail_deletion` |
| Rollback state is durable before effects, restoration requires fresh review, and unrelated state is not deliberately overwritten | [rollback.py](../response-controller/rollback.py), [promotion_hold.py](../response-controller/actions/promotion_hold.py) | [test_rollback.py](../response-controller/tests/test_rollback.py): `test_snapshot_is_durable_before_any_external_effect`, `test_rollback_keeps_the_original_number_of_approvals`, `test_state_drift_after_rollback_snapshot_blocks_compensation` |
| Model advice cannot choose, suppress, or parameterize containment in the policy path | [bridge.py](../response-controller/bridge.py), [incident_policy.py](../response-controller/incident_policy.py) | [test_bridge.py](../response-controller/tests/test_bridge.py): `test_recommendation_cannot_trigger_or_suppress_containment`; [test_separation.py](../response-controller/tests/test_separation.py): `test_nothing_imports_an_ai_copilot_module` |

The root [integration suite](../tests/test_e2e_response_bridge.py) exercises the
detection API, Copilot worker, controller processes, local GitHub API, and audit
journal together. Its rollback case checks authentication, a fresh approval,
restart persistence, and that synchronization cannot reinstate a rolled-back hold.

## Failure behavior

| Failure | Controller behavior | Operator implication |
|---|---|---|
| Expired or mismatched approval | Refuse or expire without a target write | Review the current proposal or request a new one |
| Preconditions cannot be checked | Invalidate without acting; ordinary precondition errors do not trip the stop | Restore target availability and reassess |
| Automatic rate exhausted | Trip `auto-off`; approval is required | Inspect the event burst before considering manual execution |
| Missing or malformed operator stop, or corrupt existing tripwire | Execution off and AI off | Repair state deliberately; absence of a tripwire alone is normal |
| Action raises or post-check fails | Record failure and trip execution off | The target may already have changed |
| Required audit write fails before effect | Block the effect and attempt to persist the stop | Inspect storage and stop state |
| Audit write fails after effect | Return failure and attempt to persist the stop | Inspect remote state; the effect is not automatically undone |
| Decision chain fails during `sync` | Stop synchronization; trip execution off and AI off | Investigate the decision database before restoring operation |
| Process exits after `executing` | Original ID cannot be retried through the review flow | Reconcile the journal and target; review rollback if a snapshot exists |
| Emergency-stop audit fails | Stop is engaged first; CLI reports the audit failure | Check `status` rather than treating a nonzero exit as proof the stop failed |
| Stop state cannot be written | Report the error; a critical log is possible for tripwire failure | A durable stop cannot be assumed on an unwritable host |

`audit-verify` and other read commands report integrity errors; invoking a read
command is not itself a guarantee that a stop file was written. Execution paths
fail closed when they cannot record their requests.

## Boundaries of the guarantees

### Availability and event provenance

The hold prevents future CI promotion while the workflow observes the variable;
it does not revoke an already published image or cancel an in-flight promotion.
An attacker able to inject accepted events can cause a denial of service by
freezing releases. Deterministic policy and schema validation do not replace G1
authentication. A valid event is evidence to inspect, not an authenticated
attestation of an attack.

### Local persistence and remote transactions

SQLite commits, filesystem locks, and GitHub writes are not a single atomic
transaction. Execution markers provide at-most-once attempts through the review
flow, not exactly-once remote outcomes. A stopped or failed operation may have
partially completed. The kill switch cannot cancel an HTTP request already in
flight. Rollback checks recorded state and target identity, but the variable API
has no conditional delete; coordinate other writers during state changes.

### Integrity, confidentiality, and retention

The audit chain covers ordered event payloads. It is not encryption, a signature,
or independent verification of the proposal and approval tables. A privileged
writer can replace the database or recompute a consistent chain. Tail deletion
requires an independently retained checkpoint to detect; a freshly computed head
cannot prove that history is complete. External anchoring and backup retention
are not automated by the controller.

Approval secrets and authorization headers are not intentional audit fields,
and the GitHub client keeps its token out of its representation and network
error messages. This is not universal redaction: prior hold values, operator
reasons, parameters, and recommendation text may be sensitive. Restrict the
whole state directory and exported logs. The default file creation mode does
not repair permissions on an existing database or configure deployment users.

### Recovery and approval invalidation

There is no authenticated `resume` command. Stops do not globally revoke stored
approvals; pending partial approvals can survive a stop. Manual recovery must
inspect those approvals before restoring execution. A rollback cannot undo
downstream releases, and legacy executions without snapshots need manual
reconciliation. Future irreversible or catalog-only actions do not acquire a
safe compensation merely by being listed in `UNDO`.

## Operator verification

These checks inspect the current configuration and state without enabling live
execution. Run from `response-controller/` with `BANTIS_STATE_DIR` pointing at
the intended state directory:

```bash
python3 cli.py status
python3 cli.py pending
python3 cli.py audit-verify
python3 cli.py audit --action-id ACTUAL_ACTION_ID
```

Compare with a checkpoint retained outside the controller's write access:

```bash
python3 cli.py audit-verify --expected-head "$TRUSTED_HEAD"
```

`TRUSTED_HEAD` must be the saved head for the checkpoint being compared. An
exact-head mismatch also occurs after legitimate appends; reconcile those events
with the trusted checkpoint record rather than declaring all mismatches attacks.
For a deployment drill, engage `python3 cli.py emergency-stop`, verify execution
off and AI off with `status`, and confirm a pending action cannot mutate the
target. Recovery remains a deliberate manual operation documented in the
component guide. Completing a drill does not satisfy G1 or G2.

To reproduce the code checks from the repository root in an environment with the
component test dependencies installed and loopback listeners permitted:

```bash
(cd response-controller && ../range/.venv/bin/python -m pytest tests -q)
range/.venv/bin/python -m pytest tests -q
git diff --check
```

`range/.venv/bin/python` is the local project environment; substitute your
prepared interpreter when using a different environment. See the
[integration setup](../tests/README.md) for dependencies. These tests use
temporary storage and local stand-ins; they do not validate production IAM,
filesystem permissions, independent audit anchoring, or live incident provenance.
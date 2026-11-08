# M5 Closure: Response Controller (Sprint 5)

Sprint 5 closes the local Response Controller implementation milestone: what was
delivered, how it was checked, and what remains before live deployment.
Verification was run on 2026-11-08 using Python 3.14.4 against repository revision
`f9f7483`, before this documentation change. This is an implementation closure,
not production approval or acceptance of [ADR 0006](adr/0006-response-actions-and-kill-switch.md),
which remains **Proposed**.

## Outcome

The supply-chain pipeline now reaches a guarded response: scenario events arrive
at detection-engine, its scheduler forms an incident, the Copilot records
analysis, and the controller can queue or execute a deterministic promotion hold.
Operators can review, approve, modify, dismiss, stop, inspect, and roll back
supported actions through the local CLI. The Copilot still only recommends:
its output cannot select, parameterize, trigger, or suppress a policy action.

All actions ship disabled, dry run is the default, and automatic execution is
off until explicitly configured. The implemented target effects are promotion
holds and hold releases on one configured GitHub repository. Authenticated
rollback restores their saved prior state. The remaining catalog entries do
not become executable merely by being enabled in configuration.

## What was delivered

| Area | Delivered | Evidence and documentation |
|---|---|---|
| Controller foundation | Closed action catalog, strict parameters, proposal hashes and expiry, executor checks, read-only planning, and post-checks | [Design](response-controller-design.md), [executor tests](../response-controller/tests/test_executor.py) |
| Real response action | Verified `hold_promotion`, approved `lift_promotion_hold`, fixed repository variable, scoped Variables API client, read-only hold status | [Component guide](../response-controller/README.md), [promotion tests](../response-controller/tests/test_promotion_hold.py) |
| Manual review | Persistent Approve / Modify / Dismiss queue, prompted operator authentication, distinct approvers, fresh approval after modification, serialized decisions | [Review flow](../response-controller/approval_flow.py), [review tests](../response-controller/tests/test_approval_flow.py) |
| Audit trail | Ordered SHA-256 event chain, executor and initiator identities, UTC times, attempt IDs, verified export, checkpoint comparison, legacy migration baseline | [Security guarantees](response-controller-security.md), [audit tests](../response-controller/tests/test_audit.py) |
| Emergency stopping | Fail-closed operator and tripwire files, stronger-stop precedence, atomic writes, concurrent writer protection, emergency command and local Tk button | [Kill switch](../response-controller/kill_switch.py), [switch tests](../response-controller/tests/test_kill_switch.py), [CLI tests](../response-controller/tests/test_cli.py) |
| Bounded automation | Opt-in hold runner pinned to one repository and exact policy rule; one automatic reservation per incident and 1–5 attempts per rolling hour | [Automatic execution tests](../response-controller/tests/test_automatic.py) |
| Detection and Copilot bridge | Paginated incident/evidence reads, deterministic hold proposals, verified read-only recommendation context, late-context refresh without replay, `sync --execute` | [Bridge tests](../response-controller/tests/test_bridge.py) |
| Rollback | Durable pre-effect snapshots, a separate authenticated proposal, preserved approval count, exact prior-state restoration, drift checks, and restart-safe replay protection | [Rollback tests](../response-controller/tests/test_rollback.py), [design](response-controller-design.md#rollback) |
| Credential containment drill | Guarded, disposable rotation and revocation simulation with synthetic tokens and no external service | [Drill guide](credential-containment-drill.md), [standalone tests](../range/tests/test_credential_drill.py) |
| Integration and CI | Attack-to-audit coverage, isolated integration databases, dynamic ports, restored logging state, and the complete root suite as an image-publication prerequisite | [Integration guide](../tests/README.md), [CI workflow](../.github/workflows/ci.yml) |
| Security documentation | Implemented behavior separated from roadmap requirements; controls linked to code and tests; trust assumptions, failure modes, and remaining gates | [Design](response-controller-design.md), [security guarantees](response-controller-security.md), [threat model](threat-model.md) |

Real credential rotation and revocation remain outside the controller catalog.
The drill is an in-memory exercise, not a provider integration or remediation of
a real leaked key.

## Integration problems addressed

- **Tests shared the first imported database.** Updating `DATABASE_URL` for each
  test did not recreate the import-time engine. The shared fixture now creates
  a per-test SQLite engine, rebinds the API and scheduler session factory, checks
  the database path, and restores state on teardown.
- **Fixed ports made the integration suite dependent on host availability.**
  In-process detection tests now reserve OS-assigned loopback ports. Their HTTP
  helpers use the actual fixture URL.
- **CI covered only one integration file.** `security-e2e` now runs every root
  integration test before image publication. Its local reproduction command is
  documented alongside component dependency installation.
- **The design described future guarantees as current behavior.** Documentation
  now identifies authenticated resume, global approval invalidation, external
  anchoring, and catalog-only actions as outstanding work.

The corresponding regression coverage remains in the
[shared fixture](../tests/conftest.py),
[root suite](../tests/README.md), and
[controller tests](../response-controller/tests/).

## Verification at closure

All of the following were run locally and passed:

| Suite | Result | Scope |
|---|---|---|
| `response-controller/tests` | 273 passed | Policy boundaries, execution, review, concurrency, audit, stops, automation, rollback |
| Root `tests/` | 15 passed | Cross-component HTTP and separate-process response path |
| `ai-copilot/tests` | 241 passed | Existing Copilot regression suite |
| `detection-engine/tests` | 94 passed | Existing detection regression suite |
| `attack-sim/tests` | 111 passed | Existing scenario regression suite |
| Standalone credential drill unittest suite | 9 passed | Synthetic rotation, revocation, guard, failures, and output handling |

That is **734 pytest cases plus 9 standalone unittest cases**. At M4 closure the
root integration suite had 5 cases and no controller suite was reported; these
counts describe the tested repository snapshot, not a target for future suites.

The credential drill was also invoked in dry run, simulated rotation, and
simulated revocation modes. Dry run returned `verified: false` without creating
credentials. Both executed simulations returned `verified: true`, confirming
old-token rejection and, for rotation, replacement acceptance.

The root suite wrote JUnit output to `/tmp/sprint5-security-e2e.xml`.
Its HTTP stack emitted upstream asyncio/websocket deprecation warnings; there
were no test failures. CI is configured to run the root suite on Python 3.12;
the local results above do not claim a separate Python 3.12 or remote CI run.

### Reproduce

Use an environment with the component test dependencies installed, following
the [integration setup](../tests/README.md). From the repository root:

```bash
for component in attack-sim detection-engine ai-copilot response-controller; do
  (cd "$component" && ../range/.venv/bin/python -m pytest tests -q) || exit 1
done
range/.venv/bin/python -m pytest tests -q --junitxml=/tmp/sprint5-security-e2e.xml
range/.venv/bin/python -m unittest discover -s range/tests -p test_credential_drill.py -v
BANTIS_ENV=range-local range/.venv/bin/python range/scripts/credential_drill.py rotate
BANTIS_ENV=range-local range/.venv/bin/python range/scripts/credential_drill.py rotate --execute
BANTIS_ENV=range-local range/.venv/bin/python range/scripts/credential_drill.py revoke --execute
```

`range/.venv/bin/python` is the local project interpreter; substitute your
prepared interpreter if necessary. Loopback listeners must be permitted.
Each suite runs separately to preserve the components' import boundaries.

The attack-to-audit cases use real scenario mutations and cleanup, event HTTP
transport, detection scheduling, worker processing, policy execution, and audit
storage. Docker, Git, and Gitleaks subprocess results are controlled fixtures;
the provider and GitHub API are local stand-ins. These checks build no images,
create no commits, and contact no real provider or GitHub repository. They prove
integration and control behavior, not live model quality or production access.

## Known limitations

| Area | Limitation at closure | Consequence |
|---|---|---|
| Event provenance | Detection ingestion remains unauthenticated | Forged accepted events can freeze promotions when response is enabled; G1 remains open |
| Audit integrity | Hash chain and checkpoint comparison are local; external anchoring is not automated | A privileged writer can replace or rebuild the journal; G2 remains open |
| Deployment isolation | Code separation exists; OS accounts, directory permissions, and credential scopes are not provisioned by the controller | G3 needs deployment evidence; the trusted host remains a security boundary |
| Recovery | No authenticated `resume`; stopping does not globally revoke pending approvals | Manual recovery must inspect partial approvals and incomplete attempts |
| Supported effects | Evidence preservation, notifications, image rollback, and IP blocking are catalog-only | Only holds, hold releases, and their supported compensation are implemented |
| Remote atomicity | SQLite and GitHub writes are not one transaction; variable deletion is not conditional | At-most-once attempts do not guarantee exactly-once effects; external writers need coordination |
| Rollback scope | Snapshots are required; legacy executions have none; downstream promotions cannot be undone by restoring a hold | Partial or historical incidents may require manual reconciliation |
| Stop timing | A remote request already in flight may finish; durable stop files need writable storage | A stop cannot retract completed effects or guarantee persistence on an unwritable host |
| Distribution | Locks, quotas, and identity tracking assume cooperating processes sharing one local journal | No distributed execution or multi-host rate guarantee |
| User interface | Local CLI and emergency button exist; no dashboard or approval HTTP endpoint | Operators still review through host-local tools |
| Model and deployment validation | No live model scoring, real GitHub changes, Postgres run, Docker-backed range run, or operational latency measurement was performed for this closure | Local passing tests are not evidence of production readiness or measured explanation quality |

An operator drill on the actual deployment is still required for G4. G5's safe
defaults are implemented, but accepting the design or enabling an action remains
a separate deployment decision. Detailed guarantees and test references are in
the [security guide](response-controller-security.md).

## What changed from M4's carried work

| Carried concern | Position at M5 closure |
|---|---|
| No operator approval workflow | Local authenticated review and execution now exist in the separate controller |
| Copilot output must not acquire execution authority | Preserved: recommendations remain context; deterministic policy selects actions |
| Authenticate detection ingestion and queries | Still open; response makes forged-input availability risk more consequential |
| Anchor logs outside their writer's control | Partial tooling only: action journal verification and checkpoint comparison exist; independent anchoring remains open |
| Dashboard and analysis retrieval | Local bridge displays recorded context; a dashboard and controller approval API are not delivered |
| Real explanation scoring, Postgres, range forwarding, and live latency evidence | Not established by this closure; do not carry forward local stand-in results as those measurements |

The [M4 closure](m4-closure.md) remains the historical Sprint 4 record.

## Carried into the next sprint

1. **Close G1 before enabling response on reachable ingestion.** Authenticate
   event producers and incident queries; test rejection of unauthorized inputs.
2. **Close G2 with independent retention.** Store trusted checkpoints outside the
   executor's write access and exercise detection of tail deletion and replacement.
3. **Prove deployment boundaries and the stop drill.** Provision scoped credentials
   and OS permissions, rehearse stopping the intended deployment, and record G3/G4
   evidence rather than relying only on local test doubles.
4. **Build authenticated resume with approval invalidation.** Resume must require
   review and a reason, prevent an old approval backlog from firing, and record
   the recovery decision.
5. **Reconcile incomplete effects and coordinate writers.** Document target
   inspection and rollback eligibility for interrupted attempts before expanding
   automatic scope or adding more effectful implementations.
6. **Complete validation outside this local evidence boundary.** Revisit live model
   scoring, Postgres and range integration, dependency deprecations, and operational
   latency before claiming those properties. Add dashboard or catalog-only actions
   only with their own implementation, tests, and authorization review.
# tests/ (repo root)

Integration tests that span more than one independently-deployable
component — including `attack-sim` → `detection-engine` and the detection /
Copilot / Response Controller path. Each component's
own test suite (`attack-sim/tests/`, `range/tests/`,
`detection-engine/tests/`) stays scoped to itself and never imports
another component's code; tests that genuinely need two components
running together live here instead, so that boundary stays honest.

## Response bridge end to end

From the repository root, using an environment with the component test
dependencies installed:

```bash
python -m pytest tests/test_e2e_response_bridge.py -q
```

This suite starts a real detection-engine API against temporary SQLite
storage, runs the real Copilot worker with an in-process recording provider,
then invokes the controller in separate processes. A local GitHub API stand-in
receives any action effects; no provider API or real GitHub repository is used.
Tests cover bounded automatic execution, authenticated approval, dry-run,
emergency stop, late recommendations, replay protection, decision-log tampering,
authenticated rollback across controller restarts, and the inability of model
advice to trigger or suppress a policy action. Rollback requests only queue a
proposal; a fresh authenticated approval restores the saved target state.
The test environment must permit loopback HTTP listeners.

## Attack to audit CI check

The `security-e2e` job in `.github/workflows/ci.yml` runs every root integration
test on Python 3.12 and must pass before image publication. Changes to any
pipeline component or root integration tests trigger the workflow. Its result
is included in the pipeline notification, and pytest writes a JUnit report to
`test-results/security-e2e.xml` on the runner.

To reproduce the CI check from the repository root:

```bash
python -m pip install -r tests/requirements.txt -r attack-sim/requirements.txt -r ai-copilot/requirements.txt -r response-controller/requirements.txt
python -m pytest tests -v --junitxml=/tmp/security-e2e.xml
```

The two `test_attack_to_response_audit_pipeline` cases connect every stage:

1. Execute the malicious dependency and leaked secret scenarios against temporary
   files and forward their real structured log events over HTTP.
2. Wait for the detection engine's background scheduler to correlate those exact
   event IDs, without calling correlation directly.
3. Run the Copilot worker with a recording provider; verify the evidence, secret
   redaction, persisted analysis attempt, and decision hash chain.
4. Execute the deterministic promotion hold policy through the controller and
   verify the effect on the local GitHub API stand-in.
5. Check incident and action IDs, evidence IDs, execution order, successful
   post-check, and audit chain integrity against a saved checkpoint.
6. Restart the worker and controller to check that neither analysis nor response
   repeats. When both attacks are defended, analysis still occurs and no response
   is executed.

Docker, Git, and Gitleaks subprocess results are controlled fixtures; the model
provider and GitHub API are local stand-ins. Scenario mutations, cleanup, event
transport, detection, worker processing, policy execution, and audit storage use
the real implementations. The tests create no commits, build no images, call no
external APIs, and do not measure a live model's analysis quality.

## Running

The in-process detection tests use a fresh SQLite database under each test's
temporary directory and an operating-system-assigned loopback port. The shared
fixture rebinds the API and scheduler session factory together, checks the
database path, and restores database and logging state during teardown. No
existing detection database is dropped or reused by these tests. Loopback HTTP
listeners must be permitted by the test environment.

Install the component dependencies with the command above, then run from the
repository root:

```bash
python -m pytest tests -v
```

## `run_m2_baseline.py`

Not a pytest file (no `test_` prefix, so the command above skips it) —
a standalone CI script that runs all four M2 scenarios in sequence
against a live detection-engine and exits non-zero if either existing
correlation rule doesn't fire as documented. See
[`docs/m2-detection-baseline.md`](../docs/m2-detection-baseline.md) for
the recorded baseline result and how to reproduce it.
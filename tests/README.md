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
and the inability of model advice to trigger or suppress a policy action.
The test environment must permit loopback HTTP listeners.

## Running

```bash
cd tests
pip install -r requirements.txt
python -m pytest . -v
```

## `run_m2_baseline.py`

Not a pytest file (no `test_` prefix, so `pytest . -v` above skips it) —
a standalone CI script that runs all four M2 scenarios in sequence
against a live detection-engine and exits non-zero if either existing
correlation rule doesn't fire as documented. See
[`docs/m2-detection-baseline.md`](../docs/m2-detection-baseline.md) for
the recorded baseline result and how to reproduce it.
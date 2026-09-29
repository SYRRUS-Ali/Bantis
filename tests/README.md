# tests/ (repo root)

Integration tests that span more than one independently-deployable
component — today, `attack-sim` → `detection-engine`. Each component's
own test suite (`attack-sim/tests/`, `range/tests/`,
`detection-engine/tests/`) stays scoped to itself and never imports
another component's code; tests that genuinely need two components
running together live here instead, so that boundary stays honest.

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
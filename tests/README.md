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
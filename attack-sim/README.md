# attack-sim

M2's attack simulation component — scripted, reversible scenarios that
exercise the four supply-chain attack paths planned in
[`docs/scenarios-plan.md`](../docs/scenarios-plan.md), run against the
target environment in [`range/`](../range/).

This is a separate, independently-deployable component from `range/` —
it attacks the range from outside, so it doesn't share the range's
dependencies or lifecycle, even though both are Python.

## Structure

```
attack-sim/
├── scenarios/        # Scenario interface + individual scenario implementations
│   ├── base.py                  # Scenario ABC: run(), cleanup(), log_result()
│   ├── noop.py                   # No-op scenario used to test the interface itself
│   ├── malicious_dependency.py   # Scenario 1: malicious dependency injection
│   └── leaked_secret.py          # Scenario 2: leaked secret exploitation
├── logging_config.py  # JSON structured logging, matching docs/event-schema.md
├── tests/              # Unit tests for the interface and each scenario
└── requirements.txt
```

## Status

Two of the four planned scenarios are implemented: malicious dependency
injection and leaked secret exploitation. See
[`docs/scenarios.md`](../docs/scenarios.md) for how the two compare, and
[`docs/scenarios-plan.md`](../docs/scenarios-plan.md) for the remaining
two (compromised CI step, typosquatting) and the overall build order.

## Running the tests

```bash
cd attack-sim
pip install -r requirements.txt
python -m pytest tests -v
```

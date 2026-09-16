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
├── cli.py             # Command-line entrypoint: list / run / cleanup
├── scenarios/        # Scenario interface + individual scenario implementations
│   ├── base.py                  # Scenario ABC: run(), cleanup(), log_result()
│   ├── replay.py                 # @register + replay(scenario_id) — the CLI's engine
│   ├── noop.py                   # No-op scenario used to test the interface itself
│   ├── malicious_dependency.py   # Scenario 1: malicious dependency injection
│   ├── leaked_secret.py          # Scenario 2: leaked secret exploitation
│   ├── compromised_ci_step.py    # Scenario 3: compromised CI step
│   └── typosquatting.py          # Scenario 4: typosquatted package
├── logging_config.py  # JSON structured logging, matching docs/event-schema.md
├── tests/              # Unit tests for the interface, each scenario, and the CLI
└── requirements.txt
```

## Status

All four planned scenarios are implemented: malicious dependency
injection, leaked secret exploitation, compromised CI step, and
typosquatting. See [`docs/scenarios.md`](../docs/scenarios.md) for how
the scenarios compare, and [`docs/scenarios-plan.md`](../docs/scenarios-plan.md)
for the overall build order.

Every scenario is replayable by id through `scenarios/replay.py`, which
the CLI below is a thin wrapper around.

## CLI usage

```bash
cd attack-sim
python cli.py list                       # show every available scenario id + MITRE technique
python cli.py run <scenario>              # run one scenario end-to-end: run() -> log_result() -> cleanup()
python cli.py cleanup <scenario>          # force-cleanup a scenario without running it first
```

`run <scenario>` exits `0` for both a successful attack (`SUCCESS`) and a
successfully *defended* one (`FAILURE`) — both are a completed, working
test. It only exits `1` when the scenario itself couldn't run at all
(`ERROR`, e.g. a required tool like `docker` or `gitleaks` is missing) or
when `<scenario>` isn't a recognized id.

`cleanup <scenario>` exists for recovery: if a previous `run` crashed or
was interrupted before its own cleanup completed, this re-instantiates
the scenario fresh and calls `cleanup()` on it directly — every
scenario's `cleanup()` is written to safely recover a dirty state left by
an earlier, uncleaned run, even with no memory of what that run did.

Example:

```bash
$ python cli.py list
compromised-ci-step      T1195.002
leaked-secret            T1552.001
malicious-dependency     T1195.001
noop                     N/A
typosquatting            T1195.001

$ python cli.py run noop
success: no-op scenario executed
```

## Running the tests

```bash
cd attack-sim
pip install -r requirements.txt
python -m pytest tests -v
```

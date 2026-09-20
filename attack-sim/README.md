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

## Safety barrier: BANTIS_ENV

Every scenario mutates or executes something for real — a file, a real
`git` commit, a real `pip install`. Before any scenario can even be
*instantiated* (not just run), `Scenario.__new__()` in
[`scenarios/base.py`](scenarios/base.py) requires:

```bash
export BANTIS_ENV=range-local
```

Without it — unset, or set to anything else — instantiation raises
`ScenarioEnvironmentError` immediately, with a message naming exactly
what's wrong. This is checked in `__new__`, not `__init__`, specifically
so a future scenario can't accidentally skip it by forgetting to call
`super().__init__()` — every scenario is covered unconditionally, with
no per-scenario opt-in required.

- `python cli.py list` never instantiates a scenario (it only reads
  class attributes), so it works with no environment variable set.
- `python cli.py run <scenario>` and `python cli.py cleanup <scenario>`
  both instantiate one, so both require `BANTIS_ENV=range-local` and
  fail with a clear `error: ...` message (exit code `1`) otherwise —
  never a raw traceback.
- The test suite sets this automatically via an autouse fixture in
  [`tests/conftest.py`](tests/conftest.py), so existing tests don't need
  to set it themselves; `tests/test_environment_guard.py` is the one
  place that deliberately overrides it, to test the barrier itself.

This exists so that running attack-sim can never be a one-line accident
against an environment nobody deliberately confirmed is the disposable
local range — the string has to be typed on purpose.

## CLI usage

```bash
cd attack-sim
export BANTIS_ENV=range-local             # required by run/cleanup — see "Safety barrier" above
python cli.py list                       # show every available scenario id + MITRE technique
python cli.py run <scenario>              # run one scenario end-to-end: run() -> log_result() -> cleanup()
python cli.py cleanup <scenario>          # force-cleanup a scenario without running it first
```

`run <scenario>` exits `0` for both a successful attack (`SUCCESS`) and a
successfully *defended* one (`FAILURE`) — both are a completed, working
test. It only exits `1` when the scenario itself couldn't run at all
(`ERROR`, e.g. a required tool like `docker` or `gitleaks` is missing, or
`BANTIS_ENV` isn't set) or when `<scenario>` isn't a recognized id.

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
error: refusing to run: BANTIS_ENV must be set to 'range-local', got None. Set BANTIS_ENV=range-local to confirm this is the disposable local range before running any attack-sim scenario.

$ export BANTIS_ENV=range-local
$ python cli.py run noop
success: no-op scenario executed
```

## Known issues

Real problems found during a 2026-09-20 isolation/cleanup review — not
hypothetical ones. Same honest what/why/fix format as
[`docs/known-issues.md`](../docs/known-issues.md), scoped to attack-sim.

### `cleanup()` could silently fail to remove its own scratch state

**Symptom:** `leaked_secret.py` and `typosquatting.py` both called
`shutil.rmtree(self._workdir, ignore_errors=True)`. If that removal ever
failed for any reason (a permissions issue, a file still open, a locked
handle), `cleanup()` returned normally — no exception, no log line — even
though the scratch directory (still holding the fake secret or the fake
package) was never actually deleted.

**Root cause:** every existing test for these two scenarios only ever
exercised the path where `rmtree` succeeds — nothing forced a failure, so
nothing caught that "success" and "actual success" had quietly diverged.
This is exactly backwards for a scenario whose whole safety story is "no
trace left on disk" (see `test_cleanup_leaves_no_trace_of_the_secret_on_disk`
and its typosquatting equivalent, both of which only ever asserted the
happy path).

**Fix:** dropped `ignore_errors=True`; a failed removal now logs a clear
warning through the shared `attack_sim` logger and re-raises, so both
`replay()` and the CLI surface it instead of reporting a clean state that
isn't real. `cli.py`'s `run`/`cleanup` commands catch this as a plain
`error: ...` message (exit code `1`), not a raw traceback. Verified with
tests that force the removal to fail — confirmed those tests actually
fail against the old `ignore_errors=True` code before trusting the fix.

### A failed post-cleanup rebuild left no signal at all

**Symptom:** `malicious_dependency.py`'s `_rebuild()` (added after a
successful run, to replace a Docker image built with the poisoned
dependency — see `docs/scenarios/malicious-dependency.md`'s documented
cleanup contract) caught `FileNotFoundError`/`TimeoutExpired` and did
nothing else, and never checked the rebuild's own `returncode` at all —
so even a rebuild that ran and failed outright (docker daemon
unreachable, transient build error) was treated identically to success.

**Fix:** both failure paths (the rebuild raising, and the rebuild running
but returning non-zero) now log a warning naming the scenario and the
reason — still best-effort (a docker rebuild failing shouldn't crash
`cleanup()`, unlike the scratch-directory case above), but no longer
silent. The source file is still correctly reverted either way; only the
image-rebuild step's own success is what's now visible when it isn't
guaranteed.

Confirmed clean by the same review: `compromised-ci-step`'s cleanup (pure
file writes, nothing swallowed) and the `BANTIS_ENV` guard's own failure
paths (already raise loudly by design). A full `/tmp` and `git status`
snapshot diff across the entire test suite, before and after, showed zero
residual state beyond pytest's own managed temp directories.

## Running the tests

```bash
cd attack-sim
pip install -r requirements.txt
python -m pytest tests -v
```

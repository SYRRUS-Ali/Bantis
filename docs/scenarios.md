# Scenarios: Full Reference

All four attack-sim scenarios planned in [`docs/scenarios-plan.md`](scenarios-plan.md)
are implemented. This is the complete, implementation-level reference for
each one — target, injection mechanism, isolation guarantee, event
schema output, and cleanup contract — as opposed to
[`docs/scenarios-plan.md`](scenarios-plan.md) (the overview/build order)
and the individual attack-narrative writeups in
[`docs/scenarios/`](scenarios/) (the planned attacker *why*, not the
*how*). Every scenario below is runnable directly:

```bash
cd attack-sim
export BANTIS_ENV=range-local
python cli.py run <scenario-id>
```

See [`attack-sim/README.md`](../attack-sim/README.md) for full CLI docs
and the `BANTIS_ENV` safety barrier every scenario requires.

All four subclass the same [`Scenario`](../attack-sim/scenarios/base.py)
ABC and emit through the same `log_result()` / `attack_scenario_run`
envelope defined in [`docs/event-schema.md`](event-schema.md), using the
same `artifact` / `tool_returncode` / `tool_output_tail` field
convention documented there. `ScenarioStatus` reflects the *attacker's*
outcome, not the tool's: `SUCCESS` means the attack got through,
`FAILURE` means it was defended, `ERROR` means the scenario itself
couldn't run (a missing tool, a bad environment).

---

## 1. Malicious Dependency Injection

- **Scenario id:** `malicious-dependency`
- **MITRE:** Primary `T1195.001` (Supply Chain Compromise: Compromise
  Software Dependencies and Development Tools), Secondary `T1059`
  (Command and Scripting Interpreter, once an install-time script runs)
- **Full narrative:** [`docs/scenarios/malicious-dependency.md`](scenarios/malicious-dependency.md)

**Attack narrative.** A new dependency line is added to
`range/api/requirements.txt` under a name that doesn't exist on PyPI. If
CI's build accepts it anyway, the same mechanism could carry a real
malicious package whose install-time script executes arbitrary code —
this is deliberately not caught by anything else in the pipeline
(pip-audit only flags *known*-CVE packages, Semgrep scans source not
third-party code).

**Target and injection.** Appends one line to the real, tracked
`range/api/requirements.txt` — this scenario has to touch the real file,
since the entire point is testing whether the real `range/` build
pipeline accepts the package. No other file changes.

**Verification.** Runs `docker compose build api` against the range for
real. `SUCCESS` = build accepted the injected package (`returncode == 0`,
the expected-to-fail case actually passing); `FAILURE` = build rejected
it (`returncode != 0`, the expected outcome, since the package name
doesn't exist).

**Why it's safe.** The injected name
(`bantis-attack-sim-simulated-malicious-dependency==0.0.0`) is inert by
construction — nothing on PyPI will ever resolve it, so there's no real
payload to contain.

**`details` fields:** `artifact` (the injected requirement line),
`tool_returncode`, `tool_output_tail` (docker's combined stdout+stderr,
last ~2000 chars).

**Cleanup.** Restores the original file text from a cached copy. If the
build had *succeeded* (the poisoned image got tagged), cleanup also
rebuilds `api` against the now-clean file, so the last built image isn't
left poisoned — this rebuild is deliberately best-effort (logs a warning
on failure rather than raising; a docker rebuild is more failure-prone
than a local file write) but is no longer silent either way, per the
2026-09-20 isolation review (see `attack-sim/README.md`'s Known issues).
A duplicate-run guard checks the *file's current contents* for the
injected line, so it also recovers a file left dirty by a different,
uncleaned instance.

---

## 2. Leaked Secret Exploitation

- **Scenario id:** `leaked-secret`
- **MITRE:** Primary `T1552.001` (Unsecured Credentials: Credentials In
  Files), Secondary `T1078` (Valid Accounts, if the leaked credential is
  later used to authenticate)
- **Full narrative:** [`docs/scenarios/leaked-secret.md`](scenarios/leaked-secret.md)

**Attack narrative.** A commit adds a real-looking secret to a tracked
file — the one scenario of the four with an existing, working CI control
(Gitleaks already scans every push). The interesting question isn't
whether detection is *possible*, it's whether a scanner finding becomes
an actionable, correlated incident rather than just a red X.

**Target and injection.** Never touches the real Bantis repository. Creates
a disposable scratch git repository under a fresh temp directory
(`git init`, local `user.name`/`user.email`, no `--global`), writes a
`config.py` carrying a fake AWS credential, and commits it for real —
Gitleaks scans *a* git history, not specifically this repo's, so a
scratch repo gets the identical detection signal without ever touching
this repository's actual history.

**Verification.** Runs `gitleaks git <scratch-repo> --verbose` for real.
Gitleaks' own exit-code convention is inverted relative to a build:
`SUCCESS` = exit `0`, no leaks found (the secret went undetected —
attacker wins); `FAILURE` = exit `1`, leak found (caught, as it is in
real CI today).

**Why it's safe.** `AKIAFAKEBANTISATSIM1` is shaped to trip Gitleaks'
`aws-access-token` rule (`AKIA` + 16 chars, matching the real format
length) but maps to no real AWS account. The paired "secret"
(`FAKE/BANTIS-ATTACK-SIM/DO-NOT-USE/NOT-REAL`) is deliberately *not*
valid base64 — it only needs to look plausible enough for the narrative,
never functional. Verified directly in `test_leaked_secret_safety.py`:
the constants carry explicit `FAKE`/`DO-NOT-USE` markers, the scratch
repo always resolves under the system temp directory and never inside
this project's own tree, and after `cleanup()` the leaked file — and the
credential inside it — no longer exists anywhere on disk.

**`details` fields:** `artifact` (the leaked file name, `config.py`),
`tool_returncode`, `tool_output_tail` (gitleaks' combined output).

**Cleanup.** Deletes the entire scratch directory — the whole attack
surface disappears with it. As of the 2026-09-20 isolation review, a
failed removal (previously silently swallowed via
`shutil.rmtree(..., ignore_errors=True)`) now logs a clear warning and
re-raises instead of reporting a clean state that isn't real — this
scenario's whole safety story is "no trace left on disk," so a silent
failure here was the one place that claim could quietly stop being true.

---

## 3. Compromised CI Step

- **Scenario id:** `compromised-ci-step`
- **MITRE:** Primary `T1195.002` (Supply Chain Compromise: Compromise
  Software Supply Chain), Secondary `T1059` (Command and Scripting
  Interpreter)
- **Full narrative:** [`docs/scenarios/compromised-ci-step.md`](scenarios/compromised-ci-step.md)

**Attack narrative.** A step is added to `.github/workflows/ci.yml`
itself — the pipeline's own trust boundary, per
[`docs/range-architecture.md`](range-architecture.md): "a compromise here
bypasses every other check." This is the highest-severity of the four
scenarios and currently has **zero automated control** in this repo —
nothing lints or diffs workflow-file changes for review today.

**Target and injection.** Unlike the leaked-secret scenario, this one
*does* mutate the real `.github/workflows/ci.yml` in place — the task
this scenario tests for is specifically "does the real pipeline's own
definition get changed unnoticed," which a scratch copy can't
meaningfully stand in for. A new step is inserted as the first step of
the first job (`build`), located by finding the first `    steps:\n`
anchor via plain text search — deliberately **not** via a YAML
parse-and-redump round trip, since that would silently reformat
comments/quoting and make "restore the original" ambiguous. The anchor
line is guaranteed newline-terminated in any valid YAML file, so the
injected block can be inserted and later removed as one self-contained
unit with no separator bookkeeping.

**The payload is inert by design** — task 2 of this scenario's own build
requirement. The injected step is a single line:
```yaml
- name: BANTIS-ATTACK-SIM-INJECTED - Suspicious Execution Marker
  run: echo "::warning::BANTIS-ATTACK-SIM suspicious execution detected..."
```
Verified directly (`test_compromised_ci_step_safety.py`): the `run:` line
starts with `echo` and only that, and contains none of `curl`, `wget`,
`secrets.`, `nc `, `ncat`, `/dev/tcp`, `base64 -d`, or `eval`.

**Verification.** None yet — no real GitHub Actions run is triggered (out
of scope: that would need a real push/`act`, and this scenario's own
design doc notes detection here is about the *effects* of a compromised
step, not the YAML change itself, since no scanner catches that today).
`run()` always returns `SUCCESS` once the step is written — that's a
statement about the current detection gap, not a bug.

**`details` fields:** `artifact` (the step marker string), `path` (the
workflow file path) — no `tool_returncode`/`tool_output_tail`, since no
external tool runs here; per `docs/event-schema.md`, these are omitted
entirely rather than reported as a meaningless value.

**Cleanup.** Restores the original file text from a cached copy,
verified byte-for-byte identical in `test_compromised_ci_step_cleanup.py`
— not just "semantically equivalent," since this file is the pipeline's
own trust boundary and any drift here is worse than for any other
scenario's target. A duplicate-run guard checks the file's current
content for the marker before injecting, so two competing copies of the
step can never coexist; the fallback recovery path (for a workflow left
dirty by an uncleaned prior run) is confirmed in
`test_compromised_ci_step_conflict.py`. Reviewed clean in the
2026-09-20 isolation pass — pure file writes, nothing here silently
swallows a failure.

---

## 4. Typosquatted Package

- **Scenario id:** `typosquatting`
- **MITRE:** Primary `T1195.001` (Supply Chain Compromise: Compromise
  Software Dependencies and Development Tools), Secondary `T1027`
  (Obfuscated Files or Information, if the payload is hidden)
- **Full narrative:** [`docs/scenarios/typosquatting.md`](scenarios/typosquatting.md)

**Attack narrative.** A one-character typo of a real dependency gets
installed instead of (or alongside) the intended one — the fake package
used is `redsi`, a transposition typo of `redis`, a real dependency in
`range/api/requirements.txt` (`redis[hiredis]==5.2.1`). Verified as a
genuine near-miss, not an arbitrary name:
`test_typosquatting_name_choice.py` confirms `redis` is an actual current
dependency, `redsi` is not an exact match of any real one, and their
Levenshtein distance is 2 (a plausible glance-past typo, not a
coincidence).

**Target and injection — the one scenario that actually runs `pip
install` for real.** This is the one meaningfully different scenario of
the four: instead of editing a file and building/scanning it, it
hand-builds a minimal, valid *wheel* using only the stdlib (`zipfile` +
`hashlib` — no `setuptools`/`build` dependency added), containing only an
inert `__init__.py`. A wheel is a pre-built archive with **no
install-time build step**, so "installing" it can never execute
arbitrary code — confirmed directly in
`test_wheel_contains_no_build_hooks_or_executable_code_paths`.

**Isolation — the most scrutinized of the four, by design.** The install
runs as `pip install --no-index --find-links <scratch-dir> --target
<scratch-dir> redsi==0.0.1`:
- `--no-index` makes it *physically impossible* for pip to resolve
  anything from the real PyPI, not just unlikely — verified by spying on
  the actual subprocess command in `test_typosquatting_isolation.py`.
- `--target` writes to a plain scratch directory, never `site-packages`
  — verified that `sys.path` and `sys.modules` are unchanged before and
  after `run()`, so the "attack" never becomes importable in the calling
  process.
- Confirmed empirically during the 2026-09-20 review (not just asserted
  in a test): ran the scenario for real and searched the entire pip
  cache and home directory afterward — zero trace of `redsi` anywhere
  outside its own scratch directory.

**Verification.** The install itself is the verification. `SUCCESS` =
`pip install` returned `0` (installed — expected, since we control the
local index) — this scenario's "attack succeeds" by construction, which
is itself the finding: there is no name-similarity check anywhere in
this pipeline today, so nothing would stop this if it happened for real.

**`details` fields:** `artifact` (`redsi==0.0.1`), `impersonates`
(`redis`), `tool_returncode`, `tool_output_tail`, plus two fields unique
to this scenario: `install_target` and `wheel_path` (both scratch paths,
useful for a human inspecting what actually got installed).

**Cleanup.** Deletes the entire scratch directory (index + installed
package together). Same 2026-09-20 fix as leaked-secret: a failed
removal now logs a warning and re-raises rather than silently reporting
success — `test_cleanup_leaves_no_trace_of_the_installed_package_on_disk`
and the new `test_typosquatting_cleanup_surfaces_a_failed_removal` cover
both the happy path and the forced-failure path respectively.

---

## Summary: MITRE mapping

| # | Scenario id | Primary technique | Tactic | Secondary technique |
|---|---|---|---|---|
| 1 | `malicious-dependency` | T1195.001 — Compromise Software Dependencies and Development Tools | Initial Access | T1059 — Command and Scripting Interpreter |
| 2 | `leaked-secret` | T1552.001 — Unsecured Credentials: Credentials In Files | Credential Access | T1078 — Valid Accounts |
| 3 | `compromised-ci-step` | T1195.002 — Compromise Software Supply Chain | Initial Access | T1059 — Command and Scripting Interpreter |
| 4 | `typosquatting` | T1195.001 — Compromise Software Dependencies and Development Tools | Initial Access | T1027 — Obfuscated Files or Information |

Matches [`docs/mitre-mapping.md`](mitre-mapping.md), the design-time
version of this table — this one additionally reflects that all four are
now implemented and replayable, not just planned.

## Shared plumbing (unaffected by any of the above)

- All four subclass [`Scenario`](../attack-sim/scenarios/base.py) and
  only implement `run()` / `cleanup()` — `log_result()` is never
  reimplemented per scenario, and instantiating any of them requires
  `BANTIS_ENV=range-local` (enforced in `Scenario.__new__()`, so a future
  scenario can't skip it by forgetting to call `super().__init__()`).
- All four report through the same `attack_scenario_run` event type
  using the same `artifact`/`tool_returncode`/`tool_output_tail`
  convention (`docs/event-schema.md`), so a future Detection Engine (M3)
  ingests them identically regardless of which one ran.
- All four are registered with `@register` (`scenarios/replay.py`) and
  runnable by id through `replay()` / `python cli.py run <id>` — the
  same entrypoint regardless of scenario.
- All four treat an unavailable external tool (`docker`, `gitleaks`) and
  a timed-out one as `ScenarioStatus.ERROR`, distinct from the attack's
  own `SUCCESS`/`FAILURE` verdict — a missing tool is an inconclusive
  test run, not a defended attack.
- Three of the four (`malicious-dependency`, `leaked-secret`,
  `typosquatting`) also had a genuine cleanup-visibility bug — a failed
  removal/rebuild silently reporting success — found and fixed in the
  2026-09-20 isolation review; `compromised-ci-step` was reviewed and
  confirmed already clean. Full honest write-up in
  [`attack-sim/README.md`](../attack-sim/README.md#known-issues).
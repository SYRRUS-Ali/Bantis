# Scenario Implementations: Malicious Dependency vs. Leaked Secret

**Status: draft.** This documents how the two attack-sim scenarios
implemented so far actually work at the code level, and where they
diverge in design — as opposed to [`docs/scenarios-plan.md`](scenarios-plan.md)
(the overview/build order) and the individual attack-narrative writeups in
[`docs/scenarios/`](scenarios/) (the planned *why*, not the *how*). It will
grow to cover the remaining two scenarios (compromised CI step,
typosquatting) once they're implemented.

Both scenarios implement the same [`Scenario`](../attack-sim/scenarios/base.py)
interface and emit through the same `log_result()` / `docs/event-schema.md`
`attack_scenario_run` envelope — the comparison below is everything that
differs underneath that shared contract.

## Side by side

| | [Malicious Dependency Injection](../attack-sim/scenarios/malicious_dependency.py) | [Leaked Secret Exploitation](../attack-sim/scenarios/leaked_secret.py) |
|---|---|---|
| MITRE technique | T1195.001 | T1552.001 |
| Target of the attack | The real range: `range/api/requirements.txt` | A disposable scratch git repo created under a temp directory — never the real Bantis repo |
| How the payload is delivered | Appending one line to a shared, real, tracked file | Committing a new file into a throwaway repo via real `git init`/`add`/`commit` |
| What verifies the outcome | `docker compose build api` against the range | `gitleaks git <scratch-repo> --verbose` against the scratch repo |
| Attacker "success" means | The build accepted the injected package (`returncode == 0`) | Gitleaks exited `0` — the committed secret went undetected |
| Attacker "failure" means | The build rejected the package (`returncode != 0`) | Gitleaks exited `1` — the secret was caught, as it is in real CI today |
| State mutated by `run()` | One shared file's contents, plus (on success) a real Docker image tag | A brand-new, uniquely-named temp directory — nothing shared |
| Re-run guard | Checks the *file's current contents* for the injected line, so it also catches a dirty file left by a different, uncleaned instance | Checks the *instance's own* `_workdir` handle — each run gets its own scratch directory, so there's no shared state for another instance to leave dirty |
| `cleanup()` | Restores the original file text, and — if the build had succeeded — rebuilds the `api` image so the last tagged image isn't left poisoned | Deletes the entire scratch directory (`shutil.rmtree`) — the whole attack surface disappears with it |
| Can the payload ever function for real? | The injected package name (`bantis-attack-sim-simulated-malicious-dependency==0.0.0`) doesn't exist on PyPI, so the build is expected to fail closed | The fake credential (`AKIAFAKEBANTISATSIM1` / a deliberately non-base64 "secret") maps to no real AWS account and never leaves the scratch repo, so it cannot authenticate anywhere even if a leak scan misses it |

## Why the injection targets differ

The dependency scenario has to mutate a real, shared file — the whole
point is testing whether the *real* `range/` build pipeline accepts the
package, so there's no way to fake that without a real
`docker compose build`.

The secret scenario doesn't need the real repo at all — Gitleaks scans
*a* git history, not specifically Bantis's. Using a disposable scratch
repo instead of a real commit against `range/` gets the same detection
signal without ever touching this repository's actual history, which
matters doubly here since attack-sim scenarios must be safe to run
repeatedly and unattended.

## Why the safety guarantee differs in shape

Both scenarios are designed so the simulated attack can never do real
harm, but the *mechanism* differs:

- **Malicious dependency:** safety comes from the payload being inert by
  construction — a nonexistent package name that no build tool will ever
  resolve. There's no "leak" risk since nothing sensitive is involved.
- **Leaked secret:** safety comes from the *credential* being
  structurally fake — shaped like a real AWS access key ID only closely
  enough to trip Gitleaks' pattern-matching rule, paired with a "secret"
  value that isn't even valid base64. Even in the worst case (a scan
  misses it, or someone reads the scratch repo before `cleanup()` runs),
  there is no real AWS account behind it to reach.

## Shared plumbing (unaffected by the above)

- Both subclass [`Scenario`](../attack-sim/scenarios/base.py) and only
  implement `run()` / `cleanup()` — `log_result()` is never
  reimplemented per scenario.
- Both report through the same `attack_scenario_run` event type
  (`docs/event-schema.md`), so a future Detection Engine (M3) ingests
  them identically regardless of which one ran.
- Both treat an unavailable external tool (`docker`, `gitleaks`) and a
  timed-out one as `ScenarioStatus.ERROR`, distinct from the attack's own
  `SUCCESS`/`FAILURE` verdict — a missing tool is an inconclusive test
  run, not a defended attack.

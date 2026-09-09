# Scenario: Typosquatted Package

## MITRE ATT&CK
- **Primary:** T1195.001 — Supply Chain Compromise: Compromise Software
  Dependencies and Development Tools *(Initial Access)*
- **Secondary:** T1027 — Obfuscated Files or Information *(Defense
  Evasion)* — if the malicious payload is hidden inside the package
  (e.g. minified, base64-encoded, or only triggered conditionally to
  evade casual review).

## Attacker goal
Get a look-alike package installed in place of a legitimate one, relying
on a typo, transposition, or naming confusion during a manual edit of
`requirements.txt` (as opposed to Scenario 1, where the malicious package
is added deliberately under its own name).

## Preconditions
- Someone manually adds or edits a dependency line by hand rather than
  via a lockfile/pinned hash, and doesn't double-check the exact package
  name against PyPI.

## Concrete injection point
`range/api/requirements.txt` — e.g. a plausible typo of an existing
dependency already in that file (`fastapi`, `pyjwt`, `python-multipart`,
`asyncpg`, `redis`) or of a common transitive one.

## Attack narrative
1. A single-character typo/transposition of a real dependency name is
   added to `requirements.txt` (e.g. a swapped or dropped letter in an
   existing package name). It's easy to miss in a PR diff because the
   line still *looks* right at a glance.
2. `pip install` resolves and installs the typo'd package instead of (or
   alongside) the intended one — same build-time execution path as
   Scenario 1 (Dockerfile runs `pip install -r requirements.txt`
   unconditionally).
3. Unlike Scenario 1, the payload here is specifically designed to be
   **inconspicuous** — the whole point of typosquatting is relying on the
   victim not noticing, so the payload is more likely to be obfuscated
   (T1027) and to imitate the real package's public API so nothing
   obviously breaks at import time.

## Why this scenario matters (the actual detection gap)
Same gap as Scenario 1 (pip-audit/Semgrep/Gitleaks don't catch a novel
package), plus an additional one specific to typosquatting: there is
**no name-similarity check** against the real dependency list anywhere in
this pipeline today. A future control worth scoping for M2/M3 — not
built yet — is a simple Levenshtein-distance check of
`requirements.txt` entries against a known-good package list, flagging
anything suspiciously close to (but not equal to) an intended name.

## Detection success criteria
- Same runtime-signal detection target as Scenario 1 (`T1195.001`), plus
  correctly tagging `T1027` when the payload is deliberately obfuscated
  rather than plain.
- Stretch goal: the name-similarity check above catching the typo at
  dependency-review time, before the payload ever executes.

## Cleanup
Revert the `requirements.txt` line to the correctly-spelled package and
rebuild.

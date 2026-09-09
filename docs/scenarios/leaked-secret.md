# Scenario: Leaked Secret Exploitation

## MITRE ATT&CK
- **Primary:** T1552.001 — Unsecured Credentials: Credentials In Files
  *(Credential Access)*
- **Secondary:** T1078 — Valid Accounts *(Persistence / Initial Access)* —
  if the leaked credential is actually used to authenticate afterward.

## Attacker goal
Recover a real credential (DB password, `JWT_SECRET_KEY`, Redis password,
GHCR token) from source history and use it to access something it
protects.

## Preconditions
- A contributor commits a real secret instead of a placeholder — most
  plausibly by editing `.env` and accidentally `git add -A`-ing it despite
  `.gitignore`, or by hardcoding a value directly in a source file "just
  to test something."
- The commit reaches a shared branch before anyone notices.

## Concrete injection point
Any tracked file — most realistically `range/.env` (already gitignored,
so this specifically tests the "someone forces past `.gitignore`" case)
or a hardcoded value inside `range/api/app/security.py` /
`range/api/app/db.py`.

## Attack narrative
1. A commit adds a real-looking secret (e.g. a `JWT_SECRET_KEY` or
   `DATABASE_URL` with embedded credentials) to a tracked file.
2. The commit is pushed. **Secret Scanning (Gitleaks)** already runs on
   every push/PR against `range/**` and scans full git history
   (`fetch-depth: 0`, `gitleaks git . --verbose`) — this is the one
   scenario where a real CI control already exists specifically for it.
3. Two branches to plan for:
   - **Gitleaks catches it before merge** — the interesting case is
     confirming the finding actually surfaces somewhere a human sees it
     (today: a failed CI job; Bantis should turn this into a correlated,
     tagged incident, not just a red X).
   - **Gitleaks is bypassed or the secret reaches `main` anyway** (force
     push, admin override, or the secret is added in a way Gitleaks'
     default ruleset doesn't recognize) — this is where T1078 applies:
     the leaked credential is later used to authenticate directly against
     `db`/`redis`/the API, and detecting *that use* (not just the leak)
     becomes the real test for M3.

## Why this scenario matters
It's the only one of the four with an existing, working CI control
(Gitleaks) — so M2's job here isn't proving detection is possible, it's
proving Bantis correlates a scanner finding into an actionable incident,
and separately, that credential *misuse* after a successful leak is still
observable even when the leak itself slipped through.

## Detection success criteria
- Leak path: Gitleaks finding is surfaced as a tagged `T1552.001` incident
  with the offending commit/file identified.
- Misuse path: an authenticated request using the leaked credential is
  tagged `T1078` and correlated back to the leak event if both occurred
  within the same simulation run.

## Cleanup
Rotate the leaked value in `.env`, revert the commit, and treat the old
value as permanently burned (never reuse a "leaked" secret even in a
test range).

# Scenario: Malicious Dependency Injection

## MITRE ATT&CK
- **Primary:** T1195.001 — Supply Chain Compromise: Compromise Software
  Dependencies and Development Tools *(Initial Access)*
- **Secondary:** T1059 — Command and Scripting Interpreter *(Execution)* —
  once the package's install/build-time script runs.

## Attacker goal
Get arbitrary code to execute inside the build or runtime environment by
getting a malicious package accepted as a legitimate dependency.

## Preconditions
- Write access to `range/api/requirements.txt` (a compromised contributor
  account, or an unreviewed PR that gets merged).
- The package is either brand-new (no CVE history yet) or a
  legitimate-looking fork with an added payload — not something a
  vulnerability database would already flag.

## Concrete injection point
`range/api/requirements.txt` — a single new line adding a package name
and version. No other file needs to change; the Dockerfile already runs
`pip install -r requirements.txt` unconditionally on every image build.

## Attack narrative
1. A new dependency is added to `requirements.txt`, e.g. a package whose
   `setup.py`/build hook runs a benign PoC payload at install time (for
   this range: write a marker file and make a request to a
   simulator-controlled local endpoint — never a real exfiltration
   target).
2. CI's **Build** job builds the `api` image, which runs `pip install`,
   which executes the payload during the Docker build.
3. If the build isn't rejected, the image is later deployed by
   **deploy-staging** and promoted to `:latest` — the payload now runs on
   every container start, not just once during build.

## Why this scenario matters (the actual detection gap)
This is deliberately **not** caught by anything in the pipeline today:
- **pip-audit** only flags packages with a *known* CVE/advisory — a novel
  malicious package has none yet.
- **Semgrep** scans `range/` source, not third-party dependency code
  pulled from PyPI.
- **Gitleaks** looks for secret patterns, not malicious package behavior.

So this scenario is the one that specifically justifies Bantis's
behavioral/runtime detection layer (M3) rather than relying on CI
scanners alone — the interesting question for M2 is what *signal* the
payload's execution leaves (unexpected outbound connection during
`docker build`, an unexpected process/file write) that M3 could ingest.

## Detection success criteria
- Event tagged with `T1195.001` (and `T1059` if the payload's execution
  is what's actually observed) shows up in Bantis within a defined
  time-to-detect target (to be set once M3 exists).
- No reliance on the payload being "loud" — a quiet payload (single file
  write, one outbound call) must still be detectable, since that's the
  realistic case.

## Cleanup
Revert the `requirements.txt` line and rebuild; no persistent state
outside the `api` image itself.

# Scenario: Compromised CI Step

## MITRE ATT&CK
- **Primary:** T1195.002 — Supply Chain Compromise: Compromise Software
  Supply Chain *(Initial Access)*
- **Secondary:** T1059 — Command and Scripting Interpreter *(Execution)*

## Attacker goal
Inject an arbitrary shell step into `.github/workflows/ci.yml` that runs
with the pipeline's own privileges — repo secrets (`GITHUB_TOKEN`, GHCR
push access, `TELEGRAM_BOT_TOKEN`), and whatever the runner can reach.

## Preconditions
- Write access to `.github/workflows/ci.yml` (compromised contributor
  account, or a PR from a fork that a reviewer approves without reading
  the workflow diff carefully).

## Concrete injection point
`.github/workflows/ci.yml` itself — as `docs/range-architecture.md`
already states, this file *is* the pipeline's own trust boundary: "a
compromise here bypasses every other check." A single added `run:` line
in any job is sufficient; no other file needs to change.

## Attack narrative
1. A step is added to an existing job (most damaging: the `push` or
   `promote-latest` job, which already has `packages: write` and GHCR
   credentials in scope) that, for example, exfiltrates
   `secrets.GITHUB_TOKEN` to an external endpoint, or quietly appends a
   step to the `api` Docker build that plants a backdoor in the image
   before it's pushed to GHCR.
2. The step runs with full job permissions and whatever secrets that job
   already has access to — no separate credential theft is needed.
3. Because this file is also the thing every *other* control (SAST,
   secret scan, dependency scan, smoke test) trusts to run correctly, a
   compromise here can also disable or falsify those controls in the same
   change (e.g. neutering the `sast`/`secrets-scan` job while leaving
   their job names intact so the workflow still "looks" green).

## Why this scenario matters (the actual detection gap)
This is the highest-severity scenario of the four and currently has
**zero automated control** in this repo — Semgrep's `p/dockerfile` and
`p/python` configs don't lint GitHub Actions YAML, and nothing today
diffs workflow-file changes for review. The realistic mitigations are
mostly outside this pipeline (branch protection requiring review on
`.github/workflows/**`, `CODEOWNERS`), which is why this scenario is
about detecting the *effects* of a compromised step (anomalous outbound
network calls from a runner, an image pushed to GHCR that doesn't match
the source it claims to be built from) rather than catching the YAML
change itself.

## Detection success criteria
- A step added to `ci.yml` that makes an unexpected outbound network call
  during a run is tagged `T1059`/`T1195.002` and flagged as anomalous
  relative to the job's normal step list.
- Bonus (stretch for M2): detect a mismatch between the image pushed to
  GHCR and what the visible workflow + source would produce.

## Cleanup
Revert the workflow change; treat any secrets that were in scope during
the compromised run (`GITHUB_TOKEN` is short-lived and auto-expires, but
`TELEGRAM_BOT_TOKEN`/GHCR credentials are not) as rotated-required.

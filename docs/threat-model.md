# Threat Model

## Purpose and Scope
Bantis v1 focuses on **supply chain attacks** against a CI/CD pipeline and its
dependencies, running inside a self-hosted range. It is not a general-purpose
network intrusion detection system in v1.

## Assumptions
- The range (Docker Compose based CI/CD pipeline + multi-service app) is
  isolated on the operator's own infrastructure.
- The operator has legitimate administrative access to both the range and
  Bantis itself.
- API keys and secrets provided during setup belong to the operator, used at
  their own cost and risk.

## Assumed Attacker Capabilities (in scope for v1)
- Introducing a malicious or unsigned dependency into the pipeline (e.g. a
  compromised or typosquatted package).
- Committing code that leaks a credential or secret (accidentally, or via a
  compromised contributor account).
- Modifying or injecting a malicious step into a CI/CD workflow definition.
- Causing an unverified/untrusted container image to be pulled during a build.

## Explicitly Out of Scope (v1)
- Network-layer intrusion (lateral movement, port scanning, OS exploitation) —
  deferred to a later milestone (second attack layer).
- Attacks against the AI provider's own infrastructure.
- Multi-tenant isolation — v1 assumes a single operator, single environment.
- Fully autonomous AI-driven response without human confirmation — the
  default is recommend-only, with a narrow whitelist for auto-execution.
- Detecting anything that never emits an event into Bantis's event schema —
  Bantis only sees what its instrumented services report.

## Trust Boundaries
- **Operator ⟷ Bantis**: trusted, authenticated via the admin account
  created in the setup wizard.
- **Bantis ⟷ AI provider**: semi-trusted. Only correlated incident data is
  sent for analysis, never raw secrets or credentials.
- **Bantis ⟷ Range**: the range is intentionally the vulnerable surface being
  monitored, not part of Bantis's own trust boundary.

## What "Success" Looks Like
Bantis reliably detects the supply-chain scenarios defined later in the
attack simulation milestone, with a measured detection rate and false
positive rate reported via the scorecard.

## Known Limitations
This threat model covers v1 scope only. It will be revisited before adding a
second attack layer or autonomous response modes.
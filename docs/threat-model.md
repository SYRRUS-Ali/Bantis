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
- **Operator ⟷ Bantis**: trusted host access is the current controller
  boundary. CLI approval, modification, dismissal, and rollback requests also
  require the operator's private approver secret and use the current OS identity.
  A setup-wizard admin account is not an implemented controller authentication
  mechanism.
- **Bantis ⟷ AI provider**: semi-trusted. Only correlated incident data is
  sent for analysis, never raw secrets or credentials — the exact
  allowlisted shape is fixed in
  [`docs/ai-copilot-contract.md`](ai-copilot-contract.md).
- **Bantis ⟷ Range**: the range is intentionally the vulnerable surface being
  monitored, not part of Bantis's own trust boundary.

## Response Controller

The [controller design](response-controller-design.md) and
[security guarantees](response-controller-security.md) describe the current
action path, enforcement points, tests, and deployment gates.

The controller can automatically hold promotions only within an explicitly
enabled repository and policy scope. Model output supplies untrusted review
context, not executable policy input. Hold releases and rollback require fresh
approval. Event ingestion is still unauthenticated, so forged incidents can
freeze releases when execution is enabled; deterministic policy does not prove
event provenance.

The local event hash chain detects inconsistent history, but cannot stop a
privileged host writer from replacing or rebuilding it. Independent checkpoints
and external anchoring remain necessary. OS separation and credential permissions
are deployment responsibilities. Concurrent external GitHub variable changes,
remote requests already in flight, and effects completed before a crash are not
made atomic by the controller's local locks.

## What "Success" Looks Like
Bantis reliably detects the supply-chain scenarios defined later in the
attack simulation milestone, with a measured detection rate and false
positive rate reported via the scorecard.

## Known Limitations
This threat model covers v1 scope only. It will be revisited before adding a
second attack layer or autonomous response modes.

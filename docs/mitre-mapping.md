# MITRE ATT&CK Mapping

This maps the supply-chain attack scenarios planned for the attack
simulation milestone (M2) to MITRE ATT&CK Enterprise techniques. This gives
each scenario a recognized reference point instead of an ad-hoc label, and
will later drive the tags shown on each incident in the dashboard.

## Scenario 1 — Malicious Dependency Injection
An unsigned or malicious package is added to the project's dependencies.

- **Primary:** T1195.001 — Supply Chain Compromise: Compromise Software
  Dependencies and Development Tools *(Initial Access)*
- **Secondary:** T1059 — Command and Scripting Interpreter *(Execution)* —
  once the malicious package's install/build script runs.

## Scenario 2 — Leaked Secret Exploitation
A commit exposes a credential or API key that could be used by an attacker.

- **Primary:** T1552.001 — Unsecured Credentials: Credentials In Files
  *(Credential Access)*
- **Secondary:** T1078 — Valid Accounts *(Persistence / Initial Access)* —
  if the leaked credential is later used to authenticate.

## Scenario 3 — Compromised CI Step
A malicious step is injected into a CI/CD workflow definition.

- **Primary:** T1195.002 — Supply Chain Compromise: Compromise Software
  Supply Chain *(Initial Access)*
- **Secondary:** T1059 — Command and Scripting Interpreter *(Execution)*

## Scenario 4 — Typosquatted Package
A package with a name similar to a legitimate one is installed by mistake.

- **Primary:** T1195.001 — Supply Chain Compromise: Compromise Software
  Dependencies and Development Tools *(Initial Access)*
- **Secondary:** T1027 — Obfuscated Files or Information *(Defense Evasion)*
  — if the malicious payload is hidden inside the package.

## Summary Table

| Scenario | Primary Technique | Tactic |
|---|---|---|
| Malicious dependency injection | T1195.001 | Initial Access |
| Leaked secret exploitation | T1552.001 | Credential Access |
| Compromised CI step | T1195.002 | Initial Access |
| Typosquatted package | T1195.001 | Initial Access |

## Notes
This mapping covers v1 scope (supply chain layer) only. A second mapping
will be added if/when a network/host attack layer is introduced later.
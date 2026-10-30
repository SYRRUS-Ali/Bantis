# Range credential containment drill

Sprint 5 / M5: simulate rotation or revocation of a leaked credential.
This is an operator-run drill, outside the response-controller catalog:
ADR 0006 excludes real credential operations (tier C). No catalog or
approval policy changes are required for this simulation.

The drill uses a disposable in-memory credential verifier and synthetic
random tokens. It has no network, filesystem mutation, service restart,
provider SDK, user-supplied secret, or target endpoint. It does not rotate
JWT_SECRET_KEY, database passwords, AWS keys, or GitHub tokens. It proves
the containment sequence against a stand-in, not a deployed service.

From the repository root after applying the patch:

```bash
BANTIS_ENV=range-local python3 range/scripts/credential_drill.py rotate
BANTIS_ENV=range-local python3 range/scripts/credential_drill.py rotate --execute
BANTIS_ENV=range-local python3 range/scripts/credential_drill.py revoke --execute
python3 -m unittest discover -s range/tests -p test_credential_drill.py -v
```

The environment guard is mandatory even in dry run. Dry run is the default;
it generates no tokens and reports `verified: false`. `--execute` still
means simulation only. Rotation authenticates the leaked synthetic token,
issues and verifies a fresh replacement, revokes the old token, then checks
old rejection and replacement acceptance. Revocation checks old rejection
without issuing a replacement. Tokens and hashes never appear in output.
Failures return exit code 1; successful drills and dry runs return 0.
The JSON result records the checks, with no claim of a real remediation.

Cleanup is automatic when the process exits: no files or persistent
credentials exist. Each invocation starts a fresh identity; this is not a
persistent revocation service. Never reuse a real leaked credential. For a
real incident, an operator must revoke it at its issuer, distribute a new
value to consumers, and verify access independently; that procedure is
outside this drill and the controller's current authorization.
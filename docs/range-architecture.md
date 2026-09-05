# Range Architecture

The range is Bantis's target environment — a real, running application
stack that later milestones (Attack Simulation, Detection Engine) attack
and monitor. It is reused from
[compose-multiservice-app](https://github.com/SYRRUS-Ali/compose-multiservice-app),
instrumented with structured logging, and wrapped in a supply-chain CI/CD
pipeline that becomes the actual attack surface for M2.

## Components

| Service | Image / Base            | Role                                          |
|---------|--------------------------|------------------------------------------------|
| `api`   | Built from `api/Dockerfile` (Python 3.12-slim) | FastAPI app: auth, tasks, health, version |
| `db`    | `postgres:16-alpine`     | Persistent storage for users and tasks         |
| `redis` | `redis:7-alpine`         | Cache layer for the API                        |
| `nginx` | `nginx:1.27-alpine`      | Reverse proxy, single entry point (port 8080)  |

All four run under the `range` Compose profile
([ADR](adr/0002-no-terraform-compose-primary.md)), activated automatically
via `COMPOSE_PROFILES=range` in `.env` — this keeps the range opt-in once a
root-level Bantis orchestrator exists (M3+), without changing today's
`docker compose up` workflow.

## Runtime data flow

```
client → nginx (:8080) → api (:8000) → db (:5432) / redis (:6379)
```

Nginx is the only service exposed to the host; `api`, `db`, and `redis`
are only reachable on the internal Compose network.

## CI/CD Pipeline

`.github/workflows/ci.yml` (adapted from
[cicd-pipeline-demo](https://github.com/SYRRUS-Ali/cicd-pipeline-demo)),
scoped to `range/**` changes only. Jobs, in order:

1. **Build** — builds the `api` Docker image (no push).
2. **Test & Lint** — Ruff + pytest, run against a full `docker compose`
   stack (not a bare container — see
   [lessons from Sprint 1](../README.md)).
3. **SAST (Semgrep)** — static analysis of `range/` source.
4. **Secret Scanning (Gitleaks)** — scans full git history.
5. **Dependency Scan (pip-audit)** — audits `api/requirements.txt` and
   `tests/requirements.txt`.
6. **Push to GHCR** — only on `main`, only if 2–5 pass.
7. **Deploy (Staging Simulation)** — pulls the published image, runs the
   full stack, smoke-tests `/health` and `/version`.
8. **Promote to Latest** — retags the validated image as `:latest`.
9. **Notify** — Telegram status message (success/failure, verified against
   each job's actual `needs.*.result`).

## Attack surface available for M2 (Attack Simulation)

These are the concrete injection points the supply-chain scenarios (see
[mitre-mapping.md](mitre-mapping.md)) will target:

| Entry point | What a scenario can do here |
|---|---|
| `range/api/requirements.txt` | Add an unsigned/malicious or typosquatted dependency — caught (or missed) by **Dependency Scan**. |
| Any commit in `range/` | Introduce a leaked credential/secret pattern — caught (or missed) by **Secret Scanning**. |
| `.github/workflows/ci.yml` | Inject a malicious pipeline step — this file is the pipeline's own trust boundary; a compromise here bypasses every other check. |
| `range/api/app/**` source | Introduce a vulnerable code pattern — caught (or missed) by **SAST**. |
| The built Docker image (GHCR) | An untrusted/unverified base or layer — relevant once M7 (second attack layer) considers image provenance. |

## Known limitations

- The range's own `Deploy (Staging Simulation)` step pulls from GHCR, but
  the range has no separate "production" environment — staging and the
  eventual "real" deployment are the same Compose stack today.
- Event correlation across `api` and `nginx` logs has a documented
  duration-unit mismatch and non-uniform `event_id` format — see
  [event-schema.md](event-schema.md#known-limitation).
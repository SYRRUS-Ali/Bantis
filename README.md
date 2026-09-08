# Bantis

Bantis is a self-hosted, open-source security platform that combines automated attack detection, AI-assisted incident response, and supply chain defense simulation — all running entirely on your own infrastructure.

> 🚧 Early development. Architecture docs are in `docs/`.

## Scope (v1)

Bantis v1 focuses on **supply chain attacks** against a CI/CD pipeline and its dependencies, with AI-assisted analysis and human-approved response. See [`docs/threat-model.md`](docs/threat-model.md) for what's explicitly in and out of scope, and [`docs/mitre-mapping.md`](docs/mitre-mapping.md) for the attack techniques covered.

## Design principles

- Fully self-hosted, no cloud dependency ([ADR 0001](docs/adr/0001-self-hosted-only.md))
- Docker Compose primary, Helm advanced, no Terraform ([ADR 0002](docs/adr/0002-no-terraform-compose-primary.md))
- Human-in-the-loop by default; AI recommends, operator approves ([ADR 0004](docs/adr/0004-recommend-only-default.md))

## M1: Range v1

✅ Complete — the target environment and its CI/CD pipeline are up and
running. This is the foundation M2 (Attack Simulation) will attack.

### What's in it

- **The range**: a FastAPI + PostgreSQL + Redis + Nginx stack (reused from
  [compose-multiservice-app](https://github.com/SYRRUS-Ali/compose-multiservice-app)),
  instrumented with structured JSON logging and a documented
  [event schema](docs/event-schema.md).
- **A supply-chain-hardened CI/CD pipeline** (`.github/workflows/ci.yml`):
  build → lint + test against a real running stack → SAST (Semgrep) →
  secret scanning (Gitleaks) → dependency scanning (pip-audit) → smoke
  test → push to GHCR → staging deploy → promote to `latest`, plus a
  manual rollback path and Telegram notifications on every run.
- This pipeline is also the actual attack surface for M2 — see
  [`docs/mitre-mapping.md`](docs/mitre-mapping.md) and the "Attack surface"
  table in [`docs/range-architecture.md`](docs/range-architecture.md).

### How to run it

```bash
cd range
cp .env.example .env        # fill in real values — see comments in the file
docker compose up -d
./scripts/smoke-test.sh     # verifies every container is up and responding
curl http://localhost:8080/health
```

Manual smoke-test details: [`range/README.md`](range/README.md#smoke-test).

### Architecture (short version)

```
client → nginx (:8080) → api (:8000) → db (:5432)
                                      → redis (:6379)
```

Nginx is the only service exposed to the host; `api`, `db`, and `redis`
are only reachable on the internal Compose network. All four run under a
single `range` Compose profile, kept opt-in for a future root-level
orchestrator (M3+). Full component table and data flow:
[`docs/range-architecture.md`](docs/range-architecture.md).

### Known issues

Being upfront about what's rough, not just what works:

- **No real staging environment** — `deploy-staging` and a genuine
  production deploy are the same Compose stack today; there's no
  isolation between them.
- **Log correlation has two known mismatches** between `api` and `nginx`:
  request duration is reported in different units (ms vs. seconds), and
  `event_id` isn't a uniform format across sources. Both are documented
  and left for the Detection Engine (M3) to normalize — see
  [`docs/event-schema.md#known-limitation`](docs/event-schema.md#known-limitation).
- **Real problems hit and fixed while building this** — a missing
  `/version` endpoint, a Telegram notification that reported success even
  when jobs failed, 28 CVEs turned up by `pip-audit`, a CI test job with
  no server to actually test against, a Compose profile change that
  silently broke CI — are logged in full, with root cause and fix, in
  [`docs/known-issues.md`](docs/known-issues.md). Worth reading before
  assuming the pipeline is bulletproof.

## License

MIT
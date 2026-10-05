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

## M2: Attack Simulation

✅ Complete — all four planned supply-chain attack scenarios are
implemented, tested, and replayable by id. This exercises the pipeline
M1 built, from outside it.

### What's in it

- **Four scenarios**, each mapped to a MITRE ATT&CK technique: malicious
  dependency injection (`T1195.001`), leaked secret exploitation
  (`T1552.001`), a compromised CI step (`T1195.002`), and a typosquatted
  package (`T1195.001`/`T1027`). Full detail on each — target, injection
  mechanism, isolation guarantee, cleanup contract — in
  [`docs/scenarios.md`](docs/scenarios.md).
- **A CLI** (`attack-sim/cli.py`): `list` shows every scenario, `run
  <scenario>` runs one end-to-end (`run()` → `log_result()` →
  `cleanup()`), `cleanup <scenario>` recovers a state left dirty by a
  crashed or interrupted prior run.
- **A safety barrier**: no scenario can even be instantiated without
  `BANTIS_ENV=range-local` set explicitly — enforced once, centrally, so
  a future scenario can't skip it by accident. See
  [`attack-sim/README.md`](attack-sim/README.md#safety-barrier-bantis_env).
- **The same event schema as M1**: every scenario run emits an
  `attack_scenario_run` event through the identical envelope `api` and
  `nginx` already use, with a shared `artifact`/`tool_returncode`/
  `tool_output_tail` field convention across all four — see
  [`docs/event-schema.md`](docs/event-schema.md).
- attack-sim is a separate, independently-deployable component from
  `range/` — it attacks the range from outside, sharing no dependencies
  or lifecycle with it.

### How to run it

```bash
cd attack-sim
pip install -r requirements.txt
export BANTIS_ENV=range-local   # required before any scenario can run — see "Safety barrier" above
python cli.py list
python cli.py run malicious-dependency
python cli.py cleanup malicious-dependency   # if a run is ever interrupted before its own cleanup
```

Full command reference: [`attack-sim/README.md`](attack-sim/README.md#cli-usage).

### Known limitations

Being upfront about what's rough, not just what works:

- **`compromised-ci-step` has no real verification step.** Unlike the
  other three, nothing actually triggers a GitHub Actions run against the
  injected step — that would need a real push or `act`, and this
  scenario's own design doc frames detection here as being about the
  *effects* of a compromised step (an unexpected outbound call, an
  unverified image), not the YAML change itself, since nothing in this
  pipeline lints or diffs workflow files today. `run()` always returns
  `SUCCESS` — a statement about that gap, not a bug.
- **Nothing consumes these events yet.** Every scenario emits a
  structured `attack_scenario_run` event, but there's no Detection Engine
  (M3) running to correlate or act on them — today they only reach
  whatever's tailing `attack-sim`'s logs.
- **Real problems found and fixed while building this** — a per-job
  Telegram breakdown that used to only say "something failed," an event
  schema with three different field names for the same concept across
  scenarios, and two scenarios whose `cleanup()` could silently report
  success without actually removing their scratch state — are logged
  honestly, with root cause and fix, in
  [`attack-sim/README.md`](attack-sim/README.md#known-issues) and
  [`docs/scenarios.md`](docs/scenarios.md). Worth reading before assuming
  a scenario always cleans up after itself.

## M3: Detection Engine

🚧 Sprint 3 closed — ingestion, three correlation rules, a scorecard
(detection rate / false positives / MTTD), and a read-only incidents
query API are built. What it does not do yet, and what must be fixed
before it is exposed beyond localhost (notably: no authentication on
any route), is in [`docs/m3-closure.md`](docs/m3-closure.md). The
AI-assisted analysis layer (M4) and the dashboard come next.

### What's in it

- **Ingestion**: `POST /events` accepts the same envelope M1 and M2
  already emit, validating identifier fields and `level` at the boundary
  rather than storing malformed data. Idempotent on `event_id`.
- **Three correlation rules**, applied most-specific-first: a composite
  dependency+secret pairing, a single untrusted-registry image pull, and
  a generic same-source burst (scoped to discrete attacker-relevant
  events — ordinary `http_request` traffic is excluded). One shared
  formula computes every rule's confidence score. Full rules reference:
  [`docs/correlation-design.md`](docs/correlation-design.md).
- **A scorecard generator** (`detection-engine/app/scorecard.py`):
  detection rate, false positives, and MTTD for a run, scored against a
  known-good expectation — the measurement
  [`docs/threat-model.md`](docs/threat-model.md) names as what "success"
  looks like.
- **A read-only incidents API** (`GET /incidents`, `GET
  /incidents/{id}`) — filterable, paginated, the foundation the
  dashboard queries against.
- A separate, independently-deployable component from `range/` and
  `attack-sim/`, sharing no dependencies or lifecycle with either.

### How to run it

```bash
cd detection-engine
pip install -r requirements.txt
python -m uvicorn app.main:app --reload
curl http://localhost:8000/health
curl http://localhost:8000/incidents
```

### Architecture (short version)

```
range/api, nginx, attack-sim → POST /events → events table
                                                    │
                                             run_correlation()
                                                    │
                                             incidents table
                                                    │
                                   GET /incidents, /incidents/{id}
                                                    │
                                   (dashboard — M4+, not built yet)
```

Full component table, data flow, and rules reference:
[`docs/detection-engine-architecture.md`](docs/detection-engine-architecture.md).

### Known limitations

- **`run_correlation()` isn't scheduled or triggered automatically
  yet** — it's invoked manually or by a test script today; ingestion and
  correlation are intentionally decoupled stages.
- **No authentication on the API** — the current trust model assumes a
  single local operator, same as the rest of v1; revisit before this is
  reachable beyond localhost.
- **Real problems found and fixed while building this** — an
  incidents table that a real app startup never created, an
  `ERROR`-status scenario run that was being correlated as if it were a
  real attack outcome, ordinary API traffic that was a 25% false-positive
  source, and two race conditions (a duplicate-event ingestion crash and
  non-deterministic correlation ordering under timestamp ties) — are
  logged in full, with root cause and fix, in
  [`detection-engine/README.md`](detection-engine/README.md#known-issues).
  Worth reading before assuming the correlation rules were right on the
  first try.

## License

MIT
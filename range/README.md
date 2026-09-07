# Range

This is the target environment for Bantis's supply-chain attack scenarios —
a FastAPI + PostgreSQL + Redis + Nginx stack reused from
[compose-multiservice-app](https://github.com/SYRRUS-Ali/compose-multiservice-app),
instrumented and intentionally exposed as the attack surface that later
milestones (Attack Simulation, Detection Engine) operate against.

This is not a standalone project — see the root [README](../README.md) for
the full Bantis scope.

## Smoke test

[`scripts/smoke-test.sh`](scripts/smoke-test.sh) is a quick, read-only
check that the compose stack is actually up before trusting it for
anything deeper — pytest, manual poking, or a CI deploy gate. It checks,
in order:

1. **Container status** — `api`, `db`, `redis`, and `nginx` are all in the
   `running` state (`docker compose ps`).
2. **Container health** — `api`, `db`, and `redis` each report `healthy`
   on their compose healthcheck (`docker inspect`). `nginx` has no
   healthcheck of its own, so it's only covered by the container-status
   check and the HTTP checks below.
3. **HTTP endpoints** — `GET /`, `/health`, and `/version` all respond
   through nginx (`http://localhost:${NGINX_PORT:-8080}`), with the
   expected JSON shape.

It exits `0` if every check passes, `1` if any fail, printing an
`OK`/`FAIL` line per check so a failure is easy to spot in CI logs.

It's used as a step in `.github/workflows/ci.yml`, in both the `test` job
(after the stack comes up, before pytest runs) and the `deploy-staging`
job (after the published image comes up, replacing the old ad-hoc
`curl | grep` steps).

### Running it manually

```bash
cd range
docker compose up -d       # start the stack (needs a real .env — see below)
./scripts/smoke-test.sh
```

Expected output when everything is healthy:

```
== Bantis range smoke test ==

-- Container status (docker ps) --
OK    api is running
OK    db is running
OK    redis is running
OK    nginx is running

-- Container health checks --
OK    api health: healthy
OK    db health: healthy
OK    redis health: healthy

-- HTTP endpoint checks (via nginx on :8080) --
OK    GET /: {"message":"compose-multiservice-app API is running"}
OK    GET /health: {"status":"ok"}
OK    GET /version: {"version":"0.1.0"}

== All smoke checks passed ==
```

If `NGINX_PORT` in your `.env` isn't `8080`, export it before running the
script so the HTTP checks hit the right port, e.g. `NGINX_PORT=9000
./scripts/smoke-test.sh`.
# Known Issues Encountered While Building the Range

This documents real problems hit while getting the range and its CI/CD
pipeline running for the first time — not hypothetical ones. Each entry:
what broke, why, and how it was fixed.

## Missing `/version` endpoint
**Symptom:** CI's staging smoke test expected a `/version` endpoint that
didn't exist in the copied `compose-multiservice-app` code.
**Fix:** Added a minimal `/version` endpoint to `app/main.py`.

## Telegram notification always reported "success"
**Symptom:** The pipeline's Telegram notification said ✅ success even
when `test` and `dependency-scan` jobs had actually failed.
**Root cause:** The status-detection step used `grep` against `toJSON()`
output, but `toJSON()` inserts a space after the colon (`"result": "failure"`)
that the grep pattern didn't account for — so the match never fired and the
code fell through to the success branch every time.
**Fix:** Replaced the string-matching logic with explicit
`needs.<job>.result` checks per job.

## Ruff false positive on FastAPI's `Depends()` pattern
**Symptom:** Lint failed with 9 `B008` errors on every `Depends(...)`
default argument — FastAPI's standard, documented dependency-injection
pattern, not a real bug.
**Fix:** Added `range/ruff.toml` explicitly ignoring `B008`, with a comment
explaining why.

## Known CVEs in pinned dependencies
**Symptom:** `pip-audit` found 28 known vulnerabilities across `pyjwt`,
`python-multipart`, and `starlette` (the last one only reachable via a
FastAPI upgrade, since the old FastAPI pin capped Starlette below the
patched range). A later CI run also caught a CVE in `pytest` itself.
**Fix:** Upgraded `fastapi` (which pulled a compatible, patched
`starlette`), and pinned `pyjwt`, `python-multipart`, and `pytest` to their
patched minimum versions — verified locally with `pip-audit` before
committing, not just trusting the advisory numbers blindly.

## CI test job had no real server or database to test against
**Symptom:** All 7 integration tests failed with `Connection refused` —
the test suite intentionally hits a real running server and a real
database (by design, per `conftest.py`), but the CI job only had bare
Python installed, no services.
**Fix:** Rebuilt the `test` job to spin up the full `docker compose` stack
(api + db + redis + nginx) with a generated `.env`, wait for `/health`,
then run pytest against it — instead of mocking the server or rewriting
the tests to avoid needing one.

## Staging deploy ran the API alone, without its dependencies
**Symptom:** `deploy-staging` ran the published image with a bare
`docker run`, no Postgres or Redis — the API crashed on startup (as
`.env.example` itself warns), so the health check never passed.
**Fix:** Rebuilt this job the same way as the test job: pull the published
image, tag it to match `compose.yaml`'s expected name, and bring up the
full stack with `docker compose up -d` (no `--build`, using the real
published image).

## Compose profile change silently broke CI
**Symptom:** After gating all range services behind a `range` Compose
profile (so a future root orchestrator can opt in), CI's generated `.env`
files didn't set `COMPOSE_PROFILES=range` — meaning zero containers would
have started on the next CI run.
**Fix:** Caught locally before pushing by testing the change end-to-end
first; added `COMPOSE_PROFILES=range` to both CI-generated `.env` files.

## Docker build cache corruption
**Symptom:** A local `docker compose up --build` failed once with
`failed to prepare extraction snapshot ... does not exist` — unrelated to
any code change.
**Fix:** `docker builder prune` cleared the corrupted cache. Transient
Docker infrastructure issue, not a project bug.
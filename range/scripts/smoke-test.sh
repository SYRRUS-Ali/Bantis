#!/usr/bin/env bash
# Bantis range smoke test.
#
# Verifies the compose stack is actually up and responding before trusting
# it for anything deeper (pytest, manual poking, a CI deploy gate). Run it
# after `docker compose up -d`.
#
# Usage:
#   cd range && ./scripts/smoke-test.sh
#
# Env overrides:
#   NGINX_PORT   host port nginx is published on (default: 8080)
set -euo pipefail

cd "$(dirname "$0")/.."

NGINX_PORT="${NGINX_PORT:-8080}"
BASE_URL="http://localhost:${NGINX_PORT}"

# db and redis have no HTTP endpoint of their own — their compose
# healthcheck (pg_isready / redis-cli ping) is the only signal available,
# so they're checked via `docker inspect` health status instead of curl.
SERVICES=(api db redis nginx)
HEALTHCHECKED_SERVICES=(api db redis)
FAILED=0

echo "== Bantis range smoke test =="
echo
echo "-- Container status (docker ps) --"

for service in "${SERVICES[@]}"; do
  if docker compose ps --status running --services | grep -qx "$service"; then
    echo "OK    $service is running"
  else
    echo "FAIL  $service is not running"
    FAILED=1
  fi
done

echo
echo "-- Container health checks --"

for service in "${HEALTHCHECKED_SERVICES[@]}"; do
  cid=$(docker compose ps -q "$service")
  if [[ -z "$cid" ]]; then
    echo "FAIL  $service: no container id (not started?)"
    FAILED=1
    continue
  fi
  health=$(docker inspect --format='{{.State.Health.Status}}' "$cid" 2>/dev/null || echo "none")
  if [[ "$health" == "healthy" ]]; then
    echo "OK    $service health: healthy"
  else
    echo "FAIL  $service health: $health"
    FAILED=1
  fi
done

echo
echo "-- HTTP endpoint checks (via nginx on :${NGINX_PORT}) --"

check_endpoint() {
  local path="$1" expect="$2" body
  if ! body=$(curl --silent --show-error --fail --max-time 5 "${BASE_URL}${path}"); then
    echo "FAIL  GET ${path}: request failed"
    FAILED=1
    return
  fi
  if grep -q "$expect" <<<"$body"; then
    echo "OK    GET ${path}: ${body}"
  else
    echo "FAIL  GET ${path}: unexpected response: ${body}"
    FAILED=1
  fi
}

check_endpoint "/" '"message"'
check_endpoint "/health" '"status":"ok"'
check_endpoint "/version" '"version"'

echo
if [[ "$FAILED" -eq 0 ]]; then
  echo "== All smoke checks passed =="
  exit 0
else
  echo "== Smoke test FAILED =="
  exit 1
fi

#!/usr/bin/env bash
# Bantis range smoke test.
#
# Verifies the compose stack is actually up before trusting it for anything
# deeper (pytest, manual poking, a CI deploy gate). Run it after
# `docker compose up -d`.
#
# Usage:
#   cd range && ./scripts/smoke-test.sh
set -euo pipefail

cd "$(dirname "$0")/.."

SERVICES=(api db redis nginx)
FAILED=0

echo "== Bantis range smoke test =="
echo
echo "-- Container status --"

for service in "${SERVICES[@]}"; do
  if docker compose ps --status running --services | grep -qx "$service"; then
    echo "OK    $service is running"
  else
    echo "FAIL  $service is not running"
    FAILED=1
  fi
done

echo
if [[ "$FAILED" -eq 0 ]]; then
  echo "== All smoke checks passed =="
  exit 0
else
  echo "== Smoke test FAILED =="
  exit 1
fi

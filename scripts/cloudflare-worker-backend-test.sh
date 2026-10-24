#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PACKAGE="packages/cloudflare-worker"
ARTIFACT_DIR="target/cloudflare-worker-backend-test"
rm -rf "$ARTIFACT_DIR"
mkdir -p "$ARTIFACT_DIR"
cp "$PACKAGE/tests/backend.dev.vars.fixture" "$PACKAGE/tests/.dev.vars"

node "$PACKAGE/tests/backend-server.mjs" >"$ARTIFACT_DIR/backend.log" 2>&1 &
backend_pid=$!
(
  cd "$PACKAGE"
  npx wrangler dev --config tests/wrangler.backend.jsonc --ip 127.0.0.1 --port 18788 \
    >"$ROOT/$ARTIFACT_DIR/wrangler.log" 2>&1
) &
wrangler_pid=$!
cleanup() {
  kill "$wrangler_pid" "$backend_pid" 2>/dev/null || true
  wait "$wrangler_pid" "$backend_pid" 2>/dev/null || true
  rm -f "$PACKAGE/tests/.dev.vars"
}
trap cleanup EXIT

for _ in $(seq 1 60); do
  if curl -fsS http://127.0.0.1:18788/ >"$ARTIFACT_DIR/response.json"; then
    break
  fi
  sleep 0.25
done
jq -e '.protocol_version == 1 and .artifacts[0].version == "fixture-v1"' \
  "$ARTIFACT_DIR/response.json" >/dev/null
if rg -n 'worker-backend-fixture-secret' "$ARTIFACT_DIR"; then
  echo "Worker/backend test artifacts disclosed the fixture secret" >&2
  exit 1
fi

#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
DOCKER_CONTEXT="${DOCKER_CONTEXT:-colima}"

docker --context "$DOCKER_CONTEXT" run --rm \
  -v "$ROOT/examples/nginx/nginx.conf:/etc/nginx/nginx.conf:ro" \
  nginx:stable-alpine nginx -t
docker --context "$DOCKER_CONTEXT" run --rm \
  -v "$ROOT/examples/caddy/Caddyfile:/etc/caddy/Caddyfile:ro" \
  caddy:alpine caddy validate --config /etc/caddy/Caddyfile

rg -q 'auth_request /_aux_sidecar_check' examples/nginx/nginx.conf
rg -q 'forward_auth unix/' examples/caddy/Caddyfile
rg -q 'proxy_pass_request_body off' examples/nginx/nginx.conf
if rg -q 'proxy_set_header X-Aux-[A-Za-z-]+ \$http_x_aux_' examples/nginx/nginx.conf \
  | rg -v 'Subject-ID|Country'; then
  echo "nginx example forwards a context header outside the documented allowlist" >&2
  exit 1
fi

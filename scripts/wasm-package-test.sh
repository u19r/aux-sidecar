#!/usr/bin/env bash
set -euo pipefail

if [ "${WASM_PACKAGE_SKIP_BUILD:-0}" != "1" ]; then
  scripts/wasm-build.sh
fi

for package in node web bundler; do
  dir="target/sidecar-wasm-$package"
  test -s "$dir/sidecar_wasm_bg.wasm"
  test -s "$dir/sidecar_wasm.d.ts"
  rg -q 'export class SidecarClient' "$dir/sidecar_wasm.d.ts"
  rg -q 'export interface BlocklistDecisionRequest' "$dir/sidecar_wasm.d.ts"
  rg -q 'export interface HostedLoginCompletionRequest' "$dir/sidecar_wasm.d.ts"
  rg -q 'export interface SidecarPublicError' "$dir/sidecar_wasm.d.ts"
  rg -q 'completeHostedLogin' "$dir/sidecar_wasm.d.ts"
  rg -q 'refreshHostedLogin' "$dir/sidecar_wasm.d.ts"
  rg -q 'getRateLimitConfig' "$dir/sidecar_wasm.d.ts"
  rg -q 'sync' "$dir/sidecar_wasm.d.ts"
  rg -q 'acquireLeases' "$dir/sidecar_wasm.d.ts"
  rg -q 'checkRateLimit' "$dir/sidecar_wasm.d.ts"
  rg -q 'giveBackLeases' "$dir/sidecar_wasm.d.ts"
  rg -q 'decideBlocklist' "$dir/sidecar_wasm.d.ts"
  rg -q 'decidePolicy' "$dir/sidecar_wasm.d.ts"
  rg -q 'evaluateAuthz' "$dir/sidecar_wasm.d.ts"
  rg -q 'evaluateEntitlements' "$dir/sidecar_wasm.d.ts"
done

node --input-type=module <<'NODE'
import init, { SidecarClient } from './target/sidecar-wasm-web/sidecar_wasm.js';
if (typeof init !== 'function' || typeof SidecarClient !== 'function') {
  throw new Error('web package does not expose its initializer and SidecarClient');
}
NODE

node --input-type=module <<'NODE'
import * as wasm from './target/sidecar-wasm-bundler/sidecar_wasm.js';
if (typeof wasm.SidecarClient !== 'function') {
  throw new Error('bundler package does not expose SidecarClient');
}
NODE

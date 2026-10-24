#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PACKAGE_DIR="packages/cloudflare-worker"
OUTPUT_DIR="${1:-target/cloudflare-worker-package}"
if [ "${WASM_PACKAGE_SKIP_BUILD:-0}" != "1" ]; then
  scripts/wasm-build.sh
fi
rm -rf "$PACKAGE_DIR/wasm" "$OUTPUT_DIR"
mkdir -p "$PACKAGE_DIR/wasm" "$OUTPUT_DIR"
cp -R target/sidecar-wasm-web/. "$PACKAGE_DIR/wasm/"

(
  cd "$PACKAGE_DIR"
  npm install --ignore-scripts
  npm run check
  npm test
  npm run build
  npm run dry-run
)

(
  cd "$PACKAGE_DIR"
  npm pack --ignore-scripts --pack-destination "$ROOT/$OUTPUT_DIR"
)
package_archive="$OUTPUT_DIR/auxfn-sidecar-cloudflare-worker-0.1.0.tgz"
compressed_bytes="$(wc -c <"$package_archive" | tr -d ' ')"
if [ "$compressed_bytes" -gt 9437184 ]; then
  echo "Cloudflare Worker package exceeds the 9 MiB compressed budget" >&2
  exit 1
fi
printf 'compressed_bytes=%s\ncompressed_budget_bytes=9437184\n' "$compressed_bytes" \
  >"$OUTPUT_DIR/size-report.txt"

node --input-type=module - "$OUTPUT_DIR" <<'NODE'
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
const directory = process.argv[2];
const archive = "auxfn-sidecar-cloudflare-worker-0.1.0.tgz";
const sourceHead = execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim();
const sourceDirty = execFileSync("git", ["status", "--porcelain"], { encoding: "utf8" }).trim().length > 0;
const sha256 = createHash("sha256").update(readFileSync(join(directory, archive))).digest("hex");
writeFileSync(join(directory, "artifact-receipt.json"), JSON.stringify({
  format_version: "aux-sidecar-worker-package.v1", archive, sha256,
  source_head: sourceHead, source_dirty: sourceDirty,
  checks: { types: "passed", worker_tests: "passed", deployment_dry_run: "passed" }
}, null, 2) + "\n");
NODE

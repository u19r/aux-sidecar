#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
OUTPUT_DIR="${1:-target/lambda-layers}"
TARGET_DIR="$(cargo metadata --locked --format-version 1 --no-deps | jq -r '.target_directory')"
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

for entry in x86_64:x86_64-unknown-linux-gnu arm64:aarch64-unknown-linux-gnu; do
  architecture="${entry%%:*}"
  target="${entry#*:}"
  "$ROOT/scripts/build-linux-binary.sh" "$target" sidecar-lambda-extension aux-sidecar \
    "$TARGET_DIR/$target/release/aux-sidecar"
  staging="$OUTPUT_DIR/$architecture/extensions"
  mkdir -p "$staging"
  install -m 0755 "$TARGET_DIR/$target/release/aux-sidecar" "$staging/aux-sidecar"
  test -x "$staging/aux-sidecar"
  file "$staging/aux-sidecar" >"$OUTPUT_DIR/$architecture-file.txt"
  case "$architecture" in
    x86_64) rg -q 'x86-64' "$OUTPUT_DIR/$architecture-file.txt" ;;
    arm64) rg -q 'ARM aarch64' "$OUTPUT_DIR/$architecture-file.txt" ;;
  esac
  TZ=UTC touch -t 198001010000 "$OUTPUT_DIR/$architecture/extensions" "$staging/aux-sidecar"
  (cd "$OUTPUT_DIR/$architecture" && zip -X -q -r "../aux-sidecar-$architecture.zip" extensions)
  unzip -Z1 "$OUTPUT_DIR/aux-sidecar-$architecture.zip" | rg -qx 'extensions/aux-sidecar'
  shasum -a 256 "$OUTPUT_DIR/aux-sidecar-$architecture.zip" \
    >"$OUTPUT_DIR/aux-sidecar-$architecture.zip.sha256"
done

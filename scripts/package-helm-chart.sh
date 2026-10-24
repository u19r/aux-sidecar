#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
OUTPUT_DIR="${1:-target/helm}"
SMOKE="examples/kubernetes/helm-smoke"
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

helm lint charts/aux-sidecar
helm dependency build "$SMOKE"
helm lint "$SMOKE"
helm template aux-sidecar-smoke "$SMOKE" >"$OUTPUT_DIR/rendered.yaml"
rg -q 'kind: Deployment' "$OUTPUT_DIR/rendered.yaml"
if rg -q 'kind: (Service|Ingress)|hostPort:|privileged: true|AUX_API_KEY[[:space:]]*value:' "$OUTPUT_DIR/rendered.yaml"; then
  echo "unsafe resource or secret rendering found in Helm output" >&2
  exit 1
fi
rg -q 'readOnlyRootFilesystem: true' "$OUTPUT_DIR/rendered.yaml"
rg -q 'command: \["/usr/local/bin/sidecar", healthcheck, live\]' "$OUTPUT_DIR/rendered.yaml"
rg -q 'command: \["/usr/local/bin/sidecar", healthcheck, ready\]' "$OUTPUT_DIR/rendered.yaml"
helm package charts/aux-sidecar --destination "$OUTPUT_DIR" >/dev/null
shasum -a 256 "$OUTPUT_DIR"/*.tgz >"$OUTPUT_DIR/aux-sidecar-chart.sha256"

#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
target=${1:?Rust target is required}
package=${2:?Cargo package is required}
binary=${3:?binary name is required}
output=${4:?output path is required}
case "$target" in
  x86_64-unknown-linux-gnu) platform=linux/amd64 ;;
  aarch64-unknown-linux-gnu) platform=linux/arm64 ;;
  *) printf 'Unsupported Linux target: %s\n' "$target" >&2; exit 1 ;;
esac
staging=$(mktemp -d)
trap 'rm -rf "$staging"' EXIT
docker buildx build --platform "$platform" --target binary \
  --file "$repo_root/docker/sidecar.Dockerfile" \
  --build-arg PACKAGE="$package" --build-arg BIN="$binary" \
  --output "type=local,dest=$staging" "$repo_root"
mkdir -p "$(dirname -- "$output")"
install -m 755 "$staging/binary" "$output"

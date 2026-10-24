#!/usr/bin/env bash
set -euo pipefail

cargo build --locked --release -p sidecar-wasm --target wasm32-unknown-unknown
target_dir="$(cargo metadata --locked --format-version 1 --no-deps | jq -r '.target_directory')"
wasm_input="$target_dir/wasm32-unknown-unknown/release/sidecar_wasm.wasm"

for target in nodejs web bundler; do
	case "$target" in
	nodejs) output="target/sidecar-wasm-node" ;;
	web) output="target/sidecar-wasm-web" ;;
	bundler) output="target/sidecar-wasm-bundler" ;;
	esac
	rm -rf "$output"
	mkdir -p "$output"
	wasm-bindgen \
		"$wasm_input" \
		--target "$target" \
		--out-dir "$output" \
		--out-name sidecar_wasm \
		--typescript
done

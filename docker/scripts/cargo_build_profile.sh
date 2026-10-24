#!/bin/sh

set -eu

case "${1:-release}" in
    dev)
        CARGO_BUILD_PROFILE_ARGS="--profile dev"
        CARGO_BUILD_OUTPUT_DIR="debug"
        ;;
    fast-release)
        CARGO_BUILD_PROFILE_ARGS="--profile fast-release"
        CARGO_BUILD_OUTPUT_DIR="fast-release"
        ;;
    release)
        CARGO_BUILD_PROFILE_ARGS="--release"
        CARGO_BUILD_OUTPUT_DIR="release"
        ;;
    *)
        echo "unsupported BUILD_PROFILE: ${1:-}" >&2
        return 1 2>/dev/null || exit 1
        ;;
esac

export CARGO_BUILD_PROFILE_ARGS
export CARGO_BUILD_OUTPUT_DIR

# Versions: software-versions.json; details in software-version-consumers.md.
# Canonical optional SDK cache entrypoints. Generated copies are maintained by aux-infra versions-sync.
# Tool/image versions come from software-versions.snapshot.json and software-versions.json.
import 'build-cache.just'

[private]
[positional-arguments]
_aux-cache-sdk configuration operation selection platform *arguments:
    #!/usr/bin/env bash
    set -euo pipefail
    configuration=$1 operation=$2 selection=$3 platform=$4
    shift 4
    case "$operation" in bake|build) ;; *) printf 'Unknown cache operation: %s\n' "$operation" >&2; exit 1 ;; esac
    umask 077
    private=$(mktemp -d)
    trap 'rm -rf "$private"' EXIT
    cp "$configuration" "$private/cache.json"
    export AWS_REGION=$(jq -er '.region' "$private/cache.json")
    export AWS_RETRY_MODE=standard AWS_MAX_ATTEMPTS=8 AWS_PAGER=''
    test "$(aws sts get-caller-identity --query Account --output text)" = "$(jq -er '.identity.account_id' "$private/cache.json")"
    export PUBLICATION_DOCKER_CONFIG="${DOCKER_CONFIG:-$HOME/.docker}"
    export BUILDX_CONFIG="${BUILDX_CONFIG:-$PUBLICATION_DOCKER_CONFIG/buildx}"
    export DOCKER_CONFIG="$private/docker"
    just --working-directory "$PWD" --justfile docker/build-cache.just -- _aux-cache-prepare "$private"
    just --working-directory "$PWD" --justfile docker/sdk-build-cache.just -- "_aux-cache-$operation" "$private" "$selection" "$platform" "$@"

[private]
[positional-arguments]
_aux-cache-build private selection platform *arguments:
    #!/usr/bin/env bash
    set -euo pipefail
    private=$1 selection=$2 platform=$3
    shift 3
    repository=$(jq -er '.oci_repository' "$private/cache.json")
    dependencies="${repository%/*}/aux-infra"
    syntax_digest=$(jq -er '.lock.images.dockerfile.digest' software-versions.snapshot.json)
    base_digest=$(jq -er '.lock.images.ubi.digest' software-versions.snapshot.json)
    reference="$repository:${platform//\//-}-$selection"
    docker buildx build --platform "$platform" --secret "id=sccache_config,src=$private/sccache.toml" --secret "id=sccache_credentials,src=$private/sccache.credentials" \
      --build-arg "BUILDKIT_SYNTAX=$dependencies@$syntax_digest" --build-arg "UBI_IMAGE=$dependencies@$base_digest" \
      --cache-from "type=registry,ref=$reference" --cache-to "type=registry,ref=$reference,mode=max,oci-mediatypes=true,image-manifest=true" "$@"

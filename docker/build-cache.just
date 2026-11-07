# Versions: software-versions.json; details in software-version-consumers.md.
# Canonical native cache recipes. Generated copies are maintained by aux-infra versions-sync.
# Tool/image versions come from software-versions.snapshot.json and software-versions.json.

[private]
[positional-arguments]
_aux-cache-prepare private:
    #!/usr/bin/env bash
    set -euo pipefail
    private=$1
    cache="$private/cache.json"
    mkdir -p "$DOCKER_CONFIG"
    if test -d "$PUBLICATION_DOCKER_CONFIG/contexts"; then cp -R "$PUBLICATION_DOCKER_CONFIG/contexts" "$DOCKER_CONFIG/"; fi
    if test -f "$PUBLICATION_DOCKER_CONFIG/config.json"; then jq 'del(.auths,.credsStore,.credHelpers)' "$PUBLICATION_DOCKER_CONFIG/config.json" > "$DOCKER_CONFIG/config.json"; fi
    region=$(jq -er '.region' "$cache")
    repository=$(jq -er '.oci_repository' "$cache")
    registry=${repository%%/*}
    # Empty Docker auth config auto-selects the macOS keychain. Populate its
    # standard auth record first, using ECR's native token without secret arguments.
    if ! test -f "$DOCKER_CONFIG/config.json"; then printf '%s\n' '{"auths":{}}' > "$DOCKER_CONFIG/config.json"; fi
    aws ecr get-authorization-token --output json --region "$region" --registry-ids "${registry%%.*}" | jq -e --arg registry "$registry" --slurpfile config "$DOCKER_CONFIG/config.json" \
      'if (.authorizationData | length) != 1 or .authorizationData[0].proxyEndpoint != ("https://" + $registry) then error("ECR registry mismatch") else .authorizationData[0].authorizationToken as $auth | $config[0] | .auths[$registry] = {auth:$auth} end' > "$DOCKER_CONFIG/next.json"
    mv "$DOCKER_CONFIG/next.json" "$DOCKER_CONFIG/config.json"
    jq -r '"[cache.multilevel]\nchain = [\"disk\", \"s3\"]\nwrite_error_policy = \"l0\"\n[cache.disk]\ndir = \"/var/cache/aux-rust-sccache\"\nsize = \(.compiler.local_size_gib * 1073741824)\n[cache.s3]\nno_credentials = false\nbucket = \(.compiler.bucket_name | tojson)\nregion = \(.region | tojson)\nkey_prefix = \(.compiler.key_prefix | tojson)"' "$cache" > "$private/sccache.toml"
    aws configure export-credentials --format process | jq -er '"[default]\naws_access_key_id=\(.AccessKeyId)\naws_secret_access_key=\(.SecretAccessKey)\n" + (if (.SessionToken // "") == "" then "" else "aws_session_token=\(.SessionToken)\n" end)' > "$private/sccache.credentials"

[private]
[positional-arguments]
_aux-cache-bake private bake platform *arguments:
    #!/usr/bin/env bash
    set -euo pipefail
    private=$1 bake=$2 platform=$3
    shift 3
    arguments=("$@")
    repository=$(jq -er '.oci_repository' "$private/cache.json")
    for secret in "sccache_config:$private/sccache.toml" "sccache_credentials:$private/sccache.credentials"; do
        arguments+=(--set "*.secrets+=id=${secret%%:*},src=${secret#*:}" --allow "fs.read=${secret#*:}")
    done
    definition=$(docker buildx bake --file docker-bake.hcl "$bake" "${arguments[@]}" --print)
    dependencies="${repository%/*}/aux-infra"
    syntax_digest=$(jq -er '.lock.images.dockerfile.digest' software-versions.snapshot.json)
    # Mirror transport preserves content identity; a missing mirror fails without upstream fallback.
    arguments+=(--set "*.args.BUILDKIT_SYNTAX=$dependencies@$syntax_digest")
    while IFS=$'\t' read -r argument digest; do
        test -n "$digest" && test "$digest" != null
        arguments+=(--set "*.args.$argument=$dependencies@$digest")
    done < <(jq -r '.target[].args | to_entries[] | select(.key == "UBI_IMAGE" or .key == "UBI_MICRO_IMAGE" or .key == "NODE_BUILDER_IMAGE" or .key == "NODE_RUNTIME_IMAGE") | [.key, (.value | split("@")[1])] | @tsv' <<< "$definition" | sort -u)
    platform_key=${platform//\//-}
    platform_key=${platform_key//,/--}
    while IFS= read -r target; do
        reference="$repository:$platform_key-$target"
        arguments+=(--set "$target.cache-from=type=registry,ref=$reference" --set "$target.cache-to=type=registry,ref=$reference,mode=max,oci-mediatypes=true,image-manifest=true")
    done < <(jq -er '.target | keys[]' <<< "$definition")
    docker buildx bake --file docker-bake.hcl "$bake" --set "*.platform=$platform" "${arguments[@]}"


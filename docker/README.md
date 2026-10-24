# Container builds

Build the native service from the repository root with Docker Buildx:

```sh
docker buildx build --load -f docker/sidecar.Dockerfile -t aux-sidecar:local .
```

The Dockerfile pins Red Hat UBI builder and UBI Micro runtime images by digest. It installs
the Rust toolchain and checksum-verified mold linker, then builds the locked public workspace.
The runtime runs as UID 65532 and contains the native binary, its shared libraries, and CA roots.

Keep the sidecar on a trusted network. For a local loopback-only smoke check:

```sh
docker run --rm -p 127.0.0.1:9001:9001 \
  -e AUX_BASE_URL=https://tenant.example.com \
  -e AUX_API_KEY -e AUX_RESOURCE_AUDIENCES=api://orders \
  -e AUX_BIND_ADDR=0.0.0.0:9001 -e AUX_UNSAFE_BIND_NON_LOOPBACK=true \
  aux-sidecar:local
```

In another terminal, call `curl --fail http://127.0.0.1:9001/sidecar/live`.
Do not publish this port on an untrusted interface. Set `AUX_API_KEY` in the host environment
before starting the container; keep credentials out of image layers and command history.

Use `scripts/build-linux-binary.sh` to export a native Linux binary through the same Dockerfile.
Use Docker Buildx `--platform linux/amd64,linux/arm64` with a registry output for multi-platform
images. The private canary and release orchestration are not required to build this image.

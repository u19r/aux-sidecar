# syntax=docker/dockerfile:1.28
# Versions: software-versions.json; details in software-version-consumers.md.
ARG RUST_VERSION=1.99.1
ARG UBI_IMAGE=registry.access.redhat.com/ubi9/ubi:9.8@sha256:217dd5692d369799d34d09ffb6f5f3404efebc7900834490fdf9ae92fd6721d4
ARG UBI_MICRO_IMAGE=registry.access.redhat.com/ubi9/ubi-micro:9.8@sha256:5be877a2a280ae36eb9ab80ca4efb28bbf77c57abbba38137cdc37a03b8465e6

FROM ${UBI_IMAGE} AS builder
ARG RUST_VERSION
ARG PACKAGE=sidecar
ARG BIN=sidecar
ARG BUILD_PROFILE=release
ENV PATH=/root/.cargo/bin:${PATH}
WORKDIR /workspace

COPY --chmod=755 scripts/install-mold.sh /usr/local/bin/install-mold.sh
ENV RUSTFLAGS="-C link-arg=-B/opt/aux-mold-3.0.0/libexec/mold -C link-arg=-fuse-ld=bfd"
ENV LDFLAGS="-B/opt/aux-mold-3.0.0/libexec/mold"
ENV CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/opt/aux-mold-3.0.0/bin/mold-cc
ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=/opt/aux-mold-3.0.0/bin/mold-cc

RUN dnf -y install gcc gcc-c++ tar gzip curl-minimal make pkgconf-pkg-config openssl-devel ca-certificates git && \
    dnf clean all && \
    /usr/local/bin/install-mold.sh && \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain "${RUST_VERSION}"

COPY --chmod=755 docker/scripts/cargo_build_profile.sh /usr/local/bin/cargo_build_profile.sh

COPY . ./aux-sidecar

WORKDIR /workspace/aux-sidecar
RUN --mount=type=cache,id=aux-sidecar-cargo-registry,sharing=locked,target=/root/.cargo/registry \
    --mount=type=cache,id=aux-sidecar-target,sharing=locked,target=/workspace/aux-sidecar/target \
    . /usr/local/bin/cargo_build_profile.sh "$BUILD_PROFILE" && \
    cargo build --locked $CARGO_BUILD_PROFILE_ARGS -p "${PACKAGE}" --bin "${BIN}" && \
    cp "target/${CARGO_BUILD_OUTPUT_DIR}/${BIN}" "/tmp/${BIN}" && \
    mkdir -p /tmp/runtime-root && \
    ldd "/tmp/${BIN}" | \
        awk '/=> \// { print $3 } /^[[:space:]]*\// && $1 !~ /:$/ && $1 !~ /^\/lib\// { print $1 }' | \
        sort -u | \
        xargs -r -I '{}' sh -c 'case "$1" in /lib64/*) dest="/tmp/runtime-root/usr$1" ;; *) dest="/tmp/runtime-root$1" ;; esac && mkdir -p "$(dirname "$dest")" && cp -L "$1" "$dest"' _ '{}'

FROM scratch AS binary
ARG BIN=sidecar
COPY --from=builder /tmp/${BIN} /binary

FROM ${UBI_MICRO_IMAGE} AS runtime
ARG BIN=sidecar
ENV HOME=/var/lib/aux-sidecar
RUN mkdir -p /var/lib/aux-sidecar /etc/aux-sidecar && \
    chown -R 65532:65532 /var/lib/aux-sidecar /etc/aux-sidecar
COPY --from=builder /etc/pki/ca-trust /etc/pki/ca-trust
COPY --from=builder /etc/pki/tls/certs /etc/pki/tls/certs
COPY --from=builder /tmp/sidecar /usr/local/bin/sidecar
COPY --from=builder /tmp/runtime-root/ /
USER 65532:65532
EXPOSE 9001
VOLUME ["/var/lib/aux-sidecar"]
ENTRYPOINT ["/usr/local/bin/sidecar"]

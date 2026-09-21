# syntax=docker/dockerfile:1
# webauthn-rs-demo Docker container.
#
# See ./demo/README.md#run-from-docker for more information.
ARG RUST_VERSION=1.98.1
ARG DEBIAN_VERSION=trixie

# Fetch pre-built cargo-leptos binary
FROM scratch AS leptos-linux-amd64
ADD \
    --checksum=sha256:35657e0ada6a026389cfffe2c22ca8eacee46250c27fe88b869955fe17a3d05f \
    --unpack \
    https://github.com/leptos-rs/cargo-leptos/releases/download/v0.3.9/cargo-leptos-x86_64-unknown-linux-gnu.tar.gz \
    /cargo-leptos

FROM scratch AS leptos-linux-arm64
ADD \
    --checksum=sha256:91461f8f8200b46eba94975b134d035604cbf9cd800231245e8a123c305e2ad5 \
    --unpack \
    https://github.com/leptos-rs/cargo-leptos/releases/download/v0.3.9/cargo-leptos-aarch64-unknown-linux-gnu.tar.gz \
    /cargo-leptos

# COPY --from doesn't allow variable expansion, so expand it here.
FROM leptos-${TARGETOS}-${TARGETARCH}${TARGETVARIANT} AS leptos

# Docker's rust image is owned by rust-lang: https://github.com/rust-lang/docker-rust
FROM rust:${RUST_VERSION}-${DEBIAN_VERSION} AS builder

COPY --from=leptos /cargo-leptos /cargo-leptos/

RUN \
    --mount=type=cache,target=/usr/local/cargo/git/db \
    --mount=type=cache,target=/usr/local/cargo/registry/,sharing=locked \
    <<EOT sh
    set -e
    rustup target add wasm32-unknown-unknown
    install /cargo-leptos/cargo-leptos-$(rustc --print host-tuple)/cargo-leptos /usr/local/bin/
EOT

WORKDIR /src
COPY Cargo.toml .
COPY attestation-ca ./attestation-ca/
COPY base64urlsafedata ./base64urlsafedata/
COPY demo ./demo/
COPY device-catalog ./device-catalog/
COPY webauthn-rs ./webauthn-rs/
COPY webauthn-rs-core ./webauthn-rs-core/
COPY webauthn-rs-proto ./webauthn-rs-proto/

# Stub other workspace members and prepare workspace
RUN <<EOT sh
    set -eux
    for l in \
        cable-tunnel-server/backend \
        cable-tunnel-server/common \
        cable-tunnel-server/frontend \
        fido-hid-rs \
        fido-key-manager \
        fido-mds \
        fido-mds-tool \
        sshkey-attest \
        tutorial/server/actix_web \
        tutorial/server/axum \
        tutorial/wasm \
        webauthn-authenticator-rs \
        webauthn-rp-proxy
    do
        cargo new --vcs none --lib \$l
    done
    mkdir /src/.cargo
EOT

# Build web artefacts
FROM builder AS builder-web
WORKDIR /src/demo/
RUN cargo leptos build --release

# Build database migration tool
FROM builder AS builder-migration
WORKDIR /src/demo/migration/
RUN cargo build --release

# Final image
FROM debian:${DEBIAN_VERSION}-slim AS final

LABEL org.opencontainers.image.source=https://github.com/kanidm/webauthn-rs
LABEL org.opencontainers.image.authors=william@blackhats.net.au

WORKDIR /app
COPY ./docker_startup.sh ./release/
COPY --from=builder-migration /src/target/release/migration ./migration
COPY --from=builder-web /src/target/release/webauthn-rs-demo ./webauthn-rs-demo
COPY --from=builder-web /src/target/site ./site/
EXPOSE 3000

VOLUME ["/data"]

ENV \
    DATABASE_URL="sqlite:///data/state.db3?mode=rwc" \
    LEPTOS_SITE_ADDR="0.0.0.0:3000" \
    RP_NAME="webauthn-rs demo" \
    RP_ORIGIN="http://localhost:3000"

CMD ["/app/release/docker_startup.sh"]

# webauthn-rs demo site Docker container.
ARG RUST_VERSION=1.98.1
ARG DEBIAN_VERSION=trixie

# Docker's rust image sources are owned by rust-lang:
# https://github.com/rust-lang/docker-rust
FROM rust:${RUST_VERSION}-${DEBIAN_VERSION} AS builder

ADD --unpack \
    https://github.com/leptos-rs/cargo-leptos/releases/download/v0.3.9/cargo-leptos-x86_64-unknown-linux-gnu.tar.gz \
    /cargo-leptos

RUN \
    --mount=type=cache,target=/usr/local/cargo/git/db \
    --mount=type=cache,target=/usr/local/cargo/registry/,sharing=locked \
    <<EOT sh
    set -e
    rustup target add wasm32-unknown-unknown
    install /cargo-leptos/cargo-leptos-x86_64-unknown-linux-gnu/cargo-leptos /usr/local/bin/
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

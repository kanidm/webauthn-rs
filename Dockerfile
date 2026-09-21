# webauthn-rs demo site Docker container.
ARG RUST_VERSION=1.98.1

# Docker's rust image sources are owned by rust-lang:
# https://github.com/rust-lang/docker-rust
FROM rust:${RUST_VERSION}-trixie AS builder

ADD --unpack \
	https://github.com/leptos-rs/cargo-leptos/releases/download/v0.3.9/cargo-leptos-x86_64-unknown-linux-gnu.tar.gz \
	/cargo-leptos

RUN \
    --mount=type=cache,target=/usr/local/cargo/git/db \
    --mount=type=cache,target=/usr/local/cargo/registry/,sharing=locked \
    <<EOT sh
    set -e
    rustup target add wasm32-unknown-unknown
    cargo install --locked sea-orm-cli --no-default-features --features sqlx-sqlite,codegen,runtime-tokio
	exit 1
EOT

COPY . /src/
RUN mkdir /src/.cargo
WORKDIR /src/demo/

# RUN cp cargo_vendor.config .cargo/config
RUN cargo build --release

# == end builder setup, we now have static artifacts.
FROM run_base
MAINTAINER william@blackhats.net.au
EXPOSE 8080
WORKDIR /

RUN cd /etc && \
    ln -sf ../usr/share/zoneinfo/Australia/Brisbane localtime

COPY --from=builder /src/target/release/webauthn-rs-demo /bin/
COPY --from=builder /src/compat_tester/webauthn-rs-demo/pkg /pkg

ENV RUST_BACKTRACE 1
CMD ["/bin/webauthn-rs-demo"]

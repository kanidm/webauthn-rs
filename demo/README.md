# webauthn-rs-demo2

Work in progress rewrite of the demo site using axum and leptos.

Currently does very little. :)

## Prerequisites

Install a recent Rust toolchain for your host and `wasm32-unknown-unknown`.

Install [`cargo-leptos`][1].

[1]: https://github.com/leptos-rs/cargo-leptos

## Run the development server

```sh
# WebAuthn must be served over HTTPS, so we generate some self-signed certs.
./generate_certs.sh

# Run the server without hot-reloading (as HTTPS isn't supported)
cargo leptos serve
```

Then point your browser at https://localhost:3000

## Axum Server

This demonstrates using Axum as the backend.

By default, it serves the WASM front-end ([located here](https://github.com/kanidm/webauthn-rs/tree/master/tutorial/wasm "located here")). You will need to build this yourself first then copy the output into the assets directory.

If you want to use the HTML/Javascript front-end instead, run the following command
```rust
cargo run --no-default-features --features javascript
```
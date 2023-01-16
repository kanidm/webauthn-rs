## Axum Server

This demonstrates using Axum as the backend.

By default, it serves the WASM front-end ([located here](https://github.com/kanidm/webauthn-rs/tree/master/tutorial/wasm "located here")).
This needs to be built first by running the below ([wasm-pack](https://rustwasm.github.io/wasm-pack/installer/) is required).
```sh
./build_wasm.sh
```

If you want to use the HTML/Javascript front-end instead, run the following command.
```sh
cargo run --no-default-features --features javascript
```
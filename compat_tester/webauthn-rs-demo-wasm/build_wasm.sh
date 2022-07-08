#!/bin/sh
RUSTFLAGS="--cfg=web_sys_unstable_apis" wasm-pack build --target web && \
    cp -r ./pkg/snippets ./pkg/webauthn_rs_demo_wasm.js ./pkg/webauthn_rs_demo_wasm.d.ts ./pkg/webauthn_rs_demo_wasm_bg.wasm.d.ts ./pkg/webauthn_rs_demo_wasm_bg.wasm ../webauthn-rs-demo/pkg/


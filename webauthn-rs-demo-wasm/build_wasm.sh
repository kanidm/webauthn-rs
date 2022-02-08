#!/bin/sh
RUSTFLAGS="--cfg=web_sys_unstable_apis" wasm-pack build --target web && \
    rollup ./main.js --format iife --file ./pkg/bundle.js && \
    cp ./pkg/bundle.js ../webauthn-rs-demo/pkg/ && \
    cp ./pkg/webauthn_rs_demo_wasm_bg.wasm ../webauthn-rs-demo/pkg/


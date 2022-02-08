import init, { run_app } from './pkg/webauthn_rs_demo_wasm.js';
async function main() {
   await init('/pkg/webauthn_rs_demo_wasm_bg.wasm');
   run_app();
}
main()

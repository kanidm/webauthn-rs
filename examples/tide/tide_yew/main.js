import init, { run_app } from './pkg/tide_yew.js';
async function main() {
   await init('/pkg/tide_yew_bg.wasm');
   run_app();
}
main()

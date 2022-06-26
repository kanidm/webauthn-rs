// #![deny(warnings)]
#![warn(unused_extern_crates)]
#![recursion_limit = "512"]
use wasm_bindgen::prelude::*;

mod compat;
mod condui;
mod demo;
mod error;
mod manager;
mod utils;
// mod uv;

#[wasm_bindgen]
pub fn run_app() -> Result<(), JsValue> {
    yew::start_app::<manager::ManagerApp>();
    Ok(())
}

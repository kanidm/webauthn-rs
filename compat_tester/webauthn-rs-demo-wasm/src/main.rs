// #![deny(warnings)]
#![warn(unused_extern_crates)]
#![recursion_limit = "512"]

mod compat;
mod demo;
mod error;
mod manager;
mod utils;

pub fn main() {
    yew::Renderer::<manager::ManagerApp>::new().render();
}

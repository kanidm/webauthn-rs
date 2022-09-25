#[macro_use]
extern crate tracing;

mod core;

fn main() {
    tracing_subscriber::fmt::init();

    core::event_loop();
}

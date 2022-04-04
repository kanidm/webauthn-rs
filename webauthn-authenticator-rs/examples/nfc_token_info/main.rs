#[macro_use]
extern crate tracing;

#[cfg(feature = "nfc")]
mod core;

#[cfg(feature = "nfc")]
fn main() {
    tracing_subscriber::fmt::init();

    core::event_loop();
}

#[cfg(not(feature = "nfc"))]
fn main() {
    tracing_subscriber::fmt::init();

    error!("This example requires the feature \"nfc\" to be enabled.");
}

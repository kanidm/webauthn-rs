#[macro_use]
extern crate tracing;

#[cfg(feature = "nfc_raw_transmit")]
mod core;

#[cfg(feature = "nfc_raw_transmit")]
fn main() {
    tracing_subscriber::fmt::init();
    core::main();
}

#[cfg(not(feature = "nfc_raw_transmit"))]
fn main() {
    tracing_subscriber::fmt::init();
    error!("This example requires the feature \"nfc_raw_transmit\" to be enabled.");
}

#[macro_use]
extern crate tracing;

mod core;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    core::event_loop().await;
}

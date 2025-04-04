use clap::Subcommand;

use authenticator::{
    authenticatorservice::{AuthenticatorService, CtapVersion},
    statecallback::StateCallback,
    InfoResult, StatusUpdate,
};
use std::sync::mpsc::{channel, RecvError};
use std::thread;
use tracing::{debug, error, info, level_filters::LevelFilter, trace};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Subcommand)]
#[clap(about = "Authenticator Utility")]
enum Opt {
    List,
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::DEBUG.into())
                .from_env_lossy(),
        )
        .compact()
        .init();

    info!("Starting...");
    let timeout_ms = 25000;

    let mut manager = AuthenticatorService::new(CtapVersion::CTAP2)
        .expect("The auth service should initialize safely");

    // Later we need to add common options for transports to consume.
    manager.add_u2f_usb_hid_platform_transports();

    let (status_tx, status_rx) = channel::<StatusUpdate>();
    thread::spawn(move || loop {
        match status_rx.recv() {
            Ok(StatusUpdate::DeviceAvailable { dev_info }) => {
                trace!("STATUS: device available: {}", dev_info)
            }
            Ok(StatusUpdate::SelectDeviceNotice) => {
                info!("STATUS: Please select a device by touching one of them.");
            }
            Ok(StatusUpdate::DeviceSelected(dev_info)) => {
                debug!("STATUS: Continuing with device: {}", dev_info);
            }
            Err(RecvError) => {
                error!("STATUS: end");
                return;
            }
            e => {
                error!("Unexpected State {:?}", e);
            }
        }
    });

    let (register_tx, register_rx) = channel();
    let callback = StateCallback::new(Box::new(move |rv| {
        register_tx.send(rv).unwrap();
    }));

    if let Err(e) = manager.info(timeout_ms, status_tx, callback) {
        error!("Couldn't setup info request - {:?}", e);
    }

    while let Ok(info_result) = register_rx.recv() {
        match info_result {
            Ok(InfoResult::CTAP2(info)) => {
                info!("{}", info);
            }
            Err(e) => {
                error!("An error occured: {:?}", e);
            }
        }
    }
}

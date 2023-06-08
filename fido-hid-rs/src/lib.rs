//! `fido-hid-rs` is a low-level library for communicating with USB HID FIDO
//! authenticators.
//! 
//! This is an internal implementation detail of [webauthn-authenticator-rs][0].
//! It has **no guarantees of API stability**, and is not intended for use by
//! other parties.
//! 
//! [0]: https://github.com/kanidm/webauthn-rs/tree/master/webauthn-authenticator-rs
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
compile_error!("USB support is not implemented on this platform");

#[cfg(target_os = "macos")]
#[macro_use]
extern crate core_foundation;

#[cfg(target_os = "windows")]
#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate tracing;

pub mod traits;

#[cfg(any(test, target_os = "linux"))]
mod descriptors;

#[cfg_attr(target_os = "linux", path = "linux/mod.rs")]
#[cfg_attr(target_os = "macos", path = "macos/mod.rs")]
#[cfg_attr(target_os = "windows", path = "windows/mod.rs")]
pub mod os;

use thiserror::Error;

// u2f_hid.h
const FIDO_USAGE_PAGE: u16 = 0xf1d0;
const FIDO_USAGE_U2FHID: u16 = 0x01;
const HID_RPT_SIZE: usize = 64;
const HID_RPT_SEND_SIZE: usize = HID_RPT_SIZE + 1;
const U2FHID_TRANS_TIMEOUT: i32 = 3000;

pub type HidReportBytes = [u8; HID_RPT_SIZE];
pub type HidSendReportBytes = [u8; HID_RPT_SEND_SIZE];

pub type Result<T> = std::result::Result<T, HidError>;

#[derive(Debug, Error, PartialEq, Eq, PartialOrd, Ord)]
pub enum HidError {
    #[error("I/O error communicating with device: {0}")]
    IoError(String),
    #[error("internal error, likely library bug")]
    Internal,
    #[error("attempted to communicate with a closed device")]
    Closed,
    #[error("device sent an unexpected message length")]
    InvalidMessageLength,
    #[error("could not send data to device")]
    SendError,
}

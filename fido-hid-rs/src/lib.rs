//! `fido-hid-rs` implements a minimal set of platform-specific USB HID bindings
//! for communicating with FIDO authenticators.
//!
//! **Important:** this library is an _internal implementation detail_ of
//! [webauthn-authenticator-rs][0] to work around Cargo limitations.
//!
//! **This library has no guarantees of API stability, and is not intended for
//! use by other parties.**
//!
//! If you want to interface with USB HID FIDO authenticators, use
//! [webauthn-authenticator-rs][0] instead of this library.
//!
//! If you're looking for a general-purpose Rust USB HID library, try
//! [hidapi][].
//!
//! [0]: https://github.com/kanidm/webauthn-rs/tree/master/webauthn-authenticator-rs
//! [hidapi]: https://docs.rs/hidapi/latest/hidapi/
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

mod error;
mod traits;

#[cfg(any(test, target_os = "linux"))]
mod descriptors;

#[cfg_attr(target_os = "linux", path = "linux/mod.rs")]
#[cfg_attr(target_os = "macos", path = "macos/mod.rs")]
#[cfg_attr(target_os = "windows", path = "windows/mod.rs")]
mod os;

#[doc(inline)]
pub use crate::{
    error::{HidError, Result},
    os::{USBDeviceImpl, USBDeviceInfoImpl, USBDeviceManagerImpl},
    traits::{USBDevice, USBDeviceInfo, USBDeviceManager, WatchEvent},
};

// u2f_hid.h
const FIDO_USAGE_PAGE: u16 = 0xf1d0;
const FIDO_USAGE_U2FHID: u16 = 0x01;
const HID_RPT_SIZE: usize = 64;
const HID_RPT_SEND_SIZE: usize = HID_RPT_SIZE + 1;
#[allow(dead_code)]
const U2FHID_TRANS_TIMEOUT: i32 = 3000;

pub type HidReportBytes = [u8; HID_RPT_SIZE];
pub type HidSendReportBytes = [u8; HID_RPT_SEND_SIZE];

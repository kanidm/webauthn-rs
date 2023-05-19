//! Platform-specific USB HID API bindings.
//!
//! These typically implement a minimal subset of the platform's USB HID API
//! which is necessary to support FIDO tokens.

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
compile_error!("USB support is not implemented on this platform");

pub mod traits;

#[cfg(any(test, target_os = "linux"))]
pub mod descriptors;

#[cfg_attr(target_os = "linux", path = "linux/mod.rs")]
#[cfg_attr(target_os = "macos", path = "macos/mod.rs")]
#[cfg_attr(target_os = "windows", path = "windows/mod.rs")]
pub mod os;

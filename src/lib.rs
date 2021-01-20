//! Webauthn-rs - Webauthn for Rust Server Applications
//!
//! Webauthn is a standard allowing communication between servers, browsers and authenticators
//! to allow strong, passwordless, cryptographic authentication to be performed. Webauthn
//! is able to operate with many authenticator types, such as U2F.
//!
//! This library aims to provide a secure Webauthn implementation that you can
//! plug into your application, so that you can provide Webauthn to your users.
//!
//! For examples, see our examples folder.
//!
//! To use this library yourself, you will want to reference the `WebauthnConfig` trait to
//! develop site specific policy and configuration, and the `Webauthn` struct for Webauthn
//! interactions.

// #![deny(warnings)]
#![warn(unused_extern_crates)]
#![warn(missing_docs)]

extern crate base64;

#[macro_use]
extern crate serde_derive;
// extern crate byteorder;
#[cfg(feature = "core")]
extern crate openssl;

#[macro_use]
extern crate nom;

#[macro_use]
mod macros;
#[cfg(feature = "core")]
pub mod attestation;
pub mod base64_data;
mod constants;
#[cfg(feature = "core")]
pub mod core;
#[cfg(feature = "core")]
pub mod crypto;
#[cfg(feature = "core")]
pub mod ephemeral;
pub mod error;
pub mod proto;

#[cfg(feature = "core")]
pub use crate::core::*;

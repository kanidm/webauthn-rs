//! Webauthn-rs - Webauthn for Rust Server Applications
//!
//! Webauthn is a standard allowing communication between servers, browsers and authenticators
//! to allow strong, passwordless, cryptographic authentication to be performed. Webauthn
//! is able to operate with many authenticator types, such as U2F.
//!
//! This library aims to provide a secure Webauthn implementation that you can
//! plug into your application, so that you can provide Webauthn to your users.
//!
//! To use this library yourself, you will want to reference the `WebauthnConfig` trait to
//! develop site specific policy and configuration, and the `Webauthn` struct for Webauthn
//! interactions.

#![deny(warnings)]
#![warn(unused_extern_crates)]
#![warn(missing_docs)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
// #![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]

#[macro_use]
extern crate tracing;

#[macro_use]
mod macros;

mod constants;

mod attestation;
mod crypto;

pub mod core;
pub mod error;

pub mod interface;
mod internals;

/// Protocol bindings
pub mod proto {
    pub use crate::interface::*;
    pub use base64urlsafedata::Base64UrlSafeData;
    pub use webauthn_rs_proto::*;
}

pub use attestation::verify_attestation_ca_chain;
pub use attestation::AttestationFormat;

pub use crate::core::*;

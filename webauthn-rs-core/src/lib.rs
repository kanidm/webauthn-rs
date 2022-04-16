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
    pub use webauthn_rs_proto::*;
}

pub use crate::core::*;

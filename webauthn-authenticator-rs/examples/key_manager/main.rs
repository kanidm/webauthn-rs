extern crate tracing;

use std::io::{stdin, stdout, Write};

use clap::{ArgAction, ArgGroup, Args, Parser, Subcommand};

use futures::executor::block_on;
use webauthn_authenticator_rs::ctap2::{select_one_token, CtapAuthenticator};
use webauthn_authenticator_rs::transport::*;
use webauthn_authenticator_rs::ui::Cli;

#[derive(Debug, Args)]
pub struct SetPinOpt {
    #[clap(short, long)]
    pub new_pin: String,
}

#[derive(Debug, Args)]
pub struct ChangePinOpt {
    #[clap(short, long)]
    pub old_pin: String,

    #[clap(short, long)]
    pub new_pin: String,
}

#[derive(Debug, Args)]
#[clap(group(
    ArgGroup::new("policy")
        .multiple(true)
        .required(true)
        .args(&["length", "rpids", "force-change"])))]
pub struct SetPinPolicyOpt {
    /// Sets the minimum PIN length, in Unicode codepoints.
    #[clap(short, long)]
    pub length: Option<u32>,

    /// Sets the RPIDs which are authorised to use the `minPinLength` extension. May be specified many times.
    #[clap(short, long)]
    pub rpids: Option<Vec<String>>,

    /// Invalidates the existing PIN, forcing it to be changed before the token can be used again.
    #[clap(long, action = ArgAction::SetTrue)]
    pub force_change: bool,
}

#[derive(Debug, Subcommand)]
#[clap(about = "authenticator key manager")]
pub enum Opt {
    /// Request user presence on a connected FIDO token.
    Selection,
    /// Show information about the connected FIDO token.
    Info,
    /// Resets the connected FIDO token to factory settings, deleting all keys.
    ///
    /// This command will only work for the first 10 seconds since the token was
    /// plugged in, _may_ only work on _one_ transport (for multi-interface
    /// tokens), and is only _guaranteed_ to work over USB HID.
    FactoryReset,
    /// Toggles the "Always Require User Verification" feature.
    ToggleAlwaysUv,
    /// Enables the "Enterprise Attestation" feature.
    EnableEnterpriseAttestation,
    /// Gets information about biometric authentication on the device.
    BioInfo,
    /// Enrolls a fingerprint on the device.
    EnrollFingerprint,
    /// Sets policies for PINs.
    SetPinPolicy(SetPinPolicyOpt),
    /// Sets a PIN on a FIDO token which does not already have one.
    SetPin(SetPinOpt),
    /// Changes a PIN on a FIDO token which already has a PIN set.
    ChangePin(ChangePinOpt),
}

#[derive(Debug, clap::Parser)]
#[clap(about = "Fido Metadata Service parsing tool")]
pub struct CliParser {
    #[clap(subcommand)]
    pub commands: Opt,
}

fn main() {
    println!("DANGER: make sure you only have one key connected");
    let opt = CliParser::parse();
    tracing_subscriber::fmt::init();

    let ui = Cli {};
    let mut transport = AnyTransport::default();
    let mut tokens = transport.connect_all(&ui).expect("connect_all");

    if tokens.is_empty() {
        println!("No tokens available!");
        return;
    }
    // let authenticator = select_transport(&ui);
    let authenticator = &tokens[0];

    match opt.commands {
        Opt::Selection => {
            let token = block_on(select_one_token(tokens.iter()));
            println!("selected token: {:?}", token);
        }

        Opt::Info => {
            for token in &tokens {
                println!("{:?}", token.get_info());
            }
        }

        Opt::FactoryReset => {
            assert_eq!(tokens.len(), 1);
            println!("Resetting token to factory settings. Type 'yes' to continue.");
            let mut buf = String::new();
            stdout().flush().ok();
            stdin().read_line(&mut buf).expect("Cannot read stdin");

            if buf == "yes\n" {
                block_on(authenticator.factory_reset()).expect("Error resetting token");
            } else {
                panic!("Unexpected response {:?}, exiting!", buf);
            }
        }

        Opt::ToggleAlwaysUv => {
            assert_eq!(tokens.len(), 1);
            block_on(authenticator.toggle_always_uv()).expect("Error toggling UV");
        }

        Opt::EnableEnterpriseAttestation => {
            assert_eq!(tokens.len(), 1);
            block_on(authenticator.enable_enterprise_attestation())
                .expect("Error enabling enterprise attestation");
        }

        Opt::BioInfo => {
            for token in &tokens {
                if let CtapAuthenticator::Fido21(t) = token {
                    let i = block_on(t.get_fingerprint_sensor_info());
                    println!("Fingerprint sensor info: {:?}", i);
                } else {
                    println!("Authenticator does not support biometrics")
                }
            }
        }

        Opt::EnrollFingerprint => {
            let tokens: Vec<_> = tokens
                .drain(..)
                .filter_map(|t| {
                    if let CtapAuthenticator::Fido21(t) = t {
                        if t.get_info().supports_ctap21_biometrics() {
                            return Some(t);
                        }
                    }
                    None
                })
                .collect();
            assert_eq!(tokens.len(), 1, "Expected exactly 1 CTAP2.1 authenticator supporting biometrics");
            block_on(tokens[0].enroll_fingerprint()).expect("enrolling fingerprint");
        }

        Opt::SetPinPolicy(o) => {
            assert_eq!(tokens.len(), 1);
            block_on(authenticator.set_min_pin_length(
                o.length,
                o.rpids.unwrap_or_default(),
                if o.force_change { Some(true) } else { None },
            ))
            .expect("error setting policy");
        }

        Opt::SetPin(o) => {
            assert_eq!(tokens.len(), 1);
            block_on(authenticator.set_new_pin(&o.new_pin)).expect("Error setting PIN");
        }

        Opt::ChangePin(o) => {
            assert_eq!(tokens.len(), 1);
            block_on(authenticator.change_pin(&o.old_pin, &o.new_pin)).expect("Error changing PIN");
        }
    }
}

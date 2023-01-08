extern crate tracing;

use std::io::{stdin, stdout, Write};
use std::time::Duration;

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

#[derive(Debug, Args)]
pub struct EnrollFingerprintOpt {
    /// A human-readable name for the finger (eg: 'left thumb')
    #[clap()]
    pub friendly_name: Option<String>,
}

#[derive(Debug, Args)]
pub struct RenameFingerprintOpt {
    /// The template ID
    #[clap()]
    pub id: String,

    /// A human-readable name for the finger (eg: 'left thumb')
    #[clap()]
    pub friendly_name: String,
}

#[derive(Debug, Args)]
pub struct RemoveFingerprintOpt {
    /// The template ID
    #[clap(min_values(1), required(true))]
    pub id: Vec<String>,
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
    EnrollFingerprint(EnrollFingerprintOpt),
    /// Lists all enrolled fingerprints on the device.
    ListFingerprints,
    /// Renames an enrolled fingerprint.
    RenameFingerprint(RenameFingerprintOpt),
    /// Removes an enrolled fingerprint.
    RemoveFingerprint(RemoveFingerprintOpt),
    /// Sets policies for PINs.
    SetPinPolicy(SetPinPolicyOpt),
    /// Sets a PIN on a FIDO token which does not already have one.
    SetPin(SetPinOpt),
    /// Changes a PIN on a FIDO token which already has a PIN set.
    ChangePin(ChangePinOpt),
}

#[derive(Debug, clap::Parser)]
#[clap(about = "FIDO key management tool")]
pub struct CliParser {
    #[clap(subcommand)]
    pub commands: Opt,
}

pub fn base16_encode<T: IntoIterator<Item = u8>>(i: T) -> String {
    i.into_iter().map(|c| format!("{:02X}", c)).collect()
}

pub fn base16_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect::<Result<Vec<_>, _>>()
        .ok()
}

fn main() {
    println!("DANGER: make sure you only have one key connected");
    let opt = CliParser::parse();
    tracing_subscriber::fmt::init();

    let ui = Cli {};
    let mut transport = AnyTransport::new().unwrap();
    let mut tokens = transport.connect_all(&ui).expect("connect_all");

    if tokens.is_empty() {
        println!("No tokens available!");
        return;
    }

    let token_count = tokens.len();
    // let authenticator = select_transport(&ui);
    let authenticator = &mut tokens[0];

    match opt.commands {
        Opt::Selection => {
            let token = block_on(select_one_token(tokens.iter_mut()));
            println!("selected token: {:?}", token);
        }

        Opt::Info => {
            for token in &tokens {
                println!("{:?}", token.get_info());
            }
        }

        Opt::FactoryReset => {
            assert_eq!(token_count, 1);
            println!("Resetting token to factory settings. Type 'yes' to continue.");
            let mut buf = String::new();
            stdout().flush().ok();
            stdin().read_line(&mut buf).expect("Cannot read stdin");
            buf = buf.trim_end().to_ascii_lowercase();

            if buf == "yes" {
                block_on(authenticator.factory_reset()).expect("Error resetting token");
            } else {
                panic!("Unexpected response {:?}, exiting!", buf);
            }
        }

        Opt::ToggleAlwaysUv => {
            assert_eq!(token_count, 1);
            block_on(authenticator.toggle_always_uv()).expect("Error toggling UV");
        }

        Opt::EnableEnterpriseAttestation => {
            assert_eq!(token_count, 1);
            block_on(authenticator.enable_enterprise_attestation())
                .expect("Error enabling enterprise attestation");
        }

        Opt::BioInfo => {
            for token in &mut tokens {
                if let CtapAuthenticator::Fido21(t) = token {
                    let i = block_on(t.get_fingerprint_sensor_info());
                    println!("Fingerprint sensor info: {:?}", i);
                } else {
                    println!("Authenticator does not support biometrics")
                }
            }
        }

        Opt::EnrollFingerprint(o) => {
            let mut tokens: Vec<_> = tokens
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
            assert_eq!(
                token_count, 1,
                "Expected exactly 1 CTAP2.1 authenticator supporting biometrics"
            );
            let id =
                block_on(tokens[0].enroll_fingerprint(Duration::from_secs(30), o.friendly_name))
                    .expect("enrolling fingerprint");
            println!("Enrolled fingerpint {}", base16_encode(id));
        }

        Opt::ListFingerprints => {
            let mut tokens: Vec<_> = tokens
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
            assert_eq!(
                tokens.len(),
                1,
                "Expected exactly 1 CTAP2.1 authenticator supporting biometrics"
            );
            let fingerprints =
                block_on(tokens[0].list_fingerprints()).expect("listing fingerprints");

            println!("{} enrolled fingerprint(s):", fingerprints.len());
            for t in fingerprints {
                println!(
                    "* ID: {}, Name: {:?}",
                    base16_encode(t.id),
                    t.friendly_name.unwrap_or_default()
                );
            }
        }

        Opt::RenameFingerprint(o) => {
            let mut tokens: Vec<_> = tokens
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
            assert_eq!(
                tokens.len(),
                1,
                "Expected exactly 1 CTAP2.1 authenticator supporting biometrics"
            );

            block_on(
                tokens[0].rename_fingerprint(
                    base16_decode(&o.id).expect("decoding ID"),
                    o.friendly_name,
                ),
            )
            .expect("renaming fingerprint");
        }

        Opt::RemoveFingerprint(o) => {
            let mut tokens: Vec<_> = tokens
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
            assert_eq!(
                token_count, 1,
                "Expected exactly 1 CTAP2.1 authenticator supporting biometrics"
            );
            let ids: Vec<Vec<u8>> =
                o.id.iter()
                    .map(|i| base16_decode(i).expect("decoding ID"))
                    .collect();
            block_on(tokens[0].remove_fingerprints(ids)).expect("removing fingerprint");
        }

        Opt::SetPinPolicy(o) => {
            assert_eq!(token_count, 1);
            block_on(authenticator.set_min_pin_length(
                o.length,
                o.rpids.unwrap_or_default(),
                if o.force_change { Some(true) } else { None },
            ))
            .expect("error setting policy");
        }

        Opt::SetPin(o) => {
            assert_eq!(token_count, 1);
            block_on(authenticator.set_new_pin(&o.new_pin)).expect("Error setting PIN");
        }

        Opt::ChangePin(o) => {
            assert_eq!(token_count, 1);
            block_on(authenticator.change_pin(&o.old_pin, &o.new_pin)).expect("Error changing PIN");
        }
    }
}

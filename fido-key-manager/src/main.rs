#[cfg(not(any(feature = "nfc", feature = "usb")))]
compile_error!(
    "you must build this tool with either the 'nfc' or 'usb' feature for it to do something useful"
);

extern crate tracing;

use std::io::{stdin, stdout, Write};
use std::time::Duration;

use clap::{ArgAction, ArgGroup, Args, Parser, Subcommand};

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
    /// The template ID(s) to remove
    #[clap(required = true)]
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
    ///
    /// Note: you must set a PIN on the device before you can enroll any
    /// fingerprints.
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
    GetCredentialMetadata,
    ListRps,
}

#[derive(Debug, clap::Parser)]
#[clap(about = "FIDO key management tool")]
pub struct CliParser {
    #[clap(subcommand)]
    pub commands: Opt,
}

pub fn base16_encode<T: IntoIterator<Item = u8>>(i: T) -> String {
    i.into_iter().map(|c| format!("{c:02X}")).collect()
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

#[tokio::main]
async fn main() {
    println!("DANGER: make sure you only have one key connected");
    let opt = CliParser::parse();
    tracing_subscriber::fmt::init();

    let ui = Cli {};
    let mut transport = AnyTransport::new().await.unwrap();
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
            let token = select_one_token(tokens.iter_mut()).await;
            println!("selected token: {token:?}");
        }

        Opt::Info => {
            for token in &tokens {
                println!("{}", token.get_info());
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
                authenticator
                    .factory_reset()
                    .await
                    .expect("Error resetting token");
            } else {
                panic!("Unexpected response {buf:?}, exiting!");
            }
        }

        Opt::ToggleAlwaysUv => {
            let mut tokens: Vec<_> = tokens
                .drain(..)
                .filter_map(|t| match t {
                    CtapAuthenticator::Fido21(a) => Some(a),
                    _ => None,
                })
                .filter(|t| t.supports_config())
                .collect();
            assert_eq!(
                tokens.len(),
                1,
                "Expected exactly one authenticator supporting CTAP 2.1 authenticatorConfig"
            );
            tokens[0]
                .toggle_always_uv()
                .await
                .expect("Error toggling UV");
        }

        Opt::EnableEnterpriseAttestation => {
            let mut tokens: Vec<_> = tokens
                .drain(..)
                .filter_map(|t| match t {
                    CtapAuthenticator::Fido21(a) => Some(a),
                    _ => None,
                })
                .filter(|t| t.supports_config() && t.supports_enterprise_attestation())
                .collect();
            assert_eq!(
                tokens.len(),
                1,
                "Expected exactly one authenticator supporting CTAP 2.1 authenticatorConfig"
            );
            tokens[0]
                .enable_enterprise_attestation()
                .await
                .expect("Error enabling enterprise attestation");
        }

        Opt::BioInfo => {
            for token in &mut tokens {
                if let Some(b) = token.bio() {
                    let i = b.get_fingerprint_sensor_info().await;
                    println!("Fingerprint sensor info: {i:?}");
                } else {
                    println!("Authenticator does not support biometrics")
                }
            }
        }

        Opt::EnrollFingerprint(o) => {
            let mut tokens: Vec<_> = tokens
                .drain(..)
                .filter(|t| t.supports_biometrics())
                .collect();
            assert_eq!(
                tokens.len(),
                1,
                "Expected exactly one authenticator supporting biometrics"
            );
            let id = tokens[0]
                .bio()
                .unwrap()
                .enroll_fingerprint(Duration::from_secs(30), o.friendly_name)
                .await
                .expect("enrolling fingerprint");
            println!("Enrolled fingerpint {}", base16_encode(id));
        }

        Opt::ListFingerprints => {
            let mut tokens: Vec<_> = tokens
                .drain(..)
                .filter(|t| t.supports_biometrics())
                .collect();
            assert_eq!(
                tokens.len(),
                1,
                "Expected exactly one authenticator supporting biometrics"
            );
            let fingerprints = tokens[0]
                .bio()
                .unwrap()
                .list_fingerprints()
                .await
                .expect("listing fingerprints");

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
                .filter(|t| t.supports_biometrics())
                .collect();
            assert_eq!(
                tokens.len(),
                1,
                "Expected exactly one authenticator supporting biometrics"
            );

            tokens[0]
                .bio()
                .unwrap()
                .rename_fingerprint(base16_decode(&o.id).expect("decoding ID"), o.friendly_name)
                .await
                .expect("renaming fingerprint");
        }

        Opt::RemoveFingerprint(o) => {
            let mut tokens: Vec<_> = tokens
                .drain(..)
                .filter(|t| t.supports_biometrics())
                .collect();
            assert_eq!(
                tokens.len(),
                1,
                "Expected exactly one authenticator supporting biometrics"
            );

            let ids: Vec<Vec<u8>> =
                o.id.iter()
                    .map(|i| base16_decode(i).expect("decoding ID"))
                    .collect();
            tokens[0]
                .bio()
                .unwrap()
                .remove_fingerprints(ids)
                .await
                .expect("removing fingerprint");
        }

        Opt::SetPinPolicy(o) => {
            let mut tokens: Vec<_> = tokens
                .drain(..)
                .filter_map(|t| match t {
                    CtapAuthenticator::Fido21(a) => Some(a),
                    _ => None,
                })
                .filter(|t| t.supports_config())
                .collect();
            assert_eq!(
                tokens.len(),
                1,
                "Expected exactly one authenticator supporting CTAP 2.1 authenticatorConfig"
            );
            tokens[0]
                .set_min_pin_length(
                    o.length,
                    o.rpids.unwrap_or_default(),
                    if o.force_change { Some(true) } else { None },
                )
                .await
                .expect("error setting policy");
        }

        Opt::SetPin(o) => {
            assert_eq!(token_count, 1);
            authenticator
                .set_new_pin(&o.new_pin)
                .await
                .expect("Error setting PIN");
        }

        Opt::ChangePin(o) => {
            assert_eq!(token_count, 1);
            authenticator
                .change_pin(&o.old_pin, &o.new_pin)
                .await
                .expect("Error changing PIN");
        }

        Opt::GetCredentialMetadata => {
            let mut tokens: Vec<_> = tokens
                .drain(..)
                .filter(|t| t.supports_credential_management())
                .collect();
            assert_eq!(
                tokens.len(),
                1,
                "Expected exactly one authenticator supporting credential management"
            );

            let (creds, remain) = tokens[0]
                .credential_management()
                .unwrap()
                .get_credentials_metadata()
                .await
                .expect("Error getting credential metadata");
            println!("{creds} discoverable credential(s), {remain} maximum slot(s) free");
        }

        Opt::ListRps => {
            let mut tokens: Vec<_> = tokens
                .drain(..)
                .filter(|t| t.supports_credential_management())
                .collect();
            assert_eq!(
                tokens.len(),
                1,
                "Expected exactly one authenticator supporting credential management"
            );

            let rps = tokens[0]
                .credential_management()
                .unwrap()
                .enumerate_rps()
                .await
                .expect("Error enumerating RPs");
            println!("{} RP(s):", rps.len());
            for (rp, hash) in rps.iter() {
                println!("* RP: {rp:?}, hash: {hash:?}");
            }
        }
    }
}

#[cfg(not(any(feature = "nfc", feature = "usb")))]
compile_error!(
    "you must build this tool with either the 'nfc' or 'usb' feature for it to do something useful"
);

extern crate tracing;

use hex::{FromHex, FromHexError};
use std::io::{stdin, stdout, Write};
use std::time::Duration;
use webauthn_authenticator_rs::ctap2::commands::UserCM;

use clap::{ArgAction, ArgGroup, Args, Parser, Subcommand};
use openssl::sha::Sha256;

use webauthn_authenticator_rs::{
    ctap2::{select_one_token, CtapAuthenticator},
    transport::*,
    ui::Cli,
    SHA256Hash,
};
use webauthn_rs_core::interface::COSEKeyType;

/// Parses a Base-16 encoded string.
///
/// This function is intended for use as a `clap` `value_parser`.
pub fn parse_hex<T>(i: &str) -> Result<T, FromHexError>
where
    T: FromHex<Error = FromHexError>,
{
    FromHex::from_hex(i)
}

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

#[derive(Debug, Args)]
#[clap(after_help = "\
If no filtering options are specified, this command will show a list of all RPs
with discoverable credentials.")]
pub struct ListCredentialsOpt {
    /// List credentials for a relying party ID (eg: "example.com")
    #[clap(long, value_name = "RPID", conflicts_with = "hash")]
    pub rpid: Option<String>,

    /// List credentials for the SHA-256 hash of a relying party ID
    /// (eg: "a379a6f6eeafb9a55e378c118034e2751e682fab9f2d30ab13d2125586ce1947")
    #[clap(long, value_parser = parse_hex::<SHA256Hash>, value_name = "HASH")]
    pub hash: Option<SHA256Hash>,
}

#[derive(Debug, Args)]
pub struct DeleteCredentialOpt {
    /// Credential ID to delete.
    #[clap(required = true, action = ArgAction::Set, value_parser = parse_hex::<Vec<u8>>, value_name = "HASH")]
    // Must use full `std::vec::Vec` syntax: https://docs.rs/clap/latest/clap/_derive/index.html#arg-types
    pub id: std::vec::Vec<u8>,
}

#[derive(Debug, Args)]
#[clap(group(
    ArgGroup::new("user_info")
        .multiple(true)
        .required(true)
        .args(&["name", "display_name"])))]
pub struct UpdateCredentialUserOpt {
    /// Credential ID to update.
    #[clap(required = true, action = ArgAction::Set, value_parser = parse_hex::<Vec<u8>>, value_name = "CRED_ID")]
    pub credential_id: std::vec::Vec<u8>,

    /// User ID to update.
    #[clap(required = true, action = ArgAction::Set, value_parser = parse_hex::<Vec<u8>>, value_name = "USER_ID")]
    pub user_id: std::vec::Vec<u8>,

    /// Human-palatable identifier for the user account, such as a username,
    /// email address or phone number.
    ///
    /// If this option is not specified, the existing name will be removed.
    #[clap(long)]
    pub name: Option<String>,

    /// Human-palatable display name for the user account.
    ///
    /// If this option is not specified, the existing display name will be
    /// removed.
    #[clap(long, value_name = "NAME")]
    pub display_name: Option<String>,
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
    /// Gets a token's discoverable credential storage metadata.
    GetCredentialMetadata,
    /// Lists all discoverable credentials on this token.
    ListCredentials(ListCredentialsOpt),
    /// Deletes a discoverable credential on this token.
    DeleteCredential(DeleteCredentialOpt),
    /// Updates user information for a discoverable credential on this token.
    UpdateCredentialUser(UpdateCredentialUserOpt),
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

            let metadata = tokens[0]
                .credential_management()
                .unwrap()
                .get_credentials_metadata()
                .await
                .expect("Error getting credential metadata");
            println!(
                "{} discoverable credential(s), {} maximum slot(s) free",
                metadata.existing_resident_credentials_count,
                metadata.max_possible_remaining_resident_credentials_count,
            );
        }

        Opt::ListCredentials(o) => {
            let mut tokens: Vec<_> = tokens
                .drain(..)
                .filter(|t| t.supports_credential_management())
                .collect();
            assert_eq!(
                tokens.len(),
                1,
                "Expected exactly one authenticator supporting credential management"
            );

            let cm = tokens[0].credential_management().unwrap();

            let rp_id_hash = if let Some(rpid) = &o.rpid {
                let mut h = Sha256::new();
                h.update(rpid.as_bytes());
                h.finish()
            } else if let Some(hash) = o.hash {
                hash
            } else {
                let rps = cm.enumerate_rps().await.expect("Error enumerating RPs");
                println!("{} RP{}:", rps.len(), if rps.len() != 1 { "s" } else { "" });
                for rp in rps {
                    print!(
                        "* {}: {}",
                        hex::encode(rp.hash.unwrap_or_default()),
                        rp.id.unwrap_or_default()
                    );
                    if let Some(name) = &rp.name {
                        println!(" {:?}", name);
                    } else {
                        println!();
                    }
                }
                return;
            };

            let creds = cm
                .enumerate_credentials_by_hash(rp_id_hash)
                .await
                .expect("Error listing credentials");

            print!(
                "{} credential{} for ",
                creds.len(),
                if creds.len() != 1 { "s" } else { "" }
            );

            if let Some(rpid) = o.rpid {
                println!("{rpid} ({}):", hex::encode(rp_id_hash));
            } else {
                println!("{}:", hex::encode(rp_id_hash));
            }

            let mut pii_warn = false;
            for (i, cred) in creds.iter().enumerate() {
                println!("Credential #{}:", i + 1);
                if let Some(cred_id) = &cred.credential_id {
                    println!("  ID: {}", hex::encode(&cred_id.id));
                }
                if let Some(user) = &cred.user {
                    println!("  User info:");
                    println!("    User ID: {}", hex::encode(&user.id));
                    if let Ok(s) = std::str::from_utf8(&user.id) {
                        // User IDs are supposed to be opaque byte sequences,
                        // and NOT contain personally identifying information.
                        // The fact we can decode it as UTF-8 is suspicious...
                        println!("      As UTF-8: {s:?}");

                        // Explicitly flag the issue if it matches one of the
                        // other fields, because it means the RP has done
                        // something extremely bad.
                        if user
                            .name
                            .as_ref()
                            .map(|name| name.eq_ignore_ascii_case(s))
                            .unwrap_or_default()
                        {
                            println!("      User ID = name, which is PII!");
                            pii_warn = true;
                        }

                        if user
                            .display_name
                            .as_ref()
                            .map(|name| name.eq_ignore_ascii_case(s))
                            .unwrap_or_default()
                        {
                            println!("      User ID = display name, which is PII!");
                            pii_warn = true;
                        }
                    }

                    if let Some(name) = &user.name {
                        println!("    Name: {:?}", name);
                    }
                    if let Some(display_name) = &user.display_name {
                        println!("    Display name: {:?}", display_name);
                    }
                }

                if let Some(public_key) = &cred.public_key {
                    println!("  Public key algorithm: {:?}", public_key.type_);
                    match &public_key.key {
                        COSEKeyType::EC_OKP(okp) => {
                            println!("  Octet key pair, curve {:?}", okp.curve);
                            println!("    X-coordinate: {}", hex::encode(okp.x));
                        }
                        COSEKeyType::EC_EC2(ec) => {
                            println!("  Elliptic curve key, curve {:?}", ec.curve);
                            println!("    X-coordinate: {}", hex::encode(&ec.x.0));
                            println!("    Y-coordinate: {}", hex::encode(&ec.y.0));
                        }
                        COSEKeyType::RSA(rsa) => {
                            println!("  RSA modulus: {}", hex::encode(&rsa.n.0));
                            println!("    Exponent: {}", hex::encode(rsa.e));
                        }
                    }
                }
                if let Some(policy) = &cred.cred_protect {
                    println!("  Credential protection policy: {:?}", policy);
                }

                if let Some(key) = &cred.large_blob_key {
                    println!("  Large blob key: {}", hex::encode(key));
                }
            }

            if pii_warn {
                let p = if creds.len() == 1 {
                    "this credential"
                } else {
                    "these credentials"
                };
                println!();
                println!(
                    "The relying party which created {p} has included PII \
                    (personally-identifying information) in the user ID, which \
                    is *explicitly forbidden* by the WebAuthn specification \
                    for privacy reasons."
                );
                println!();
                println!(
                    "Please inform the relying party that they have a privacy \
                    bug they need to fix."
                );
                println!();
                println!(
                    "More information can be found in these sections of the \
                    WebAuthn specification:"
                );
                println!(" * https://w3c.github.io/webauthn/#dom-publickeycredentialuserentity-id");
                println!(" * https://w3c.github.io/webauthn/#sctn-user-handle-privacy");
                println!();
                println!("Thank you!");
            }
        }

        Opt::DeleteCredential(o) => {
            let mut tokens: Vec<_> = tokens
                .drain(..)
                .filter(|t| t.supports_credential_management())
                .collect();
            assert_eq!(
                tokens.len(),
                1,
                "Expected exactly one authenticator supporting credential management"
            );

            println!("Deleting credential {}...", hex::encode(&o.id));
            tokens[0]
                .credential_management()
                .unwrap()
                .delete_credential(o.id.into())
                .await
                .expect("Error deleting credential");
        }

        Opt::UpdateCredentialUser(o) => {
            let mut tokens: Vec<_> = tokens
                .drain(..)
                .filter_map(|t| match t {
                    CtapAuthenticator::Fido21(a) => Some(a),
                    _ => None,
                })
                .filter(|t| t.supports_ctap21_credential_management())
                .collect();
            assert_eq!(
                tokens.len(),
                1,
                "Expected exactly one authenticator supporting CTAP 2.1 credential management"
            );
            let user = UserCM {
                id: o.user_id,
                name: o.name,
                display_name: o.display_name,
            };

            println!(
                "Updating user information for credential {}...",
                hex::encode(&o.credential_id)
            );
            tokens[0]
                .update_credential_user(o.credential_id.into(), user)
                .await
                .expect("Error updating credential");
        }
    }
}

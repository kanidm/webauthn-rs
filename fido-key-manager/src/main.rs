#[cfg(not(any(feature = "bluetooth", feature = "nfc", feature = "usb")))]
compile_error!(
    "you must build this tool with either the 'bluetooth', 'nfc' and/or 'usb' feature(s) for it to do something useful"
);

#[macro_use]
extern crate tracing;

use clap::{ArgAction, ArgGroup, Args, Parser, Subcommand};
use hex::{FromHex, FromHexError};
use std::io::{stdin, stdout, Write};
use std::time::Duration;
use tokio_stream::StreamExt;
#[cfg(feature = "yubikey")]
use webauthn_authenticator_rs::ctap2::YubiKeyAuthenticator;
#[cfg(feature = "solokey")]
use webauthn_authenticator_rs::{ctap2::SoloKeyAuthenticator, prelude::WebauthnCError};
use webauthn_authenticator_rs::{
    ctap2::{
        commands::UserCM, select_one_device, select_one_device_predicate,
        select_one_device_version, Ctap21Authenticator, CtapAuthenticator,
    },
    transport::*,
    ui::Cli,
    SHA256Hash,
};
use webauthn_rs_core::proto::COSEKeyType;

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
pub struct InfoOpt {
    /// Continue watching for connected devices until the program is explicitly
    /// terminated (Ctrl + C).
    #[clap(long)]
    pub watch: bool,
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

#[cfg(feature = "usb")]
#[derive(Debug, Args)]
pub struct WinkOpt {
    /// Continue watching for connected devices until the program is explicitly
    /// terminated (Ctrl + C).
    #[clap(long)]
    pub watch: bool,
}

#[derive(Debug, Subcommand)]
#[clap(about = "authenticator key manager")]
pub enum Opt {
    /// Request user presence on a connected FIDO token.
    Selection,
    /// Show information about all connected FIDO tokens.
    Info(InfoOpt),
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
    BioInfo(InfoOpt),
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
    #[cfg(feature = "solokey")]
    /// Gets info about a connected SoloKey 2 or Trussed device.
    SoloKeyInfo(InfoOpt),
    #[cfg(feature = "solokey")]
    /// Gets some random bytes from a connected SoloKey 2 or Trussed device.
    SoloKeyRandom,
    #[cfg(feature = "yubikey")]
    YubikeyGetConfig,
    #[cfg(feature = "usb")]
    /// Wink a connected USB device.
    Wink(WinkOpt),
}

#[derive(Debug, clap::Parser)]
#[clap(about = "FIDO key management tool")]
pub struct CliParser {
    #[clap(subcommand)]
    pub commands: Opt,
}

#[tokio::main]
async fn main() {
    let opt = CliParser::parse();
    tracing_subscriber::fmt::init();

    let ui = Cli {};
    let transport = AnyTransport::new().await.unwrap();
    let mut stream = transport.watch().await.unwrap();

    match opt.commands {
        Opt::Selection => {
            let token = select_one_device(stream, &ui).await;
            println!("selected token: {token:?}");
        }

        Opt::Info(o) => {
            while let Some(event) = stream.next().await {
                match event {
                    TokenEvent::Added(t) => {
                        let authenticator = match CtapAuthenticator::new(t, &ui).await {
                            Some(a) => a,
                            None => continue,
                        };
                        println!("{}", authenticator.get_info());
                    }
                    TokenEvent::EnumerationComplete => {
                        if o.watch {
                            println!("Initial enumeration completed, watching for more devices...");
                            println!("Press Ctrl + C to stop watching.");
                        } else {
                            break;
                        }
                    }
                    _ => (),
                }
            }
        }

        Opt::FactoryReset => {
            while let Some(event) = stream.next().await {
                // Keep advancing the stream until enumeration complete, we want
                // to ignore everything already connected.
                if matches!(event, TokenEvent::EnumerationComplete) {
                    break;
                }
            }

            println!("Please disconnect and reconnect your token to reset to factory settings.");

            let mut authenticator = None;
            while let Some(event) = stream.next().await {
                if let TokenEvent::Added(t) = event {
                    authenticator = Some(CtapAuthenticator::new(t, &ui).await.unwrap());
                    break;
                }
            }

            let mut authenticator = authenticator.unwrap();

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
            let mut token: Ctap21Authenticator<AnyToken, Cli> =
                select_one_device_version(stream, &ui, |a| {
                    let o = Ctap21Authenticator::supports_config(a);
                    if !o {
                        warn!("token does not support CTAP 2.1 config");
                    }
                    o
                })
                .await
                .unwrap();

            token.toggle_always_uv().await.expect("Error toggling UV");
        }

        Opt::EnableEnterpriseAttestation => {
            let mut token: Ctap21Authenticator<AnyToken, Cli> =
                select_one_device_version(stream, &ui, |a| {
                    if !Ctap21Authenticator::supports_config(a) {
                        warn!("token does not support CTAP 2.1 config");
                        return false;
                    }

                    if !a.supports_enterprise_attestation() {
                        warn!("token does not support CTAP 2.1 enterprise attestation");
                        return false;
                    }

                    true
                })
                .await
                .unwrap();

            token
                .enable_enterprise_attestation()
                .await
                .expect("Error enabling enterprise attestation");
        }

        Opt::BioInfo(o) => {
            while let Some(event) = stream.next().await {
                match event {
                    TokenEvent::Added(t) => {
                        let mut authenticator = match CtapAuthenticator::new(t, &ui).await {
                            Some(a) => a,
                            None => continue,
                        };
                        if let Some(b) = authenticator.bio() {
                            let i = b.get_fingerprint_sensor_info().await;
                            println!("Fingerprint sensor info: {i:?}");
                        } else {
                            println!("Authenticator does not support biometrics");
                        }
                    }
                    TokenEvent::EnumerationComplete => {
                        if o.watch {
                            println!("Initial enumeration completed, watching for more devices...");
                            println!("Press Ctrl-C to stop watching.");
                        } else {
                            break;
                        }
                    }
                    _ => (),
                }
            }
        }

        Opt::EnrollFingerprint(o) => {
            let mut token: CtapAuthenticator<AnyToken, Cli> =
                select_one_device_predicate(stream, &ui, |a| a.supports_biometrics())
                    .await
                    .unwrap();

            let id = token
                .bio()
                .unwrap()
                .enroll_fingerprint(Duration::from_secs(30), o.friendly_name)
                .await
                .expect("enrolling fingerprint");
            println!("Enrolled fingerpint {}", hex::encode(id));
        }

        Opt::ListFingerprints => {
            let mut token: CtapAuthenticator<AnyToken, Cli> =
                select_one_device_predicate(stream, &ui, |a| a.supports_biometrics())
                    .await
                    .unwrap();

            let fingerprints = token
                .bio()
                .unwrap()
                .list_fingerprints()
                .await
                .expect("listing fingerprints");

            println!("{} enrolled fingerprint(s):", fingerprints.len());
            for t in fingerprints {
                println!(
                    "* ID: {}, Name: {:?}",
                    hex::encode(t.id),
                    t.friendly_name.unwrap_or_default()
                );
            }
        }

        Opt::RenameFingerprint(o) => {
            let mut token: CtapAuthenticator<AnyToken, Cli> =
                select_one_device_predicate(stream, &ui, |a| a.supports_biometrics())
                    .await
                    .unwrap();

            token
                .bio()
                .unwrap()
                .rename_fingerprint(hex::decode(&o.id).expect("decoding ID"), o.friendly_name)
                .await
                .expect("renaming fingerprint");
        }

        Opt::RemoveFingerprint(o) => {
            let mut token: CtapAuthenticator<AnyToken, Cli> =
                select_one_device_predicate(stream, &ui, |a| a.supports_biometrics())
                    .await
                    .unwrap();

            let ids: Vec<Vec<u8>> =
                o.id.iter()
                    .map(|i| hex::decode(i).expect("decoding ID"))
                    .collect();
            token
                .bio()
                .unwrap()
                .remove_fingerprints(ids)
                .await
                .expect("removing fingerprint");
        }

        Opt::SetPinPolicy(o) => {
            let mut token: Ctap21Authenticator<AnyToken, Cli> =
                select_one_device_version(stream, &ui, |a| {
                    if !Ctap21Authenticator::supports_config(a) {
                        warn!("token does not support CTAP 2.1 config");
                        return false;
                    }
                    true
                })
                .await
                .unwrap();

            token
                .set_min_pin_length(
                    o.length,
                    o.rpids.unwrap_or_default(),
                    if o.force_change { Some(true) } else { None },
                )
                .await
                .expect("error setting policy");
        }

        Opt::SetPin(o) => {
            let mut token: CtapAuthenticator<AnyToken, Cli> =
                select_one_device(stream, &ui).await.unwrap();

            token
                .set_new_pin(&o.new_pin)
                .await
                .expect("Error setting PIN");
        }

        Opt::ChangePin(o) => {
            let mut token: CtapAuthenticator<AnyToken, Cli> =
                select_one_device(stream, &ui).await.unwrap();

            token
                .change_pin(&o.old_pin, &o.new_pin)
                .await
                .expect("Error changing PIN");
        }

        Opt::GetCredentialMetadata => {
            let mut token: CtapAuthenticator<AnyToken, Cli> =
                select_one_device_predicate(stream, &ui, |a| a.supports_credential_management())
                    .await
                    .unwrap();

            let metadata = token
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
            let mut token: CtapAuthenticator<AnyToken, Cli> =
                select_one_device_predicate(stream, &ui, |a| a.supports_credential_management())
                    .await
                    .unwrap();

            let cm = token.credential_management().unwrap();

            let (creds, rp) = if let Some(rpid) = o.rpid {
                (cm.enumerate_credentials_by_rpid(&rpid).await, rpid)
            } else if let Some(hash) = o.hash {
                (
                    cm.enumerate_credentials_by_hash(hash).await,
                    hex::encode(hash),
                )
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
                        println!(" {name:?}");
                    } else {
                        println!();
                    }
                }
                return;
            };
            let creds = creds.expect("Error listing credentials");

            println!(
                "{} credential{} for {rp}:",
                creds.len(),
                if creds.len() != 1 { "s" } else { "" }
            );

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
                        println!("    Name: {name:?}");
                    }
                    if let Some(display_name) = &user.display_name {
                        println!("    Display name: {display_name:?}");
                    }
                }

                if let Some(public_key) = &cred.public_key {
                    println!("  Public key algorithm: {:?}", public_key.type_);
                    match &public_key.key {
                        COSEKeyType::EC_OKP(okp) => {
                            println!("  Octet key pair, curve {:?}", okp.curve);
                            println!("    X-coordinate: {}", hex::encode(&okp.x));
                        }
                        COSEKeyType::EC_EC2(ec) => {
                            println!("  Elliptic curve key, curve {:?}", ec.curve);
                            println!("    X-coordinate: {}", hex::encode(&ec.x));
                            println!("    Y-coordinate: {}", hex::encode(&ec.y));
                        }
                        COSEKeyType::RSA(rsa) => {
                            println!("  RSA modulus: {}", hex::encode(&rsa.n));
                            println!("    Exponent: {}", hex::encode(rsa.e));
                        }
                    }
                }
                if let Some(policy) = &cred.cred_protect {
                    println!("  Credential protection policy: {policy:?}");
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
            let mut token: CtapAuthenticator<AnyToken, Cli> =
                select_one_device_predicate(stream, &ui, |a| a.supports_credential_management())
                    .await
                    .unwrap();

            println!("Deleting credential {}...", hex::encode(&o.id));
            token
                .credential_management()
                .unwrap()
                .delete_credential(o.id.into())
                .await
                .expect("Error deleting credential");
        }

        Opt::UpdateCredentialUser(o) => {
            let mut token: Ctap21Authenticator<AnyToken, Cli> =
                select_one_device_version(stream, &ui, |a| {
                    if !Ctap21Authenticator::supports_ctap21_credential_management(a) {
                        warn!("token does not support CTAP 2.1 credential management");
                        return false;
                    }
                    true
                })
                .await
                .unwrap();

            let user = UserCM {
                id: o.user_id,
                name: o.name,
                display_name: o.display_name,
            };

            println!(
                "Updating user information for credential {}...",
                hex::encode(&o.credential_id)
            );
            token
                .update_credential_user(o.credential_id.into(), user)
                .await
                .expect("Error updating credential");
        }

        #[cfg(feature = "solokey")]
        Opt::SoloKeyInfo(o) => {
            println!("Looking for SoloKey 2 or Trussed devices...");
            while let Some(event) = stream.next().await {
                match event {
                    TokenEvent::Added(t) => {
                        let mut authenticator = match CtapAuthenticator::new(t, &ui).await {
                            Some(a) => a,
                            None => continue,
                        };

                        // TODO: filter this to just SoloKey devices in a safe way
                        let uuid = match authenticator.get_solokey_uuid().await {
                            Ok(v) => v,
                            Err(WebauthnCError::NotSupported)
                            | Err(WebauthnCError::U2F(_))
                            | Err(WebauthnCError::InvalidMessageLength) => {
                                println!("Device is not a SoloKey!");
                                continue;
                            }
                            Err(e) => panic!("could not get SoloKey UUID: {e:?}"),
                        };

                        let version = match authenticator.get_solokey_version().await {
                            Ok(v) => v,
                            Err(WebauthnCError::NotSupported)
                            | Err(WebauthnCError::U2F(_))
                            | Err(WebauthnCError::InvalidMessageLength) => {
                                println!("Device is not a SoloKey!");
                                continue;
                            }
                            Err(e) => panic!("could not get SoloKey version: {e:?}"),
                        };

                        let secure_boot = if match authenticator.get_solokey_lock().await {
                            Ok(v) => v,
                            Err(WebauthnCError::NotSupported)
                            | Err(WebauthnCError::U2F(_))
                            | Err(WebauthnCError::InvalidMessageLength) => {
                                println!("Device is not a SoloKey!");
                                continue;
                            }
                            Err(e) => panic!("could not get SoloKey lock state: {e:?}"),
                        } {
                            "enabled"
                        } else {
                            "disabled"
                        };

                        println!("SoloKey info:");
                        println!("  Device UUID: {uuid}");
                        println!("  Version:     {version:#x}");
                        println!("  Secure boot: {secure_boot}");
                    }
                    TokenEvent::EnumerationComplete => {
                        if o.watch {
                            println!("Initial enumeration completed, watching for more devices...");
                            println!("Press Ctrl + C to stop watching.");
                        } else {
                            break;
                        }
                    }
                    _ => (),
                }
            }
        }

        #[cfg(feature = "solokey")]
        Opt::SoloKeyRandom => {
            // TODO: filter this to just SoloKey devices in a safe way
            println!("Insert a SoloKey 2 or Trussed device...");
            let mut token: CtapAuthenticator<AnyToken, Cli> =
                select_one_device(stream, &ui).await.unwrap();

            let r = token
                .get_solokey_random()
                .await
                .expect("Error getting random data");
            println!("Random bytes: {}", hex::encode(r));
        }

        #[cfg(feature = "yubikey")]
        Opt::YubikeyGetConfig => {
            // TODO: filter this to just YubiKey devices in a safe way
            println!("Insert a YubiKey device...");
            let mut token: CtapAuthenticator<AnyToken, Cli> =
                select_one_device(stream, &ui).await.unwrap();

            let cfg = token
                .get_yubikey_config()
                .await
                .expect("Error getting YubiKey config");

            println!("YubiKey config:");
            println!("{cfg}")
        }

        #[cfg(feature = "usb")]
        Opt::Wink(o) => {
            use webauthn_authenticator_rs::usb::USBTransport;

            println!("Insert a USB device...");
            let transport = USBTransport::new().await.unwrap();
            let mut stream = transport.watch().await.unwrap();
            while let Some(event) = stream.next().await {
                match event {
                    TokenEvent::Added(mut token) => {
                        if !token.supports_wink() {
                            println!("Token does not support the wink function.");
                        } else {
                            token.wink().await.expect("Failed to wink USB device");
                        }

                        if !o.watch {
                            break;
                        }
                    }
                    TokenEvent::EnumerationComplete => {
                        if o.watch {
                            println!("Initial enumeration completed, watching for more devices...");
                            println!("Press Ctrl + C to stop watching.");
                        } else {
                            break;
                        }
                    }
                    _ => (),
                }
            }
        }
    }
}

#[macro_use]
extern crate tracing;

#[cfg(feature = "softtoken")]
use std::fs::OpenOptions;
use std::io::{stdin, stdout, Write};
use std::time::{Duration, SystemTime};

#[cfg(any(feature = "cable", feature = "softtoken"))]
use clap::Args;
use clap::{Parser, Subcommand, ValueEnum};
use crypto_glue::{
    ecdsa_p256,
    rand::{rngs::ThreadRng, Rng, RngExt},
    x509::Certificate,
};
#[cfg(feature = "cable")]
use tokio_tungstenite::tungstenite::http::uri::Builder;
#[cfg(feature = "cable-override-tunnel")]
use tokio_tungstenite::tungstenite::http::{uri::Parts, Uri};
use tracing_subscriber::{filter::LevelFilter, EnvFilter};
#[cfg(feature = "cable")]
use webauthn_authenticator_rs::prelude::WebauthnCError;
#[cfg(feature = "softtoken")]
use webauthn_authenticator_rs::softtoken::{SoftToken, SoftTokenFile};
#[cfg(feature = "ctap2")]
use webauthn_authenticator_rs::{ctap2::CtapAuthenticator, transport::*};
use webauthn_authenticator_rs::{
    prelude::Url,
    types::CableRequestType,
    ui::{Cli, UiCallback},
    AuthenticatorBackend, WebauthnAuthenticator,
};
use webauthn_rs_core::{
    error::WebauthnResult,
    proto::{
        AttestationMetadata, CredentialV5, ParsedAttestation, ParsedAttestationData,
        RequestAuthenticationExtensions,
    },
    WebauthnCore as Webauthn,
};
use webauthn_rs_proto::{
    AttestationConveyancePreference, AttestationFormat, CredProtect, CredentialProtectionPolicy,
    ExtnState, RegisteredExtensions, RequestRegistrationExtensions, UserVerificationPolicy,
};

/// Performs a WebAuthn registration and authentication ceremony with a fake RP.
///
/// This is used to test authenticators and transports with `webauthn-authenticator-rs`.
#[derive(Debug, clap::Parser)]
#[clap(about = "Registration and authentication tester")]
pub struct CliParser {
    /// Provider to use.
    #[clap(subcommand)]
    provider: Provider,

    /// User verification policy for the request.
    #[clap(short, long, value_enum, default_value_t)]
    verification_policy: UvPolicy,

    /// Credential protection policy at registration time.
    #[clap(short, long, value_enum, default_value_t)]
    credential_protection_policy: CredProtectPolicy,

    /// If set, registration fails if the authenticator cannot enforce the provided credential
    /// protection policy.
    #[clap(long)]
    enforce_credential_protection_policy: bool,

    /// If set, requests the authenticator's minimum PIN length at registration time. This only
    /// works if the authenticator has a configured `setMinPINLength` and
    /// `demo.webauthn-authenticator-rs.example` is in its `minPinLengthRPIDs`.
    #[clap(long)]
    min_pin_length: bool,

    /// Don't perform a registration ceremony, and just present random fake credentials for
    /// authentication.
    #[clap(long)]
    only_fakes: bool,

    /// Send the fake credential IDs during the registration request as excluded credentials.
    #[clap(long, conflicts_with = "only_fakes")]
    fakes_in_registration: bool,

    /// Number of fake credentials to place before the registered credential during the
    /// authentication ceremony.
    ///
    /// Fake credential IDs contain a random length of random bytes.
    #[clap(long, default_value_t)]
    fakes_before: usize,

    /// Number of fake credentials to place after the registered credential during the
    /// authentication ceremony.
    #[clap(long, default_value_t)]
    fakes_after: usize,
}

#[derive(ValueEnum, Clone, Copy, Default, Debug)]
pub enum UvPolicy {
    Discouraged,
    #[default]
    Preferred,
    Required,
}

impl From<UvPolicy> for UserVerificationPolicy {
    fn from(value: UvPolicy) -> Self {
        match value {
            UvPolicy::Discouraged => UserVerificationPolicy::Discouraged_DO_NOT_USE,
            UvPolicy::Preferred => UserVerificationPolicy::Preferred,
            UvPolicy::Required => UserVerificationPolicy::Required,
        }
    }
}

#[derive(ValueEnum, Clone, Copy, Default, Debug)]
pub enum CredProtectPolicy {
    /// No explicit credential protection policy is set.
    #[default]
    Unset,

    /// This reflects `FIDO_2_0` semantics. In this configuration, performing some form of user
    /// verification at authentication time is OPTIONAL with or without `credentialID` list.
    Optional,

    /// User verification at authentication time is OPTIONAL when providing a `credentialID` list
    /// (ie: required for resident keys, optional for non-resident keys). This demo always provides
    /// a credential ID list and discourages the use of resident keys, so this is essentially the
    /// same as `optional`.
    OptionalWithCredIdList,

    /// User verification at authentication time is REQUIRED.
    Required,
}

impl From<CredProtectPolicy> for Option<CredentialProtectionPolicy> {
    fn from(value: CredProtectPolicy) -> Self {
        match value {
            CredProtectPolicy::Unset => None,
            CredProtectPolicy::Optional => {
                Some(CredentialProtectionPolicy::UserVerificationOptional)
            }
            CredProtectPolicy::OptionalWithCredIdList => {
                Some(CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIDList)
            }
            CredProtectPolicy::Required => {
                Some(CredentialProtectionPolicy::UserVerificationRequired)
            }
        }
    }
}

#[cfg(feature = "ctap2")]
async fn select_transport<U: UiCallback>(ui: &U) -> impl AuthenticatorBackend + '_ {
    use futures::StreamExt;

    let reader = AnyTransport::new().await.unwrap();
    info!("Using reader: {:?}", reader);

    match reader.watch().await {
        Ok(mut tokens) => {
            while let Some(event) = tokens.next().await {
                match event {
                    TokenEvent::Added(token) => {
                        let auth = CtapAuthenticator::new(token, ui).await;

                        if let Some(auth) = auth {
                            return auth;
                        }
                    }

                    TokenEvent::EnumerationComplete => {
                        info!("device enumeration completed without detecting a FIDO2 authenticator, connect one to authenticate!");
                    }

                    TokenEvent::Removed(_) => {}
                }
            }
        }
        Err(e) => panic!("Error: {e:?}"),
    }

    panic!("No tokens available!");
}

#[cfg(feature = "softtoken")]
#[derive(Debug, Args, Clone)]
pub struct SoftTokenOpt {
    /// Path to serialised key data, created by the softtoken example.
    ///
    /// If not supplied, creates a temporary key in memory.
    #[clap()]
    pub path: Option<String>,
}

#[cfg(feature = "cable")]
#[derive(Debug, Args, Clone)]
pub struct CableOpt {
    #[cfg(feature = "cable-override-tunnel")]
    /// Overrides the WebSocket tunnel protocol and domain,
    /// eg: ws://localhost:8080
    ///
    /// The authenticator will need the same override set, as setting this
    /// option makes the library incompatible with other caBLE implementations.
    #[clap(long)]
    pub tunnel_uri: Option<String>,
}

#[cfg(feature = "cable")]
impl CableOpt {
    fn get_cable_tunnel_uri(&self) -> Option<Builder> {
        #[cfg(feature = "cable-override-tunnel")]
        if let Some(u) = &self.tunnel_uri {
            let parts: Parts = u.parse::<Uri>().unwrap().into_parts();
            return Some(
                Builder::new()
                    .scheme(parts.scheme.unwrap())
                    .authority(parts.authority.unwrap()),
            );
        }

        None
    }
}

#[derive(Debug, Clone, Subcommand)]
enum Provider {
    #[cfg(feature = "softtoken")]
    /// Software token provider
    SoftToken(SoftTokenOpt),

    #[cfg(feature = "ctap2")]
    /// CtapAuthenticator using Transport/Token backends (NFC, USB HID)
    ///
    /// Requires administrative permissions on Windows.
    Ctap,

    #[cfg(feature = "cable")]
    /// caBLE/Hybrid authenticator, using a QR code, BTLE and Websockets.
    ///
    /// This requires Bluetooth permission - see the
    /// [webauthn_authenticator_rs::cable] documentation for more information.
    Cable(CableOpt),

    #[cfg(feature = "mozilla")]
    /// Mozilla webauthn-authenticator-rs provider, supporting USB HID only.
    Mozilla,

    #[cfg(feature = "win10")]
    /// Windows 10 WebAuthn API, supporting BTLE, NFC and USB HID.
    Win10,
}

impl Provider {
    #[allow(unused_variables)]
    async fn connect_provider<'a, U: UiCallback>(
        &self,
        request_type: CableRequestType,
        ui: &'a U,
    ) -> Box<dyn AuthenticatorBackend + 'a> {
        match self {
            #[cfg(feature = "softtoken")]
            Provider::SoftToken(o) => {
                if let Some(path) = &o.path {
                    let file = OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create(false)
                        .open(path)
                        .unwrap();
                    Box::new(SoftTokenFile::open(file).unwrap())
                } else {
                    Box::new(SoftToken::new(false).unwrap().0)
                }
            }
            #[cfg(feature = "ctap2")]
            Provider::Ctap => Box::new(select_transport(ui).await),
            #[cfg(feature = "cable")]
            Provider::Cable(o) => Box::new(
                if let Some(connect_uri) = o.get_cable_tunnel_uri() {
                    #[cfg(not(feature = "cable-override-tunnel"))]
                    unreachable!();

                    #[cfg(feature = "cable-override-tunnel")]
                    webauthn_authenticator_rs::cable::connect_cable_authenticator_with_tunnel_uri(request_type, ui, connect_uri).await
                } else {
                    webauthn_authenticator_rs::cable::connect_cable_authenticator(request_type, ui).await
                }
                    .map_err(|e| {
                        if e == WebauthnCError::PermissionDenied {
                            println!("Permission denied: please grant Bluetooth permissions to your terminal app.");
                            println!("See the webauthn_authenticator_rs::cable module documentation for more info.")
                        }
                        e
                    })
                    .unwrap(),
            ),
            #[cfg(feature = "mozilla")]
            Provider::Mozilla => Box::<webauthn_authenticator_rs::mozilla::MozillaAuthenticator>::default(),
            #[cfg(feature = "win10")]
            Provider::Win10 => Box::<webauthn_authenticator_rs::win10::Win10>::default(),
        }
    }
}

/// Generate a fake credential that matches the verification policy.
fn fake_credential(
    rng: &mut ThreadRng,
    verification_policy: UvPolicy,
) -> WebauthnResult<CredentialV5> {
    let cred_len = rng.random_range(16..=64);
    let mut cred_id: Vec<u8> = vec![0; cred_len];
    rng.fill_bytes(&mut cred_id);

    let key = ecdsa_p256::new_key();
    let cred = (&key.public_key()).try_into()?;

    Ok(CredentialV5 {
        cred_id,
        cred,
        counter: 0,
        transports: None,
        user_verified: matches!(
            verification_policy,
            UvPolicy::Preferred | UvPolicy::Required
        ),
        backup_eligible: false,
        backup_state: false,
        registration_policy: verification_policy.into(),
        extensions: RegisteredExtensions {
            cred_protect: ExtnState::NotRequested,
            hmac_create_secret: ExtnState::NotRequested,
            appid: ExtnState::NotRequested,
            cred_props: ExtnState::Ignored,
        },
        attestation: ParsedAttestation {
            data: ParsedAttestationData::None,
            metadata: AttestationMetadata::None,
        },
        attestation_format: AttestationFormat::None,
    })
}

fn print_certs(certs: &[Certificate]) {
    for (i, cert) in certs.iter().enumerate() {
        println!("### Certificate {}", i + 1);
        println!("Issuer: {}", cert.tbs_certificate().issuer());
        println!("Subject: {}", cert.tbs_certificate().subject());
        println!("Serial: {}", cert.tbs_certificate().serial_number());

        println!("");
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .compact()
        .init();
    let mut rng = ThreadRng::default();

    let opt = CliParser::parse();
    let ui = Cli {};
    let provider = opt.provider;
    let mut u: Box<dyn AuthenticatorBackend>;

    let origin = Url::parse("https://demo.webauthn-authenticator-rs.example").unwrap();

    // WARNING: don't use this as an example of how to use the library!
    let wan = Webauthn::new_unsafe_experts_only(
        "webauthn-authenticator-rs demo",
        "demo.webauthn-authenticator-rs.example",
        vec![origin.clone()],
        Duration::from_secs(60),
        None,
        None,
    );

    let mut creds =
        Vec::with_capacity(opt.fakes_before + opt.fakes_after + if opt.only_fakes { 0 } else { 1 });
    for _ in 0..(opt.fakes_before + opt.fakes_after) {
        creds.push(
            fake_credential(&mut rng, opt.verification_policy).expect("Cannot generate fake"),
        );
    }

    if !opt.only_fakes {
        u = provider
            .connect_provider(CableRequestType::MakeCredential, &ui)
            .await;

        let mut unique_id = [0u8; 16];
        rng.fill_bytes(&mut unique_id);
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default();
        let user_name = format!("demo-{}", now.as_secs());
        let display_name = format!("Authenticate Demo {}", now.as_secs());

        let mut extensions: Option<RequestRegistrationExtensions> = None;

        if let Some(credential_protection_policy) = opt.credential_protection_policy.into() {
            let extensions = extensions.get_or_insert_default();
            extensions.cred_protect = Some(CredProtect {
                credential_protection_policy,
                enforce_credential_protection_policy: Some(
                    opt.enforce_credential_protection_policy,
                ),
            });
        }

        if opt.min_pin_length {
            let extensions = extensions.get_or_insert_default();
            extensions.min_pin_length = Some(true);
        }

        let mut builder = wan
            .new_challenge_register_builder(&unique_id, &user_name, &display_name)
            .unwrap()
            .attestation(AttestationConveyancePreference::None)
            .user_verification_policy(opt.verification_policy.into());

        if opt.fakes_in_registration {
            builder = builder.exclude_credentials(Some(
                creds.iter().map(|cred| cred.cred_id.clone()).collect(),
            ))
        }

        if let Some(extensions) = extensions {
            builder = builder.extensions(Some(extensions));
        }

        let (chal, reg_state) = wan.generate_challenge_register(builder).unwrap();

        info!("🍿 challenge -> {chal:x?}");

        // Do registration on the authenticator side (navigator.credentials.create)
        let r = u.do_registration(origin.clone(), chal).unwrap();
        trace!("Registering: {r:?}");

        // Register with the RP.
        let cred = wan.register_credential(&r, &reg_state, None).unwrap();
        trace!("Registered: {cred:?}");

        match &cred.attestation.data {
            ParsedAttestationData::None => {
                println!("## No attestation data");
            }
            ParsedAttestationData::Self_ => {
                println!("## Self-attestation");
            }
            ParsedAttestationData::ECDAA => {
                println!("## ECDAA attestation (not yet implemented)");
            }
            ParsedAttestationData::Uncertain => {
                println!("## Uncertain attestation (not trustworthy)");
            }
            ParsedAttestationData::Basic(certs) => {
                println!(
                    "## Basic attestation, {} certificate{}",
                    certs.len(),
                    if certs.len() == 1 { "" } else { "s" },
                );

                print_certs(certs);
            }
            ParsedAttestationData::AttCa(certs) => {
                println!(
                    "## CA attestation, {} certificate{}",
                    certs.len(),
                    if certs.len() == 1 { "" } else { "s" },
                );
                print_certs(certs);
            }
            ParsedAttestationData::AnonCa(certs) => {
                println!(
                    "## Anonymous CA attestation, {} certificate{}",
                    certs.len(),
                    if certs.len() == 1 { "" } else { "s" },
                );
                print_certs(certs);
            }
        }

        println!("## Extensions");
        println!("credProtect: {:?}", cred.extensions.cred_protect);

        creds.insert(opt.fakes_before, cred);
        println!("WARNING: Some NFC keys need to be power-cycled before you can authenticate.");
    }

    if creds.is_empty() {
        panic!("No credentials available to authenticate with.");
    }

    println!("Press ENTER to authenticate, or Ctrl-C to abort");
    stdout().flush().ok();

    let mut buf = String::new();
    stdin().read_line(&mut buf).expect("Cannot read stdin");

    loop {
        u = provider
            .connect_provider(CableRequestType::GetAssertion, &ui)
            .await;

        let (chal, auth_state) = wan
            .new_challenge_authenticate_builder(creds.clone(), None)
            .map(|builder| {
                builder.extensions(Some(RequestAuthenticationExtensions {
                    appid: Some("example.app.id".to_string()),
                    uvm: None,
                    hmac_get_secret: None,
                }))
            })
            .and_then(|b| wan.generate_challenge_authenticate(b))
            .unwrap();

        // Do authentication on the authenticator side (ie: navigator.credentials.get)
        match u.do_authentication(origin.clone(), chal) {
            Ok(cred) => {
                info!("Authenticator response: {cred:x?}");

                // Authenticate with the RP
                match wan.authenticate_credential(&cred, &auth_state) {
                    Ok(auth_res) => {
                        info!("RP auth success: {auth_res:x?}");
                    }

                    Err(e) => {
                        error!("RP auth failure: {e}");
                    }
                }
            }

            Err(e) => {
                error!("Authenticator error: {e:?}");
            }
        }

        println!("Press ENTER to try again, or Ctrl-C to abort");
        stdout().flush().ok();

        let mut buf = String::new();
        stdin().read_line(&mut buf).expect("Cannot read stdin");
    }
}

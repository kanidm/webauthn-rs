//! caBLE / Hybrid Authenticator
//!
//! **tl;dr:** scan a QR code with a `FIDO:/` URL, mobile device sends a BTLE
//! advertisement, this is used to establish a doubly-encrypted (TLS and
//! [Noise][]) Websocket tunnel over which the platform can send a single CTAP
//! 2.x command and get a response.
//!
//! A caBLE transaction involves three entities:
//!
//! * The *initator* (typically a web browser) starts the caBLE session for a
//!   `MakeCredential` or `GetAssertion` request on behalf of a relying party.
//!
//! * The *authenticator* (or mobile device) stores credential(s) for the user
//!   in a secure fashion, with some sort of local authentication (biometrics /
//!   PIN), instead of using a security key.
//!
//! * The *tunnel server* provides a two-way channel for the initator and
//!   authenticator to communicate over WebSockets. There are well-known servers
//!   operated by Apple (`wss://cable.auth.com`) and Google
//!   (`wss://cable.ua5v.com`), and an algorithm to generate tunnel server
//!   domain names from a hash to allow for future expansion.
//!
//!   You can also build the library with the `cable-override-tunnel` feature,
//!   which allows it to connect to an arbitrary tunnel server over HTTP
//!   (`ws://`) or HTTPS (`wss://`), instead of the *proper* tunnel server.
//!
//! This module implements both the [initator][connect_cable_authenticator] and
//! [authenticator][share_cable_authenticator] side of caBLE, provided
//! [you have appropriate hardware](#requirements).
//!
//! The *initiator* implementation provides a [`CtapAuthenticator`][] (so works
//! like other authenticator backends), and uses a [`UiCallback`][]
//! implementation to display the QR code the user. Authenticators on Android
//! and iOS only allow the initiator to send a single command before hanging up,
//! so other features like credential management won't work.
//!
//! The *authenticator* implementation takes an input URL (parsed from the QR
//! code), a [`AuthenticatorBackendHashedClientData`] and an [`Advertiser`] to
//! establish a tunnel and respond to an initator's request. This allows one to
//! share many of the authenticator backends this library already supports over
//! a caBLE tunnel.
//!
//! ## Warning
//!
//! **This implementation is incomplete, and has not been reviewed from a
//! cryptography standpoint.**
//!
//! There is **no** publicly-published spec from this protocol, aside from
//! [Chromium's C++ implementation][crcable], so this aims to do whatever
//! Chromium does.
//!
//! We've attempted to document and untangle things as best we can, but there
//! are probably errors in this implementation and its documentation. caBLE's
//! design appears to have changed multiple times during its development, while
//! attempting to preserve compatibility with older versions of Chromium.
//!
//! ## Features
//!
//! There are two major versions of caBLE, and this only implements caBLE v2.
//! There are also several minor versions of caBLE v2, which aren't fully
//! explained (or implemented here); this mostly implements what we *think* is
//! caBLE v2.1 as both an initiator and an authenticator.
//!
//! Known-missing functionality includes:
//!
//! * caBLE v1: protocol is significantly different
//! * caBLE v2.0: this has some quirks that this doesn't fully implement
//! * [caBLE over AOA][cableaoa] (Android Open Accessory Protocol)
//! * [caBLE over Firebase Cloud Messaging][cablefcm]
//! * Pairing (aka: "contact lists", "remember this computer")
//!
//! It is impossible to know for certain how many gaps there are until the caBLE
//! working group publishes documentation *publicly*.
//!
//! The library is complete enough as an initiator to communicate with
//! authenticators on Android and iOS 16, and complete enough as an
//! authenticator to work with Chrome and Safari as initiators.
//!
//! ## Requirements
//!
//! The initator (or "browser") requires:
//!
//! * a Bluetooth Low Energy (BTLE) adaptor with
//!   [appropriate permissions](#permissions).
//!
//! * an internet connection
//!
//! The authenticator (mobile device) requires:
//!
//! * a caBLE implementation, such as:
//!
//!   * [Android 7 or later][android-ver] with
//!     [a recent version of Chrome and Google Play Services (October 2022)][android]
//!
//!   * [iOS 16 or later][ios][^ios15]
//!
//!   * [this library][share_cable_authenticator]
//!
//! * a Bluetooth Low Energy (BTLE) radio which can transmit service data
//!   advertisements[^adv]
//!
//! * a camera and QR code scanner[^qr]
//!
//! * an internet connection
//!
//! **On Android,** Chrome handles the `FIDO:/` URL and establishes the
//! Websocket tunnel, and proxies commands to
//! [Google Play's FIDO2 API][gpfido2]. The authenticator
//! [is stored in Google Password Manager][android-sec], and it also supports
//! [devicePubKey][] to attest a specific device's identity.
//!
//! **On iOS,** the authenticator is stored in the iCloud Keychain and shared
//! with all devices signed in to that iCloud account. There is no way to
//! identify *which* device was used.
//!
//! In both cases, the credential is cached in the device's secure element, and
//! requires user verification (lock screen pattern, PIN, password or biometric
//! authentication) to access. This user verification is performed on-device,
//! and is entirely separate to CTAP2's PIN/UV auth.
//!
//! [^ios15]: iOS 15 will recognise caBLE QR codes and offer to authenticate,
//! but this version of the protocol is not supported.
//!
//! ## Permissions
//!
//! These permissions apply for using this library as an *initiator* (ie:
//! accessing an authenticator on a mobile device).
//!
//! ### Linux
//!
//! This library needs to be able to communicate with `bluez` via D-Bus. This is
//! generally available to users in the `bluetooth` group, which you can add a
//! user to with:
//!
//! ```sh
//! sudo gpasswd -a $USER bluetooth
//! ```
//!
//! You'll need to log out and log in again to get the new permission.
//!
//! ### macOS
//!
//! On macOS 11 (Big Sur) and later, additional permissions are required for
//! applications to use Bluetooth. This library doesn't try to request it.
//!
//! If using this library with a command-line program running from a terminal or
//! IDE:
//!
//! 1. Go to System Settings → Privacy & Security → Bluetooth.
//!
//!    In macOS 11 (Big Sur) and 12 (Monterey), go to System Preferences →
//!    Security & Privacy → Privacy → Bluetooth, and then click the lock icon
//!    (🔒) to make changes (you'll be prompted for your password or Touch ID).
//!
//! 2. Click the plus icon (➕).
//!
//!    On macOS 13 (Ventura) and later, you may be prompted for your password or
//!    Touch ID.
//!
//! 3. Select your terminal application or IDE (iTerm, Terminal, etc.) and click
//!    Open to add it to the list.
//!
//! 4. Quit and restart your terminal application.
//!
//! If using this library in a bundled GUI application (`.app`), you'll need
//! to set [NSBluetoothAlwaysUsageDescription][] in `Info.plist`. If your
//! application uses the [App Sandbox][], you'll *also* need to add the
//! [Bluetooth entitlement][entitlement].
//!
//! ### Windows
//!
//! An [App Capabilities Declaration][] is required to grant Bluetooth access to
//! applications distributed via the Windows Store on Windows 10 and later.
//!
//! These controls **do not** apply to applications compiled locally, or
//! distributed outside of the Windows Store.
//!
//! The Windows WebAuthn API does not (presently) support caBLE authenticators,
//! nor does it limit direct access to them, so this does *not* need to run as
//! Administrator.
//!
//! ## Protocol overview
//!
//! The user attempts to register or sign in using WebAuthn, and chooses to use
//! caBLE ("create a passkey on another device", "save a passkey on a device
//! with a camera"). This application becomes the _initator_ of the caBLE
//! session.
//!
//! The initator generates a CBOR message ([HandshakeV2][]) containing the
//! desired transaction type (`MakeCredential` or `GetAssertion`),
//! [a shared secret][qr-secret] and some protocol version information. It
//! encodes the message as a `FIDO:/` URL by encoding the CBOR as [base10], and
//! then displays it as a QR code for the user to scan with their authenticator.
//!
//! The user scans this QR code using their authenticator (mobile device), which
//! deserialises the [HandshakeV2][] message.
//!
//! Both the initiator and authenticator
//! [derive the tunnel ID][discovery::Discovery::derive_tunnel_id] from the QR
//! code's [shared secret][qr-secret].
//!
//! The authenticator establishes a connection to
//! [a well-known WebSocket tunnel server][tunnel::get_domain] of *its*
//! choosing. Once established, the tunnel server provides a routing ID, which
//! allows the initiator to connect to this session.
//!
//! The authenticator takes [the routing ID][routing_id],
//! [tunnel server ID][tunnel_server_id], and
//! [a nonce of its choosing][nonce] (not shared with the tunnel server) into an
//! [Eid][], and then encrypts and signs it using a secret derived from the QR
//! code's [shared secret][qr-secret]. It then broadcasts this encrypted [Eid][]
//! as a BTLE service data advertisement.
//!
//! Meanwhile, the initiator scans for caBLE BTLE service data advertisements,
//! and [tries to decrypt and parse them][discovery::Discovery::decrypt_advert].
//! On success, it can then find which
//! [tunnel server to connect to][tunnel_server_id], the
//! [routing ID][routing_id], and [the nonce][nonce].
//!
//! Both the initator and the authenticator
//! [derive a pre-shared key][discovery::Discovery::derive_psk] from the
//! [shared secret][qr-secret] and [nonce][].
//!
//! The initator connects to the tunnel server, and starts a handshake with the
//! authenticator using a non-standard version of the [Noise protocol][Noise]
//! ([CableNoise][]), using the pre-shared key and a new
//! ephemeral session key.
//!
//! They use the [CableNoise][] to derive traffic keys for [Crypter][]. All
//! further communications between the initiator and authenticator occur over
//! the [Crypter][] channel.
//!
//! The authenticator immediately sends a [GetInfoResponse][], and will also
//! send a pairing payload once the user has accepted or refused consent[^pair].
//!
//! The initiator can then send a *single* `MakeCredential` or `GetAssertion`
//! command to the authenticator in CTAP 2.0 format. This request *does not* use
//! PIN/UV auth – user verification is handled internally by the authenticator
//! *outside* the CTAP 2.0 protocol[^uv].
//!
//! Once the command is sent, the authenticator will prompt the user to approve
//! the request in a user-verifying way (biometric or lock screen pattern,
//! password or PIN), showing the user and relying party name.
//!
//! Once approved or rejected, the authenticator returns the response to the
//! command, and then closes the Websocket channel. A new handshake must be
//! performed if the user wishes to perform another transaction.
//!
//! The initiator then sends the authenticator's response to the relying party
//! using the usual WebAuthn APIs.
//!
//! [Advertiser]: btle::Advertiser
//! [android]: https://developers.google.com/identity/passkeys/supported-environments
//! [android-sec]: https://security.googleblog.com/2022/10/SecurityofPasskeysintheGooglePasswordManager.html
//! [android-ver]: https://source.chromium.org/chromium/chromium/src/+/main:chrome/android/features/cablev2_authenticator/java/src/org/chromium/chrome/browser/webauth/authenticator/CableAuthenticatorUI.java;l=170-171;drc=4a8573cb240df29b0e4d9820303538fb28e31d84
//! [App Capabilities Declaration]: https://learn.microsoft.com/en-us/windows/uwp/packaging/app-capability-declarations
//! [App Sandbox]: https://developer.apple.com/documentation/security/app_sandbox
//! [cableaoa]: https://source.chromium.org/chromium/chromium/src/+/main:device/fido/aoa/
//! [CableNoise]: noise::CableNoise
//! [cablefcm]: https://source.chromium.org/chromium/chromium/src/+/main:device/fido/cable/v2_authenticator.h;l=150-161;drc=eef4e6f76aff3defa06b9f8d921fcd46bb3e4dc1
//! [crcable]: https://source.chromium.org/chromium/chromium/src/+/main:device/fido/cable/
//! [Crypter]: noise::Crypter
//! [devicePubKey]: https://w3c.github.io/webauthn/#sctn-device-publickey-extension
//! [Eid]: discovery::Eid
//! [entitlement]: https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_device_bluetooth
//! [GetInfoResponse]: crate::ctap2::GetInfoResponse
//! [gpfido2]: https://developers.google.com/android/reference/com/google/android/gms/fido/fido2/Fido2PrivilegedApiClient
//! [HandshakeV2]: handshake::HandshakeV2
//! [ios]: https://developer.apple.com/videos/play/wwdc2022/10092/
//! [Noise]: http://noiseprotocol.org/noise.html
//! [nonce]: discovery::Eid::nonce
//! [NSBluetoothAlwaysUsageDescription]: https://developer.apple.com/documentation/bundleresources/information_property_list/nsbluetoothalwaysusagedescription
//! [qr-secret]: handshake::HandshakeV2::secret
//! [routing_id]: discovery::Eid::routing_id
//! [tunnel_server_id]: discovery::Eid::tunnel_server_id
//!
//! [^adv]: Unfortunately, most platform Bluetooth APIs do not allow sending
//! arbitrary Bluetooth service data advertisements, so
//! [your code must provide one][Advertiser]. The `cable_tunnel` example
//! provides an implementation using a Bluetooth HCI controller connected to a
//! serial UART.
//!
//! [^pair]: Pairing payloads are only supported on Android. Where supported,
//! pairing payloads will always be sent, padded to a constant size,
//! *regardless* of whether the user consented to pairing. If the user did not
//! consent, the payload will just be null bytes.
//!
//! [^uv]: Chromium and Safari won't even attempt PIN/UV auth, even if the
//! [GetInfoResponse][] suggested it was required.
//!
//! [^qr]: Most mobile device camera apps have an integrated QR code scanner.
#[allow(rustdoc::private_intra_doc_links)]
#[cfg(doc)]
use crate::stubs::*;

mod base10;
mod btle;
mod discovery;
mod framing;
mod handshake;
mod noise;
mod tunnel;

use std::collections::BTreeMap;

pub use self::{base10::DecodeError, btle::Advertiser, tunnel::get_domain};
use tokio_tungstenite::tungstenite::http::uri::Builder;

use crate::{
    authenticator_hashed::{
        perform_auth_with_request, perform_register_with_request,
        AuthenticatorBackendHashedClientData,
    },
    cable::{
        btle::Scanner,
        discovery::Discovery,
        framing::{CableFrameType, RequestType, SHUTDOWN_COMMAND},
        handshake::HandshakeV2,
        tunnel::Tunnel,
    },
    ctap2::{CtapAuthenticator, GetInfoResponse},
    error::{CtapError, WebauthnCError},
    transport::Token,
    types::{CableRequestType, CableState},
    ui::UiCallback,
};

type Psk = [u8; 32];

impl CableRequestType {
    fn to_cable_string(self) -> String {
        use CableRequestType::*;
        match self {
            GetAssertion => String::from("ga"),
            DiscoverableMakeCredential => String::from("mc"),
            MakeCredential => String::from("mc"),
        }
    }

    fn from_cable_string(
        val: &str,
        supports_non_discoverable_make_credential: bool,
    ) -> Option<Self> {
        use CableRequestType::*;
        match val {
            "ga" => Some(GetAssertion),
            "mc" => Some(if supports_non_discoverable_make_credential {
                MakeCredential
            } else {
                DiscoverableMakeCredential
            }),
            _ => None,
        }
    }
}

/// Establishes a connection to a caBLE authenticator using QR codes, Bluetooth
/// Low Energy and a Websocket tunnel.
///
/// The QR code to be displayed will be passed via [UiCallback::cable_qr_code].
///
/// The resulting connection is passed as a [CtapAuthenticator], but the remote
/// device will only accept a single command (specified in the `request_type`
/// parameter) and then close the underlying Websocket.
///
/// ## Permissions
///
/// On some platforms, Bluetooth access requires additional permissions. If this
/// is not available, this returns [WebauthnCError::PermissionDenied]. See
/// [this module's documentation][self] for more information.
#[inline]
pub async fn connect_cable_authenticator<'a, U: UiCallback + 'a>(
    request_type: CableRequestType,
    ui_callback: &'a U,
) -> Result<CtapAuthenticator<'a, Tunnel, U>, WebauthnCError> {
    connect_cable_authenticator_impl(request_type, ui_callback, None).await
}

#[cfg(any(doc, feature = "cable-override-tunnel"))]
/// Connect to an authenticator using caBLE, overriding the WebSocket tunnel
/// protocol and domain.
///
/// This is intended to allow a caBLE tunnel server developer to test their code
/// locally, without needing to register an appropriate domain name, set up DNS,
/// or get a TLS certificate.
///
/// This is only available with the `cable-override-tunnel` feature, and can
/// only used with an authenticator with the same override in place (see
/// [`ShareCableAuthenticatorOptions::tunnel_uri()`]).
///
/// ## Warning
///
/// This is **incompatible with other caBLE implementations**, and also allows
/// connecting to tunnel servers over unencrypted HTTP.
///
/// Use [`connect_cable_authenticator()`] instead.
#[inline]
pub async fn connect_cable_authenticator_with_tunnel_uri<'a, U: UiCallback + 'a>(
    request_type: CableRequestType,
    ui_callback: &'a U,
    connect_uri: Builder,
) -> Result<CtapAuthenticator<'a, Tunnel, U>, WebauthnCError> {
    connect_cable_authenticator_impl(request_type, ui_callback, Some(connect_uri)).await
}

#[doc(hidden)]
async fn connect_cable_authenticator_impl<'a, U: UiCallback + 'a>(
    request_type: CableRequestType,
    ui_callback: &'a U,
    connect_uri: Option<Builder>,
) -> Result<CtapAuthenticator<'a, Tunnel, U>, WebauthnCError> {
    // TODO: it may be better to return a caBLE-specific authenticator object,
    // rather than CtapAuthenticator, because the device will close the
    // Websocket connection as soon as we've sent a single command.
    trace!("Creating discovery QR code...");
    let disco = Discovery::new(request_type)?;
    let handshake = disco.make_handshake()?;
    let url = handshake.to_qr_url()?;
    ui_callback.cable_qr_code(request_type, url);

    trace!("Opening BTLE...");
    let scanner = Scanner::new().await?;
    trace!("Waiting for beacon...");
    let eid = disco
        .wait_for_matching_response(&scanner)
        .await?
        .ok_or_else(|| {
            error!("No caBLE EID received!");
            WebauthnCError::NoSelectedToken
        })?;
    ui_callback.dismiss_qr_code();
    drop(scanner);

    let psk = disco.derive_psk(&eid)?;

    let tunnel_id = disco.derive_tunnel_id()?;
    let connect_uri = match connect_uri {
        Some(u) => eid.build_connect_uri(u, tunnel_id),
        None => eid.get_connect_uri(tunnel_id),
    }
    .ok_or_else(|| {
        error!("unknown WebSocket tunnel URL for {:?}", eid);
        WebauthnCError::NotSupported
    })?;

    let tun = Tunnel::connect_initiator(
        &connect_uri,
        psk,
        disco.local_identity.as_ref(),
        ui_callback,
    )
    .await?;

    tun.get_authenticator(ui_callback).ok_or_else(|| {
        error!("no supported protocol versions!");
        WebauthnCError::NotSupported
    })
}

/// Options for [sharing an authenticator over caBLE][0].
///
/// ## Examples
///
/// The [`Default`] options should be suitable for most use cases:
///
/// ```
/// # #[cfg(feature = "cable")]
/// # {
/// # use webauthn_authenticator_rs::cable::ShareCableAuthenticatorOptions;
/// let opts = ShareCableAuthenticatorOptions::default();
/// # }
/// ```
///
/// You can customise options using a builder pattern:
///
/// ```
/// # #[cfg(feature = "cable")]
/// # {
/// # use webauthn_authenticator_rs::cable::ShareCableAuthenticatorOptions;
/// let opts = ShareCableAuthenticatorOptions::default()
///     .tunnel_server_id(0);
/// # }
/// ```
///
/// [0]: share_cable_authenticator
#[non_exhaustive]
#[derive(Debug, Default)]
pub struct ShareCableAuthenticatorOptions {
    #[doc(hidden)]
    tunnel_server_id: u16,
    #[doc(hidden)]
    stay_open_after_one_command: bool,
    #[doc(hidden)]
    tunnel_uri: Option<Builder>,
}

impl ShareCableAuthenticatorOptions {
    /// The [well-known tunnel server][0] to connect to.
    ///
    /// By default, this is set to `0` (Google Chrome's tunnel server).
    ///
    /// [0]: tunnel::get_domain
    pub fn tunnel_server_id(mut self, v: u16) -> Self {
        self.tunnel_server_id = v;
        self
    }

    /// By default (`false`), the library (like other caBLE implementations)
    /// will automatically close the connection after the first `MakeCredential`
    /// or `GetAssertion` command.
    ///
    /// If set to `true`, [`share_cable_authenticator()`] will instead allow
    /// multiple `MakeCredential` or `GetAssertion` commands to be sent.
    /// Commands are still limited to those declared in the `FIDO:/` URL's
    /// [CableRequestType].
    pub fn stay_open_after_one_command(mut self, v: bool) -> Self {
        self.stay_open_after_one_command = v;
        self
    }

    #[cfg(any(doc, feature = "cable-override-tunnel"))]
    /// Override the WebSocket tunnel server protocol and hostname.
    ///
    /// This is intended to allow a tunnel server developer to test their code
    /// locally, without needing to register an appropriate domain name, set up
    /// DNS, or get a TLS certificate.
    ///
    /// This option is *only* available with the `cable-override-tunnel`
    /// feature, and can only be used with an initiator with the same override
    /// in place (see [`connect_cable_authenticator_with_tunnel_uri()`])
    ///
    /// ## Warning
    ///
    /// Setting this option **is incompatible with other caBLE
    /// implementations**, as it will continue to broadcast advertisements with
    /// the provided [`tunnel_server_id`].
    ///
    /// This also allows connecting to tunnel servers over unencrypted HTTP.
    ///
    /// [`tunnel_server_id`]: Self::tunnel_server_id
    pub fn tunnel_uri(mut self, v: Builder) -> Self {
        self.tunnel_uri = Some(v);
        self
    }
}

/// Share an authenicator using caBLE.
///
/// * `backend` is a [AuthenticatorBackendHashedClientData] implementation.
///
/// * `info` is the [GetInfoResponse] from the authenticator.
///
///   This can be passed through as-is from a physical authenticator: this
///   function will update it appropriately for caBLE (eg: removing PIN/UV
///   support flags).
///
/// * `url` is the `FIDO:/` URL from the initiator's QR code.
///
/// * `advertiser` is reference to an [Advertiser] for starting and stopping
///   Bluetooth Low Energy advertisements. See `examples/cable_tunnel` for an
///   example which uses a Bluetooth HCI controller connected to a serial UART.
///
/// * `ui_callback` trait for prompting for user interaction where needed.
///
/// * `options` is a [ShareCableAuthenticatorOptions] with additional options,
///   though using [`Default::default()`] should be sufficient.
#[inline]
pub async fn share_cable_authenticator<'a, U>(
    backend: &mut impl AuthenticatorBackendHashedClientData,
    mut info: GetInfoResponse,
    url: &str,
    advertiser: &mut impl Advertiser,
    ui_callback: &'a U,
    options: ShareCableAuthenticatorOptions,
) -> Result<(), WebauthnCError>
where
    U: UiCallback + 'a,
{
    // Because AuthenticatorBackendWithRequests does PIN/UV auth for us, we need
    // to remove anything from GetInfoResponse that would suggest the remote
    // side should attempt PIN/UV auth.
    //
    // Chromium and Safari appear to ignore these options, but we actually do
    // this properly. For now, we're just going to set this to "known" values.
    info.options = Some(BTreeMap::from([
        // Possibly a lie.
        ("uv".to_string(), true),
    ]));
    info.pin_protocols = None;
    let transports = info.transports.get_or_insert(Default::default());
    transports.push("cable".to_string());
    transports.push("hybrid".to_string());

    let handshake = HandshakeV2::from_qr_url(url)?;
    let discovery = handshake.to_discovery()?;

    let tunnel_uri = match options.tunnel_uri {
        Some(u) => discovery.build_new_tunnel_uri(u)?,
        None => discovery.get_new_tunnel_uri(options.tunnel_server_id)?,
    };

    let mut tunnel = Tunnel::connect_authenticator(
        &tunnel_uri,
        &discovery,
        options.tunnel_server_id,
        &handshake.peer_identity,
        info,
        advertiser,
        ui_callback,
    )
    .await?;

    trace!("tunnel established");
    let timeout_ms = 30000;

    loop {
        ui_callback.cable_status_update(CableState::WaitingForInitiatorCommand);
        let msg = tunnel.recv().await?.ok_or(WebauthnCError::Closed)?;

        ui_callback.cable_status_update(CableState::Processing);
        let resp = match msg.message_type {
            CableFrameType::Shutdown => {
                break;
            }
            CableFrameType::Ctap => match (handshake.request_type, msg.parse_request()?) {
                (CableRequestType::MakeCredential, RequestType::MakeCredential(mc))
                | (CableRequestType::DiscoverableMakeCredential, RequestType::MakeCredential(mc)) => {
                    perform_register_with_request(backend, mc, timeout_ms)
                }
                (CableRequestType::GetAssertion, RequestType::GetAssertion(ga)) => {
                    perform_auth_with_request(backend, ga, timeout_ms)
                }
                (c, v) => {
                    error!("Unhandled command {:02x?} for {:?}", v, c);
                    Err(WebauthnCError::NotSupported)
                }
            },
            CableFrameType::Update => {
                warn!("Linking information is not supported, ignoring update message");
                continue;
            }

            _ => {
                error!("unhandled command: {:?}", msg);
                Err(WebauthnCError::NotSupported)
            }
        };

        // Re-insert the error code as needed.
        let resp = match resp {
            Err(e) => match e {
                WebauthnCError::Ctap(c) => vec![c.into()],
                _ => vec![CtapError::Ctap1InvalidParameter.into()],
            },
            Ok(mut resp) => {
                resp.reserve(1);
                resp.insert(0, CtapError::Ok.into());
                resp
            }
        };

        // Send the response to the command
        tunnel
            .send(framing::CableFrame {
                protocol_version: 1,
                message_type: CableFrameType::Ctap,
                data: resp,
            })
            .await?;

        if !options.stay_open_after_one_command {
            tunnel.send(SHUTDOWN_COMMAND).await?;
            break;
        }
    }

    // Hang up
    tunnel.close().await?;
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn cable_request_type() {
        assert_eq!(
            Some(CableRequestType::DiscoverableMakeCredential),
            CableRequestType::from_cable_string("mc", false)
        );
        assert_eq!(
            Some(CableRequestType::MakeCredential),
            CableRequestType::from_cable_string("mc", true)
        );
        assert_eq!(
            Some(CableRequestType::GetAssertion),
            CableRequestType::from_cable_string("ga", false)
        );
        assert_eq!(
            Some(CableRequestType::GetAssertion),
            CableRequestType::from_cable_string("ga", true)
        );
        assert_eq!(None, CableRequestType::from_cable_string("nonsense", false));

        assert_eq!(
            "mc",
            CableRequestType::DiscoverableMakeCredential.to_cable_string()
        );
        assert_eq!("mc", CableRequestType::MakeCredential.to_cable_string());
        assert_eq!("ga", CableRequestType::GetAssertion.to_cable_string());
    }
}

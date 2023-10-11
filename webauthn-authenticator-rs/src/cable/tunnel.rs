//! Tunnel functions
#[cfg(doc)]
use crate::stubs::*;

use std::collections::BTreeMap;
use std::fmt::Debug;

use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use openssl::{
    ec::EcKeyRef,
    pkey::{Private, Public},
};
use serde::Serialize;
use serde_cbor_2::{ser::to_vec_packed, Value};
use tokio::net::TcpStream;
#[cfg(feature = "cable")]
use tokio_tungstenite::{
    connect_async,
    tungstenite::{client::IntoClientRequest, http::HeaderValue, Message},
};
use tokio_tungstenite::{tungstenite::http::Uri, MaybeTlsStream, WebSocketStream};
use webauthn_rs_proto::AuthenticatorTransport;

use crate::{
    cable::{
        btle::{Advertiser, FIDO_CABLE_SERVICE_U16},
        discovery::{Discovery, Eid},
        framing::{CableFrame, CableFrameType, SHUTDOWN_COMMAND},
        noise::{CableNoise, Crypter},
        CableState, Psk,
    },
    crypto::compute_sha256,
    ctap2::{
        commands::{value_to_vec_u8, GetInfoResponse},
        CBORResponse, CtapAuthenticator,
    },
    error::CtapError,
    prelude::WebauthnCError,
    transport::Token,
    ui::UiCallback,
};

/// Manually-assigned domains.
///
/// Source: <https://source.chromium.org/chromium/chromium/src/+/main:device/fido/cable/v2_handshake.cc;l=123-125;drc=6767131b3528fefd866f604b32ebbb278c35d395>
const ASSIGNED_DOMAINS: [&str; 2] = [
    // Google
    "cable.ua5v.com",
    // Apple
    "cable.auth.com",
];

/// The number of manually-assigned domains known by this module.
pub const ASSIGNED_DOMAINS_COUNT: u32 = ASSIGNED_DOMAINS.len() as u32;

const TUNNEL_SERVER_SALT: &[u8] = b"caBLEv2 tunnel server domain\0\0\0";
const TUNNEL_SERVER_ID_OFFSET: usize = TUNNEL_SERVER_SALT.len() - 3;
const TUNNEL_SERVER_TLDS: [&str; 4] = [".com", ".org", ".net", ".info"];
const BASE32_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Derives a caBLE tunnel server hostname from a `domain_id`.
///
/// Returns a hostname (eg: `cable.ua5v.com`) on success, or `None` if
/// `domain_id` is unknown.
///
/// **Reference:** [Chromium's `tunnelserver::DecodeDomain`][0]
///
/// ## Example
///
/// ```
/// use webauthn_authenticator_rs::cable::get_domain;
///
/// // Known static assignment
/// assert_eq!(get_domain(0).unwrap(), "cable.ua5v.com");
///
/// // Unknown static assignment
/// assert_eq!(get_domain(255), None);
///
/// // Hostname derived from checksum
/// assert_eq!(get_domain(266).unwrap(), "cable.wufkweyy3uaxb.com");
/// ```
///
/// **Tip:** The `cable_domain` example derives tunnel server hostnames at the
/// command line. For more information, run:
///
/// ```sh
/// cargo run --example cable_domain --features cable -- --help
/// ```
///
/// [0]: https://source.chromium.org/chromium/chromium/src/+/main:device/fido/cable/v2_handshake.cc?q=symbol%3A%5Cbdevice%3A%3Acablev2%3A%3Atunnelserver%3A%3ADecodeDomain%5Cb%20case%3Ayes
pub fn get_domain(domain_id: u16) -> Option<String> {
    if domain_id < 256 {
        return match ASSIGNED_DOMAINS.get(usize::from(domain_id)) {
            Some(d) => Some(d.to_string()),
            None => {
                warn!("Invalid tunnel server ID {:04x}", domain_id);
                None
            }
        };
    }

    let mut buf = TUNNEL_SERVER_SALT.to_vec();
    buf[TUNNEL_SERVER_ID_OFFSET..TUNNEL_SERVER_ID_OFFSET + 2]
        .copy_from_slice(&domain_id.to_le_bytes());
    let digest = compute_sha256(&buf);
    let mut result = u64::from_le_bytes(digest[..8].try_into().ok()?);

    let tld = TUNNEL_SERVER_TLDS[(result & 3) as usize];

    let mut o = String::from("cable.");
    result >>= 2;
    while result != 0 {
        o.push(char::from_u32(BASE32_CHARS[(result & 31) as usize].into())?);
        result >>= 5;
    }
    o.push_str(tld);

    Some(o)
}

/// Websocket tunnel to a caBLE authenticator.
///
/// This implements [Token], but unlike most transports:
///
/// * this only allows a single command to be executed
/// * the command must be specified in the [HandshakeV2][super::handshake::HandshakeV2] QR code
/// * the remote side "hangs up" after a single command
pub struct Tunnel {
    // psk: Psk,
    stream: WebSocketStream<MaybeTlsStream<TcpStream>>,
    crypter: Crypter,
    info: GetInfoResponse,
}

impl Tunnel {
    pub(super) async fn connect(
        uri: &Uri,
    ) -> Result<(WebSocketStream<MaybeTlsStream<TcpStream>>, Option<Vec<u8>>), WebauthnCError> {
        let mut request = IntoClientRequest::into_client_request(uri)?;
        let headers = request.headers_mut();
        headers.insert(
            "Sec-WebSocket-Protocol",
            HeaderValue::from_static("fido.cable"),
        );
        let origin = format!("wss://{}", uri.host().unwrap_or_default());
        headers.insert(
            "Origin",
            HeaderValue::from_str(&origin).map_err(|_| WebauthnCError::Internal)?,
        );

        trace!(?request);
        let (stream, response) = connect_async(request).await.map_err(|e| {
            error!("websocket error: {uri}: {e:?}");
            WebauthnCError::Internal
        })?;

        trace!(?response);
        // Get the routing-id from the response header
        let routing_id = response
            .headers()
            .get("X-caBLE-Routing-ID")
            .and_then(|v| hex::decode(v.as_bytes()).ok());
        trace!("Routing ID: {:02x?}", routing_id);

        Ok((stream, routing_id))
    }

    pub async fn connect_initiator(
        uri: &Uri,
        psk: Psk,
        local_identity: &EcKeyRef<Private>,
        ui: &impl UiCallback,
    ) -> Result<Tunnel, WebauthnCError> {
        ui.cable_status_update(CableState::ConnectingToTunnelServer);
        let (mut stream, _) = Self::connect(uri).await?;

        // BuildInitialMessage
        // https://source.chromium.org/chromium/chromium/src/+/main:device/fido/cable/v2_handshake.cc;l=880;drc=38321ee39cd73ac2d9d4400c56b90613dee5fe29
        ui.cable_status_update(CableState::Handshaking);
        let (noise, handshake_message) =
            CableNoise::build_initiator(Some(local_identity), psk, None)?;
        trace!("Sending initial handshake...");
        trace!(">!> {}", hex::encode(&handshake_message));
        stream.send(Message::Binary(handshake_message)).await?;

        // Handshake sent, get response
        ui.cable_status_update(CableState::WaitingForAuthenticatorResponse);
        trace!("Waiting for handshake response...");
        let resp = stream.next().await.ok_or(WebauthnCError::Closed)??;

        ui.cable_status_update(CableState::Handshaking);
        let mut crypter = if let Message::Binary(v) = resp {
            trace!("<!< {}", hex::encode(&v));
            noise.process_response(&v)?
        } else {
            error!("Unexpected websocket response type");
            return Err(WebauthnCError::Unknown);
        };

        // Waiting for post-handshake message
        ui.cable_status_update(CableState::WaitingForAuthenticatorResponse);
        trace!("Waiting for post-handshake message...");
        let resp = stream.next().await.ok_or(WebauthnCError::Closed)??;
        ui.cable_status_update(CableState::Handshaking);

        let v = if let Message::Binary(v) = resp {
            trace!("<!< {}", hex::encode(&v));
            v
        } else {
            error!("Unexpected websocket response type");
            return Err(WebauthnCError::Unknown);
        };

        let decrypted = crypter.decrypt(&v)?;
        trace!("<<< {}", hex::encode(&decrypted));

        // If Chromium on Android uses caBLE v2.0 if the supports_linking field
        // is missing, or v2.1 if it is present (even if false)[0]. When using
        // v2.0, it sends a different initial message with extra padded CBOR and
        // linking info.
        //
        // As an initiator, Chromium will try to decode this message as v2.1,
        // falling back to v2.0[1] on a parser error. However, serde_cbor_2 is
        // happy to parse the padded value regardless.
        //
        // [0]: https://source.chromium.org/chromium/chromium/src/+/main:chrome/android/features/cablev2_authenticator/native/cablev2_authenticator_android.cc;l=688-693;drc=9d8024e69625a0c457a4999f4d1aca32c24eb494
        // [1]: https://source.chromium.org/chromium/chromium/src/+/main:device/fido/cable/fido_tunnel_device.cc;l=368-375;drc=52fa5a7f263b37149bcfbac06da00fec5abcc416
        let v: BTreeMap<u32, Value> =
            serde_cbor_2::from_slice(&decrypted).map_err(|_| WebauthnCError::Cbor)?;

        let frame = CablePostHandshake::try_from(v)?;
        trace!(?frame);

        let info = frame.info;

        let t = Self {
            // psk,
            stream,
            crypter,
            info,
        };

        Ok(t)
    }

    pub async fn connect_authenticator(
        uri: &Uri,
        discovery: &Discovery,
        tunnel_server_id: u16,
        peer_identity: &EcKeyRef<Public>,
        info: GetInfoResponse,
        advertiser: &mut impl Advertiser,
        ui: &impl UiCallback,
    ) -> Result<Tunnel, WebauthnCError> {
        ui.cable_status_update(CableState::ConnectingToTunnelServer);
        let (mut stream, routing_id) = Self::connect(uri).await?;

        let eid = if let Some(routing_id) = routing_id {
            Eid::new(
                tunnel_server_id,
                routing_id.try_into().map_err(|_| {
                    error!("Incorrect routing-id header length");
                    WebauthnCError::Internal
                })?,
            )?
        } else {
            error!("Missing or invalid routing-id header");
            return Err(WebauthnCError::Internal);
        };

        let psk = discovery.derive_psk(&eid)?;
        let encrypted_eid = discovery.encrypt_advert(&eid)?;
        advertiser.start_advertising(FIDO_CABLE_SERVICE_U16, &encrypted_eid)?;

        // Wait for initial message from initiator
        trace!("Advertising started, waiting for initiator...");
        ui.cable_status_update(CableState::WaitingForInitiatorConnection);
        let resp = stream.next().await.ok_or(WebauthnCError::Closed)??;

        advertiser.stop_advertising()?;
        ui.cable_status_update(CableState::Handshaking);
        let resp = if let Message::Binary(v) = resp {
            trace!("<!< {}", hex::encode(&v));
            v
        } else {
            error!("Unexpected websocket response type");
            return Err(WebauthnCError::Unknown);
        };

        let (mut crypter, response) =
            CableNoise::build_responder(None, psk, Some(peer_identity), &resp)?;
        trace!("Sending response to initiator challenge");
        trace!(">!> {}", hex::encode(&response));
        stream.send(Message::Binary(response)).await?;

        // Send post-handshake message
        let phm = CablePostHandshake {
            info: info.to_owned(),
            linking_info: None,
        };
        trace!("Post-handshake message: {:02x?}", &phm);
        let phm = serde_cbor_2::to_vec(&phm).map_err(|_| WebauthnCError::Cbor)?;
        crypter.use_new_construction();

        let mut t = Self {
            // psk,
            stream,
            crypter,
            info,
        };

        t.send_raw(&phm).await?;

        // Now we're ready for our first command
        Ok(t)
    }

    /// Establishes a [CtapAuthenticator] connection for communicating with a
    /// caBLE authenticator using CTAP 2.x.
    ///
    /// See [CtapAuthenticator::new] for further detail.
    pub fn get_authenticator<U: UiCallback>(
        self,
        ui_callback: &U,
    ) -> Option<CtapAuthenticator<'_, Self, U>> {
        CtapAuthenticator::new_with_info(self.info.to_owned(), self, ui_callback)
    }

    pub(super) async fn send(&mut self, cmd: CableFrame) -> Result<(), WebauthnCError> {
        let cmd = cmd.to_bytes().ok_or(WebauthnCError::ApduConstruction)?;
        self.send_raw(&cmd).await
    }

    async fn send_raw(&mut self, cmd: &[u8]) -> Result<(), WebauthnCError> {
        trace!(">>> {}", hex::encode(cmd));
        let encrypted = self.crypter.encrypt(cmd)?;
        trace!(">!> {}", hex::encode(&encrypted));
        self.stream.send(Message::Binary(encrypted)).await?;
        Ok(())
    }

    pub(super) async fn recv(&mut self) -> Result<Option<CableFrame>, WebauthnCError> {
        let resp = match self.stream.next().await {
            None => return Ok(None),
            Some(r) => r?,
        };

        let resp = if let Message::Binary(v) = resp {
            v
        } else {
            error!("Incorrect message type");
            return Err(WebauthnCError::Unknown);
        };

        trace!("<!< {}", hex::encode(&resp));
        let decrypted = self.crypter.decrypt(&resp)?;
        trace!("<<< {}", hex::encode(&decrypted));
        // TODO: protocol version
        Ok(Some(CableFrame::from_bytes(1, &decrypted)))
    }
}

impl Debug for Tunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tunnel")
            .field("stream", &self.stream)
            .finish()
    }
}

#[async_trait]
impl Token for Tunnel {
    type Id = ();

    fn get_transport(&self) -> AuthenticatorTransport {
        AuthenticatorTransport::Hybrid
    }

    async fn transmit_raw<U>(&mut self, cbor: &[u8], ui: &U) -> Result<Vec<u8>, WebauthnCError>
    where
        U: UiCallback,
    {
        let f = CableFrame {
            // TODO: handle protocol versions
            protocol_version: 1,
            message_type: CableFrameType::Ctap,
            data: cbor.to_vec(),
        };
        self.send(f).await?;
        ui.cable_status_update(CableState::WaitingForAuthenticatorResponse);
        let mut data = loop {
            let resp = match self.recv().await? {
                Some(r) => r,
                None => {
                    // end of stream
                    self.close().await?;
                    return Err(WebauthnCError::Closed);
                }
            };

            if resp.message_type == CableFrameType::Ctap {
                break resp.data;
            } else {
                // TODO: handle these.
                warn!("unhandled message type: {:?}", resp);
            }
        };
        self.close().await?;
        ui.cable_status_update(CableState::Processing);

        let err = CtapError::from(data.remove(0));
        if !err.is_ok() {
            return Err(err.into());
        }
        Ok(data)
    }

    async fn cancel(&mut self) -> Result<(), WebauthnCError> {
        // There is no way to cancel transactions without closing in caBLE
        Ok(())
    }

    async fn init(&mut self) -> Result<(), WebauthnCError> {
        Ok(())
    }

    async fn close(&mut self) -> Result<(), WebauthnCError> {
        // We don't care if this errors
        self.send(SHUTDOWN_COMMAND).await.ok();
        self.stream.close(None).await.ok();
        Ok(())
    }
}

/// Message sent by the authenticator after completing the CableNoise handshake.
///
/// <https://source.chromium.org/chromium/chromium/src/+/main:device/fido/cable/fido_tunnel_device.cc;l=368-395;drc=38321ee39cd73ac2d9d4400c56b90613dee5fe29>
///
/// * Two protocol versions here, protocol 1 and protocol 0.
/// * Protocol 1 has a CBOR map:
///   * 1: GetInfoResponse bytes
///   * 2: linking info (optional)
/// * Protocol 0: Padded map (not implemented)
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(try_from = "BTreeMap<u32, Value>", into = "BTreeMap<u32, Value>")]
struct CablePostHandshake {
    info: GetInfoResponse,
    linking_info: Option<Vec<u8>>,
}

impl TryFrom<BTreeMap<u32, Value>> for CablePostHandshake {
    type Error = WebauthnCError;

    fn try_from(mut raw: BTreeMap<u32, Value>) -> Result<Self, Self::Error> {
        // trace!("raw = {:?}", raw);
        let info = raw
            .remove(&0x01)
            .and_then(|v| value_to_vec_u8(v, "0x01"))
            .ok_or(WebauthnCError::MissingRequiredField)?;
        let info = <GetInfoResponse as CBORResponse>::try_from(info.as_slice())?;

        let linking_info = raw.remove(&0x02).and_then(|v| value_to_vec_u8(v, "0x02"));

        Ok(Self { info, linking_info })
    }
}

impl From<CablePostHandshake> for BTreeMap<u32, Value> {
    fn from(h: CablePostHandshake) -> Self {
        let mut o = BTreeMap::new();

        if let Ok(info) = to_vec_packed(&h.info) {
            o.insert(0x01, Value::Bytes(info));
        }

        if let Some(linking_info) = h.linking_info {
            o.insert(0x02, Value::Bytes(linking_info));
        }

        o
    }
}

#[cfg(test)]
mod test {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn check_known_tunnel_server_domains() {
        assert_eq!(get_domain(0), Some(String::from("cable.ua5v.com")));
        assert_eq!(get_domain(1), Some(String::from("cable.auth.com")));
        assert_eq!(
            get_domain(266),
            Some(String::from("cable.wufkweyy3uaxb.com"))
        );

        assert_eq!(get_domain(255), None);

        // 🦀 = \u{1f980}
        assert_eq!(
            get_domain(0xf980),
            Some(String::from("cable.my4kstlhndi4c.net"))
        )
    }

    #[test]
    fn check_all_hashed_tunnel_servers() {
        for x in 256..=u16::MAX {
            assert_ne!(get_domain(x), None);
        }
    }

    #[test]
    fn posthandshake_android_chrome() {
        // https://source.chromium.org/chromium/chromium/src/+/main:device/fido/cable/v2_authenticator.cc;l=242-273;drc=a0f2b9dcc9512d175ff2cf18322cfdeb5348085c
        let _ = tracing_subscriber::fmt().try_init();
        let expected = CablePostHandshake {
            info: GetInfoResponse {
                versions: BTreeSet::from(["FIDO_2_0".to_string(), "FIDO_2_1".to_string()]),
                extensions: Some(vec!["devicePubKey".to_string(), "prf".to_string()]),
                aaguid: Some(uuid::uuid!("00000000-0000-0000-0000-000000000000")),
                options: Some(BTreeMap::from([
                    ("rk".to_string(), true),
                    ("uv".to_string(), true),
                ])),
                transports: Some(vec![
                    "cable".to_string(),
                    "hybrid".to_string(),
                    "internal".to_string(),
                ]),
                ..Default::default()
            },
            linking_info: None,
        };

        let get_info = hex::decode("a101585ca50182684649444f5f325f30684649444f5f325f3102826c6465766963655075624b65796370726603500000000000000000000000000000000004a262726bf5627576f50983656361626c656668796272696468696e7465726e616c").unwrap();
        let v: BTreeMap<u32, Value> = serde_cbor_2::from_slice(&get_info)
            .map_err(|_| WebauthnCError::Cbor)
            .unwrap();

        let frame = CablePostHandshake::try_from(v).unwrap();
        assert_eq!(expected, frame);
    }

    #[test]
    fn posthandshake_ios16() {
        let _ = tracing_subscriber::fmt().try_init();
        let expected = CablePostHandshake {
            info: GetInfoResponse {
                versions: BTreeSet::from(["FIDO_2_0".to_string()]),
                aaguid: Some(uuid::uuid!("f24a8e70-d0d3-f82c-2937-32523cc4de5a")),
                options: Some(BTreeMap::from([
                    ("rk".to_string(), true),
                    ("uv".to_string(), true),
                ])),
                transports: Some(vec!["internal".to_string(), "hybrid".to_string()]),
                ..Default::default()
            },
            linking_info: None,
        };

        let get_info = hex::decode("a101583aa40181684649444f5f325f300350f24a8e70d0d3f82c293732523cc4de5a04a262726bf5627576f5098268696e7465726e616c66687962726964").unwrap();
        let v: BTreeMap<u32, Value> = serde_cbor_2::from_slice(&get_info)
            .map_err(|_| WebauthnCError::Cbor)
            .unwrap();

        let frame = CablePostHandshake::try_from(v).unwrap();
        assert_eq!(expected, frame);
    }
}

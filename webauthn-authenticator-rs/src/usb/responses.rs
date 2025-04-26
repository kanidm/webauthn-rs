//! All [Response] frame types, used by FIDO tokens over USB HID.
use crate::error::WebauthnCError;
use crate::transport::{
    iso7816::ISO7816ResponseAPDU,
    types::{
        CBORResponse, U2FError, U2FHID_CBOR, U2FHID_ERROR, U2FHID_KEEPALIVE, U2FHID_MSG,
        U2FHID_PING,
    },
    TYPE_INIT,
};
use crate::usb::framing::U2FHIDFrame;
use crate::usb::*;

const CAPABILITY_WINK: u8 = 0x01;
const CAPABILITY_CBOR: u8 = 0x04;
const CAPABILITY_NMSG: u8 = 0x08;

/// Response type [U2FHID_INIT]
#[derive(Debug, PartialEq, Eq)]
pub struct InitResponse {
    pub nonce: Vec<u8>,
    /// Allocated channel identifier
    pub cid: u32,
    /// U2F protocol version (2)
    pub protocol_version: u8,
    pub device_version_major: u8,
    pub device_version_minor: u8,
    pub device_version_build: u8,
    pub capabilities: u8,
}

impl InitResponse {
    /// `true` if the device supports CTAPv1 / U2F protocol.
    pub fn supports_ctap1(&self) -> bool {
        self.capabilities & CAPABILITY_NMSG == 0
    }

    /// `true` if the device supports CTAPv2 / CBOR protocol.
    pub fn supports_ctap2(&self) -> bool {
        self.capabilities & CAPABILITY_CBOR > 0
    }

    /// `true` if the device supports wink function.
    pub fn supports_wink(&self) -> bool {
        self.capabilities & CAPABILITY_WINK > 0
    }
}

impl TryFrom<&[u8]> for InitResponse {
    type Error = WebauthnCError;
    fn try_from(d: &[u8]) -> Result<Self, Self::Error> {
        if d.len() < 17 {
            return Err(WebauthnCError::MessageTooShort);
        }

        let (nonce, d) = d.split_at(8);
        let nonce = nonce.to_vec();
        let (cid, d) = d.split_at(4);
        let cid = u32::from_be_bytes(
            cid.try_into()
                .map_err(|_| WebauthnCError::MessageTooShort)?,
        );

        Ok(InitResponse {
            nonce,
            cid,
            protocol_version: d[0],
            device_version_major: d[1],
            device_version_minor: d[2],
            device_version_build: d[3],
            capabilities: d[4],
        })
    }
}

/// Parser for a response [U2FHIDFrame].
///
/// The frame must be complete (ie: all fragments received) before parsing.
impl TryFrom<&U2FHIDFrame> for Response {
    type Error = WebauthnCError;

    fn try_from(f: &U2FHIDFrame) -> Result<Response, WebauthnCError> {
        if !f.complete() {
            error!("cannot parse incomplete frame");
            return Err(WebauthnCError::Internal);
        }

        let b = &f.data[..];
        Ok(match f.cmd {
            U2FHID_INIT => InitResponse::try_from(b).map(Response::Init)?,
            U2FHID_PING => Response::Ping(b.to_vec()),
            U2FHID_MSG => ISO7816ResponseAPDU::try_from(b).map(Response::Msg)?,
            U2FHID_WINK => Response::Wink,
            U2FHID_CBOR => CBORResponse::try_from(b).map(Response::Cbor)?,
            U2FHID_KEEPALIVE => Response::KeepAlive(KeepAliveStatus::from(b)),
            U2FHID_ERROR => Response::Error(U2FError::from(b)),
            _ => {
                error!(
                    "unknown USB HID command: 0x{:02x} (0x{:02x})",
                    f.cmd,
                    f.cmd ^ TYPE_INIT
                );
                Response::Unknown
            }
        })
    }
}

#[allow(clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctap2::commands::GetInfoResponse;
    use crate::ctap2::CBORResponse;
    use uuid::uuid;

    #[test]
    fn init() {
        let c = U2FHIDFrame {
            cid: 0xffffffff,
            cmd: 0x86,
            len: 0x08,
            data: vec![0x7f, 0x4d, 0x02, 0x24, 0x8e, 0xb5, 0xcb, 0x48],
        };

        let expected: HidSendReportBytes = [
            0x00, // Report
            0xff, 0xff, 0xff, 0xff, // CID
            0x86, // Command
            0x00, 0x08, // Length
            0x7f, 0x4d, 0x02, 0x24, 0x8e, 0xb5, 0xcb, 0x48, // InitRequest nonce
            // Padding
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        assert_eq!(HidSendReportBytes::from(&c), expected);

        let d: HidReportBytes = [
            0xff, 0xff, 0xff, 0xff, // CID
            0x86, // Command
            0x00, 0x11, // Length
            // InitResponse
            0x7f, 0x4d, 0x02, 0x24, 0x8e, 0xb5, 0xcb, 0x48, // nonce
            0x00, 0x27, 0x00, 0x01, // CID
            0x02, // Protocol version
            0x05, 0x02, 0x04, // Device version
            0x05, // Capabilities
            // Padding
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let expected = Response::Init(InitResponse {
            nonce: vec![0x7f, 0x4d, 0x02, 0x24, 0x8e, 0xb5, 0xcb, 0x48],
            cid: 2555905,
            protocol_version: 2,
            device_version_major: 5,
            device_version_minor: 2,
            device_version_build: 4,
            capabilities: 5,
        });

        let frame: U2FHIDFrame = <U2FHIDFrame>::try_from(&d).expect("init frame");

        assert_eq!(frame.cid, 0xffffffff);
        assert_eq!(frame.cmd, 0x86);
        assert_eq!(frame.len, 0x11);
        assert_eq!(frame.data.len(), 0x11);

        let r: Response = Response::try_from(&frame).expect("init response");
        assert_eq!(r, expected);
        if let Response::Init(r) = r {
            assert!(r.supports_ctap1());
            assert!(r.supports_ctap2());
            assert!(r.supports_wink());
        } else {
            panic!("bad response");
        }

        // Skip leading byte (report ID)
        assert_eq!(HidSendReportBytes::from(&frame)[1..], d)
    }

    #[test]
    fn init_capabilities() {
        // Yubico Security Key NFC C in FIDO2-only mode
        let d: [u8; 64] = [
            0xff, 0xff, 0xff, 0xff, // CID
            0x86, // Command
            0x00, 0x11, // Length
            // InitResponse
            0xb2, 0xe7, 0xc4, 0xd6, 0x1c, 0x9e, 0x17, 0x0a, // nonce
            0x0a, 0xa4, 0xcb, 0x08, // CID
            0x02, // Protocol version
            0x05, 0x04, 0x03, // Device version
            0x0d, // Capabilities
            // Padding
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let frame: U2FHIDFrame = <U2FHIDFrame>::try_from(&d).expect("init frame");
        let r: Response = Response::try_from(&frame).expect("init response");
        if let Response::Init(r) = r {
            assert!(!r.supports_ctap1());
            assert!(r.supports_ctap2());
            assert!(r.supports_wink());
        } else {
            panic!("bad response");
        }

        // Nitrokey U2F Plug-up
        let d: [u8; 64] = [
            0xff, 0xff, 0xff, 0xff, // CID
            0x86, // Command
            0x00, 0x11, // Length
            // InitResponse
            0x52, 0x49, 0x4a, 0x8a, 0x40, 0x46, 0xb9, 0xe4, // nonce
            0xbe, 0x31, 0x2d, 0x40, // CID
            0x02, // Protocol version
            0x01, 0x06, 0x07, // Device version
            0x00, // Capabilities
            // Padding
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let frame: U2FHIDFrame = <U2FHIDFrame>::try_from(&d).expect("init frame");
        let r: Response = Response::try_from(&frame).expect("init response");
        if let Response::Init(r) = r {
            assert!(r.supports_ctap1());
            assert!(!r.supports_ctap2());
            assert!(!r.supports_wink());
        } else {
            panic!("bad response");
        }
    }

    #[test]
    fn error() {
        let d: [u8; 64] = [
            0x6f, 0xdf, 0x43, 0x22, // CID
            0xbf, // Command
            0x00, 0x01, // Length
            0x01, // Error
            // Padding
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let frame: U2FHIDFrame = <U2FHIDFrame>::try_from(&d).expect("error frame");
        assert_eq!(frame.cid, 0x6fdf4322);
        assert_eq!(frame.len, 1);

        let r: Response = Response::try_from(&frame).expect("error response");
        assert_eq!(r, Response::Error(U2FError::InvalidCommand));
    }

    #[test]
    fn get_info() {
        let _ = tracing_subscriber::fmt().try_init();
        let d: [[u8; 64]; 4] = [
            [
                0x6f, 0x1c, 0xc9, 0xca, 0x90, 0x00, 0xc5, 0x00, 0xac, 0x01, 0x82, 0x68, 0x46, 0x49,
                0x44, 0x4f, 0x5f, 0x32, 0x5f, 0x30, 0x6c, 0x46, 0x49, 0x44, 0x4f, 0x5f, 0x32, 0x5f,
                0x31, 0x5f, 0x50, 0x52, 0x45, 0x02, 0x82, 0x6b, 0x63, 0x72, 0x65, 0x64, 0x50, 0x72,
                0x6f, 0x74, 0x65, 0x63, 0x74, 0x6b, 0x68, 0x6d, 0x61, 0x63, 0x2d, 0x73, 0x65, 0x63,
                0x72, 0x65, 0x74, 0x03, 0x50, 0x14, 0x9a, 0x20,
            ],
            [
                0x6f, 0x1c, 0xc9, 0xca, 0x00, 0x21, 0x8e, 0xf6, 0x41, 0x33, 0x96, 0xb8, 0x81, 0xf8,
                0xd5, 0xb7, 0xf1, 0xf5, 0x04, 0xa5, 0x62, 0x72, 0x6b, 0xf5, 0x62, 0x75, 0x70, 0xf5,
                0x64, 0x70, 0x6c, 0x61, 0x74, 0xf4, 0x69, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x50,
                0x69, 0x6e, 0xf5, 0x75, 0x63, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c,
                0x4d, 0x67, 0x6d, 0x74, 0x50, 0x72, 0x65, 0x76,
            ],
            [
                0x6f, 0x1c, 0xc9, 0xca, 0x01, 0x69, 0x65, 0x77, 0xf5, 0x05, 0x19, 0x04, 0xb0, 0x06,
                0x82, 0x02, 0x01, 0x07, 0x08, 0x08, 0x18, 0x80, 0x09, 0x82, 0x63, 0x6e, 0x66, 0x63,
                0x63, 0x75, 0x73, 0x62, 0x0a, 0x82, 0xa2, 0x63, 0x61, 0x6c, 0x67, 0x26, 0x64, 0x74,
                0x79, 0x70, 0x65, 0x6a, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x2d, 0x6b, 0x65, 0x79,
                0xa2, 0x63, 0x61, 0x6c, 0x67, 0x27, 0x64, 0x74,
            ],
            [
                0x6f, 0x1c, 0xc9, 0xca, 0x02, 0x79, 0x70, 0x65, 0x6a, 0x70, 0x75, 0x62, 0x6c, 0x69,
                0x63, 0x2d, 0x6b, 0x65, 0x79, 0x0d, 0x04, 0x0e, 0x1a, 0x00, 0x05, 0x04, 0x03, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
        ];

        let frames: Vec<U2FHIDFrame> = d
            .iter()
            .map(<U2FHIDFrame>::try_from)
            .collect::<Result<Vec<U2FHIDFrame>, WebauthnCError>>()
            .unwrap();

        let frame: U2FHIDFrame = frames.iter().sum();
        let r: Response = Response::try_from(&frame).expect("init response");
        let r = if let Response::Cbor(r) = r {
            r
        } else {
            panic!("expected Response::Cbor");
        };

        let a: GetInfoResponse = CBORResponse::try_from(&r.data).expect("failed to decode message");

        // Assert the content
        // info!(?a);

        assert!(a.versions.len() == 2);
        assert!(a.versions.contains("FIDO_2_0"));
        assert!(a.versions.contains("FIDO_2_1_PRE"));

        assert!(a.extensions == Some(vec!["credProtect".to_string(), "hmac-secret".to_string()]));
        assert_eq!(
            a.aaguid,
            Some(uuid!("149a2021-8ef6-4133-96b8-81f8d5b7f1f5"))
        );

        let m = a.options.as_ref().unwrap();
        assert!(m.len() == 5);
        assert!(m.get("clientPin") == Some(&true));
        assert!(m.get("credentialMgmtPreview") == Some(&true));
        assert!(m.get("plat") == Some(&false));
        assert!(m.get("rk") == Some(&true));
        assert!(m.get("up") == Some(&true));

        assert!(a.max_msg_size == Some(1200));
        assert!(a.max_cred_count_in_list == Some(8));
        assert!(a.max_cred_id_len == Some(128));

        assert!(a.transports == Some(vec!["nfc".to_string(), "usb".to_string()]));
    }
}

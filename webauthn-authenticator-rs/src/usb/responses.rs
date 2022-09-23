//! All [Response] frame types, used by FIDO tokens over USB HID.
use crate::error::WebauthnCError;
use crate::transport::iso7816::ISO7816ResponseAPDU;
use crate::usb::framing::U2FHIDFrame;
use crate::usb::*;

/// Response type [U2FHID_INIT]
#[derive(Debug, PartialEq, Eq)]
pub struct InitResponse {
    pub nonce: Vec<u8>,
    /// Allocated channel identifier
    pub cid: u32,
    /// U2F protocol version (2)
    protocol_version: u8,
    device_version_major: u8,
    device_version_minor: u8,
    device_version_build: u8,
    capabilities: u8,
}

impl InitResponse {
    /// `true` if the device suports CTAPv1 / U2F protocol
    pub fn supports_ctap1(&self) -> bool {
        self.capabilities & CAPABILITY_NMSG == 0
    }

    /// `true` if the device suports CTAPv2 / CBOR protocol
    pub fn supports_ctap2(&self) -> bool {
        self.capabilities & CAPABILITY_CBOR > 0
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

/// CTAPv2 CBOR message
#[derive(Debug, PartialEq, Eq)]
pub struct CBORResponse {
    /// Status code
    pub status: u8,
    /// Data payload
    pub data: Vec<u8>,
}

impl TryFrom<&[u8]> for CBORResponse {
    type Error = WebauthnCError;
    fn try_from(d: &[u8]) -> Result<Self, Self::Error> {
        if d.is_empty() {
            return Err(WebauthnCError::MessageTooShort);
        }
        Ok(Self {
            status: d[0],
            data: d[1..].to_vec(),
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum U2FError {
    None,
    InvalidCommand,
    InvalidParameter,
    InvalidMessageLength,
    InvalidMessageSequencing,
    MessageTimeout,
    ChannelBusy,
    ChannelRequiresLock,
    SyncCommandFailed,
    Unspecified,
    Unknown,
}

impl From<u8> for U2FError {
    fn from(v: u8) -> Self {
        match v {
            0x00 => U2FError::None,
            0x01 => U2FError::InvalidCommand,
            0x02 => U2FError::InvalidParameter,
            0x03 => U2FError::InvalidMessageLength,
            0x04 => U2FError::InvalidMessageSequencing,
            0x05 => U2FError::MessageTimeout,
            0x06 => U2FError::ChannelBusy,
            0x0a => U2FError::ChannelRequiresLock,
            0x0b => U2FError::SyncCommandFailed,
            0x7f => U2FError::Unspecified,
            _ => U2FError::Unknown,
        }
    }
}

impl From<&[u8]> for U2FError {
    fn from(d: &[u8]) -> Self {
        if !d.is_empty() {
            U2FError::from(d[0])
        } else {
            U2FError::Unknown
        }
    }
}

/// Type for parsing all responses from a FIDO token.
#[derive(Debug, PartialEq, Eq)]
pub enum Response {
    Init(InitResponse),
    Msg(ISO7816ResponseAPDU),
    Cbor(CBORResponse),
    Error(U2FError),
    Unknown,
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
            U2FHID_MSG => ISO7816ResponseAPDU::try_from(b).map(Response::Msg)?,
            U2FHID_CBOR => CBORResponse::try_from(b).map(Response::Cbor)?,
            U2FHID_ERROR => Response::Error(U2FError::from(b)),
            _ => Response::Unknown,
        })
    }
}

#[allow(clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;

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
            .map(|f| <U2FHIDFrame>::try_from(f))
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
        assert!(
            a.aaguid
                == vec![20, 154, 32, 33, 142, 246, 65, 51, 150, 184, 129, 248, 213, 183, 241, 245]
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

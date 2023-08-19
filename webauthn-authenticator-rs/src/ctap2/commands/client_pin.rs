#[cfg(doc)]
use crate::stubs::*;

use bitflags::bitflags;
use serde::{Deserialize, Serialize};
use serde_cbor_2::Value;
use webauthn_rs_core::proto::{COSEEC2Key, COSEKey, COSEKeyType, COSEKeyTypeId, ECDSACurve};
use webauthn_rs_proto::COSEAlgorithm;

use self::CBORCommand;
use super::*;

/// `authenticatorclientPin` request type.
///
/// See:
///
/// * [ClientPinSubCommand] for command types
/// * `crate::ctap2::pin_uv` constructs this command
///
/// Reference: <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authnrClientPin-cmd-dfn>
#[derive(Serialize, Debug, Clone, Default, PartialEq, Eq)]
#[serde(into = "BTreeMap<u32, Value>")]
pub struct ClientPinRequest {
    /// PIN / UV protocol version chosen by the platform
    pub pin_uv_protocol: Option<u32>,
    /// Action being requested
    pub sub_command: ClientPinSubCommand,
    /// The platform-agreement key
    pub key_agreement: Option<COSEKey>,
    /// Output of calling "Authenticate" on some context specific to
    /// [sub_command][Self::sub_command]
    pub pin_uv_auth_param: Option<Vec<u8>>,
    /// An encrypted PIN
    pub new_pin_enc: Option<Vec<u8>>,
    /// An encrypted proof-of-knowledge of a PIN
    pub pin_hash_enc: Option<Vec<u8>>,
    /// Permissions bitfield for
    /// [GetPinUvAuthTokenUsingUvWithPermissions][ClientPinSubCommand::GetPinUvAuthTokenUsingUvWithPermissions]
    /// and
    /// [GetPinUvAuthTokenUsingPinWithPermissions][ClientPinSubCommand::GetPinUvAuthTokenUsingPinWithPermissions].
    ///
    /// Field is omitted if `0`.
    pub permissions: Permissions,
    /// The RP ID to assign as the permissions RP ID
    pub rp_id: Option<String>,
}

/// [ClientPinRequest::sub_command] type code
///
/// Reference: <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authnrClientPin-cmd-dfn>
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum ClientPinSubCommand {
    #[default]
    GetPinRetries = 0x01,
    GetKeyAgreement = 0x02,
    SetPin = 0x03,
    ChangePin = 0x04,
    GetPinToken = 0x05,
    GetPinUvAuthTokenUsingUvWithPermissions = 0x06,
    GetUvRetries = 0x07,
    GetPinUvAuthTokenUsingPinWithPermissions = 0x09,
}

bitflags! {
    /// Permissions bitfield for
    /// [GetPinUvAuthTokenUsingUvWithPermissions][ClientPinSubCommand::GetPinUvAuthTokenUsingUvWithPermissions]
    /// and
    /// [GetPinUvAuthTokenUsingPinWithPermissions][ClientPinSubCommand::GetPinUvAuthTokenUsingPinWithPermissions].
    ///
    /// Reference: <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#gettingPinUvAuthToken>
    #[derive(Default)]
    pub struct Permissions: u8 {
        const MAKE_CREDENTIAL = 0x01;
        const GET_ASSERTION = 0x02;
        const CREDENTIAL_MANAGEMENT = 0x04;
        const BIO_ENROLLMENT = 0x08;
        const LARGE_BLOB_WRITE = 0x10;
        const AUTHENTICATOR_CONFIGURATION = 0x20;
    }
}

impl CBORCommand for ClientPinRequest {
    const CMD: u8 = 0x06;
    type Response = ClientPinResponse;
}

/// `authenticatorClientPin` response type.
#[derive(Deserialize, Debug, Default, PartialEq, Eq)]
#[serde(try_from = "BTreeMap<u32, Value>")]
pub struct ClientPinResponse {
    /// The result of the authenticator calling `getPublicKey`, which can be
    /// used to encapsulate encrypted payloads between the authenticator and
    /// platform.
    pub key_agreement: Option<COSEKey>,
    /// The `pinUvAuthToken`, encrypted with the shared secret.
    pub pin_uv_auth_token: Option<Vec<u8>>,
    /// Number of PIN attempts remaining until lock-out.
    pub pin_retries: Option<u32>,
    /// If present and `true`, the authenticator requires a power cycle before
    /// any future pin operation.
    ///
    /// Only included in response to [ClientPinSubCommand::GetPinRetries].
    pub power_cycle_state: Option<bool>,
    /// Number of UV attempts remaining until lock-out.
    pub uv_retries: Option<u32>,
}

impl From<ClientPinRequest> for BTreeMap<u32, Value> {
    fn from(value: ClientPinRequest) -> Self {
        let ClientPinRequest {
            pin_uv_protocol,
            sub_command,
            key_agreement,
            pin_uv_auth_param,
            new_pin_enc,
            pin_hash_enc,
            permissions,
            rp_id,
        } = value;

        let mut keys = BTreeMap::new();

        if let Some(v) = pin_uv_protocol {
            keys.insert(0x01, Value::Integer(v.into()));
        }
        keys.insert(0x02, Value::Integer((sub_command as u32).into()));
        if let Some(v) = key_agreement {
            if let COSEKeyType::EC_EC2(e) = v.key {
                // This uses the special type of COSE key for PinUvToken
                let m = BTreeMap::from([
                    (Value::Integer(1), Value::Integer(2)),    // kty
                    (Value::Integer(3), Value::Integer(-25)),  // alg
                    (Value::Integer(-1), Value::Integer(1)),   // crv
                    (Value::Integer(-2), Value::Bytes(e.x.0)), // x
                    (Value::Integer(-3), Value::Bytes(e.y.0)), // y
                ]);

                keys.insert(0x03, Value::Map(m));
            }
        }
        if let Some(v) = pin_uv_auth_param {
            keys.insert(0x04, Value::Bytes(v));
        }
        if let Some(v) = new_pin_enc {
            keys.insert(0x05, Value::Bytes(v));
        }
        if let Some(v) = pin_hash_enc {
            keys.insert(0x06, Value::Bytes(v));
        }
        if !permissions.is_empty() {
            keys.insert(0x09, Value::Integer(permissions.bits().into()));
        }
        if let Some(v) = rp_id {
            keys.insert(0x0a, Value::Text(v));
        }

        keys
    }
}

impl TryFrom<BTreeMap<u32, Value>> for ClientPinResponse {
    type Error = &'static str;
    fn try_from(mut raw: BTreeMap<u32, Value>) -> Result<Self, Self::Error> {
        trace!(?raw);
        Ok(Self {
            key_agreement: raw
                .remove(&0x01)
                .and_then(|v| if let Value::Map(m) = v { Some(m) } else { None })
                .and_then(|mut m| {
                    // Reference: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#pinProto1
                    //
                    // Result of the authenticator calling `getPublicKey()`. This is a `COSE_Key` with some specific,
                    // but partially incorrect values, so we need to deserialise it specially:
                    //
                    //  1 (kty) = 2 (EC2)
                    //  3 (alg) = -25 (not the algorithm actually used)
                    // -1 (crv) = 1 (P-256)
                    if m.remove(&Value::Integer(1))
                        != Some(Value::Integer(COSEKeyTypeId::EC_EC2 as i128))
                        || m.remove(&Value::Integer(3)) != Some(Value::Integer(-25))
                        || m.remove(&Value::Integer(-1))
                            != Some(Value::Integer(ECDSACurve::SECP256R1 as i128))
                    {
                        return None;
                    }

                    // -2 (x) = 32 byte big-endian encoding of the x-coordinate of xB
                    // -3 (y) = 32 byte big-endian encoding of the y-coordinate of xB
                    let x = m
                        .remove(&Value::Integer(-2))
                        .and_then(|v| value_to_vec_u8(v, "-2"))?;
                    let y = m
                        .remove(&Value::Integer(-3))
                        .and_then(|v| value_to_vec_u8(v, "-3"))?;
                    if x.len() != 32 || y.len() != 32 {
                        return None;
                    }

                    Some(COSEKey {
                        type_: COSEAlgorithm::PinUvProtocol,
                        key: COSEKeyType::EC_EC2(COSEEC2Key {
                            curve: ECDSACurve::SECP256R1,
                            x: x.to_vec().into(),
                            y: y.to_vec().into(),
                        }),
                    })
                }),
            pin_uv_auth_token: raw.remove(&0x02).and_then(|v| value_to_vec_u8(v, "0x02")),
            pin_retries: raw.remove(&0x03).and_then(|v| value_to_u32(&v, "0x03")),
            power_cycle_state: raw.remove(&0x04).and_then(|v| value_to_bool(&v, "0x04")),
            uv_retries: raw.remove(&0x05).and_then(|v| value_to_u32(&v, "0x05")),
        })
    }
}

crate::deserialize_cbor!(ClientPinResponse);

#[cfg(test)]
mod tests {
    use base64urlsafedata::Base64UrlSafeData;

    use super::*;
    #[test]
    fn get_pin_retries() {
        let c = ClientPinRequest {
            pin_uv_protocol: Some(1),
            sub_command: ClientPinSubCommand::GetPinRetries,
            ..Default::default()
        };

        // FIDO protocol requires definite length parameters
        assert_eq!(
            vec![0x06, (5 << 5) | 2, 1, 1, 2, 1],
            c.cbor().expect("encode error")
        );

        let r = vec![0xa1, 0x03, 0x08];
        let a = <ClientPinResponse as CBORResponse>::try_from(r.as_slice())
            .expect("Failed to decode message");

        assert_eq!(
            ClientPinResponse {
                pin_retries: Some(8),
                ..Default::default()
            },
            a
        );
    }

    #[test]
    fn get_key_agreement() {
        let c = ClientPinRequest {
            pin_uv_protocol: Some(2),
            sub_command: ClientPinSubCommand::GetKeyAgreement,
            ..Default::default()
        };

        assert_eq!(
            vec![0x06, (5 << 5) | 2, 1, 2, 2, 2],
            c.cbor().expect("encode error")
        );

        let r = vec![
            0xa1, 0x01, 0xa5, 0x01, 0x02, 0x03, 0x38, 0x18, 0x20, 0x01, 0x21, 0x58, 0x20, 0x74,
            0xf4, 0x6b, 0xdc, 0x1c, 0x60, 0xac, 0xcc, 0xbb, 0xf3, 0x9a, 0x37, 0xe4, 0xcc, 0x9e,
            0xac, 0x80, 0xf0, 0x01, 0x66, 0x27, 0xc7, 0xb6, 0x17, 0x44, 0x55, 0xb4, 0x4f, 0xe0,
            0x4a, 0xc4, 0x70, 0x22, 0x58, 0x20, 0x38, 0xe6, 0xd6, 0xf1, 0x8d, 0xaa, 0x1f, 0x26,
            0x9f, 0x3a, 0x95, 0xd1, 0x89, 0x34, 0xab, 0x72, 0x60, 0xe3, 0xd9, 0x50, 0x6a, 0x90,
            0xe6, 0x8a, 0xc8, 0x35, 0xb4, 0x9f, 0xbe, 0xc4, 0x51, 0x21,
        ];
        let a = <ClientPinResponse as CBORResponse>::try_from(r.as_slice())
            .expect("Failed to decode message");

        assert_eq!(
            ClientPinResponse {
                key_agreement: Some(COSEKey {
                    type_: COSEAlgorithm::PinUvProtocol,
                    key: COSEKeyType::EC_EC2(COSEEC2Key {
                        curve: ECDSACurve::SECP256R1,
                        x: Base64UrlSafeData(vec![
                            0x74, 0xf4, 0x6b, 0xdc, 0x1c, 0x60, 0xac, 0xcc, 0xbb, 0xf3, 0x9a, 0x37,
                            0xe4, 0xcc, 0x9e, 0xac, 0x80, 0xf0, 0x01, 0x66, 0x27, 0xc7, 0xb6, 0x17,
                            0x44, 0x55, 0xb4, 0x4f, 0xe0, 0x4a, 0xc4, 0x70
                        ]),
                        y: Base64UrlSafeData(vec![
                            0x38, 0xe6, 0xd6, 0xf1, 0x8d, 0xaa, 0x1f, 0x26, 0x9f, 0x3a, 0x95, 0xd1,
                            0x89, 0x34, 0xab, 0x72, 0x60, 0xe3, 0xd9, 0x50, 0x6a, 0x90, 0xe6, 0x8a,
                            0xc8, 0x35, 0xb4, 0x9f, 0xbe, 0xc4, 0x51, 0x21
                        ]),
                    }),
                }),
                ..Default::default()
            },
            a,
        );
    }

    #[test]
    fn get_pin_token() {
        let c = ClientPinRequest {
            pin_uv_protocol: Some(2),
            sub_command: ClientPinSubCommand::GetPinToken,
            key_agreement: Some(COSEKey {
                type_: COSEAlgorithm::PinUvProtocol,
                key: COSEKeyType::EC_EC2(COSEEC2Key {
                    curve: ECDSACurve::SECP256R1,
                    x: Base64UrlSafeData(vec![
                        0x76, 0xa8, 0x64, 0x59, 0xf0, 0x2a, 0xa9, 0xa7, 0x87, 0x86, 0x21, 0x26,
                        0x45, 0x6a, 0xcb, 0x6d, 0xe0, 0x7d, 0x81, 0x4b, 0x34, 0x1c, 0x10, 0xbe,
                        0xee, 0x85, 0x8c, 0x09, 0x1d, 0x0c, 0xc4, 0xde,
                    ]),
                    y: Base64UrlSafeData(vec![
                        0xc9, 0xf5, 0x4d, 0x23, 0x4b, 0x33, 0x97, 0xdc, 0x86, 0xa4, 0x32, 0x44,
                        0x92, 0x0e, 0xe0, 0xfc, 0xd8, 0x81, 0x89, 0xd7, 0x58, 0xdc, 0x73, 0x92,
                        0xad, 0xf8, 0x51, 0x28, 0xdf, 0x22, 0x14, 0x25,
                    ]),
                }),
            }),
            pin_hash_enc: Some(vec![
                0x27, 0x5e, 0xbb, 0x6d, 0x9b, 0x29, 0xbf, 0x25, 0x77, 0xed, 0x9f, 0xfc, 0x99, 0xae,
                0x4f, 0x29, 0xba, 0x98, 0xa4, 0x0b, 0xc7, 0x32, 0x66, 0x2a, 0xcc, 0x25, 0xa3, 0x40,
                0x3d, 0xfa, 0x79, 0x79,
            ]),
            ..Default::default()
        };

        assert_eq!(
            vec![
                0x06, 0xa4, 0x01, 0x02, 0x02, 0x05, 0x03, 0xa5, 0x01, 0x02, 0x03, 0x38, 0x18, 0x20,
                0x01, 0x21, 0x58, 0x20, 0x76, 0xa8, 0x64, 0x59, 0xf0, 0x2a, 0xa9, 0xa7, 0x87, 0x86,
                0x21, 0x26, 0x45, 0x6a, 0xcb, 0x6d, 0xe0, 0x7d, 0x81, 0x4b, 0x34, 0x1c, 0x10, 0xbe,
                0xee, 0x85, 0x8c, 0x09, 0x1d, 0x0c, 0xc4, 0xde, 0x22, 0x58, 0x20, 0xc9, 0xf5, 0x4d,
                0x23, 0x4b, 0x33, 0x97, 0xdc, 0x86, 0xa4, 0x32, 0x44, 0x92, 0x0e, 0xe0, 0xfc, 0xd8,
                0x81, 0x89, 0xd7, 0x58, 0xdc, 0x73, 0x92, 0xad, 0xf8, 0x51, 0x28, 0xdf, 0x22, 0x14,
                0x25, 0x06, 0x58, 0x20, 0x27, 0x5e, 0xbb, 0x6d, 0x9b, 0x29, 0xbf, 0x25, 0x77, 0xed,
                0x9f, 0xfc, 0x99, 0xae, 0x4f, 0x29, 0xba, 0x98, 0xa4, 0x0b, 0xc7, 0x32, 0x66, 0x2a,
                0xcc, 0x25, 0xa3, 0x40, 0x3d, 0xfa, 0x79, 0x79
            ],
            c.cbor().expect("encode error")
        );

        let r = vec![
            0xa1, 0x02, 0x58, 0x30, 0xf2, 0xbd, 0x74, 0x05, 0xff, 0x54, 0xa5, 0x2e, 0xa4, 0x49,
            0xdd, 0x82, 0x19, 0x9e, 0x1b, 0x76, 0x25, 0x86, 0x0a, 0x5a, 0xfd, 0x09, 0x1e, 0xed,
            0xe3, 0x0a, 0x3f, 0x76, 0x34, 0x38, 0x5e, 0xf3, 0x51, 0x40, 0x51, 0xf3, 0x91, 0xe6,
            0x7f, 0x1a, 0x69, 0x45, 0xa9, 0x49, 0x2f, 0x1f, 0xc6, 0xc3,
        ];
        let a = <ClientPinResponse as CBORResponse>::try_from(r.as_slice())
            .expect("Failed to decode message");

        assert_eq!(
            ClientPinResponse {
                pin_uv_auth_token: Some(vec![
                    0xf2, 0xbd, 0x74, 0x05, 0xff, 0x54, 0xa5, 0x2e, 0xa4, 0x49, 0xdd, 0x82, 0x19,
                    0x9e, 0x1b, 0x76, 0x25, 0x86, 0x0a, 0x5a, 0xfd, 0x09, 0x1e, 0xed, 0xe3, 0x0a,
                    0x3f, 0x76, 0x34, 0x38, 0x5e, 0xf3, 0x51, 0x40, 0x51, 0xf3, 0x91, 0xe6, 0x7f,
                    0x1a, 0x69, 0x45, 0xa9, 0x49, 0x2f, 0x1f, 0xc6, 0xc3
                ]),
                ..Default::default()
            },
            a
        )
    }

    #[test]
    fn get_pin_uv_auth_token_using_uv_with_permissions() {
        let c = ClientPinRequest {
            pin_uv_protocol: Some(2),
            sub_command: ClientPinSubCommand::GetPinUvAuthTokenUsingUvWithPermissions,
            key_agreement: Some(COSEKey {
                type_: COSEAlgorithm::PinUvProtocol,
                key: COSEKeyType::EC_EC2(COSEEC2Key {
                    curve: ECDSACurve::SECP256R1,
                    x: Base64UrlSafeData(vec![
                        0x18, 0x6d, 0x9d, 0x21, 0xad, 0xbe, 0x1b, 0xb0, 0x46, 0xac, 0xa9, 0x64,
                        0xdf, 0x27, 0x58, 0xd7, 0xcb, 0xdc, 0x62, 0xb0, 0x4e, 0xe6, 0x34, 0xc5,
                        0xb8, 0x12, 0xa7, 0x89, 0xd9, 0x40, 0xd9, 0xde,
                    ]),
                    y: Base64UrlSafeData(vec![
                        0xfe, 0xd8, 0xf2, 0x72, 0x6f, 0x89, 0x21, 0xe2, 0xae, 0x68, 0xfe, 0x89,
                        0x66, 0x1c, 0x01, 0x6c, 0x5d, 0x0d, 0x8e, 0xd0, 0x4a, 0xe2, 0x7a, 0xd1,
                        0x1d, 0xfe, 0x49, 0xc8, 0xff, 0x7c, 0xc8, 0x7c,
                    ]),
                }),
            }),
            permissions: Permissions::GET_ASSERTION,
            rp_id: Some("localhost".to_string()),
            ..Default::default()
        };

        assert_eq!(
            vec![
                0x06, 0xa5, 0x01, 0x02, 0x02, 0x06, 0x03, 0xa5, 0x01, 0x02, 0x03, 0x38, 0x18, 0x20,
                0x01, 0x21, 0x58, 0x20, 0x18, 0x6d, 0x9d, 0x21, 0xad, 0xbe, 0x1b, 0xb0, 0x46, 0xac,
                0xa9, 0x64, 0xdf, 0x27, 0x58, 0xd7, 0xcb, 0xdc, 0x62, 0xb0, 0x4e, 0xe6, 0x34, 0xc5,
                0xb8, 0x12, 0xa7, 0x89, 0xd9, 0x40, 0xd9, 0xde, 0x22, 0x58, 0x20, 0xfe, 0xd8, 0xf2,
                0x72, 0x6f, 0x89, 0x21, 0xe2, 0xae, 0x68, 0xfe, 0x89, 0x66, 0x1c, 0x01, 0x6c, 0x5d,
                0x0d, 0x8e, 0xd0, 0x4a, 0xe2, 0x7a, 0xd1, 0x1d, 0xfe, 0x49, 0xc8, 0xff, 0x7c, 0xc8,
                0x7c, 0x09, 0x02, 0x0a, 0x69, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74
            ],
            c.cbor().expect("encode error")
        );

        // Response tested in get_pin_token
    }

    #[test]
    fn set_pin() {
        let c = ClientPinRequest {
            pin_uv_protocol: Some(2),
            sub_command: ClientPinSubCommand::SetPin,
            key_agreement: Some(COSEKey {
                type_: COSEAlgorithm::PinUvProtocol,
                key: COSEKeyType::EC_EC2(COSEEC2Key {
                    curve: ECDSACurve::SECP256R1,
                    x: Base64UrlSafeData(vec![
                        0x31, 0xe2, 0x7d, 0x95, 0xcd, 0x62, 0x93, 0x71, 0xf3, 0x26, 0x94, 0x8b,
                        0xbe, 0xe0, 0xd9, 0x7c, 0xdd, 0x6c, 0x39, 0xb9, 0x9e, 0x58, 0x3c, 0x40,
                        0x6d, 0x1f, 0xee, 0x60, 0xb1, 0x8f, 0xdc, 0xfd,
                    ]),
                    y: Base64UrlSafeData(vec![
                        0xc0, 0xec, 0xb0, 0xae, 0x0b, 0xfc, 0xa8, 0xf6, 0x11, 0x42, 0x96, 0x4f,
                        0x56, 0xaa, 0x61, 0x7c, 0x74, 0xc5, 0x1e, 0x31, 0xf6, 0x79, 0x40, 0xd1,
                        0xb4, 0x55, 0x75, 0x20, 0xd0, 0xf1, 0xa4, 0xf7,
                    ]),
                }),
            }),
            pin_uv_auth_param: Some(vec![
                0x4c, 0xea, 0xbd, 0x24, 0x07, 0x61, 0xaf, 0xca, 0xf6, 0x80, 0x8c, 0x5c, 0x03, 0x93,
                0x76, 0x3f, 0xdc, 0x90, 0x04, 0x9c, 0x1f, 0xef, 0x09, 0x18, 0x43, 0x80, 0x43, 0x5e,
                0x18, 0xe1, 0xc0, 0x5e,
            ]),
            new_pin_enc: Some(vec![
                0x66, 0x7c, 0xd5, 0xa6, 0x74, 0x8e, 0x51, 0xce, 0x8e, 0x98, 0x3a, 0x29, 0x98, 0x31,
                0x5e, 0x1d, 0xfb, 0x33, 0x25, 0xc3, 0x36, 0xb0, 0xb5, 0xd4, 0xa7, 0xc9, 0xaa, 0x10,
                0x28, 0x1a, 0xeb, 0xb4, 0xbf, 0x9c, 0xd4, 0x81, 0xf0, 0x67, 0x9c, 0x8b, 0x6d, 0x63,
                0x3a, 0x76, 0xa4, 0x69, 0x07, 0x8b, 0x96, 0x92, 0xc7, 0x41, 0xac, 0xaa, 0x4e, 0xef,
                0xc3, 0x82, 0xfe, 0x25, 0x90, 0x9a, 0x98, 0xf9, 0x2b, 0x02, 0x86, 0xfa, 0x2b, 0x53,
                0xd6, 0x6b, 0xda, 0xa8, 0xef, 0x1d, 0x90, 0x1f, 0x9f, 0x9d,
            ]),
            ..Default::default()
        };

        assert_eq!(
            vec![
                0x06, 0xa5, 0x01, 0x02, 0x02, 0x03, 0x03, 0xa5, 0x01, 0x02, 0x03, 0x38, 0x18, 0x20,
                0x01, 0x21, 0x58, 0x20, 0x31, 0xe2, 0x7d, 0x95, 0xcd, 0x62, 0x93, 0x71, 0xf3, 0x26,
                0x94, 0x8b, 0xbe, 0xe0, 0xd9, 0x7c, 0xdd, 0x6c, 0x39, 0xb9, 0x9e, 0x58, 0x3c, 0x40,
                0x6d, 0x1f, 0xee, 0x60, 0xb1, 0x8f, 0xdc, 0xfd, 0x22, 0x58, 0x20, 0xc0, 0xec, 0xb0,
                0xae, 0x0b, 0xfc, 0xa8, 0xf6, 0x11, 0x42, 0x96, 0x4f, 0x56, 0xaa, 0x61, 0x7c, 0x74,
                0xc5, 0x1e, 0x31, 0xf6, 0x79, 0x40, 0xd1, 0xb4, 0x55, 0x75, 0x20, 0xd0, 0xf1, 0xa4,
                0xf7, 0x04, 0x58, 0x20, 0x4c, 0xea, 0xbd, 0x24, 0x07, 0x61, 0xaf, 0xca, 0xf6, 0x80,
                0x8c, 0x5c, 0x03, 0x93, 0x76, 0x3f, 0xdc, 0x90, 0x04, 0x9c, 0x1f, 0xef, 0x09, 0x18,
                0x43, 0x80, 0x43, 0x5e, 0x18, 0xe1, 0xc0, 0x5e, 0x05, 0x58, 0x50, 0x66, 0x7c, 0xd5,
                0xa6, 0x74, 0x8e, 0x51, 0xce, 0x8e, 0x98, 0x3a, 0x29, 0x98, 0x31, 0x5e, 0x1d, 0xfb,
                0x33, 0x25, 0xc3, 0x36, 0xb0, 0xb5, 0xd4, 0xa7, 0xc9, 0xaa, 0x10, 0x28, 0x1a, 0xeb,
                0xb4, 0xbf, 0x9c, 0xd4, 0x81, 0xf0, 0x67, 0x9c, 0x8b, 0x6d, 0x63, 0x3a, 0x76, 0xa4,
                0x69, 0x07, 0x8b, 0x96, 0x92, 0xc7, 0x41, 0xac, 0xaa, 0x4e, 0xef, 0xc3, 0x82, 0xfe,
                0x25, 0x90, 0x9a, 0x98, 0xf9, 0x2b, 0x02, 0x86, 0xfa, 0x2b, 0x53, 0xd6, 0x6b, 0xda,
                0xa8, 0xef, 0x1d, 0x90, 0x1f, 0x9f, 0x9d
            ],
            c.cbor().expect("encode error")
        );

        // Successfully setting the pin returns an empty result
        assert_eq!(
            ClientPinResponse::default(),
            <ClientPinResponse as CBORResponse>::try_from(&[])
                .expect("deserialising empty response")
        );
    }
}

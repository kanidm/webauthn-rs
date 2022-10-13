use bitflags::bitflags;
use serde::{Deserialize, Serialize};
use serde_cbor::Value;
use webauthn_rs_core::proto::{COSEEC2Key, COSEKey, COSEKeyType, COSEKeyTypeId, ECDSACurve};
use webauthn_rs_proto::COSEAlgorithm;

use self::CBORCommand;
use super::*;

// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authnrClientPin-cmd-dfn
#[derive(Serialize, Debug, Clone, Default)]
#[serde(into = "BTreeMap<u32, Value>")]
pub struct ClientPinRequest {
    /// PIN / UV protocol version chosen by the platform
    pub pin_uv_protocol: Option<u32>,
    /// Action being requested
    pub sub_command: ClientPinSubCommand,
    pub key_agreement: Option<COSEKey>,
    /// OUtput of calling "Authenticate" on some context specific to [Self::sub_comand]
    pub pin_uv_auth_param: Option<Vec<u8>>,
    /// An encrypted PIN
    pub new_pin_enc: Option<Vec<u8>>,
    /// An encrypted proof-of-knowledge of a PIN
    pub pin_hash_enc: Option<Vec<u8>>,
    /// Permissions bitfield, omitted if 0.
    pub permissions: Permissions,
    /// The RP ID to assign as the permissions RP ID
    pub rp_id: Option<String>,
}

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
    GetPinUvAuthTokenUsingPinWithPermissions = 0x08,
}

bitflags! {
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
    const HAS_PAYLOAD: bool = true;
    type Response = ClientPinResponse;
}

#[derive(Deserialize, Debug, Default, PartialEq, Eq)]
#[serde(try_from = "BTreeMap<u32, Value>")]
pub struct ClientPinResponse {
    pub key_agreement: Option<COSEKey>,
    pub pin_uv_auth_token: Option<Vec<u8>>,
    pub pin_retries: Option<u32>,
    pub power_cycle_state: Option<bool>,
    pub uv_retries: Option<u32>,
}

// fn serialize_struct_as_map( breaks length- it's always indefinite :(

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
                    // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#pinProto1
                    if m.remove(&Value::Integer(1))
                        != Some(Value::Integer(COSEKeyTypeId::EC_EC2 as i128))
                        || m.remove(&Value::Integer(3)) != Some(Value::Integer(-25))
                        || m.remove(&Value::Integer(-1))
                            != Some(Value::Integer(ECDSACurve::SECP256R1 as i128))
                    {
                        return None;
                    }

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
            power_cycle_state: raw.remove(&0x04).and_then(|v| value_to_bool(v, "0x04")),
            uv_retries: raw.remove(&0x05).and_then(|v| value_to_u32(&v, "0x05")),
        })
    }
}

crate::deserialize_cbor!(ClientPinResponse);

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn get_pin_retries() {
        let c = ClientPinRequest {
            pin_uv_protocol: Some(1),
            sub_command: ClientPinSubCommand::GetPinRetries,
            ..Default::default()
        };

        // NB: FIDO protocol requires definite length parameters
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
}

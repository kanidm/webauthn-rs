use base64urlsafedata::Base64UrlSafeData;
use serde::{Deserialize, Serialize};
use serde_cbor_2::Value;
use std::{collections::BTreeMap, str::FromStr};
use webauthn_rs_proto::{AllowCredentials, AuthenticatorTransport, PublicKeyCredentialDescriptor};

use crate::ctap2::commands::{value_to_map, value_to_vec, value_to_vec_string};

use super::{
    value_to_bool, value_to_set_string, value_to_string, value_to_u32, value_to_vec_u8, CBORCommand,
};

/// `authenticatorGetAssertion` request type.
///
/// Reference: <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorGetAssertion>
#[derive(Serialize, Debug, Clone)]
#[serde(into = "BTreeMap<u32, Value>", try_from = "BTreeMap<u32, Value>")]
pub struct GetAssertionRequest {
    pub rp_id: String,
    pub client_data_hash: Vec<u8>,
    pub allow_list: Vec<AllowCredentials>,
    // TODO: extensions
    pub options: Option<BTreeMap<String, bool>>,
    pub pin_uv_auth_param: Option<Vec<u8>>,
    pub pin_uv_auth_proto: Option<u32>,
}

impl CBORCommand for GetAssertionRequest {
    const CMD: u8 = 0x02;
    type Response = GetAssertionResponse;
}

/// `authenticatorGetAssertion` response type.
///
/// Reference: <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorgetassertion-response-structure>
// Note: this needs to have the same names as AttestationObjectInner
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct GetAssertionResponse {
    pub credential: Option<PublicKeyCredentialDescriptor>,
    pub auth_data: Option<Vec<u8>>,
    pub signature: Option<Vec<u8>>,
    // TODO: pub user: Option<User>,
    pub number_of_credentials: Option<u32>,
    pub user_selected: Option<bool>,
    pub large_blob_key: Option<Vec<u8>>,
    // TODO: extensions
}

impl From<GetAssertionRequest> for BTreeMap<u32, Value> {
    fn from(r: GetAssertionRequest) -> Self {
        let GetAssertionRequest {
            rp_id,
            client_data_hash,
            allow_list,
            options,
            pin_uv_auth_param,
            pin_uv_auth_proto,
        } = r;

        let mut keys = BTreeMap::new();
        keys.insert(0x01, Value::Text(rp_id));
        keys.insert(0x02, Value::Bytes(client_data_hash));

        if !allow_list.is_empty() {
            keys.insert(
                0x03,
                Value::Array(
                    allow_list
                        .iter()
                        .map(|a| {
                            let mut m = BTreeMap::from([
                                (
                                    Value::Text("type".to_string()),
                                    Value::Text(a.type_.to_owned()),
                                ),
                                (
                                    Value::Text("id".to_string()),
                                    Value::Bytes(a.id.0.to_owned()),
                                ),
                            ]);

                            if let Some(transports) = &a.transports {
                                let transports: Vec<Value> = transports
                                    .iter()
                                    .map(|t| Value::Text(t.to_string()))
                                    .collect();

                                if !transports.is_empty() {
                                    m.insert(
                                        Value::Text("transports".to_string()),
                                        Value::Array(transports),
                                    );
                                }
                            }

                            Value::Map(m)
                        })
                        .collect(),
                ),
            );
        }
        // TODO: extensions
        if let Some(v) = options {
            keys.insert(
                0x05,
                Value::Map(BTreeMap::from_iter(
                    v.iter()
                        .map(|(k, o)| (Value::Text(k.to_owned()), Value::Bool(*o))),
                )),
            );
        }

        if let Some(v) = pin_uv_auth_param {
            keys.insert(0x06, Value::Bytes(v));
        }
        if let Some(v) = pin_uv_auth_proto {
            keys.insert(0x07, Value::Integer(v.into()));
        }

        keys
    }
}

impl TryFrom<BTreeMap<u32, Value>> for GetAssertionRequest {
    type Error = &'static str;
    fn try_from(mut raw: BTreeMap<u32, Value>) -> Result<Self, Self::Error> {
        trace!("raw: {:?}", raw);
        Ok(Self {
            rp_id: raw
                .remove(&0x01)
                .and_then(|v| value_to_string(v, "0x01"))
                .ok_or("parsing rpId")?,
            client_data_hash: raw
                .remove(&0x02)
                .and_then(|v| value_to_vec_u8(v, "0x02"))
                .ok_or("parsing clientDataHash")?,
            allow_list: raw
                .remove(&0x03)
                .and_then(|v| value_to_vec(v, "0x03"))
                .map(|v| {
                    v.into_iter()
                        .filter_map(|a| {
                            let mut a = value_to_map(a, "0x03")?;
                            let type_ = value_to_string(
                                a.remove(&Value::Text("type".to_string()))?,
                                "type",
                            )?;
                            let id = Base64UrlSafeData(value_to_vec_u8(
                                a.remove(&Value::Text("id".to_string()))?,
                                "id",
                            )?);
                            let transports = a
                                .remove(&Value::Text("transports".to_string()))
                                .and_then(|v| value_to_vec_string(v, "transports"))
                                .map(|v| {
                                    v.into_iter()
                                        .filter_map(|t| AuthenticatorTransport::from_str(&t).ok())
                                        .collect()
                                });
                            Some(AllowCredentials {
                                id,
                                type_,
                                transports,
                            })
                        })
                        .collect()
                })
                .unwrap_or_default(),
            // TODO
            options: None,
            pin_uv_auth_param: None,
            pin_uv_auth_proto: None,
        })
    }
}

impl From<GetAssertionResponse> for BTreeMap<u32, Value> {
    fn from(r: GetAssertionResponse) -> Self {
        let GetAssertionResponse {
            credential,
            auth_data,
            signature,
            number_of_credentials,
            user_selected,
            large_blob_key,
        } = r;

        let mut keys = BTreeMap::new();
        if let Some(credential) = credential {
            let mut m = BTreeMap::from([
                (Value::Text("id".to_string()), Value::Bytes(credential.id.0)),
                (
                    Value::Text("type".to_string()),
                    Value::Text(credential.type_),
                ),
            ]);
            if let Some(transports) = credential.transports {
                let transports = transports
                    .into_iter()
                    .map(|t| Value::Text(t.to_string()))
                    .collect();
                m.insert(
                    Value::Text("transports".to_string()),
                    Value::Array(transports),
                );
            };
            keys.insert(0x01, Value::Map(m));
        }
        if let Some(auth_data) = auth_data {
            keys.insert(0x02, Value::Bytes(auth_data));
        }
        if let Some(signature) = signature {
            keys.insert(0x03, Value::Bytes(signature));
        }
        if let Some(number_of_credentials) = number_of_credentials {
            keys.insert(0x05, Value::Integer(number_of_credentials.into()));
        }
        if let Some(user_selected) = user_selected {
            keys.insert(0x06, Value::Bool(user_selected));
        }
        if let Some(large_blob_key) = large_blob_key {
            keys.insert(0x07, Value::Bytes(large_blob_key));
        }

        keys
    }
}

impl TryFrom<BTreeMap<u32, Value>> for GetAssertionResponse {
    type Error = &'static str;
    fn try_from(mut raw: BTreeMap<u32, Value>) -> Result<Self, Self::Error> {
        trace!(?raw);
        Ok(Self {
            credential: raw.remove(&0x01).and_then(|v| {
                if let Value::Map(mut v) = v {
                    let id = v
                        .remove(&Value::Text("id".to_string()))
                        .and_then(|v| value_to_vec_u8(v, "0x01.id"))
                        .map(Base64UrlSafeData);
                    let type_ = v
                        .remove(&Value::Text("type".to_string()))
                        .and_then(|v| value_to_string(v, "0x01.type"));

                    let transports: Option<Vec<AuthenticatorTransport>> = v
                        .remove(&Value::Text("transports".to_string()))
                        .and_then(|v| value_to_set_string(v, "0x01.transports"))
                        .map(|v| {
                            v.iter()
                                .filter_map(|t| AuthenticatorTransport::from_str(t).ok())
                                .collect()
                        });
                    id.and_then(|id| {
                        type_.map(|type_| PublicKeyCredentialDescriptor {
                            type_,
                            id,
                            transports,
                        })
                    })
                } else {
                    None
                }
            }),
            auth_data: raw.remove(&0x02).and_then(|v| value_to_vec_u8(v, "0x02")),
            signature: raw.remove(&0x03).and_then(|v| value_to_vec_u8(v, "0x03")),
            // TODO: user: None, (0x04)
            number_of_credentials: raw.remove(&0x05).and_then(|v| value_to_u32(&v, "0x05")),
            user_selected: raw.remove(&0x06).and_then(|v| value_to_bool(&v, "0x06")),
            large_blob_key: raw.remove(&0x07).and_then(|v| value_to_vec_u8(v, "0x07")),
        })
    }
}

crate::deserialize_cbor!(GetAssertionRequest);
crate::deserialize_cbor!(GetAssertionResponse);

#[cfg(test)]
mod tests {
    // TODO
}

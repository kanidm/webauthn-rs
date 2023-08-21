use base64urlsafedata::Base64UrlSafeData;
use serde::{Deserialize, Serialize};
use serde_cbor_2::{value::to_value, Value};
use std::collections::BTreeMap;
use webauthn_rs_proto::{PubKeyCredParams, PublicKeyCredentialDescriptor, RelyingParty, User};

use crate::ctap2::commands::{value_to_map, value_to_vec_u8};

use super::{value_to_bool, value_to_string, CBORCommand};

/// `authenticatorMakeCredential` request type.
///
/// Reference: <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorMakeCredential>
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(into = "BTreeMap<u32, Value>", try_from = "BTreeMap<u32, Value>")]
pub struct MakeCredentialRequest {
    /// Hash of the ClientData binding specified by the host.
    pub client_data_hash: Vec<u8>,
    /// Describes the relying party which the new credential will be associated
    /// with.
    pub rp: RelyingParty,
    /// Describes the user account to which the new credential will be
    /// associated with by the [RelyingParty].
    pub user: User,
    /// List of supported algorithms for credential generation.
    pub pub_key_cred_params: Vec<PubKeyCredParams>,
    /// List of existing credentials which the [RelyingParty] has for this
    /// [User]. This prevents re-enrollment of the same authenticator.
    pub exclude_list: Vec<PublicKeyCredentialDescriptor>,
    // TODO: extensions
    /// Parameters to influence operation.
    pub options: Option<BTreeMap<String, bool>>,
    /// Result of calling `authenticate(pin_uv_auth_token, client_data_hash)`.
    pub pin_uv_auth_param: Option<Vec<u8>>,
    /// PIN/UV protocol version chosen by the platform.
    pub pin_uv_auth_proto: Option<u32>,
    /// Enterprise attestation support.  **Not yet implemented**.
    pub enterprise_attest: Option<u32>,
}

impl CBORCommand for MakeCredentialRequest {
    const CMD: u8 = 0x01;
    type Response = MakeCredentialResponse;
}

/// `authenticatorMakeCredential` response type.
///
/// Reference: <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatormakecredential-response-structure>
///
/// ## Implementation notes
///
/// This needs to be (de)serialisable to/from both `Map<u32, Value>` **and**
/// `Map<String, Value>`:
///
/// * The authenticator itself uses a map with `u32` keys. This is needed to get
///   the value from from the authenticator, and to re-serialise values for
///   caBLE (via `AuthenticatorBackendWithRequests`)
///
/// * `AuthenticatorAttestationResponseRaw` uses a map with `String` keys, which
///   need the same names as `AttestationObjectInner`.
#[derive(Deserialize, Serialize, Debug, Clone, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MakeCredentialResponse {
    /// The attestation statement format identifier.
    pub fmt: Option<String>,
    /// The authenticator data object.
    pub auth_data: Option<Value>,
    /// The attestation statement.
    pub att_stmt: Option<Value>,
    /// Indicates whether an enterprise attestation was returned for this
    /// credential.
    pub epp_att: Option<bool>,
    /// Contains the `largeBlobKey` for the credential, if requested with the
    /// `largeBlobKey` extension.
    ///
    /// **Not yet supported.**
    pub large_blob_key: Option<Value>,
    // TODO: extensions
}

impl From<MakeCredentialRequest> for BTreeMap<u32, Value> {
    fn from(value: MakeCredentialRequest) -> Self {
        let MakeCredentialRequest {
            client_data_hash,
            rp,
            user,
            pub_key_cred_params,
            exclude_list,
            options,
            pin_uv_auth_param,
            pin_uv_auth_proto,
            enterprise_attest: _,
        } = value;

        let mut keys = BTreeMap::new();

        keys.insert(0x01, Value::Bytes(client_data_hash));

        if let Ok(rp_value) = to_value(rp) {
            keys.insert(0x2, rp_value);
        }

        // Because of how webauthn-rs is made, we build this in a way that optimises for text, not
        // to ctap.
        let User {
            id,
            name,
            display_name,
        } = user;

        let mut user_map = BTreeMap::new();
        // info!("{:?}", id);
        user_map.insert(Value::Text("id".to_string()), Value::Bytes(id.0));
        user_map.insert(Value::Text("name".to_string()), Value::Text(name));
        user_map.insert(
            Value::Text("displayName".to_string()),
            Value::Text(display_name),
        );

        let user_value = Value::Map(user_map);
        // info!("{:?}", user_value);
        keys.insert(0x3, user_value);

        if let Ok(ps) = to_value(pub_key_cred_params) {
            keys.insert(0x4, ps);
        }

        if !exclude_list.is_empty() {
            keys.insert(
                0x05,
                Value::Array(
                    exclude_list
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

        if let Some(o) = options {
            let mut options_map = BTreeMap::new();
            for (option, value) in &o {
                options_map.insert(Value::Text(option.to_string()), Value::Bool(*value));
            }

            let options_value = Value::Map(options_map);
            keys.insert(0x7, options_value);
        }

        if let Some(p) = pin_uv_auth_param {
            keys.insert(0x08, Value::Bytes(p));
        }

        if let Some(p) = pin_uv_auth_proto {
            keys.insert(0x09, Value::Integer(p.into()));
        }

        keys
    }
}

impl TryFrom<BTreeMap<u32, Value>> for MakeCredentialRequest {
    type Error = &'static str;
    fn try_from(mut raw: BTreeMap<u32, Value>) -> Result<Self, Self::Error> {
        trace!("raw: {:?}", raw);
        Ok(Self {
            client_data_hash: raw
                .remove(&0x01)
                .and_then(|v| value_to_vec_u8(v, "0x01"))
                .ok_or("parsing clientDataHash")?,
            rp: raw
                .remove(&0x02)
                .and_then(|v| serde_cbor_2::value::from_value(v).ok())
                .ok_or("parsing rp")?,
            user: raw
                .remove(&0x03)
                .and_then(|v| if let Value::Map(v) = v { Some(v) } else { None })
                .and_then(|mut v| {
                    Some(User {
                        id: Base64UrlSafeData(value_to_vec_u8(
                            v.remove(&Value::Text("id".to_string()))?,
                            "id",
                        )?),
                        name: value_to_string(v.remove(&Value::Text("name".to_string()))?, "name")?,
                        display_name: value_to_string(
                            v.remove(&Value::Text("displayName".to_string()))?,
                            "displayName",
                        )?,
                    })
                })
                .ok_or("parsing user")?,
            pub_key_cred_params: raw
                .remove(&0x04)
                .and_then(|v| serde_cbor_2::value::from_value(v).ok())
                .ok_or("parsing pubKeyCredParams")?,
            exclude_list: raw
                .remove(&0x05)
                .and_then(|v| serde_cbor_2::value::from_value(v).ok())
                .unwrap_or_default(),
            options: raw
                .remove(&0x07)
                .and_then(|v| value_to_map(v, "0x07"))
                .map(|v| {
                    v.into_iter()
                        .filter_map(|(key, value)| match (key, value) {
                            (Value::Text(key), Value::Bool(value)) => Some((key, value)),
                            _ => None,
                        })
                        .collect()
                }),
            // TODO
            pin_uv_auth_param: None,
            pin_uv_auth_proto: None,
            enterprise_attest: None,
        })
    }
}

impl From<MakeCredentialResponse> for BTreeMap<u32, Value> {
    fn from(value: MakeCredentialResponse) -> Self {
        let MakeCredentialResponse {
            fmt,
            auth_data,
            att_stmt,
            epp_att,
            large_blob_key,
        } = value;

        let mut keys = BTreeMap::new();
        if let Some(fmt) = fmt {
            keys.insert(0x01, Value::Text(fmt));
        }
        if let Some(auth_data) = auth_data {
            keys.insert(0x02, auth_data);
        }
        if let Some(att_stmt) = att_stmt {
            keys.insert(0x03, att_stmt);
        }
        if let Some(epp_att) = epp_att {
            keys.insert(0x04, epp_att.into());
        }
        if let Some(large_blob_key) = large_blob_key {
            keys.insert(0x05, large_blob_key);
        }
        keys
    }
}

impl TryFrom<BTreeMap<u32, Value>> for MakeCredentialResponse {
    type Error = &'static str;
    fn try_from(mut raw: BTreeMap<u32, Value>) -> Result<Self, Self::Error> {
        trace!(?raw);
        Ok(Self {
            fmt: raw.remove(&0x01).and_then(|v| value_to_string(v, "0x01")),
            auth_data: raw.remove(&0x02),
            att_stmt: raw.remove(&0x03),
            epp_att: raw.remove(&0x04).and_then(|v| value_to_bool(&v, "0x04")),
            large_blob_key: raw.remove(&0x05),
        })
    }
}

crate::deserialize_cbor!(MakeCredentialRequest);
crate::deserialize_cbor!(MakeCredentialResponse);

#[cfg(test)]
mod test {
    use crate::ctap2::CBORResponse;

    use super::*;
    use base64urlsafedata::Base64UrlSafeData;
    use serde_cbor_2::{from_slice, to_vec, Value};
    use webauthn_rs_proto::{PubKeyCredParams, RelyingParty, User};

    #[test]
    fn sample_make_credential_request() {
        let _ = tracing_subscriber::fmt::try_init();
        // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#example-1a030b94
        /*
        {
        Integer(1): Bytes([104, 113, 52, 150, 130, 34, 236, 23, 32, 46, 66, 80, 95, 142, 210, 177, 106, 226, 47, 22, 187, 5, 184, 140, 37, 219, 158, 96, 38, 69, 241, 65]),
        Integer(2): Map({Text("id"): Text("test.ctap"), Text("name"): Text("test.ctap")}),
        Integer(3): Map({Text("id"): Bytes([43, 102, 137, 187, 24, 244, 22, 159, 6, 159, 188, 223, 80, 203, 110, 163, 198, 10, 134, 27, 154, 123, 99, 148, 105, 131, 224, 181, 119, 183, 140, 112]),
            Text("name"): Text("testctap@ctap.com"), Text("displayName"): Text("Test Ctap")}),
        Integer(4): Array([
            Map({Text("alg"): Integer(-7), Text("type"): Text("public-key")}),
            Map({Text("alg"): Integer(-257), Text("type"): Text("public-key")}),
            Map({Text("alg"): Integer(-37), Text("type"): Text("public-key")})]),
        Integer(6): Map({Text("hmac-secret"): Bool(true)}),
        Integer(7): Map({Text("rk"): Bool(true)}),
        Integer(8): Bytes([252, 67, 170, 164, 17, 217, 72, 204, 108, 55, 6, 139, 141, 161, 213, 8]),
        Integer(9): Integer(1),
        }
         */
        let expected = vec![
            1, //
            // Extensions not yet supported
            // 168,
            167, //
            // ClientDataHash
            1, 88, 32, 104, 113, 52, 150, 130, 34, 236, 23, 32, 46, 66, 80, 95, 142, 210, 177, 106,
            226, 47, 22, 187, 5, 184, 140, 37, 219, 158, 96, 38, 69, 241, 65, //
            // RelyingParty
            2, 162, 98, 105, 100, 105, 116, 101, 115, 116, 46, 99, 116, 97, 112, 100, 110, 97, 109,
            101, 105, 116, 101, 115, 116, 46, 99, 116, 97, 112, //
            // User
            3, 163, 98, 105, 100, 88, 32, 43, 102, 137, 187, 24, 244, 22, 159, 6, 159, 188, 223, 80,
            203, 110, 163, 198, 10, 134, 27, 154, 123, 99, 148, 105, 131, 224, 181, 119, 183, 140,
            112, 100, 110, 97, 109, 101, 113, 116, 101, 115, 116, 99, 116, 97, 112, 64, 99, 116,
            97, 112, 46, 99, 111, 109, 107, 100, 105, 115, 112, 108, 97, 121, 78, 97, 109, 101,
            105, 84, 101, 115, 116, 32, 67, 116, 97, 112, //
            // PubKeyCredParams
            4, 131, 162, 99, 97, 108, 103, 38, 100, 116, 121, 112, 101, 106, 112, 117, 98, 108, 105,
            99, 45, 107, 101, 121, 162, 99, 97, 108, 103, 57, 1, 0, 100, 116, 121, 112, 101, 106,
            112, 117, 98, 108, 105, 99, 45, 107, 101, 121, 162, 99, 97, 108, 103, 56, 36, 100, 116,
            121, 112, 101, 106, 112, 117, 98, 108, 105, 99, 45, 107, 101, 121,
            // Extensions not yet supported
            // 6, 161, 107, 104, 109, 97, 99, 45, 115, 101, 99, 114, 101, 116, 245,
            // Options
            7, 161, 98, 114, 107, 245, //
            // pin_uv_auth_param
            8, 80, 252, 67, 170, 164, 17, 217, 72, 204, 108, 55, 6, 139, 141, 161, 213, 8,
            // pin_uv_auth_proto
            9, 1,
        ];

        let req = MakeCredentialRequest {
            client_data_hash: vec![
                104, 113, 52, 150, 130, 34, 236, 23, 32, 46, 66, 80, 95, 142, 210, 177, 106, 226,
                47, 22, 187, 5, 184, 140, 37, 219, 158, 96, 38, 69, 241, 65,
            ],
            rp: RelyingParty {
                name: "test.ctap".to_owned(),
                id: "test.ctap".to_owned(),
            },
            user: User {
                id: Base64UrlSafeData(vec![
                    43, 102, 137, 187, 24, 244, 22, 159, 6, 159, 188, 223, 80, 203, 110, 163, 198,
                    10, 134, 27, 154, 123, 99, 148, 105, 131, 224, 181, 119, 183, 140, 112,
                ]),
                name: "testctap@ctap.com".to_owned(),
                display_name: "Test Ctap".to_owned(),
            },
            pub_key_cred_params: vec![
                PubKeyCredParams {
                    type_: "public-key".to_owned(),
                    alg: -7,
                },
                PubKeyCredParams {
                    type_: "public-key".to_owned(),
                    alg: -257,
                },
                PubKeyCredParams {
                    type_: "public-key".to_owned(),
                    alg: -37,
                },
            ],
            exclude_list: vec![],
            options: Some(BTreeMap::from([("rk".to_owned(), true)])),
            pin_uv_auth_param: Some(vec![
                252, 67, 170, 164, 17, 217, 72, 204, 108, 55, 6, 139, 141, 161, 213, 8,
            ]),
            pin_uv_auth_proto: Some(1),
            enterprise_attest: None,
        };

        assert_eq!(expected, req.cbor().expect("encode error"));

        let decoded = <MakeCredentialRequest as CBORResponse>::try_from(&expected[1..]).unwrap();
        trace!(?decoded);

        let r = vec![
            163, 1, 102, 112, 97, 99, 107, 101, 100, 2, 89, 0, 162, 0, 33, 245, 252, 11, 133, 205,
            34, 230, 6, 35, 188, 215, 209, 202, 72, 148, 137, 9, 36, 155, 71, 118, 235, 81, 81, 84,
            229, 123, 102, 174, 18, 197, 0, 0, 0, 85, 248, 160, 17, 243, 140, 10, 77, 21, 128, 6,
            23, 17, 31, 158, 220, 125, 0, 16, 244, 213, 123, 35, 221, 12, 183, 133, 104, 12, 218,
            167, 247, 228, 79, 96, 165, 1, 2, 3, 38, 32, 1, 33, 88, 32, 223, 1, 125, 11, 40, 103,
            149, 190, 161, 83, 209, 102, 160, 161, 91, 79, 107, 103, 163, 175, 74, 16, 30, 16, 232,
            73, 111, 61, 211, 197, 209, 169, 34, 88, 32, 148, 178, 37, 81, 230, 50, 93, 119, 51,
            196, 27, 178, 245, 166, 66, 173, 238, 65, 124, 151, 224, 144, 97, 151, 181, 176, 205,
            139, 141, 108, 107, 167, 161, 107, 104, 109, 97, 99, 45, 115, 101, 99, 114, 101, 116,
            245, 3, 163, 99, 97, 108, 103, 38, 99, 115, 105, 103, 88, 71, 48, 69, 2, 32, 124, 202,
            197, 122, 30, 67, 223, 36, 176, 132, 126, 235, 241, 25, 210, 141, 205, 197, 4, 143,
            125, 205, 142, 221, 121, 231, 151, 33, 196, 27, 207, 45, 2, 33, 0, 216, 158, 199, 91,
            146, 206, 143, 249, 228, 111, 231, 248, 200, 121, 149, 105, 74, 99, 229, 183, 138, 184,
            92, 71, 185, 218, 28, 88, 10, 142, 200, 58, 99, 120, 53, 99, 129, 89, 1, 151, 48, 130,
            1, 147, 48, 130, 1, 56, 160, 3, 2, 1, 2, 2, 9, 0, 133, 155, 114, 108, 178, 75, 76, 41,
            48, 10, 6, 8, 42, 134, 72, 206, 61, 4, 3, 2, 48, 71, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19,
            2, 85, 83, 49, 20, 48, 18, 6, 3, 85, 4, 10, 12, 11, 89, 117, 98, 105, 99, 111, 32, 84,
            101, 115, 116, 49, 34, 48, 32, 6, 3, 85, 4, 11, 12, 25, 65, 117, 116, 104, 101, 110,
            116, 105, 99, 97, 116, 111, 114, 32, 65, 116, 116, 101, 115, 116, 97, 116, 105, 111,
            110, 48, 30, 23, 13, 49, 54, 49, 50, 48, 52, 49, 49, 53, 53, 48, 48, 90, 23, 13, 50,
            54, 49, 50, 48, 50, 49, 49, 53, 53, 48, 48, 90, 48, 71, 49, 11, 48, 9, 6, 3, 85, 4, 6,
            19, 2, 85, 83, 49, 20, 48, 18, 6, 3, 85, 4, 10, 12, 11, 89, 117, 98, 105, 99, 111, 32,
            84, 101, 115, 116, 49, 34, 48, 32, 6, 3, 85, 4, 11, 12, 25, 65, 117, 116, 104, 101,
            110, 116, 105, 99, 97, 116, 111, 114, 32, 65, 116, 116, 101, 115, 116, 97, 116, 105,
            111, 110, 48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61,
            3, 1, 7, 3, 66, 0, 4, 173, 17, 235, 14, 136, 82, 229, 58, 213, 223, 237, 134, 180, 30,
            97, 52, 161, 142, 196, 225, 175, 143, 34, 26, 60, 125, 110, 99, 108, 128, 234, 19, 195,
            213, 4, 255, 46, 118, 33, 27, 180, 69, 37, 177, 150, 196, 76, 180, 132, 153, 121, 207,
            111, 137, 110, 205, 43, 184, 96, 222, 27, 244, 55, 107, 163, 13, 48, 11, 48, 9, 6, 3,
            85, 29, 19, 4, 2, 48, 0, 48, 10, 6, 8, 42, 134, 72, 206, 61, 4, 3, 2, 3, 73, 0, 48, 70,
            2, 33, 0, 233, 163, 159, 27, 3, 25, 117, 37, 247, 55, 62, 16, 206, 119, 231, 128, 33,
            115, 27, 148, 208, 192, 63, 63, 218, 31, 210, 45, 179, 208, 48, 231, 2, 33, 0, 196,
            250, 236, 52, 69, 168, 32, 207, 67, 18, 156, 219, 0, 170, 190, 253, 154, 226, 216, 116,
            249, 197, 211, 67, 203, 47, 17, 61, 162, 55, 35, 243,
        ];
        let a = <MakeCredentialResponse as CBORResponse>::try_from(r.as_slice())
            .expect("Failed to decode message");
        info!("r = {}", hex::encode(r));

        assert_eq!(
            a,
            MakeCredentialResponse {
                fmt: Some("packed".to_owned()),
                auth_data: Some(Value::Bytes(vec![
                    0, 33, 245, 252, 11, 133, 205, 34, 230, 6, 35, 188, 215, 209, 202, 72, 148,
                    137, 9, 36, 155, 71, 118, 235, 81, 81, 84, 229, 123, 102, 174, 18, 197, 0, 0,
                    0, 85, 248, 160, 17, 243, 140, 10, 77, 21, 128, 6, 23, 17, 31, 158, 220, 125,
                    0, 16, 244, 213, 123, 35, 221, 12, 183, 133, 104, 12, 218, 167, 247, 228, 79,
                    96, 165, 1, 2, 3, 38, 32, 1, 33, 88, 32, 223, 1, 125, 11, 40, 103, 149, 190,
                    161, 83, 209, 102, 160, 161, 91, 79, 107, 103, 163, 175, 74, 16, 30, 16, 232,
                    73, 111, 61, 211, 197, 209, 169, 34, 88, 32, 148, 178, 37, 81, 230, 50, 93,
                    119, 51, 196, 27, 178, 245, 166, 66, 173, 238, 65, 124, 151, 224, 144, 97, 151,
                    181, 176, 205, 139, 141, 108, 107, 167, 161, 107, 104, 109, 97, 99, 45, 115,
                    101, 99, 114, 101, 116, 245
                ])),
                att_stmt: Some(Value::Map(BTreeMap::from([
                    (Value::Text("alg".to_owned()), Value::Integer(-7)),
                    (
                        Value::Text("sig".to_owned()),
                        Value::Bytes(vec![
                            48, 69, 2, 32, 124, 202, 197, 122, 30, 67, 223, 36, 176, 132, 126, 235,
                            241, 25, 210, 141, 205, 197, 4, 143, 125, 205, 142, 221, 121, 231, 151,
                            33, 196, 27, 207, 45, 2, 33, 0, 216, 158, 199, 91, 146, 206, 143, 249,
                            228, 111, 231, 248, 200, 121, 149, 105, 74, 99, 229, 183, 138, 184, 92,
                            71, 185, 218, 28, 88, 10, 142, 200, 58
                        ])
                    ),
                    (
                        Value::Text("x5c".to_owned()),
                        Value::Array(vec![Value::Bytes(vec![
                            48, 130, 1, 147, 48, 130, 1, 56, 160, 3, 2, 1, 2, 2, 9, 0, 133, 155,
                            114, 108, 178, 75, 76, 41, 48, 10, 6, 8, 42, 134, 72, 206, 61, 4, 3, 2,
                            48, 71, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83, 49, 20, 48, 18,
                            6, 3, 85, 4, 10, 12, 11, 89, 117, 98, 105, 99, 111, 32, 84, 101, 115,
                            116, 49, 34, 48, 32, 6, 3, 85, 4, 11, 12, 25, 65, 117, 116, 104, 101,
                            110, 116, 105, 99, 97, 116, 111, 114, 32, 65, 116, 116, 101, 115, 116,
                            97, 116, 105, 111, 110, 48, 30, 23, 13, 49, 54, 49, 50, 48, 52, 49, 49,
                            53, 53, 48, 48, 90, 23, 13, 50, 54, 49, 50, 48, 50, 49, 49, 53, 53, 48,
                            48, 90, 48, 71, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83, 49, 20,
                            48, 18, 6, 3, 85, 4, 10, 12, 11, 89, 117, 98, 105, 99, 111, 32, 84,
                            101, 115, 116, 49, 34, 48, 32, 6, 3, 85, 4, 11, 12, 25, 65, 117, 116,
                            104, 101, 110, 116, 105, 99, 97, 116, 111, 114, 32, 65, 116, 116, 101,
                            115, 116, 97, 116, 105, 111, 110, 48, 89, 48, 19, 6, 7, 42, 134, 72,
                            206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61, 3, 1, 7, 3, 66, 0, 4, 173,
                            17, 235, 14, 136, 82, 229, 58, 213, 223, 237, 134, 180, 30, 97, 52,
                            161, 142, 196, 225, 175, 143, 34, 26, 60, 125, 110, 99, 108, 128, 234,
                            19, 195, 213, 4, 255, 46, 118, 33, 27, 180, 69, 37, 177, 150, 196, 76,
                            180, 132, 153, 121, 207, 111, 137, 110, 205, 43, 184, 96, 222, 27, 244,
                            55, 107, 163, 13, 48, 11, 48, 9, 6, 3, 85, 29, 19, 4, 2, 48, 0, 48, 10,
                            6, 8, 42, 134, 72, 206, 61, 4, 3, 2, 3, 73, 0, 48, 70, 2, 33, 0, 233,
                            163, 159, 27, 3, 25, 117, 37, 247, 55, 62, 16, 206, 119, 231, 128, 33,
                            115, 27, 148, 208, 192, 63, 63, 218, 31, 210, 45, 179, 208, 48, 231, 2,
                            33, 0, 196, 250, 236, 52, 69, 168, 32, 207, 67, 18, 156, 219, 0, 170,
                            190, 253, 154, 226, 216, 116, 249, 197, 211, 67, 203, 47, 17, 61, 162,
                            55, 35, 243
                        ])])
                    )
                ]))),
                ..Default::default()
            }
        );
    }

    #[test]
    fn make_credential() {
        let _ = tracing_subscriber::fmt().try_init();

        // clientDataHash 0x01
        // rp 0x02
        // user 0x03
        // pubKeyCredParams 0x04
        // excludeList 0x05
        // extensions 0x06
        // options 0x07
        // pinUvAuthParam 0x08
        // pinUvAuthProtocol 0x09
        // enterpriseAttestation 0x0A

        /*
        Dec 28 18:41:01.160  INFO webauthn_authenticator_rs::nfc::apdu::tests: got APDU Value response: Ok(Map(

        Integer(1): Bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        Integer(1): Bytes([104, 113, 52, 150, 130, 34, 236, 23, 32, 46, 66, 80, 95, 142, 210, 177, 106, 226, 47, 22, 187, 5, 184, 140, 37, 219, 158, 96, 38, 69, 241, 65]),
        Integer(2): Map({
            Text("id"): Text("test"),
            Text("name"): Text("test")
        }),
        Integer(2): Map({
            Text("id"): Text("test.ctap"),
            Text("name"): Text("test.ctap")
        }),
        Integer(3): Map({
            Text("id"): Bytes([116, 101, 115, 116]),
            Text("name"): Text("test"),
            Text("displayName"): Text("test")
        }),
        Integer(3): Map({
            Text("id"): Bytes([43, 102, 137, 187, 24, 244, 22, 159, 6, 159, 188, 223, 80, 203, 110, 163, 198, 10, 134, 27, 154, 123, 99, 148, 105, 131, 224, 181, 119, 183, 140, 112]),
            Text("name"): Text("testctap@ctap.com"),
            Text("displayName"): Text("Test Ctap")
        }),
        Integer(4): Array([
            Map({Text("alg"): Integer(-7), Text("type"): Text("public-key")})
        ])
        Integer(4): Array([
            Map({Text("alg"): Integer(-7), Text("type"): Text("public-key")}),
            Map({Text("alg"): Integer(-257), Text("type"): Text("public-key")}),
            Map({Text("alg"): Integer(-37), Text("type"): Text("public-key")})
        ]),
        // I think this is incorrect?
        Integer(6): Map({Text("hmac-secret"): Bool(true)}),
        // May need to set uv false?
        Integer(7): Map({Text("rk"): Bool(true)}),
        // Not needed
        Integer(8): Bytes([252, 67, 170, 164, 17, 217, 72, 204, 108, 55, 6, 139, 141, 161, 213, 8]),
        // Not needed
        Integer(9): Integer(1)}))
        */

        // Response APDU has a prepended 0x01 (error code)
        let bytes = vec![
            168, 1, 88, 32, 104, 113, 52, 150, 130, 34, 236, 23, 32, 46, 66, 80, 95, 142, 210, 177,
            106, 226, 47, 22, 187, 5, 184, 140, 37, 219, 158, 96, 38, 69, 241, 65, 2, 162, 98, 105,
            100, 105, 116, 101, 115, 116, 46, 99, 116, 97, 112, 100, 110, 97, 109, 101, 105, 116,
            101, 115, 116, 46, 99, 116, 97, 112, 3, 163, 98, 105, 100, 88, 32, 43, 102, 137, 187,
            24, 244, 22, 159, 6, 159, 188, 223, 80, 203, 110, 163, 198, 10, 134, 27, 154, 123, 99,
            148, 105, 131, 224, 181, 119, 183, 140, 112, 100, 110, 97, 109, 101, 113, 116, 101,
            115, 116, 99, 116, 97, 112, 64, 99, 116, 97, 112, 46, 99, 111, 109, 107, 100, 105, 115,
            112, 108, 97, 121, 78, 97, 109, 101, 105, 84, 101, 115, 116, 32, 67, 116, 97, 112, 4,
            131, 162, 99, 97, 108, 103, 38, 100, 116, 121, 112, 101, 106, 112, 117, 98, 108, 105,
            99, 45, 107, 101, 121, 162, 99, 97, 108, 103, 57, 1, 0, 100, 116, 121, 112, 101, 106,
            112, 117, 98, 108, 105, 99, 45, 107, 101, 121, 162, 99, 97, 108, 103, 56, 36, 100, 116,
            121, 112, 101, 106, 112, 117, 98, 108, 105, 99, 45, 107, 101, 121, 6, 161, 107, 104,
            109, 97, 99, 45, 115, 101, 99, 114, 101, 116, 245, 7, 161, 98, 114, 107, 245, 8, 80,
            252, 67, 170, 164, 17, 217, 72, 204, 108, 55, 6, 139, 141, 161, 213, 8, 9, 1,
        ];

        let v: Result<Value, _> = from_slice(bytes.as_slice());
        info!("got APDU Value response: {:?}", v);

        let mc = MakeCredentialRequest {
            client_data_hash: vec![0; 32],
            rp: RelyingParty {
                name: "test".to_string(),
                id: "test".to_string(),
            },
            user: User {
                id: Base64UrlSafeData("test".as_bytes().into()),
                name: "test".to_string(),
                display_name: "test".to_string(),
            },
            pub_key_cred_params: vec![PubKeyCredParams {
                type_: "public-key".to_string(),
                alg: -7,
            }],
            options: None,
            exclude_list: vec![],
            pin_uv_auth_param: None,
            pin_uv_auth_proto: None,
            enterprise_attest: None,
        };

        let b = to_vec(&mc).unwrap();

        let v2: Result<Value, _> = from_slice(b.as_slice());
        info!("got APDU Value encoded: {:?}", v2);

        // let pdu = mc.to_short_apdus();
        // info!("got APDU: {:?}", pdu);
        info!("got inner APDU: {}", hex::encode(b));
    }
}

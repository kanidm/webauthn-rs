use serde::{Deserialize, Serialize};
use serde_cbor::{from_slice, value::to_value, Value};
use std::collections::{BTreeMap, BTreeSet};

use base64urlsafedata::Base64UrlSafeData;
use webauthn_rs_proto::{PubKeyCredParams, PublicKeyCredentialDescriptor, RelyingParty, User};

// https://en.wikipedia.org/wiki/Smart_card_application_protocol_data_unit

pub const APPLET_U2F_V2: [u8; 8] = [0x55, 0x32, 0x46, 0x5f, 0x56, 0x32, 0x90, 0x00];
pub const APPLET_FIDO_2_0: [u8; 10] = [0x46, 0x49, 0x44, 0x4f, 0x5f, 0x32, 0x5f, 0x30, 0x90, 0x00];
//                                   CLA,  INS,  P1,   P2,   len,  data(rid)                     data(pix)         le
pub const APPLET_SELECT_CMD: [u8; 14] = [
    0x00, 0xA4, 0x04, 0x00, 0x09, 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01, 0xFF,
];

pub const FRAG_MAX: u8 = 0xF0;
pub const FRAG_HDR: [u8; 4] = [0x90, 0x10, 0x00, 0x00];
pub const HDR: [u8; 4] = [0x80, 0x10, 0x00, 0x00];

// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetInfo
pub const AUTHENTICATOR_GET_INFO_APDU: [u8; 1] = [0x4];

pub const MAX_SHORT_BUFFER_SIZE: usize = 256;
pub const MAX_EXT_BUFFER_SIZE: usize = 65536;

fn value_to_vec_string(v: Value, loc: &str) -> Option<Vec<String>> {
    if let Value::Array(v) = v {
        let mut x = Vec::with_capacity(v.len());
        for s in v.into_iter() {
            if let Value::Text(s) = s {
                x.push(s);
            } else {
                error!("Invalid value inside {}: {:?}", loc, s);
            }
        }
        Some(x)
    } else {
        error!("Invalid type for {}: {:?}", loc, v);
        None
    }
}

fn value_to_set_string(v: Value, loc: &str) -> Option<BTreeSet<String>> {
    if let Value::Array(v) = v {
        let mut x = BTreeSet::new();
        for s in v.into_iter() {
            if let Value::Text(s) = s {
                x.insert(s);
            } else {
                error!("Invalid value inside {}: {:?}", loc, s);
            }
        }
        Some(x)
    } else {
        error!("Invalid type for {}: {:?}", loc, v);
        None
    }
}

fn value_to_vec_u32(v: Value, loc: &str) -> Option<Vec<u32>> {
    if let Value::Array(v) = v {
        let x = v
            .into_iter()
            .filter_map(|i| {
                if let Value::Integer(i) = i {
                    u32::try_from(i)
                        .map_err(|_| error!("Invalid value inside {}: {:?}", loc, i))
                        .ok()
                } else {
                    error!("Invalid type for {}: {:?}", loc, i);
                    None
                }
            })
            .collect();
        Some(x)
    } else {
        error!("Invalid type for {}: {:?}", loc, v);
        None
    }
}

fn value_to_u32(v: Value, loc: &str) -> Option<u32> {
    if let Value::Integer(i) = v {
        u32::try_from(i)
            .map_err(|_| error!("Invalid value inside {}: {:?}", loc, i))
            .ok()
    } else {
        error!("Invalid type for {}: {:?}", loc, v);
        None
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct AuthenticatorRawDict {
    #[serde(flatten)]
    pub keys: BTreeMap<u32, Value>,
}

#[derive(Deserialize, Debug)]
#[serde(try_from = "AuthenticatorRawDict")]
pub struct AuthenticatorGetInfoResponse {
    pub versions: BTreeSet<String>,
    pub extensions: Option<Vec<String>>,
    pub aaguid: Vec<u8>,
    pub options: Option<BTreeMap<String, bool>>,
    pub max_msg_size: Option<u32>,
    pub pin_protocols: Option<Vec<u32>>,
    pub max_cred_count_in_list: Option<u32>,
    pub max_cred_id_len: Option<u32>,
    pub transports: Option<Vec<String>>,
    pub algorithms: Option<Value>,
}

impl TryFrom<AuthenticatorRawDict> for AuthenticatorGetInfoResponse {
    type Error = &'static str;

    fn try_from(mut raw: AuthenticatorRawDict) -> Result<Self, Self::Error> {
        let versions = raw
            .keys
            .remove(&0x01)
            .and_then(|v| value_to_set_string(v, "0x01"))
            .ok_or("0x01")?;

        let extensions = raw
            .keys
            .remove(&0x02)
            .and_then(|v| value_to_vec_string(v, "0x02"));

        let aaguid = raw
            .keys
            .remove(&0x03)
            .and_then(|v| match v {
                Value::Bytes(x) => Some(x),
                _ => {
                    error!("Invalid type for 0x03: {:?}", v);
                    None
                }
            })
            .ok_or("0x03")?;

        let options = raw.keys.remove(&0x04).and_then(|v| {
            if let Value::Map(v) = v {
                let mut x = BTreeMap::new();
                for (ka, va) in v.into_iter() {
                    match (ka, va) {
                        (Value::Text(s), Value::Bool(b)) => {
                            x.insert(s, b);
                        }
                        _ => error!("Invalid value inside 0x04"),
                    }
                }
                Some(x)
            } else {
                error!("Invalid type for 0x04: {:?}", v);
                None
            }
        });

        let max_msg_size = raw.keys.remove(&0x05).and_then(|v| value_to_u32(v, "0x05"));

        let pin_protocols = raw
            .keys
            .remove(&0x06)
            .and_then(|v| value_to_vec_u32(v, "0x06"));

        let max_cred_count_in_list = raw.keys.remove(&0x07).and_then(|v| value_to_u32(v, "0x07"));

        let max_cred_id_len = raw.keys.remove(&0x08).and_then(|v| value_to_u32(v, "0x08"));

        let transports = raw
            .keys
            .remove(&0x09)
            .and_then(|v| value_to_vec_string(v, "0x09"));

        let algorithms = raw.keys.remove(&0x0A);
        // .map(|v| );

        /*
        let max_ser_large_blob = raw.keys.remove(&0x0B)
            .map(|v| );

        let force_pin_change = raw.keys.remove(&0x0C)
            .map(|v| );

        let min_pin_len = raw.keys.remove(&0x0D)
            .map(|v| );

        let firmware_version = raw.keys.remove(&0x0E)
            .map(|v| );

        let max_cred_blob_len = raw.keys.remove(&0x0F)
            .map(|v| );

        let max_rpid_for_set_min_pin_len = raw.keys.remove(&0x10)
            .map(|v| );

        let preferred_plat_uv_attempts = raw.keys.remove(&0x11)
            .map(|v| );

        let uv_modality = raw.keys.remove(&0x12)
            .map(|v| );

        let certifications = raw.keys.remove(&0x13)
            .map(|v| );

        let remaining_discoverable_credentials = raw.keys.remove(&0x14)
            .map(|v| );

        let vendor_prototype_config_cmds = raw.keys.remove(&0x15)
            .map(|v| );
        */

        Ok(AuthenticatorGetInfoResponse {
            versions,
            extensions,
            aaguid,
            options,
            max_msg_size,
            pin_protocols,
            max_cred_count_in_list,
            max_cred_id_len,
            transports,
            algorithms,
            /*
            max_ser_large_blob,
            force_pin_change,
            min_pin_len,
            firmware_version,
            max_cred_blob_len,
            max_rpid_for_set_min_pin_len,
            preferred_plat_uv_attempts,
            uv_modality,
            certifications,
            remaining_discoverable_credentials,
            vendor_prototype_config_cmds,
            */
        })
    }
}

impl TryFrom<&[u8]> for AuthenticatorGetInfoResponse {
    type Error = ();

    fn try_from(rapdu: &[u8]) -> Result<Self, Self::Error> {
        if cfg!(debug) {
            let v: Result<Value, _> = from_slice(&rapdu);
            trace!("got APDU Value response: {:?}", v);
        }

        let agir = from_slice(&rapdu);
        trace!(?agir);
        agir.map_err(|e| ())
    }
}

pub trait ToNfcApdu: Serialize + Sized {
    const CMD: u8;

    fn to_apdu(&self) -> Vec<u8> {
        let b = serde_cbor::to_vec(self).unwrap();

        let mut x = Vec::with_capacity(b.len() + 1);
        x.push(Self::CMD);
        x.extend_from_slice(&b);
        x
    }
}

#[derive(Serialize, Debug, Clone)]
#[serde(into = "AuthenticatorRawDict")]
pub struct AuthenticatorMakeCredential {
    pub(crate) client_data_hash: Vec<u8>,
    pub(crate) rp: RelyingParty,
    pub(crate) user: User,
    pub(crate) pub_key_cred_params: Vec<PubKeyCredParams>,
    // exclude_list: Option<Vec<PublicKeyCredentialDescriptor>>,
    // extensions:
    pub(crate) options: Option<BTreeMap<String, bool>>,
    pub(crate) pin_uv_auth_param: Option<Vec<u8>>,
    pub(crate) pin_uv_auth_proto: Option<u32>,
    pub(crate) enterprise_attest: Option<u32>,
}

impl ToNfcApdu for AuthenticatorMakeCredential {
    const CMD: u8 = 0x01;
}

impl From<AuthenticatorMakeCredential> for AuthenticatorRawDict {
    fn from(value: AuthenticatorMakeCredential) -> Self {
        let AuthenticatorMakeCredential {
            client_data_hash,
            rp,
            user,
            pub_key_cred_params,
            options,
            pin_uv_auth_param,
            pin_uv_auth_proto,
            enterprise_attest,
        } = value;

        let mut keys = BTreeMap::new();

        keys.insert(0x1, Value::Bytes(client_data_hash));

        let rp_value = to_value(rp).expect("Unable to encode rp");
        keys.insert(0x2, rp_value);

        // Because of how webauthn-rs is made, we build this in a way that optimises for text, not
        // to ctap.
        let User {
            id,
            name,
            display_name,
        } = user;

        let mut user_map = BTreeMap::new();
        info!("{:?}", id);
        user_map.insert(Value::Text("id".to_string()), Value::Bytes(id.0));
        user_map.insert(Value::Text("name".to_string()), Value::Text(name));
        user_map.insert(
            Value::Text("displayName".to_string()),
            Value::Text(display_name),
        );

        let user_value = Value::Map(user_map);
        info!("{:?}", user_value);
        keys.insert(0x3, user_value);

        let pub_key_cred_params_value =
            to_value(pub_key_cred_params).expect("Unable to encode pub_key_cred_params");
        keys.insert(0x4, pub_key_cred_params_value);

        /*
        let mut options_map = BTreeMap::new();
        options_map.insert(Value::Text("rk".to_string()), Value::Bool(false));
        let options_value = Value::Map(options_map);
        keys.insert(0x7, options_value);
        */
        AuthenticatorRawDict { keys }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_cbor::to_vec;
    use std::collections::BTreeMap;

    #[test]
    fn nfc_apdu_authenticator_get_info() {
        let _ = tracing_subscriber::fmt().try_init();

        let raw_apdu: Vec<u8> = vec![
            170, 1, 131, 102, 85, 50, 70, 95, 86, 50, 104, 70, 73, 68, 79, 95, 50, 95, 48, 108, 70,
            73, 68, 79, 95, 50, 95, 49, 95, 80, 82, 69, 2, 130, 107, 99, 114, 101, 100, 80, 114,
            111, 116, 101, 99, 116, 107, 104, 109, 97, 99, 45, 115, 101, 99, 114, 101, 116, 3, 80,
            47, 192, 87, 159, 129, 19, 71, 234, 177, 22, 187, 90, 141, 185, 32, 42, 4, 165, 98,
            114, 107, 245, 98, 117, 112, 245, 100, 112, 108, 97, 116, 244, 105, 99, 108, 105, 101,
            110, 116, 80, 105, 110, 245, 117, 99, 114, 101, 100, 101, 110, 116, 105, 97, 108, 77,
            103, 109, 116, 80, 114, 101, 118, 105, 101, 119, 245, 5, 25, 4, 176, 6, 129, 1, 7, 8,
            8, 24, 128, 9, 130, 99, 110, 102, 99, 99, 117, 115, 98, 10, 130, 162, 99, 97, 108, 103,
            38, 100, 116, 121, 112, 101, 106, 112, 117, 98, 108, 105, 99, 45, 107, 101, 121, 162,
            99, 97, 108, 103, 39, 100, 116, 121, 112, 101, 106, 112, 117, 98, 108, 105, 99, 45,
            107, 101, 121,
        ];

        let a = AuthenticatorGetInfoResponse::try_from(raw_apdu.as_slice())
            .expect("Falied to decode apdu");

        // Assert the content
        info!(?a);

        assert!(a.versions.len() == 3);
        assert!(a.versions.contains("U2F_V2"));
        assert!(a.versions.contains("FIDO_2_0"));
        assert!(a.versions.contains("FIDO_2_1_PRE"));

        assert!(a.extensions == Some(vec!["credProtect".to_string(), "hmac-secret".to_string()]));
        assert!(
            a.aaguid
                == vec![47, 192, 87, 159, 129, 19, 71, 234, 177, 22, 187, 90, 141, 185, 32, 42]
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

    #[test]
    fn nfc_apdu_authenticator_make_credential() {
        let _ = tracing_subscriber::fmt().try_init();

        // let map: BTreeMap<Value, Value> = BTreeMap::new();

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

        // why is the a prepended 0x01?
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

        let mc = AuthenticatorMakeCredential {
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
            pin_uv_auth_param: None,
            pin_uv_auth_proto: None,
            enterprise_attest: None,
        };

        let b = to_vec(&mc).unwrap();

        let v2: Result<Value, _> = from_slice(b.as_slice());
        info!("got APDU Value encoded: {:?}", v2);

        let pdu = mc.to_apdu();
        info!("got APDU: {:?}", pdu);
        info!("got inner APDU: {:?}", b);
    }
}

use std::str::FromStr;

use serde::{Deserialize, Serialize};
use serde_cbor::Value;
use webauthn_rs_proto::AuthenticatorTransport;

use self::CBORCommand;
use super::*;

/// `authenticatorGetInfo` request type.
/// 
/// This request type has no fields.
/// 
/// Reference: <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorGetInfo>
#[derive(Serialize, Debug, Clone)]
pub struct GetInfoRequest {}

impl CBORCommand for GetInfoRequest {
    const CMD: u8 = 0x04;
    const HAS_PAYLOAD: bool = false;
    type Response = GetInfoResponse;
}

/// `authenticatorGetInfo` response type.
/// 
/// Reference: <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorGetInfo>
#[derive(Deserialize, Debug)]
#[serde(try_from = "BTreeMap<u32, Value>")]
pub struct GetInfoResponse {
    /// All CTAP protocol versions which the token supports.
    pub versions: BTreeSet<String>,
    /// All protocol extensions which the token supports.
    pub extensions: Option<Vec<String>>,
    /// The claimed AAGUID.
    pub aaguid: Vec<u8>,
    /// List of supported options.
    pub options: Option<BTreeMap<String, bool>>,
    /// Maximum message size supported by the authenticator.
    pub max_msg_size: Option<u32>,
    /// All PIN/UV auth protocols which the token supports.
    pub pin_protocols: Option<Vec<u32>>,
    pub max_cred_count_in_list: Option<u32>,
    pub max_cred_id_len: Option<u32>,
    /// List of supported transports as strings.
    /// 
    /// Use [get_transports][Self::get_transports] to get a list of
    /// [AuthenticatorTransport].
    pub transports: Option<Vec<String>>,
    /// List of supported algorithms for credential generation.
    pub algorithms: Option<Value>,
    /// Current minimum PIN length, in Unicode code points.
    /// 
    /// Use [get_min_pin_length][Self::get_min_pin_length] to get a default
    /// value for when this is not present.
    pub min_pin_length: Option<usize>,
}

impl GetInfoResponse {
    /// Current minimum PIN length, in Unicode code points.
    /// 
    /// If this is not present, defaults to 4.
    pub fn get_min_pin_length(&self) -> usize {
        self.min_pin_length.unwrap_or(4)
    }

    /// Gets all supported transports for this authenticator which match known
    /// [AuthenticatorTransport] values. Unknown values are silently discarded.
    pub fn get_transports(&self) -> Option<Vec<AuthenticatorTransport>> {
        self.transports.as_ref().map(|transports| {
            transports
                .iter()
                .filter_map(|transport| FromStr::from_str(transport).ok())
                .collect()
        })
    }

    /// Gets the state of an option.
    pub fn get_option(&self, option: &str) -> Option<bool> {
        self.options
            .as_ref()
            .and_then(|o| o.get(option))
            .map(|v| v.to_owned())
    }

    /// Returns `true` if the authenticator supports CTAP 2.1 biometrics
    /// commands.
    pub fn supports_ctap21_biometrics(&self) -> bool {
        self.get_option("bioEnroll").is_some()
    }

    /// Returns `true` if the authenticator supports CTAP 2.1-PRE biometrics
    /// commands.
    pub fn supports_ctap21pre_biometrics(&self) -> bool {
        self.get_option("userVerificationMgmtPreview").is_some()
    }
}

impl TryFrom<BTreeMap<u32, Value>> for GetInfoResponse {
    type Error = &'static str;

    fn try_from(mut raw: BTreeMap<u32, Value>) -> Result<Self, Self::Error> {
        // trace!("raw = {:?}", raw);
        let versions = raw
            .remove(&0x01)
            .and_then(|v| value_to_set_string(v, "0x01"))
            .ok_or("0x01")?;

        let extensions = raw
            .remove(&0x02)
            .and_then(|v| value_to_vec_string(v, "0x02"));

        let aaguid = raw
            .remove(&0x03)
            .and_then(|v| match v {
                Value::Bytes(x) => Some(x),
                _ => {
                    error!("Invalid type for 0x03: {:?}", v);
                    None
                }
            })
            .ok_or("0x03")?;

        let options = raw.remove(&0x04).and_then(|v| {
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

        let max_msg_size = raw.remove(&0x05).and_then(|v| value_to_u32(&v, "0x05"));

        let pin_protocols = raw.remove(&0x06).and_then(|v| value_to_vec_u32(v, "0x06"));

        let max_cred_count_in_list = raw.remove(&0x07).and_then(|v| value_to_u32(&v, "0x07"));

        let max_cred_id_len = raw.remove(&0x08).and_then(|v| value_to_u32(&v, "0x08"));

        let transports = raw
            .remove(&0x09)
            .and_then(|v| value_to_vec_string(v, "0x09"));

        let algorithms = raw.remove(&0x0A);
        // .map(|v| );

        let min_pin_length = raw
            .remove(&0x0d)
            .and_then(|v| value_to_u32(&v, "0x0d"))
            .map(|v| v as usize);

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

        Ok(GetInfoResponse {
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
            min_pin_length,
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

crate::deserialize_cbor!(GetInfoResponse);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::iso7816::ISO7816LengthForm;

    #[test]
    fn get_info_response_nfc_usb() {
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

        let a = <GetInfoResponse as CBORResponse>::try_from(raw_apdu.as_slice())
            .expect("Falied to decode apdu");

        // Assert the content
        // info!(?a);

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
    fn get_info_request() {
        let req = GetInfoRequest {};
        let short = vec![0x80, 0x10, 0, 0, 1, 0x4, 0];
        let ext = vec![0x80, 0x10, 0, 0, 0, 0, 1, 0x4, 0, 0];

        let a = req.to_short_apdus().unwrap();
        assert_eq!(1, a.len());
        assert_eq!(short, a[0].to_bytes(&ISO7816LengthForm::ShortOnly).unwrap());
        assert_eq!(short, a[0].to_bytes(&ISO7816LengthForm::Extended).unwrap());

        assert_eq!(
            ext,
            req.to_extended_apdu()
                .unwrap()
                .to_bytes(&ISO7816LengthForm::Extended)
                .unwrap()
        );
        assert_eq!(
            ext,
            req.to_extended_apdu()
                .unwrap()
                .to_bytes(&ISO7816LengthForm::ExtendedOnly)
                .unwrap()
        );
        assert!(req
            .to_extended_apdu()
            .unwrap()
            .to_bytes(&ISO7816LengthForm::ShortOnly)
            .is_err());
    }
}

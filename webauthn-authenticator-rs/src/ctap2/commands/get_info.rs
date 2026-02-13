use std::str::FromStr;

use serde::{Deserialize, Serialize};
use serde_cbor_2::Value;
use std::fmt;
use uuid::Uuid;
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
#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
#[serde(try_from = "BTreeMap<u32, Value>", into = "BTreeMap<u32, Value>")]
pub struct GetInfoResponse {
    /// All CTAP protocol versions which the token supports.
    pub versions: BTreeSet<String>,
    /// All protocol extensions which the token supports.
    pub extensions: Option<Vec<String>>,
    /// The claimed AAGUID.
    pub aaguid: Option<Uuid>,
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
    pub max_serialized_large_blob_array: Option<usize>,
    pub force_pin_change: bool,
    /// Current minimum PIN length, in Unicode code points.
    ///
    /// Use [get_min_pin_length][Self::get_min_pin_length] to get a default
    /// value for when this is not present.
    pub min_pin_length: Option<usize>,
    pub firmware_version: Option<i128>,
    pub max_cred_blob_length: Option<usize>,
    pub max_rpids_for_set_min_pin_length: Option<u32>,
    pub preferred_platform_uv_attempts: Option<u32>,
    pub uv_modality: Option<u32>,
    pub certifications: Option<BTreeMap<String, u8>>,

    /// Estimated number of additional discoverable credentials which could be
    /// created on the authenticator, assuming *maximally-sized* fields for all
    /// requests (ie: errs low).
    ///
    /// If a request to create a maximally-sized discoverable credential *might*
    /// fail due to storage constraints, the authenticator reports 0.
    ///
    /// This value may vary over time, depending on the size of individual
    /// discoverable credentials, and the token's storage allocation strategy.
    ///
    /// ## CTAP compatibility
    ///
    /// This field is **optional**, and may only be present on authenticators
    /// supporting CTAP 2.1 and later.
    ///
    /// On authenticators supporting [credential management][0] (including CTAP
    /// 2.1-PRE), an optimistic estimate (ie: presuming *minimally-sized*
    /// fields) may be available from
    /// [`CredentialStorageMetadata::max_possible_remaining_resident_credentials_count`][1].
    ///
    /// [0]: crate::ctap2::CredentialManagementAuthenticator
    /// [1]: super::CredentialStorageMetadata::max_possible_remaining_resident_credentials_count
    pub remaining_discoverable_credentials: Option<u32>,

    pub vendor_prototype_config_commands: Option<BTreeSet<u64>>,
}

impl fmt::Display for GetInfoResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "versions: ")?;
        if self.versions.is_empty() {
            writeln!(f, "N/A")?;
        } else {
            for v in self.versions.iter() {
                write!(f, "{v} ")?;
            }
            writeln!(f)?;
        }

        write!(f, "extensions: ")?;
        for e in self.extensions.iter().flatten() {
            write!(f, "{e} ")?;
        }
        writeln!(f)?;

        match self.aaguid {
            Some(aaguid) => writeln!(f, "aaguid: {aaguid}")?,
            None => writeln!(f, "aaguid: INVALID")?,
        }

        write!(f, "options: ")?;
        for (o, b) in self.options.iter().flatten() {
            write!(f, "{o}:{b} ")?;
        }
        writeln!(f)?;

        if let Some(v) = self.max_msg_size {
            writeln!(f, "max message size: {v}")?;
        }

        write!(f, "PIN protocols: ")?;
        if !self
            .pin_protocols
            .as_ref()
            .map(|v| !v.is_empty())
            .unwrap_or_default()
        {
            writeln!(f, "N/A")?;
        } else {
            for e in self.pin_protocols.iter().flatten() {
                write!(f, "{e} ")?;
            }
            writeln!(f)?;
        }

        if let Some(v) = self.max_cred_count_in_list {
            writeln!(f, "max cred count in list: {v}")?;
        }

        if let Some(v) = self.max_cred_id_len {
            writeln!(f, "max cred ID length: {v}")?;
        }

        write!(f, "transports: ")?;
        if !self
            .transports
            .as_ref()
            .map(|v| !v.is_empty())
            .unwrap_or_default()
        {
            writeln!(f, "N/A")?;
        } else {
            for v in self.transports.iter().flatten() {
                write!(f, "{v} ")?;
            }
            writeln!(f)?;
        }

        if let Some(v) = &self.algorithms {
            writeln!(f, "algorithms: {v:?}")?;
        }

        if let Some(v) = self.max_serialized_large_blob_array {
            writeln!(f, "max serialized large blob array: {v}")?;
        }

        writeln!(f, "force PIN change: {:?}", self.force_pin_change)?;

        if let Some(v) = self.min_pin_length {
            writeln!(f, "minimum PIN length: {v}")?;
        }

        if let Some(v) = self.firmware_version {
            writeln!(f, "firmware version: 0x{v:X}")?;
        }

        if let Some(v) = self.max_cred_blob_length {
            writeln!(f, "max cred blob length: {v}")?;
        }

        if let Some(v) = self.max_rpids_for_set_min_pin_length {
            writeln!(f, "max RPIDs for set minimum PIN length: {v}")?;
        }

        if let Some(v) = self.preferred_platform_uv_attempts {
            writeln!(f, "preferred platform UV attempts: {v}")?;
        }

        if let Some(v) = self.uv_modality {
            writeln!(f, "UV modality: 0x{v:X}")?;
        }

        if let Some(v) = &self.certifications {
            writeln!(f, "certifications: {v:?}")?;
        }

        if let Some(v) = self.remaining_discoverable_credentials {
            writeln!(f, "remaining discoverable credentials: {v}")?;
        }

        if let Some(v) = &self.vendor_prototype_config_commands {
            writeln!(f, "vendor prototype config commands: {v:x?}")?;
        }

        Ok(())
    }
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

    /// Checks if the authenticator supports and has configured CTAP 2.1
    /// biometric authentication.
    ///
    /// See also [`GetInfoResponse::ctap21pre_biometrics`][] for CTAP 2.1-PRE
    /// authenticators.
    ///
    /// # Returns
    ///
    /// * `None`: if not supported.
    /// * `Some(false)`: if supported, but not configured.
    /// * `Some(true)`: if supported and configured.
    pub fn ctap21_biometrics(&self) -> Option<bool> {
        self.get_option("bioEnroll")
    }

    /// Checks if the authenticator supports and has configured CTAP 2.1-PRE
    /// biometric authentication.
    ///
    /// See also [`GetInfoResponse::ctap21_biometrics`][] for CTAP 2.1
    /// authenticators.
    ///
    /// # Returns
    ///
    /// * `None`: if not supported.
    /// * `Some(false)`: if supported, but not configured.
    /// * `Some(true)`: if supported and configured.
    pub fn ctap21pre_biometrics(&self) -> Option<bool> {
        self.get_option("userVerificationMgmtPreview")
    }

    /// Returns `true` if the authenticator supports built-in user verification,
    /// and it has been configured.
    pub fn user_verification_configured(&self) -> bool {
        self.get_option("uv").unwrap_or_default()
    }

    /// Returns `true` if the authenticator supports CTAP 2.1 authenticator
    /// configuration commands.
    pub fn supports_config(&self) -> bool {
        self.get_option("authnrCfg").unwrap_or_default()
    }

    /// Returns `true` if the authenticator supports CTAP 2.1 enterprise
    /// attestation.
    pub fn supports_enterprise_attestation(&self) -> bool {
        self.get_option("ep").is_some()
    }

    /// Returns `true` if user verification is not required for `makeCredential`
    /// requests.
    pub fn make_cred_uv_not_required(&self) -> bool {
        self.get_option("makeCredUvNotRqd").unwrap_or_default()
    }

    /// Returns `true` if the authenticator supports CTAP 2.1 credential
    /// management.
    pub fn ctap21_credential_management(&self) -> bool {
        self.get_option("credMgmt").unwrap_or_default()
    }

    /// Returns `true` if the authenticator supports CTAP 2.1-PRE credential
    /// management.
    pub fn ctap21pre_credential_management(&self) -> bool {
        self.get_option("credentialMgmtPreview").unwrap_or_default()
    }
}

impl TryFrom<BTreeMap<u32, Value>> for GetInfoResponse {
    type Error = &'static str;

    fn try_from(mut raw: BTreeMap<u32, Value>) -> Result<Self, Self::Error> {
        trace!("raw = {:?}", raw);
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
            .and_then(|v| Uuid::from_slice(&v).ok());

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

        let max_serialized_large_blob_array =
            raw.remove(&0x0b).and_then(|v| value_to_usize(v, "0x0b"));

        let force_pin_change = raw
            .remove(&0x0c)
            .and_then(|v| value_to_bool(&v, "0x0c"))
            .unwrap_or_default();

        let min_pin_length = raw.remove(&0x0d).and_then(|v| value_to_usize(v, "0x0d"));

        let firmware_version = raw.remove(&0x0e).and_then(|v| value_to_i128(v, "0x0e"));

        let max_cred_blob_length = raw.remove(&0x0f).and_then(|v| value_to_usize(v, "0x0f"));

        let max_rpids_for_set_min_pin_length =
            raw.remove(&0x10).and_then(|v| value_to_u32(&v, "0x10"));

        let preferred_platform_uv_attempts =
            raw.remove(&0x11).and_then(|v| value_to_u32(&v, "0x11"));

        let uv_modality = raw.remove(&0x12).and_then(|v| value_to_u32(&v, "0x12"));

        let certifications = raw
            .remove(&0x13)
            .and_then(|v| value_to_map(v, "0x13"))
            .map(|v| {
                let mut x = BTreeMap::new();
                for (ka, va) in v.into_iter() {
                    if let (Value::Text(s), Value::Integer(i)) = (ka, va) {
                        if let Ok(i) = u8::try_from(i) {
                            x.insert(s, i);
                            continue;
                        }
                    }
                    error!("Invalid value inside 0x13");
                }
                x
            });

        let remaining_discoverable_credentials =
            raw.remove(&0x14).and_then(|v| value_to_u32(&v, "0x14"));

        let vendor_prototype_config_commands =
            raw.remove(&0x15).and_then(|v| value_to_set_u64(v, "0x15"));

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
            max_serialized_large_blob_array,
            force_pin_change,
            min_pin_length,
            firmware_version,
            max_cred_blob_length,
            max_rpids_for_set_min_pin_length,
            preferred_platform_uv_attempts,
            uv_modality,
            certifications,
            remaining_discoverable_credentials,
            vendor_prototype_config_commands,
        })
    }
}

impl From<GetInfoResponse> for BTreeMap<u32, Value> {
    fn from(value: GetInfoResponse) -> Self {
        let GetInfoResponse {
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
            max_serialized_large_blob_array,
            force_pin_change,
            min_pin_length,
            firmware_version,
            max_cred_blob_length,
            max_rpids_for_set_min_pin_length,
            preferred_platform_uv_attempts,
            uv_modality,
            certifications,
            remaining_discoverable_credentials,
            vendor_prototype_config_commands,
        } = value;

        let mut o = BTreeMap::from([(
            0x01,
            Value::Array(versions.into_iter().map(Value::Text).collect()),
        )]);

        if let Some(extensions) = extensions {
            o.insert(
                0x02,
                Value::Array(extensions.into_iter().map(Value::Text).collect()),
            );
        }

        if let Some(aaguid) = aaguid {
            o.insert(0x03, Value::Bytes(aaguid.as_bytes().to_vec()));
        }

        if let Some(options) = options {
            o.insert(
                0x04,
                Value::Map(
                    options
                        .into_iter()
                        .map(|(k, v)| (Value::Text(k), Value::Bool(v)))
                        .collect(),
                ),
            );
        }

        if let Some(max_msg_size) = max_msg_size {
            o.insert(0x05, Value::Integer(max_msg_size.into()));
        }

        if let Some(pin_protocols) = pin_protocols {
            o.insert(
                0x06,
                Value::Array(
                    pin_protocols
                        .into_iter()
                        .map(|v| Value::Integer(v.into()))
                        .collect(),
                ),
            );
        }

        if let Some(max_cred_count_in_list) = max_cred_count_in_list {
            o.insert(0x07, Value::Integer(max_cred_count_in_list.into()));
        }

        if let Some(max_cred_id_len) = max_cred_id_len {
            o.insert(0x08, Value::Integer(max_cred_id_len.into()));
        }

        if let Some(transports) = transports {
            o.insert(
                0x09,
                Value::Array(transports.into_iter().map(Value::Text).collect()),
            );
        }

        if let Some(algorithms) = algorithms {
            o.insert(0x0a, algorithms);
        }

        if let Some(v) = max_serialized_large_blob_array {
            o.insert(0x0b, Value::Integer((v as u32).into()));
        }

        if force_pin_change {
            o.insert(0x0c, Value::Bool(true));
        }

        if let Some(min_pin_length) = min_pin_length {
            o.insert(0x0d, Value::Integer((min_pin_length as u64).into()));
        }

        if let Some(v) = firmware_version {
            o.insert(0x0e, Value::Integer(v));
        }

        if let Some(v) = max_cred_blob_length {
            o.insert(0x0f, Value::Integer((v as u64).into()));
        }

        if let Some(v) = max_rpids_for_set_min_pin_length {
            o.insert(0x10, Value::Integer(v.into()));
        }

        if let Some(v) = preferred_platform_uv_attempts {
            o.insert(0x11, Value::Integer(v.into()));
        }

        if let Some(v) = uv_modality {
            o.insert(0x12, Value::Integer(v.into()));
        }

        if let Some(v) = certifications {
            o.insert(
                0x13,
                Value::Map(
                    v.into_iter()
                        .map(|(k, v)| (Value::Text(k), Value::Integer(v.into())))
                        .collect(),
                ),
            );
        }

        if let Some(v) = remaining_discoverable_credentials {
            o.insert(0x14, Value::Integer(v.into()));
        }

        if let Some(v) = vendor_prototype_config_commands {
            o.insert(
                0x15,
                Value::Array(v.into_iter().map(|v| Value::Integer(v.into())).collect()),
            );
        }

        o
    }
}

crate::deserialize_cbor!(GetInfoResponse);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::iso7816::ISO7816LengthForm;
    use uuid::uuid;

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
        assert_eq!(
            a.aaguid,
            Some(uuid!("2fc0579f-8113-47ea-b116-bb5a8db9202a"))
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
    fn token2_nfc() {
        let _ = tracing_subscriber::fmt().try_init();

        let raw_apdu = vec![
            178, 1, 132, 102, 85, 50, 70, 95, 86, 50, 104, 70, 73, 68, 79, 95, 50, 95, 48, 104, 70,
            73, 68, 79, 95, 50, 95, 49, 108, 70, 73, 68, 79, 95, 50, 95, 49, 95, 80, 82, 69, 2,
            133, 104, 99, 114, 101, 100, 66, 108, 111, 98, 107, 99, 114, 101, 100, 80, 114, 111,
            116, 101, 99, 116, 107, 104, 109, 97, 99, 45, 115, 101, 99, 114, 101, 116, 108, 108,
            97, 114, 103, 101, 66, 108, 111, 98, 75, 101, 121, 108, 109, 105, 110, 80, 105, 110,
            76, 101, 110, 103, 116, 104, 3, 80, 171, 50, 240, 198, 34, 57, 175, 187, 196, 112, 210,
            239, 78, 37, 77, 183, 4, 172, 98, 114, 107, 245, 98, 117, 112, 245, 100, 112, 108, 97,
            116, 244, 104, 97, 108, 119, 97, 121, 115, 85, 118, 244, 104, 99, 114, 101, 100, 77,
            103, 109, 116, 245, 105, 97, 117, 116, 104, 110, 114, 67, 102, 103, 245, 105, 99, 108,
            105, 101, 110, 116, 80, 105, 110, 245, 106, 108, 97, 114, 103, 101, 66, 108, 111, 98,
            115, 245, 110, 112, 105, 110, 85, 118, 65, 117, 116, 104, 84, 111, 107, 101, 110, 245,
            111, 115, 101, 116, 77, 105, 110, 80, 73, 78, 76, 101, 110, 103, 116, 104, 245, 112,
            109, 97, 107, 101, 67, 114, 101, 100, 85, 118, 78, 111, 116, 82, 113, 100, 245, 117,
            99, 114, 101, 100, 101, 110, 116, 105, 97, 108, 77, 103, 109, 116, 80, 114, 101, 118,
            105, 101, 119, 245, 5, 25, 6, 0, 6, 130, 2, 1, 7, 8, 8, 24, 96, 9, 130, 99, 117, 115,
            98, 99, 110, 102, 99, 10, 129, 162, 99, 97, 108, 103, 38, 100, 116, 121, 112, 101, 106,
            112, 117, 98, 108, 105, 99, 45, 107, 101, 121, 11, 25, 8, 0, 12, 244, 13, 4, 14, 25, 1,
            0, 15, 24, 32, 16, 6, 19, 161, 100, 70, 73, 68, 79, 1, 20, 24, 50,
        ];
        let a = <GetInfoResponse as CBORResponse>::try_from(raw_apdu.as_slice())
            .expect("Falied to decode apdu");

        // info!(?a);
        assert_eq!(a.versions.len(), 4);
        assert!(a.versions.contains("U2F_V2"));
        assert!(a.versions.contains("FIDO_2_0"));
        assert!(a.versions.contains("FIDO_2_1_PRE"));
        assert!(a.versions.contains("FIDO_2_1"));

        assert_eq!(
            a.extensions,
            Some(vec![
                "credBlob".to_string(),
                "credProtect".to_string(),
                "hmac-secret".to_string(),
                "largeBlobKey".to_string(),
                "minPinLength".to_string()
            ])
        );

        assert_eq!(
            a.aaguid,
            Some(uuid!("ab32f0c6-2239-afbb-c470-d2ef4e254db7"))
        );

        assert_eq!(a.get_option("alwaysUv"), Some(false));
        assert_eq!(a.get_option("authnrCfg"), Some(true));
        assert!(a.supports_config());
        assert_eq!(a.get_option("clientPin"), Some(true));
        assert_eq!(a.get_option("credMgmt"), Some(true));
        assert_eq!(a.get_option("credentialMgmtPreview"), Some(true));
        assert_eq!(a.get_option("largeBlobs"), Some(true));
        assert_eq!(a.get_option("makeCredUvNotRqd"), Some(true));
        assert!(a.make_cred_uv_not_required());
        assert_eq!(a.get_option("pinUvAuthToken"), Some(true));
        assert_eq!(a.get_option("plat"), Some(false));
        assert_eq!(a.get_option("rk"), Some(true));
        assert_eq!(a.get_option("setMinPINLength"), Some(true));
        assert_eq!(a.get_option("up"), Some(true));

        assert!(a.ctap21_biometrics().is_none());
        assert!(a.ctap21pre_biometrics().is_none());
        assert!(!a.supports_enterprise_attestation());
        assert!(!a.user_verification_configured());

        assert_eq!(a.max_msg_size, Some(1536));
        assert_eq!(a.pin_protocols, Some(vec![2, 1]));
        assert_eq!(a.max_cred_count_in_list, Some(8));
        assert_eq!(a.max_cred_id_len, Some(96));
        assert_eq!(
            a.transports,
            Some(vec!["usb".to_string(), "nfc".to_string()])
        );
        assert_eq!(
            a.get_transports(),
            Some(vec![
                AuthenticatorTransport::Usb,
                AuthenticatorTransport::Nfc
            ])
        );

        assert_eq!(a.max_serialized_large_blob_array, Some(2048));
        assert!(!a.force_pin_change);
        assert_eq!(a.min_pin_length, Some(4));
        assert_eq!(a.get_min_pin_length(), 4);
        assert_eq!(a.firmware_version, Some(0x100));
        assert_eq!(a.max_cred_blob_length, Some(32));
        assert_eq!(a.max_rpids_for_set_min_pin_length, Some(6));
        assert!(a.preferred_platform_uv_attempts.is_none());
        assert!(a.uv_modality.is_none());
        assert_eq!(
            a.certifications,
            Some(BTreeMap::from([("FIDO".to_string(), 1)]))
        );
        assert_eq!(a.remaining_discoverable_credentials, Some(50));
        assert!(a.vendor_prototype_config_commands.is_none());
    }

    #[test]
    fn get_info_request() {
        let req = GetInfoRequest {};
        let short = vec![0x80, 0x10, 0, 0, 1, 0x4, 0];
        let ext = vec![0x80, 0x10, 0, 0, 0, 0, 1, 0x4, 0, 0];

        let a = to_short_apdus(&req.cbor().unwrap());
        assert_eq!(1, a.len());
        assert_eq!(short, a[0].to_bytes(&ISO7816LengthForm::ShortOnly).unwrap());
        assert_eq!(short, a[0].to_bytes(&ISO7816LengthForm::Extended).unwrap());

        assert_eq!(
            ext,
            to_extended_apdu(req.cbor().unwrap())
                .to_bytes(&ISO7816LengthForm::Extended)
                .unwrap()
        );
        assert_eq!(
            ext,
            to_extended_apdu(req.cbor().unwrap())
                .to_bytes(&ISO7816LengthForm::ExtendedOnly)
                .unwrap()
        );
        assert!(to_extended_apdu(req.cbor().unwrap())
            .to_bytes(&ISO7816LengthForm::ShortOnly)
            .is_err());
    }
}

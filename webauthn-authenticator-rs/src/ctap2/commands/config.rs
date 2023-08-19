use serde::Serialize;
use serde_cbor_2::Value;

use self::CBORCommand;
use super::*;

/// `authenticatorConfig` request type.
///
/// See [ConfigSubCommand] and [ConfigRequest::new] for details on how to
/// construct a new [ConfigRequest].
///
/// This has no response type.
///
/// Reference: <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorConfig>
#[derive(Serialize, Debug, Clone, Default, PartialEq, Eq)]
#[serde(into = "BTreeMap<u32, Value>")]
pub struct ConfigRequest {
    /// Action being requested
    sub_command: u8,
    sub_command_params: Option<BTreeMap<Value, Value>>,
    /// PIN / UV protocol version chosen by the platform
    pin_uv_protocol: Option<u32>,
    /// Output of calling "Authenticate" on some context specific to [Self::sub_command]
    pin_uv_auth_param: Option<Vec<u8>>,
}

impl CBORCommand for ConfigRequest {
    const CMD: u8 = 0x0d;
    type Response = NoResponse;
}

/// Subcommands for [ConfigRequest].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ConfigSubCommand {
    #[default]
    Unknown,
    /// Enables the [enterprise attestation] feature.
    ///
    /// [enterprise attestation]: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#enable-enterprise-attestation
    EnableEnterpriseAttestation,
    /// Toggles the [always require user verification] feature.
    ///
    /// [always require user verification]: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#toggle-alwaysUv
    ToggleAlwaysUv,
    /// Sets a [minimum PIN length] policy.
    ///
    /// See [SetMinPinLengthParams] for further details.
    ///
    /// [minimum PIN length]: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#setMinPINLength
    SetMinPinLength(SetMinPinLengthParams),
    // VendorPrototype,
}

/// Parameters for setting minimum PIN length in a [ConfigRequest].
#[derive(Serialize, Debug, Clone, Default, PartialEq, Eq)]
#[serde(into = "BTreeMap<Value, Value>")]
pub struct SetMinPinLengthParams {
    /// Minimum PIN length, in Unicode code points.
    pub new_min_pin_length: Option<u32>,
    /// Relying Party IDs which are allowed to request this information via the
    /// `minPinLength` extension.
    pub min_pin_length_rpids: Vec<String>,
    /// If set to `true`, invalidates the authenticator's existing PIN, and
    /// forces the PIN to be changed before it can be used again.
    pub force_change_pin: Option<bool>,
}

impl From<&ConfigSubCommand> for u8 {
    fn from(c: &ConfigSubCommand) -> Self {
        use ConfigSubCommand::*;
        match c {
            Unknown => 0x00,
            EnableEnterpriseAttestation => 0x01,
            ToggleAlwaysUv => 0x02,
            SetMinPinLength(_) => 0x03,
            // VendorPrototype => 0xff,
        }
    }
}

impl From<ConfigSubCommand> for Option<BTreeMap<Value, Value>> {
    fn from(c: ConfigSubCommand) -> Self {
        use ConfigSubCommand::*;
        match c {
            SetMinPinLength(p) => Some(p.into()),
            Unknown => None,
            EnableEnterpriseAttestation => None,
            ToggleAlwaysUv => None,
            // VendorPrototype => unimplemented!(),
        }
    }
}

impl ConfigSubCommand {
    pub fn prf(&self) -> Vec<u8> {
        // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#prfValues
        let sub_command = self.into();
        let sub_command_params: Option<BTreeMap<Value, Value>> = self.to_owned().into();

        let mut o = vec![0xff; 32];
        o.push(ConfigRequest::CMD);
        o.push(sub_command);
        if let Some(p) = sub_command_params
            .as_ref()
            .and_then(|p| serde_cbor_2::to_vec(p).ok())
        {
            o.extend_from_slice(p.as_slice())
        }

        o
    }
}

impl ConfigRequest {
    pub fn new(
        s: ConfigSubCommand,
        pin_uv_protocol: Option<u32>,
        pin_uv_auth_param: Option<Vec<u8>>,
    ) -> Self {
        let sub_command = (&s).into();
        let sub_command_params = s.into();

        Self {
            sub_command,
            sub_command_params,
            pin_uv_protocol,
            pin_uv_auth_param,
        }
    }
}

impl From<ConfigRequest> for BTreeMap<u32, Value> {
    fn from(value: ConfigRequest) -> Self {
        let ConfigRequest {
            sub_command,
            sub_command_params,
            pin_uv_protocol,
            pin_uv_auth_param,
        } = value;

        let mut keys = BTreeMap::new();
        keys.insert(0x01, Value::Integer(sub_command.into()));

        if let Some(v) = sub_command_params {
            keys.insert(0x02, Value::Map(v));
        }

        if let Some(v) = pin_uv_protocol {
            keys.insert(0x03, Value::Integer(v.to_owned().into()));
        }
        if let Some(v) = pin_uv_auth_param {
            keys.insert(0x04, Value::Bytes(v));
        }

        keys
    }
}

impl From<SetMinPinLengthParams> for BTreeMap<Value, Value> {
    fn from(value: SetMinPinLengthParams) -> Self {
        let SetMinPinLengthParams {
            new_min_pin_length,
            min_pin_length_rpids,
            force_change_pin,
        } = value;

        let mut keys = BTreeMap::new();

        if let Some(v) = new_min_pin_length {
            keys.insert(Value::Integer(0x01), Value::Integer(v.to_owned().into()));
        }

        if !min_pin_length_rpids.is_empty() {
            keys.insert(
                Value::Integer(0x02),
                Value::Array(
                    min_pin_length_rpids
                        .iter()
                        .map(|v| Value::Text(v.clone()))
                        .collect(),
                ),
            );
        }

        if let Some(v) = force_change_pin {
            keys.insert(Value::Integer(0x03), Value::Bool(v.to_owned()));
        }

        keys
    }
}

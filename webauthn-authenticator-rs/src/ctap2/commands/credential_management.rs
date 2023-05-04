//! `authenticatorCredentialManagement` commands.
//!

use serde::{Deserialize, Serialize};
use serde_cbor::{
    ser::to_vec_packed,
    value::{from_value, to_value},
    Value,
};
use std::fmt::Debug;
use webauthn_rs_core::proto::COSEKey;
use webauthn_rs_proto::{PublicKeyCredentialDescriptor, RelyingParty, User};

use super::*;

/// Macro to generate for both CTAP 2.1 and 2.1-PRE.
macro_rules! cred_struct {
    (
        $(#[$outer:meta])*
        $vis:vis struct $name:ident = $cmd:tt
    ) => {
        $(#[$outer])*
        ///
        /// Related:
        ///
        /// * [xxxxx] for dynamically-constructed commands
        ///
        /// Reference: [CTAP protocol reference][ref]
        #[derive(Serialize, Debug, Clone, Default, PartialEq, Eq)]
        #[serde(into = "BTreeMap<u32, Value>")]
        pub struct $name {
            /// Action being requested
            sub_command: Option<u8>,
            sub_command_params: Option<BTreeMap<Value, Value>>,
            /// PIN / UV protocol version chosen by the platform
            pin_uv_protocol: Option<u32>,
            /// Output of calling "Authenticate" on some context specific to [Self::sub_command]
            pin_uv_auth_param: Option<Vec<u8>>,
        }

        impl CBORCommand for $name {
            const CMD: u8 = $cmd;
            type Response = CredentialManagementResponse;
        }

        impl CredentialManagementRequestTrait for $name {
/*
            const GET_MODALITY: Self = Self {
                get_modality: true,
                modality: None,
                sub_command: None,
                sub_command_params: None,
                pin_uv_protocol: None,
                pin_uv_auth_param: None,
            };

            const GET_FINGERPRINT_SENSOR_INFO: Self = Self {
                modality: Some(Modality::Fingerprint),
                sub_command: Some(0x07), // getFingerprintSensorInfo
                sub_command_params: None,
                pin_uv_protocol: None,
                pin_uv_auth_param: None,
                get_modality: false,
            };

            const FINGERPRINT_CANCEL_CURRENT_ENROLLMENT: Self =
                Self {
                    modality: Some(Modality::Fingerprint),
                    sub_command: Some(0x03), // cancelCurrentEnrollment
                    sub_command_params: None,
                    pin_uv_protocol: None,
                    pin_uv_auth_param: None,
                    get_modality: false,
                };
 */
            fn new(
                s: CredSubCommand,
                pin_uv_protocol: Option<u32>,
                pin_uv_auth_param: Option<Vec<u8>>,
            ) -> Self {
                let sub_command = (&s).into();
                let sub_command_params = s.into();

                Self {
                    sub_command: Some(sub_command),
                    sub_command_params,
                    pin_uv_protocol,
                    pin_uv_auth_param,
                }
            }
        }

        impl From<$name> for BTreeMap<u32, Value> {
            fn from(value: $name) -> Self {
                let $name {
                    sub_command,
                    sub_command_params,
                    pin_uv_protocol,
                    pin_uv_auth_param,
                } = value;

                let mut keys = BTreeMap::new();

                if let Some(v) = sub_command {
                    keys.insert(0x01, Value::Integer(v.into()));
                }

                if let Some(v) = sub_command_params {
                    keys.insert(0x02, Value::Map(v));
                }

                if let Some(v) = pin_uv_protocol {
                    keys.insert(0x03, Value::Integer(v.into()));
                }

                if let Some(v) = pin_uv_auth_param {
                    keys.insert(0x04, Value::Bytes(v));
                }

                keys
            }
        }
    };
}

/// Common functionality for CTAP 2.1 and 2.1-PRE `CredentialManegement` request types.
pub trait CredentialManagementRequestTrait:
    CBORCommand<Response = CredentialManagementResponse>
{
    /// Creates a new [CredentialManagementRequest] from the given [CredSubCommand].
    fn new(
        s: CredSubCommand,
        pin_uv_protocol: Option<u32>,
        pin_uv_auth_param: Option<Vec<u8>>,
    ) -> Self;
}

/// Wrapper for credential management command types, which can be passed to
/// [CredentialManagementRequestTrait::new].
///
/// Static commands are declared as constants of [CredentialManagementRequestTrait], see:
///
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum CredSubCommand {
    #[default]
    Unknown,
    GetCredsMetadata,  // 1 empty
    EnumerateRPsBegin, // 2 empty
    EnumerateRPsGetNextRP,
    EnumerateCredentialsBegin(/* rpIdHash */ Vec<u8>), // 4 map
    EnumerateCredentialsGetNextCredential,
    DeleteCredential(PublicKeyCredentialDescriptor), // 6 map
    UpdateUserInformation(PublicKeyCredentialDescriptor, User), // 7 map
}

impl From<&CredSubCommand> for u8 {
    fn from(c: &CredSubCommand) -> Self {
        use CredSubCommand::*;
        match c {
            Unknown => 0x00,
            GetCredsMetadata => 0x01,
            EnumerateRPsBegin => 0x02,
            EnumerateRPsGetNextRP => 0x03,
            EnumerateCredentialsBegin(_) => 0x04,
            EnumerateCredentialsGetNextCredential => 0x05,
            DeleteCredential(_) => 0x06,
            UpdateUserInformation(_, _) => 0x07,
        }
    }
}

impl From<CredSubCommand> for Option<BTreeMap<Value, Value>> {
    fn from(c: CredSubCommand) -> Self {
        use CredSubCommand::*;
        match c {
            Unknown
            | GetCredsMetadata
            | EnumerateRPsBegin
            | EnumerateRPsGetNextRP
            | EnumerateCredentialsGetNextCredential => None,
            EnumerateCredentialsBegin(rp_id_hash) => Some(BTreeMap::from([(
                Value::Integer(0x01),
                Value::Bytes(rp_id_hash),
            )])),
            DeleteCredential(credential_id) => Some(BTreeMap::from([(
                Value::Integer(0x02),
                to_value(&credential_id).ok()?,
            )])),
            UpdateUserInformation(credential_id, user) => Some(BTreeMap::from([
                (Value::Integer(0x02), to_value(&credential_id).ok()?),
                (Value::Integer(0x03), to_value(&user).ok()?),
            ])),
        }
    }
}

impl CredSubCommand {
    pub fn prf(&self) -> Vec<u8> {
        // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#prfValues
        let subcommand = self.into();
        let sub_command_params: Option<BTreeMap<Value, Value>> = self.to_owned().into();

        let mut o = Vec::new();
        o.push(subcommand);
        if let Some(p) = sub_command_params
            .as_ref()
            .and_then(|p| to_vec_packed(p).ok())
        {
            o.extend_from_slice(p.as_slice())
        }

        o
    }

    pub fn needs_auth(&self) -> bool {
        use CredSubCommand::*;
        !matches!(self, EnumerateRPsGetNextRP | EnumerateCredentialsGetNextCredential)
    }
}

/// `authenticatorCredentialManagement` response type.
///
/// References:
/// * <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorCredentialManagement>
/// * <https://fidoalliance.org/specs/fido2/vendor/CredentialManagementPrototype.pdf>
#[derive(Deserialize, Debug, Default, PartialEq, Eq)]
#[serde(try_from = "BTreeMap<u32, Value>")]
pub struct CredentialManagementResponse {
    /// Number of existing discoverable credentials present on the authenticator.
    pub existing_resident_credentials_count: Option<u32>,
    /// Maximum possible number of remaining discoverable credentials which can
    /// be created on the authenticator.
    pub max_possible_remaining_resident_credentials_count: Option<u32>,
    pub rp: Option<RelyingParty>,
    pub rp_id_hash: Option<Vec<u8>>,
    pub total_rps: Option<u32>,
    pub user: Option<User>,
    pub credential_id: Option<PublicKeyCredentialDescriptor>,
    pub public_key: Option<COSEKey>,
    pub total_credentials: Option<u32>,
    pub cred_protect: Option<u32>,
    pub large_blob_key: Option<Vec<u8>>,
}

impl TryFrom<BTreeMap<u32, Value>> for CredentialManagementResponse {
    type Error = &'static str;
    fn try_from(mut raw: BTreeMap<u32, Value>) -> Result<Self, Self::Error> {
        trace!(?raw);
        Ok(Self {
            existing_resident_credentials_count: raw
                .remove(&0x01)
                .and_then(|v| value_to_u32(&v, "0x01")),
            max_possible_remaining_resident_credentials_count: raw
                .remove(&0x02)
                .and_then(|v| value_to_u32(&v, "0x02")),
            rp: if let Some(v) = raw.remove(&0x03) {
                Some(from_value(v).map_err(|e| {
                    error!("parsing rp: {e:?}");
                    "parsing rp"
                })?)
            } else {
                None
            },
            rp_id_hash: raw.remove(&0x04).and_then(|v| value_to_vec_u8(v, "0x04")),
            total_rps: raw.remove(&0x05).and_then(|v| value_to_u32(&v, "0x05")),
            user: if let Some(v) = raw.remove(&0x06) {
                Some(from_value(v).map_err(|e| {
                    error!("Mapping user: {e:?}");
                    "parsing user"
                })?)
            } else {
                None
            },
            credential_id: if let Some(v) = raw.remove(&0x07) {
                Some(from_value(v).map_err(|e| {
                    error!("Mapping credentialID: {e:?}");
                    "parsing credentialID"
                })?)
            } else {
                None
            },
            public_key: if let Some(v) = raw.remove(&0x09) {
                Some(from_value(v).map_err(|e| {
                    error!("Mapping publicKey: {e:?}");
                    "parsing publicKey"
                })?)
            } else {
                None
            },
            total_credentials: raw.remove(&0x09).and_then(|v| value_to_u32(&v, "0x09")),
            cred_protect: raw.remove(&0x0A).and_then(|v| value_to_u32(&v, "0x0A")),
            large_blob_key: raw.remove(&0x0B).and_then(|v| value_to_vec_u8(v, "0x0B"))
        })
    }
}

crate::deserialize_cbor!(CredentialManagementResponse);

cred_struct! {
    /// CTAP 2.1 `authenticatorCredentialManagement` command (`0x0a`).
    ///
    /// [ref]: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorCredentialManagement
    pub struct CredentialManagementRequest = 0x0a
}

cred_struct! {
    /// CTAP 2.1-PRE prototype `authenticatorCredentialManagement` command (`0x41`).
    ///
    /// [ref]: https://fidoalliance.org/specs/fido2/vendor/CredentialManagementPrototype.pdf
    pub struct PrototypeCredentialManagementRequest = 0x41
}

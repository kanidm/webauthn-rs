//! `authenticatorCredentialManagement` commands.
//!

use std::{fmt::Debug, time::Duration};
use num_traits::cast::{FromPrimitive, ToPrimitive};
use serde::{Deserialize, Serialize};
use serde_cbor::Value; 

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
pub trait CredentialManagementRequestTrait: CBORCommand<Response = CredentialManagementResponse> {
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
    GetCredsMetadata, // 1 empty
    EnumerateRPsBegin, // 2 empty
    EnumerateRPsGetNextRP,  
    EnumerateCredentialsBegin, // 4 map
    EnumerateCredentialsGetNextCredential,
    DeleteCredential,  // 6 map
    UpdateUserInformation,// 7 map

}

impl From<&CredSubCommand> for u8 {
    fn from(c: &CredSubCommand) -> Self {
        use CredSubCommand::*;
        match c {
            Unknown => 0x00,
            GetCredsMetadata => 0x01,
            EnumerateRPsBegin => 0x02,
            EnumerateRPsGetNextRP => 0x03,
            EnumerateCredentialsBegin => 0x04,
            EnumerateCredentialsGetNextCredential => 0x05,
            DeleteCredential => 0x06,
            UpdateUserInformation => 0x07,
        }
    }
}

impl From<CredSubCommand> for Option<BTreeMap<Value, Value>> {
    fn from(c: CredSubCommand) -> Self {
        use CredSubCommand::*;
        match c {
            Unknown | GetCredsMetadata | EnumerateRPsBegin | EnumerateRPsGetNextRP | EnumerateCredentialsGetNextCredential => None,
            // TODO
            EnumerateCredentialsBegin => todo!(),
            DeleteCredential => todo!(),
            UpdateUserInformation => todo!(),
            
            
            // FingerprintEnrollBegin(timeout) => Some(BTreeMap::from([(
            //     Value::Integer(0x03),
            //     Value::Integer(timeout.as_millis() as i128),
            // )])),
            // FingerprintEnrollCaptureNextSample(id, timeout) => Some(BTreeMap::from([
            //     (Value::Integer(0x01), Value::Bytes(id)),
            //     (
            //         Value::Integer(0x03),
            //         Value::Integer(timeout.as_millis() as i128),
            //     ),
            // ])),
            // FingerprintEnumerateEnrollments => None,
            // FingerprintSetFriendlyName(t) => t.try_into().ok(),
            // FingerprintRemoveEnrollment(id) => {
            //     Some(BTreeMap::from([(Value::Integer(0x01), Value::Bytes(id))]))
            // }
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
            .and_then(|p| serde_cbor::to_vec(p).ok())
        {
            o.extend_from_slice(p.as_slice())
        }

        o
    }
}

/// `authenticatorBioEnrollment` response type.
///
/// References:
/// * <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorBioEnrollment>
/// * <https://fidoalliance.org/specs/fido2/vendor/BioEnrollmentPrototype.pdf>
#[derive(Deserialize, Debug, Default, PartialEq, Eq)]
#[serde(try_from = "BTreeMap<u32, Value>")]
pub struct CredentialManagementResponse {

}

impl TryFrom<BTreeMap<u32, Value>> for CredentialManagementResponse {
    type Error = &'static str;
    fn try_from(mut raw: BTreeMap<u32, Value>) -> Result<Self, Self::Error> {
        trace!(?raw);
        Ok(Self {
            // modality: raw
            //     .remove(&0x01)
            //     .and_then(|v| value_to_u32(&v, "0x01"))
            //     .and_then(Modality::from_u32),
            // fingerprint_kind: raw
            //     .remove(&0x02)
            //     .and_then(|v| value_to_u32(&v, "0x02"))
            //     .and_then(FingerprintKind::from_u32),
            // max_capture_samples_required_for_enroll: raw
            //     .remove(&0x03)
            //     .and_then(|v| value_to_u32(&v, "0x03")),
            // template_id: raw.remove(&0x04).and_then(|v| value_to_vec_u8(v, "0x04")),
            // last_enroll_sample_status: raw
            //     .remove(&0x05)
            //     .and_then(|v| value_to_u32(&v, "0x05"))
            //     .and_then(EnrollSampleStatus::from_u32),
            // remaining_samples: raw.remove(&0x06).and_then(|v| value_to_u32(&v, "0x06")),
            // template_infos: raw
            //     .remove(&0x07)
            //     .and_then(|v| {
            //         if let Value::Array(v) = v {
            //             let mut infos = vec![];
            //             for i in v {
            //                 if let Value::Map(i) = i {
            //                     if let Ok(i) = TemplateInfo::try_from(i) {
            //                         infos.push(i)
            //                     }
            //                 }
            //             }
            //             Some(infos)
            //         } else {
            //             None
            //         }
            //     })
            //     .unwrap_or_default(),
            // max_template_friendly_name: raw
            //     .remove(&0x08)
            //     .and_then(|v| value_to_u32(&v, "0x08"))
            //     .map(|v| v as usize),
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
    pub struct PrototypeCredentialManagementRequest = 0x40
}


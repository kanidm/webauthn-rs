//! `authenticatorBioEnrollment` commands.
//!
//! CTAP 2.1 defines two `authenticatorBioEnrollment` command and response
//! types, [standard][ctap21] and [prototype][ctap21pre]. Both have the same
//! parameters.
//!
//! In order to provide a consistent API and only have to write this once, the
//! [bio_struct!][] macro provides all the BioEnrollment request functionality,
//! and creates two structs:
//!
//! * [BioEnrollmentRequest]: [CTAP 2.1 version][ctap21] (`0x09`)
//! * [PrototypeBioEnrollmentRequest]: [CTAP 2.1-PRE version][ctap21pre] (`0x40`)
//!
//! Both implement [BioEnrollmentRequestTrait] for common functionality, and
//! return [BioEnrollmentResponse] to commands.
//!
//! [ctap21]: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorBioEnrollment
//! [ctap21pre]: https://fidoalliance.org/specs/fido2/vendor/BioEnrollmentPrototype.pdf
use std::{fmt::Debug, time::Duration};

use num_traits::cast::{FromPrimitive, ToPrimitive};
use serde::{Deserialize, Serialize};
use serde_cbor_2::Value;

use crate::types::EnrollSampleStatus;

use super::*;

/// Default maximum fingerprint friendly name length, in bytes.
///
/// Reference: <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#setFriendlyName>
const DEFAULT_MAX_FRIENDLY_NAME: usize = 64;

/// Macro to generate [BioEnrollmentRequest] for both CTAP 2.1 and 2.1-PRE.
macro_rules! bio_struct {
    (
        $(#[$outer:meta])*
        $vis:vis struct $name:ident = $cmd:tt
    ) => {
        $(#[$outer])*
        ///
        /// Related:
        ///
        /// * [BioSubCommand] for dynamically-constructed commands
        /// * [GET_MODALITY][Self::GET_MODALITY]
        /// * [GET_FINGERPRINT_SENSOR_INFO][Self::GET_FINGERPRINT_SENSOR_INFO]
        /// * [FINGERPRINT_CANCEL_CURRENT_ENROLLMENT][Self::FINGERPRINT_CANCEL_CURRENT_ENROLLMENT]
        ///
        /// Reference: [CTAP protocol reference][ref]
        #[derive(Serialize, Debug, Clone, Default, PartialEq, Eq)]
        #[serde(into = "BTreeMap<u32, Value>")]
        pub struct $name {
            modality: Option<Modality>,
            /// Action being requested (specific to modality)
            sub_command: Option<u8>,
            sub_command_params: Option<BTreeMap<Value, Value>>,
            /// PIN / UV protocol version chosen by the platform
            pin_uv_protocol: Option<u32>,
            /// Output of calling "Authenticate" on some context specific to [Self::sub_command]
            pin_uv_auth_param: Option<Vec<u8>>,
            /// Gets the supported bio modality for the authenticator.
            ///
            /// See [GET_MODALITY][Self::GET_MODALITY].
            get_modality: bool,
        }

        impl CBORCommand for $name {
            const CMD: u8 = $cmd;
            type Response = BioEnrollmentResponse;
        }

        impl BioEnrollmentRequestTrait for $name {
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

            fn new(
                s: BioSubCommand,
                pin_uv_protocol: Option<u32>,
                pin_uv_auth_param: Option<Vec<u8>>,
            ) -> Self {
                let (modality, sub_command) = (&s).into();
                let sub_command_params = s.into();

                Self {
                    modality: Some(modality),
                    sub_command: Some(sub_command),
                    sub_command_params,
                    pin_uv_protocol,
                    pin_uv_auth_param,
                    get_modality: false,
                }
            }
        }

        impl From<$name> for BTreeMap<u32, Value> {
            fn from(value: $name) -> Self {
                let $name {
                    modality,
                    sub_command,
                    sub_command_params,
                    pin_uv_protocol,
                    pin_uv_auth_param,
                    get_modality,
                } = value;

                let mut keys = BTreeMap::new();

                modality
                    .and_then(|v| v.to_i128())
                    .map(|v| keys.insert(0x01, Value::Integer(v)));

                if let Some(v) = sub_command {
                    keys.insert(0x02, Value::Integer(v.into()));
                }

                if let Some(v) = sub_command_params {
                    keys.insert(0x03, Value::Map(v));
                }

                if let Some(v) = pin_uv_protocol {
                    keys.insert(0x04, Value::Integer(v.into()));
                }

                if let Some(v) = pin_uv_auth_param {
                    keys.insert(0x05, Value::Bytes(v));
                }

                if get_modality {
                    keys.insert(0x06, Value::Bool(true));
                }

                keys
            }
        }
    };
}

/// Common functionality for CTAP 2.1 and 2.1-PRE `BioEnrollment` request types.
pub trait BioEnrollmentRequestTrait: CBORCommand<Response = BioEnrollmentResponse> {
    /// Command to get the supported biometric modality for the authenticator.
    ///
    /// <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#getUserVerificationModality>
    const GET_MODALITY: Self;

    /// Command to get information about the authenticator's fingerprint sensor.
    ///
    /// <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#getFingerprintSensorInfo>
    const GET_FINGERPRINT_SENSOR_INFO: Self;

    /// Command to cancel an in-progress fingerprint enrollment.
    ///
    /// <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#cancelEnrollment>
    const FINGERPRINT_CANCEL_CURRENT_ENROLLMENT: Self;

    /// Creates a new [BioEnrollmentRequest] from the given [BioSubCommand].
    fn new(
        s: BioSubCommand,
        pin_uv_protocol: Option<u32>,
        pin_uv_auth_param: Option<Vec<u8>>,
    ) -> Self;
}

/// Metadata about a stored fingerprint.
#[derive(Deserialize, Debug, Default, PartialEq, Eq, Clone)]
#[serde(try_from = "BTreeMap<Value, Value>")]
pub struct TemplateInfo {
    /// The `template_id` of the fingerprint.
    pub id: Vec<u8>,

    /// A human-readable name for the fingerprint.
    pub friendly_name: Option<String>,
}

impl TryFrom<BTreeMap<Value, Value>> for TemplateInfo {
    type Error = &'static str;
    fn try_from(mut raw: BTreeMap<Value, Value>) -> Result<Self, Self::Error> {
        // trace!(?raw);
        Ok(Self {
            id: raw
                .remove(&Value::Integer(0x01))
                .and_then(|v| value_to_vec_u8(v, "0x01"))
                .unwrap_or_default(),
            friendly_name: raw
                .remove(&Value::Integer(0x02))
                .and_then(|v| value_to_string(v, "0x02")),
        })
    }
}

impl From<TemplateInfo> for BTreeMap<Value, Value> {
    fn from(value: TemplateInfo) -> Self {
        let TemplateInfo { id, friendly_name } = value;

        let mut keys = BTreeMap::new();
        keys.insert(Value::Integer(0x01), Value::Bytes(id));
        friendly_name.map(|v| keys.insert(Value::Integer(0x02), Value::Text(v)));

        keys
    }
}

/// Modality for biometric authentication.
///
/// Returned in [BioEnrollmentResponse::modality] in response to a
/// [BioEnrollmentRequestTrait::GET_MODALITY] request.
#[derive(FromPrimitive, ToPrimitive, Debug, PartialEq, Eq, Clone, Default)]
#[repr(u8)]
pub enum Modality {
    /// Unsupported modality.
    #[default]
    Unknown = 0x00,

    /// Fingerprint authentication.
    Fingerprint = 0x01,
}

/// The type of fingerprint sensor on the device.
#[derive(FromPrimitive, ToPrimitive, Debug, PartialEq, Eq, Clone)]
#[repr(u8)]
pub enum FingerprintKind {
    /// A fingerprint sensor which requires placing the finger straight down
    /// on the sensor.
    Touch = 0x01,

    /// A fingerprint sensor which requires swiping the finger across the
    /// sensor.
    Swipe = 0x02,
}

/// Wrapper for biometric command types, which can be passed to
/// [BioEnrollmentRequestTrait::new].
///
/// Static commands are declared as constants of [BioEnrollmentRequestTrait], see:
///
/// * [GET_MODALITY][BioEnrollmentRequestTrait::GET_MODALITY]
/// * [GET_FINGERPRINT_SENSOR_INFO][BioEnrollmentRequestTrait::GET_FINGERPRINT_SENSOR_INFO]
/// * [FINGERPRINT_CANCEL_CURRENT_ENROLLMENT][BioEnrollmentRequestTrait::FINGERPRINT_CANCEL_CURRENT_ENROLLMENT]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum BioSubCommand {
    #[default]
    Unknown,

    /// Begins enrollment of a new fingerprint on the device:
    ///
    /// * [Duration]: time-out for the operation.
    ///
    /// <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#enrollingFingerprint>
    FingerprintEnrollBegin(/* timeout in milliseconds */ Duration),

    /// Captures another sample of a fingerprint while enrollment is in
    /// progress:
    ///
    /// * [`Vec<u8>`]: `template_id` of the partially-enrolled fingerprint.
    /// * [`Duration`]: time-out for the operation.
    ///
    /// <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#enrollingFingerprint>
    FingerprintEnrollCaptureNextSample(/* id */ Vec<u8>, /* timeout */ Duration),

    /// Lists all enrolled fingerprints.
    ///
    /// <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#enumerateEnrollments>
    FingerprintEnumerateEnrollments,

    /// Renames or sets the friendly name of an enrolled fingerprint.
    ///
    /// <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#setFriendlyName>
    FingerprintSetFriendlyName(TemplateInfo),

    /// Removes an enrolled fingerprint.
    ///
    /// <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#removeEnrollment>
    FingerprintRemoveEnrollment(/* id */ Vec<u8>),
}

impl From<&BioSubCommand> for (Modality, u8) {
    fn from(c: &BioSubCommand) -> Self {
        use BioSubCommand::*;
        use Modality::*;
        match c {
            BioSubCommand::Unknown => (Modality::Unknown, 0x00),
            FingerprintEnrollBegin(_) => (Fingerprint, 0x01),
            FingerprintEnrollCaptureNextSample(_, _) => (Fingerprint, 0x02),
            FingerprintEnumerateEnrollments => (Fingerprint, 0x04),
            FingerprintSetFriendlyName(_) => (Fingerprint, 0x05),
            FingerprintRemoveEnrollment(_) => (Fingerprint, 0x06),
        }
    }
}

impl From<BioSubCommand> for Option<BTreeMap<Value, Value>> {
    fn from(c: BioSubCommand) -> Self {
        use BioSubCommand::*;
        match c {
            Unknown => None,
            FingerprintEnrollBegin(timeout) => Some(BTreeMap::from([(
                Value::Integer(0x03),
                Value::Integer(timeout.as_millis() as i128),
            )])),
            FingerprintEnrollCaptureNextSample(id, timeout) => Some(BTreeMap::from([
                (Value::Integer(0x01), Value::Bytes(id)),
                (
                    Value::Integer(0x03),
                    Value::Integer(timeout.as_millis() as i128),
                ),
            ])),
            FingerprintEnumerateEnrollments => None,
            FingerprintSetFriendlyName(t) => t.try_into().ok(),
            FingerprintRemoveEnrollment(id) => {
                Some(BTreeMap::from([(Value::Integer(0x01), Value::Bytes(id))]))
            }
        }
    }
}

impl BioSubCommand {
    pub fn prf(&self) -> Vec<u8> {
        // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#prfValues
        let (modality, subcommand) = self.into();
        let sub_command_params: Option<BTreeMap<Value, Value>> = self.to_owned().into();

        let mut o = Vec::new();
        o.push(modality.to_u8().expect("Could not coerce modality into u8"));
        o.push(subcommand);
        if let Some(p) = sub_command_params
            .as_ref()
            .and_then(|p| serde_cbor_2::to_vec(p).ok())
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
pub struct BioEnrollmentResponse {
    /// Biometric authentication modality supported by the authenticator.
    ///
    /// Returned in response to a
    /// [BioEnrollmentRequestTrait::GET_MODALITY] request.
    pub modality: Option<Modality>,

    /// The kind of fingerprint sensor used on the device.
    ///
    /// Returned in response to a
    /// [BioEnrollmentRequestTrait::GET_FINGERPRINT_SENSOR_INFO] request.
    pub fingerprint_kind: Option<FingerprintKind>,

    /// The maximum number of good fingerprint samples required for enrollment.
    ///
    /// Returned in response to a
    /// [BioEnrollmentRequestTrait::GET_FINGERPRINT_SENSOR_INFO] request.
    pub max_capture_samples_required_for_enroll: Option<u32>,

    /// The identifier for the fingerprint being enrolled.
    ///
    /// Returned in response to a [BioSubCommand::FingerprintEnrollBegin]
    /// request.
    pub template_id: Option<Vec<u8>>,

    /// The state of the last collected fingerprint sample.
    ///
    /// Returned in response to a [BioSubCommand::FingerprintEnrollBegin] or
    /// [BioSubCommand::FingerprintEnrollCaptureNextSample] request.
    pub last_enroll_sample_status: Option<EnrollSampleStatus>,

    /// The number of good fingerprint samples required to complete enrollment.
    ///
    /// Returned in response to a [BioSubCommand::FingerprintEnrollBegin] or
    /// [BioSubCommand::FingerprintEnrollCaptureNextSample] request.
    pub remaining_samples: Option<u32>,

    /// A list of all enrolled fingerprints on the device.
    ///
    /// Returned in response to a
    /// [BioSubCommand::FingerprintEnumerateEnrollments] request.
    pub template_infos: Vec<TemplateInfo>,

    /// The maximum length for a [TemplateInfo::friendly_name] used on the
    /// device.
    ///
    /// Returned in response to a
    /// [BioEnrollmentRequestTrait::GET_FINGERPRINT_SENSOR_INFO] request.
    ///
    /// Prefer using the
    /// [get_max_template_friendly_name()][Self::get_max_template_friendly_name]
    /// method instead of this field, which also provides a default value if
    /// this is missing.
    pub max_template_friendly_name: Option<usize>,
}

impl BioEnrollmentResponse {
    /// Gets the maximum template friendly name size in bytes, or the default
    /// if none is provided.
    ///
    /// This value is only valid as a response to
    /// [BioEnrollmentRequestTrait::GET_FINGERPRINT_SENSOR_INFO].
    pub fn get_max_template_friendly_name(&self) -> usize {
        self.max_template_friendly_name
            .unwrap_or(DEFAULT_MAX_FRIENDLY_NAME)
    }
}

impl TryFrom<BTreeMap<u32, Value>> for BioEnrollmentResponse {
    type Error = &'static str;
    fn try_from(mut raw: BTreeMap<u32, Value>) -> Result<Self, Self::Error> {
        trace!(?raw);
        Ok(Self {
            modality: raw
                .remove(&0x01)
                .and_then(|v| value_to_u32(&v, "0x01"))
                .and_then(Modality::from_u32),
            fingerprint_kind: raw
                .remove(&0x02)
                .and_then(|v| value_to_u32(&v, "0x02"))
                .and_then(FingerprintKind::from_u32),
            max_capture_samples_required_for_enroll: raw
                .remove(&0x03)
                .and_then(|v| value_to_u32(&v, "0x03")),
            template_id: raw.remove(&0x04).and_then(|v| value_to_vec_u8(v, "0x04")),
            last_enroll_sample_status: raw
                .remove(&0x05)
                .and_then(|v| value_to_u32(&v, "0x05"))
                .and_then(EnrollSampleStatus::from_u32),
            remaining_samples: raw.remove(&0x06).and_then(|v| value_to_u32(&v, "0x06")),
            template_infos: raw
                .remove(&0x07)
                .and_then(|v| {
                    if let Value::Array(v) = v {
                        let mut infos = vec![];
                        for i in v {
                            if let Value::Map(i) = i {
                                if let Ok(i) = TemplateInfo::try_from(i) {
                                    infos.push(i)
                                }
                            }
                        }
                        Some(infos)
                    } else {
                        None
                    }
                })
                .unwrap_or_default(),
            max_template_friendly_name: raw
                .remove(&0x08)
                .and_then(|v| value_to_u32(&v, "0x08"))
                .map(|v| v as usize),
        })
    }
}

crate::deserialize_cbor!(BioEnrollmentResponse);

bio_struct! {
    /// CTAP 2.1 `authenticatorBioEnrollment` command (`0x09`).
    ///
    /// [ref]: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorBioEnrollment
    pub struct BioEnrollmentRequest = 0x09
}

bio_struct! {
    /// CTAP 2.1-PRE prototype `authenticatorBioEnrollment` command (`0x40`).
    ///
    /// [ref]: https://fidoalliance.org/specs/fido2/vendor/BioEnrollmentPrototype.pdf
    pub struct PrototypeBioEnrollmentRequest = 0x40
}

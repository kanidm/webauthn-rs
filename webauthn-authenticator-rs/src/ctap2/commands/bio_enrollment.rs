use std::time::Duration;

use num_traits::cast::{FromPrimitive, ToPrimitive};
use serde::{Deserialize, Serialize};
use serde_cbor::Value;

use self::CBORCommand;
use super::*;

/// Default maximum fingerprint friendly name length, in bytes.
///
/// Reference: <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#setFriendlyName>
const DEFAULT_MAX_FRIENDLY_NAME: usize = 64;

/// Command to get the supported biometric modality for the authenticator.
///
/// <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#getUserVerificationModality>
pub const GET_MODALITY: BioEnrollmentRequest = BioEnrollmentRequest {
    get_modality: true,
    modality: None,
    sub_command: None,
    sub_command_params: None,
    pin_uv_protocol: None,
    pin_uv_auth_param: None,
};

/// Command to get information about the authenticator's fingerprint sensor.
///
/// <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#getFingerprintSensorInfo>
pub const GET_FINGERPRINT_SENSOR_INFO: BioEnrollmentRequest = BioEnrollmentRequest {
    modality: Some(Modality::Fingerprint),
    sub_command: Some(0x07), // getFingerprintSensorInfo
    sub_command_params: None,
    pin_uv_protocol: None,
    pin_uv_auth_param: None,
    get_modality: false,
};

/// Command to cancel an in-progress fingerprint enrollment.
///
/// <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#cancelEnrollment>
pub const FINGERPRINT_CANCEL_CURRENT_ENROLLMENT: BioEnrollmentRequest = BioEnrollmentRequest {
    modality: Some(Modality::Fingerprint),
    sub_command: Some(0x03), // cancelCurrentEnrollment
    sub_command_params: None,
    pin_uv_protocol: None,
    pin_uv_auth_param: None,
    get_modality: false,
};

/// `authenticatorBioEnrollment` request type.
///
/// See:
///
/// * [BioSubCommand] for dynamically-constructed commands
/// * [GET_MODALITY]
/// * [GET_FINGERPRINT_SENSOR_INFO]
/// * [FINGERPRINT_CANCEL_CURRENT_ENROLLMENT]
///
/// <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorBioEnrollment>
#[derive(Serialize, Debug, Clone, Default, PartialEq, Eq)]
#[serde(into = "BTreeMap<u32, Value>")]
pub struct BioEnrollmentRequest {
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
    /// See [GET_MODALITY].
    get_modality: bool,
}

impl CBORCommand for BioEnrollmentRequest {
    const CMD: u8 = 0x09;
    type Response = BioEnrollmentResponse;
}

/// `authenticatorBioEnrollment` response type.
///
/// <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorBioEnrollment>
#[derive(Deserialize, Debug, Default, PartialEq, Eq)]
#[serde(try_from = "BTreeMap<u32, Value>")]
pub struct BioEnrollmentResponse {
    /// Biometric authentication modality supported by the authenticator.
    ///
    /// Returned in response to a [GET_MODALITY] request.
    pub modality: Option<Modality>,

    /// The kind of fingerprint sensor used on the device.
    ///
    /// Returned in response to a [GET_FINGERPRINT_SENSOR_INFO] request.
    pub fingerprint_kind: Option<FingerprintKind>,

    /// The maximum number of good fingerprint samples required for enrollment.
    ///
    /// Returned in response to a [GET_FINGERPRINT_SENSOR_INFO] request.
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
    /// Returned in response to a [GET_FINGERPRINT_SENSOR_INFO] request.
    ///
    /// Prefer using the
    /// [get_max_template_friendly_name()][Self::get_max_template_friendly_name]
    /// method instead of this field, which also provides a default value if
    /// this is missing.
    pub max_template_friendly_name: Option<usize>,
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

// lastEnrollSampleStatus
#[derive(FromPrimitive, ToPrimitive, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EnrollSampleStatus {
    Good = 0x00,
    TooHigh = 0x01,
    TooLow = 0x02,
    TooLeft = 0x03,
    TooRight = 0x04,
    TooFast = 0x05,
    TooSlow = 0x06,
    PoorQuality = 0x07,
    TooSkewed = 0x08,
    TooShort = 0x09,
    MergeFailure = 0x0a,
    AlreadyExists = 0x0b,
    // 0x0c unused
    NoUserActivity = 0x0d,
    NoUserPresenceTransition = 0x0e,
}

/// Modality for biometric authentication.
///
/// Returned in [BioEnrollmentResponse::modality] in response to a
/// [GET_MODALITY] request.
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
/// [BioEnrollmentRequest::new].
///
/// Static commands are declared as constants of this module, see:
///
/// * [GET_MODALITY]
/// * [GET_FINGERPRINT_SENSOR_INFO]
/// * [FINGERPRINT_CANCEL_CURRENT_ENROLLMENT]
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
            .and_then(|p| serde_cbor::to_vec(p).ok())
        {
            o.extend_from_slice(p.as_slice())
        }

        o
    }
}

impl BioEnrollmentRequest {
    /// Creates a new [BioEnrollmentRequest] from the given [BioSubCommand].
    pub fn new(
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

impl From<BioEnrollmentRequest> for BTreeMap<u32, Value> {
    fn from(value: BioEnrollmentRequest) -> Self {
        let BioEnrollmentRequest {
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

impl BioEnrollmentResponse {
    /// Gets the maximum template friendly name size in bytes, or the default
    /// if none is provided.
    ///
    /// This value is only valid as a response to [GET_FINGERPRINT_SENSOR_INFO].
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

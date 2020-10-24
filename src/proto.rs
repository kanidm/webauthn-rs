//! JSON Protocol Structs and representations for communication with authenticators
//! and clients.

use std::collections::BTreeMap;
use std::convert::TryFrom;

use crate::base64_data::Base64UrlSafeData;
use crate::crypto;
use crate::error::*;

use serde::{Deserialize, Serialize};

/// Representation of a UserId
pub type UserId = Vec<u8>;

/// Representation of a device counter
pub type Counter = u32;

/// Representation of an AAGUID
/// https://www.w3.org/TR/webauthn/#aaguid
pub type Aaguid = Vec<u8>;

/// A challenge issued by the server. This contains a set of random bytes
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Challenge(pub Vec<u8>);

impl Into<Base64UrlSafeData> for Challenge {
    fn into(self) -> Base64UrlSafeData {
        Base64UrlSafeData(self.0)
    }
}

impl From<Base64UrlSafeData> for Challenge {
    fn from(d: Base64UrlSafeData) -> Self {
        Challenge(d.0)
    }
}

/// A credential ID type. At the moment this is a vector of bytes, but
/// it could also be a future change for this to be base64 string instead.
///
/// If changed, this would likely be a major library version change.
pub type CredentialID = Vec<u8>;

/// A user's authenticator credential. It contains an id, the public key
/// and a counter of how many times the authenticator has been used.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Credential {
    /// The ID of this credential.
    pub cred_id: CredentialID,
    /// The public key of this credential
    pub cred: crypto::COSEKey,
    /// The counter for this credential
    pub counter: u32,
}

impl Credential {
    pub(crate) fn new(acd: &AttestedCredentialData, ck: crypto::COSEKey, counter: u32) -> Self {
        Credential {
            cred_id: acd.credential_id.clone(),
            cred: ck,
            counter,
        }
    }
}

impl PartialEq<Credential> for Credential {
    fn eq(&self, c: &Credential) -> bool {
        self.cred_id == c.cred_id
    }
}

/// Defines the User Authenticator Verification policy. This is documented
/// https://w3c.github.io/webauthn/#enumdef-userverificationrequirement, and each
/// variant lists it's effects.
///
/// To be clear, Verification means that the Authenticator perform extra or supplementary
/// interfaction with the user to verify who they are. An example of this is Apple Touch Id
/// required a fingerprint to be verified, or a yubico device requiring a pin in addition to
/// a touch event.
///
/// An example of a non-verified interaction is a yubico device with no pin where touch is
/// the only interaction - we only verify a user is present, but we don't have extra details
/// to the legitimacy of that user.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum UserVerificationPolicy {
    /// Require User Verification bit to be set, and fail the registration or authentication
    /// if false. If the authenticator is not able to perform verification, it may not be
    /// usable with this policy.
    Required,
    /// Prefer User Verification bit to be set, and yolo the registration or authentication
    /// if false. This means if the authenticator can perform verification, do it, but don't
    /// mind if not.
    ///
    /// WARNING: This setting is effectively useless. Either you *want* user verification
    /// so require `Required`, or you do not want it, so use `Discouraged`. This setting
    /// will prompt users for verification, but without enforcing that it is present.
    ///
    /// As a result, this setting is effectively `Discouraged` and should be AVOIDED.
    Preferred,
    /// Request that no verification is performed, and fail if it is. This is intended to
    /// minimise user interaction in workflows, but is potentially a security risk to use.
    Discouraged,
}

// These are the primary communication structures you will need to handle.
pub(crate) type JSONExtensions = BTreeMap<String, String>;

/// Relying Party Entity
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RelyingParty {
    pub name: String,
    pub id: String,
}

/// User Entity
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct User {
    pub id: Base64UrlSafeData,
    pub name: String,
    pub display_name: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct PubKeyCredParams {
    #[serde(rename = "type")]
    pub type_: String,
    // Should this be a diff size?
    pub alg: i64,
}

#[derive(Debug, Serialize, Clone, Deserialize)]
pub struct AllowCredentials {
    #[serde(rename = "type")]
    pub type_: String,
    pub id: Base64UrlSafeData,
    /// https://www.w3.org/TR/webauthn/#transport
    /// may be usb, nfc, ble, internal
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<String>>,
}

/// https://w3c.github.io/webauthn/#dictionary-makecredentialoptions
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyCredentialCreationOptions {
    pub rp: RelyingParty,
    pub user: User,
    pub challenge: Base64UrlSafeData,
    pub pub_key_cred_params: Vec<PubKeyCredParams>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<AttestationConveyancePreference>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub exclude_credentials: Option<Vec<PublicKeyCredentialDescriptor>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<JSONExtensions>,
}

/// https://www.w3.org/TR/webauthn/#dictdef-authenticatorselectioncriteria
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatorSelectionCriteria {
    /// https://www.w3.org/TR/webauthn/#attachment
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticator_attachment: Option<AuthenticatorAttachment>,

    /// https://www.w3.org/TR/webauthn/#resident-credential
    pub require_resident_key: bool,

    pub user_verification: UserVerificationPolicy,
}

/// The authenticator attachment hint. This is NOT enforced, and is only used
/// to help a user select a relevant authenticator type.
///
/// https://www.w3.org/TR/webauthn/#attachment
#[derive(Debug, Copy, Clone, Serialize, PartialEq)]
pub enum AuthenticatorAttachment {
    /// https://www.w3.org/TR/webauthn/#attachment
    #[serde(rename = "platform")]
    Platform,
    /// https://www.w3.org/TR/webauthn/#attachment
    #[serde(rename = "cross-platform")]
    CrossPlatform,
}

/// https://www.w3.org/TR/webauthn/#enumdef-attestationconveyancepreference
#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AttestationConveyancePreference {
    /// https://www.w3.org/TR/webauthn/#dom-attestationconveyancepreference-none
    None,

    /// WARNING: This allows the user to choose if they send a attestation
    /// to your service. You either want this (use `Direct`) or do not (use `None`).
    /// This option is effectively the same as `None` and should be AVOIDED.
    /// https://www.w3.org/TR/webauthn/#dom-attestationconveyancepreference-indirect
    Indirect,

    /// https://www.w3.org/TR/webauthn/#dom-attestationconveyancepreference-direct
    Direct,
}

/// https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialdescriptor
#[derive(Debug, Serialize)]
pub struct PublicKeyCredentialDescriptor {
    #[serde(rename = "type")]
    type_: String,
    id: Base64UrlSafeData,
    transports: Option<Vec<AuthenticatorTransport>>,
}

impl PublicKeyCredentialDescriptor {
    /// Constructed from a byte array
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self {
            type_: "public-key".to_string(),
            id: Base64UrlSafeData(bytes),
            transports: None,
        }
    }
}

/// https://www.w3.org/TR/webauthn/#enumdef-authenticatortransport
#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
#[allow(unused)]
pub enum AuthenticatorTransport {
    /// https://www.w3.org/TR/webauthn/#dom-authenticatortransport-usb
    Usb,
    /// https://www.w3.org/TR/webauthn/#dom-authenticatortransport-nfc
    Nfc,
    /// https://www.w3.org/TR/webauthn/#dom-authenticatortransport-ble
    Ble,
    /// https://www.w3.org/TR/webauthn/#dom-authenticatortransport-internal
    Internal,
}

/// A JSON serialisable challenge which is issued to the user's webbrowser
/// for handling. This is meant to be opaque, that is, you should not need
/// to inspect or alter the content of the struct - you should serialise it
/// and transmit it to the client only.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreationChallengeResponse {
    pub public_key: PublicKeyCredentialCreationOptions,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyCredentialRequestOptions {
    pub challenge: Base64UrlSafeData,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,
    pub rp_id: String,
    pub allow_credentials: Vec<AllowCredentials>,
    pub user_verification: UserVerificationPolicy,
    pub extensions: Option<JSONExtensions>,
}

/// A JSON serialisable challenge which is issued to the user's webbrowser
/// for handling. This is meant to be opaque, that is, you should not need
/// to inspect or alter the content of the struct - you should serialise it
/// and transmit it to the client only.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestChallengeResponse {
    pub public_key: PublicKeyCredentialRequestOptions,
}

impl RequestChallengeResponse {
    pub(crate) fn new(
        challenge: Challenge,
        timeout: u32,
        relaying_party: String,
        allow_credentials: Vec<AllowCredentials>,
        user_verification_policy: UserVerificationPolicy,
    ) -> Self {
        RequestChallengeResponse {
            public_key: PublicKeyCredentialRequestOptions {
                challenge: challenge.into(),
                timeout: Some(timeout),
                rp_id: relaying_party,
                allow_credentials,
                user_verification: user_verification_policy,
                extensions: None,
            },
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CollectedClientData {
    #[serde(rename = "type")]
    pub type_: String,
    pub challenge: Base64UrlSafeData,
    pub origin: String,
    #[serde(rename = "tokenBinding")]
    pub token_binding: Option<TokenBinding>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TokenBinding {
    pub status: String,
    pub id: Option<String>,
}

// Should this be tryfrom
impl TryFrom<&Vec<u8>> for CollectedClientData {
    type Error = WebauthnError;
    fn try_from(data: &Vec<u8>) -> Result<CollectedClientData, WebauthnError> {
        let ccd: CollectedClientData =
            serde_json::from_slice(&data).map_err(|e| WebauthnError::ParseJSONFailure(e))?;

        Ok(ccd)
    }
}

#[derive(Debug)]
pub(crate) struct AttestedCredentialData {
    pub(crate) aaguid: Aaguid,
    pub(crate) credential_id: CredentialID,
    pub(crate) credential_pk: serde_cbor::Value,
}

// https://w3c.github.io/webauthn/#sctn-attestation
#[derive(Debug)]
pub struct AuthenticatorData {
    pub(crate) rp_id_hash: Vec<u8>,
    // pub(crate) flags: u8,
    pub(crate) counter: u32,
    pub(crate) user_present: bool,
    pub(crate) user_verified: bool,
    pub(crate) acd: Option<AttestedCredentialData>,
    // pub(crate) extensions: Option<CBORExtensions>,
    pub(crate) extensions: Option<()>,
    // pub(crate) excess: Vec<u8>,
}

fn cbor_parser(i: &[u8]) -> nom::IResult<&[u8], serde_cbor::Value> {
    let v: serde_cbor::Value = serde_cbor::from_slice(&i[0..])
        .map_err(|_| nom::Err::Failure(nom::Context::Code(i, nom::ErrorKind::Custom(1))))?;

    // Now re-encode it to find the length ... yuk.
    let encoded = serde_cbor::to_vec(&v)
        .map_err(|_| nom::Err::Failure(nom::Context::Code(i, nom::ErrorKind::Custom(2))))?;
    // Finally we know the cred len
    let cred_len = encoded.len();

    Ok((&i[cred_len..], v))
}

named!( extensions_parser<&[u8], ()>,
    // Just throw the bytes into cbor?
    do_parse!(
        (())
    )
);

named!( acd_parser<&[u8], AttestedCredentialData>,
    do_parse!(
        aaguid: take!(16) >>
        cred_id_len: u16!(nom::Endianness::Big) >>
        cred_id: take!(cred_id_len) >>
        cred_pk: cbor_parser >>
        (AttestedCredentialData {
            aaguid: aaguid.to_vec(),
            credential_id: cred_id.to_vec(),
            credential_pk: cred_pk,
        })
    )
);

named!( authenticator_data_flags<&[u8], (bool, bool, bool, bool)>,
    bits!(
        do_parse!(
            exten_pres: map!(take_bits!(u8, 1), |i| i != 0)  >>
            acd_pres: map!(take_bits!(u8, 1), |i| i != 0) >>
            take_bits!(u8, 1) >>
            take_bits!(u8, 1) >>
            take_bits!(u8, 1) >>
            u_ver: map!(take_bits!(u8, 1), |i| i != 0) >>
            take_bits!(u8, 1) >>
            u_pres: map!(take_bits!(u8, 1), |i| i != 0) >>
            ((exten_pres, acd_pres, u_ver, u_pres))
        )
    )
);

named!( authenticator_data_parser<&[u8], AuthenticatorData>,
    do_parse!(
        rp_id_hash: take!(32) >>
        data_flags: authenticator_data_flags >>
        counter: u32!(nom::Endianness::Big) >>
        acd: cond!(data_flags.1, acd_parser) >>
        extensions: cond!(data_flags.0, extensions_parser) >>
        // excess: call!(nom::rest) >>
        (AuthenticatorData {
            rp_id_hash: rp_id_hash.to_vec(),
            counter: counter,
            user_verified: data_flags.2,
            user_present: data_flags.3,
            acd: acd,
            extensions: extensions,
            // excess: excess.to_vec(),
        })
    )
);

impl TryFrom<&Vec<u8>> for AuthenticatorData {
    type Error = WebauthnError;
    fn try_from(auth_data_bytes: &Vec<u8>) -> Result<Self, Self::Error> {
        authenticator_data_parser(auth_data_bytes.as_slice())
            .map_err(|e| {
                log::debug!("nom -> {:?}", e);
                WebauthnError::ParseNOMFailure
            })
            .map(|(_, ad)| ad)
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AttestationObjectInner<'a> {
    pub(crate) auth_data: &'a [u8],
    pub(crate) fmt: String,
    pub(crate) att_stmt: serde_cbor::Value,
}

#[derive(Debug)]
pub struct AttestationObject {
    pub(crate) auth_data: AuthenticatorData,
    pub(crate) auth_data_bytes: Vec<u8>,
    pub(crate) fmt: String,
    // https://w3c.github.io/webauthn/#generating-an-attestation-object
    pub(crate) att_stmt: serde_cbor::Value,
}

impl TryFrom<&[u8]> for AttestationObject {
    type Error = WebauthnError;

    fn try_from(data: &[u8]) -> Result<AttestationObject, WebauthnError> {
        let aoi: AttestationObjectInner =
            serde_cbor::from_slice(&data).map_err(|e| WebauthnError::ParseCBORFailure(e))?;
        let auth_data_bytes: Vec<u8> = aoi.auth_data.iter().map(|b| *b).collect();

        let auth_data = AuthenticatorData::try_from(&auth_data_bytes)?;

        // Yay! Now we can assemble a reasonably sane structure.
        Ok(AttestationObject {
            fmt: aoi.fmt.clone(),
            auth_data,
            auth_data_bytes,
            att_stmt: aoi.att_stmt.clone(),
        })
    }
}

/// https://w3c.github.io/webauthn/#authenticatorattestationresponse
#[derive(Debug, Deserialize, Serialize)]
pub struct AuthenticatorAttestationResponseRaw {
    /// https://w3c.github.io/webauthn/#dom-authenticatorattestationresponse-attestationobject
    #[serde(rename = "attestationObject")]
    pub attestation_object: Base64UrlSafeData,

    /// https://w3c.github.io/webauthn/#dom-authenticatorresponse-clientdatajson
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: Base64UrlSafeData,
}

pub(crate) struct AuthenticatorAttestationResponse {
    pub(crate) attestation_object: AttestationObject,
    pub(crate) client_data_json: CollectedClientData,
    pub(crate) client_data_json_bytes: Vec<u8>,
}

impl TryFrom<&AuthenticatorAttestationResponseRaw> for AuthenticatorAttestationResponse {
    type Error = WebauthnError;
    fn try_from(aarr: &AuthenticatorAttestationResponseRaw) -> Result<Self, Self::Error> {
        let ccdj = CollectedClientData::try_from(aarr.client_data_json.as_ref())?;
        let ao = AttestationObject::try_from(aarr.attestation_object.as_ref())?;

        Ok(AuthenticatorAttestationResponse {
            attestation_object: ao,
            client_data_json: ccdj,
            client_data_json_bytes: aarr.client_data_json.clone().into(),
        })
    }
}

/// A client response to a registration challenge. This contains all required
/// information to asses and assert trust in a credentials legitimacy, followed
/// by registration to a user.
///
/// You should not need to handle the inner content of this structure - you should
/// provide this to the correctly handling function of Webauthn only.
/// https://w3c.github.io/webauthn/#iface-pkcredential
#[derive(Debug, Deserialize, Serialize)]
pub struct RegisterPublicKeyCredential {
    pub id: String,

    #[serde(rename = "rawId")]
    pub raw_id: Base64UrlSafeData,

    /// https://w3c.github.io/webauthn/#dom-publickeycredential-response
    pub response: AuthenticatorAttestationResponseRaw,

    #[serde(rename = "type")]
    pub type_: String,
}

#[derive(Debug)]
pub(crate) struct AuthenticatorAssertionResponse {
    pub(crate) authenticator_data: AuthenticatorData,
    pub(crate) authenticator_data_bytes: Vec<u8>,
    pub(crate) client_data: CollectedClientData,
    pub(crate) client_data_bytes: Vec<u8>,
    pub(crate) signature: Vec<u8>,
    pub(crate) user_handle: Option<Vec<u8>>,
}

impl TryFrom<&AuthenticatorAssertionResponseRaw> for AuthenticatorAssertionResponse {
    type Error = WebauthnError;
    fn try_from(aarr: &AuthenticatorAssertionResponseRaw) -> Result<Self, Self::Error> {
        Ok(AuthenticatorAssertionResponse {
            authenticator_data: AuthenticatorData::try_from(aarr.authenticator_data.as_ref())?,
            authenticator_data_bytes: aarr.authenticator_data.clone().into(),
            client_data: CollectedClientData::try_from(aarr.client_data_json.as_ref())?,
            client_data_bytes: aarr.client_data_json.clone().into(),
            signature: aarr.signature.clone().into(),
            user_handle: aarr.user_handle.clone().map(|uh| uh.into()),
        })
    }
}

// https://w3c.github.io/webauthn/#authenticatorassertionresponse
#[derive(Debug, Deserialize, Serialize)]
pub struct AuthenticatorAssertionResponseRaw {
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: Base64UrlSafeData,

    #[serde(rename = "clientDataJSON")]
    pub client_data_json: Base64UrlSafeData,

    pub signature: Base64UrlSafeData,

    #[serde(rename = "userHandle")]
    pub user_handle: Option<Base64UrlSafeData>,
}

/// A client response to an authentication challenge. This contains all required
/// information to asses and assert trust in a credentials legitimacy, followed
/// by authentication to a user.
///
/// You should not need to handle the inner content of this structure - you should
/// provide this to the correctly handling function of Webauthn only.
#[derive(Debug, Deserialize, Serialize)]
pub struct PublicKeyCredential {
    pub id: String,
    #[serde(rename = "rawId")]
    pub raw_id: Base64UrlSafeData,
    pub response: AuthenticatorAssertionResponseRaw,
    #[serde(rename = "type")]
    pub type_: String,
}

// ===== tpm shit show begins =====

/// A magic constant that defines that a Tpm attestation comes from a TPM
pub const TPM_GENERATED_VALUE: u32 = 0xff544347;

#[derive(Debug, PartialEq)]
#[repr(u16)]
/// Tpm statement types.
pub enum TpmSt {
    /// Unused
    RspCommand = 0x00c4,
    /// Unused
    Null = 0x8000,
    /// Unused
    NoSessions = 0x8001,
    /// Unused
    Sessions = 0x8002,
    /// Unused
    ReservedA = 0x8003,
    /// Unused
    ReservedB = 0x8004,
    /// Unused
    AttestNV = 0x8014,
    /// Unused
    AttestCommandAudit = 0x8015,
    /// Unused
    AttestSessionAudit = 0x8016,
    /// Denote that this attestation contains a certify statement.
    AttestCertify = 0x8017,
    /// Unused
    AttestQuote = 0x8018,
    /// Unused
    AttestTime = 0x8019,
    /// Unused
    AttestCreation = 0x801a,
    /// Unused
    ReservedC = 0x801b,
    /// Unused
    Creation = 0x8021,
    /// Unused
    Verified = 0x8022,
    /// Unused
    AuthSecret = 0x8023,
    /// Unused
    Hashcheck = 0x8024,
    /// Unused
    AuthSigned = 0x8025,
    /// Unused
    FUManifest = 0x8029,
}

impl TpmSt {
    fn new(v: u16) -> Option<Self> {
        match v {
            0x00c4 => Some(TpmSt::RspCommand),
            0x8000 => Some(TpmSt::Null),
            0x8001 => Some(TpmSt::NoSessions),
            0x8002 => Some(TpmSt::Sessions),
            0x8003 => Some(TpmSt::ReservedA),
            0x8004 => Some(TpmSt::ReservedB),
            0x8014 => Some(TpmSt::AttestNV),
            0x8015 => Some(TpmSt::AttestCommandAudit),
            0x8016 => Some(TpmSt::AttestSessionAudit),
            0x8017 => Some(TpmSt::AttestCertify),
            0x8018 => Some(TpmSt::AttestQuote),
            0x8019 => Some(TpmSt::AttestTime),
            0x801a => Some(TpmSt::AttestCreation),
            0x801b => Some(TpmSt::ReservedC),
            0x8021 => Some(TpmSt::Creation),
            0x8022 => Some(TpmSt::Verified),
            0x8023 => Some(TpmSt::AuthSecret),
            0x8024 => Some(TpmSt::Hashcheck),
            0x8025 => Some(TpmSt::AuthSigned),
            0x8029 => Some(TpmSt::FUManifest),
            _ => None,
        }
    }
}

#[derive(Debug)]
/// Information about the TPM's clock. May be obsfucated.
pub struct TpmsClockInfo {
    clock: u64,
    reset_count: u32,
    restart_count: u32,
    safe: bool, // u8
}

named!( tpmsclockinfo_parser<&[u8], TpmsClockInfo>,
    do_parse!(
        clock: u64!(nom::Endianness::Big) >>
        reset_count: u32!(nom::Endianness::Big) >>
        restart_count: u32!(nom::Endianness::Big) >>
        safe: switch!(take!(1),
            [0] => value!(false) |
            [1] => value!(true)
        ) >>
        (TpmsClockInfo {
            clock, reset_count, restart_count, safe
        })
    )
);

#[derive(Debug)]
/// Tpm name enumeration.
pub enum Tpm2bName {
    /// No name present
    None,
    /// A handle reference
    Handle(u32),
    /// A digest of a name
    Digest(Vec<u8>),
}

#[derive(Debug)]
/// Tpm attestation union, switched by TpmSt.
pub enum TpmuAttest {
    /// The TpmuAttest contains a certify structure.
    AttestCertify(Tpm2bName, Tpm2bName),
    // AttestNV
    // AttestCommandAudit
    // AttestSessionAudit
    // AttestQuote
    // AttestTime
    // AttestCreation
    /// An invalid union
    Invalid,
}

#[derive(Debug)]
/// Tpm attestation structure.
pub struct TpmsAttest {
    /// Magic. Should be set to TPM_GENERATED_VALUE
    pub magic: u32,
    /// The type of attestation for typeattested.
    pub type_: TpmSt,
    /// Ignored in webauthn.
    pub qualified_signer: Tpm2bName,
    /// Ignored in webauthn.
    pub extra_data: Option<Vec<u8>>,
    /// Tpm Clock Information
    pub clock_info: TpmsClockInfo,
    /// The TPM firmware version. May be obfuscated.
    pub firmware_version: u64,
    /// The attestation.
    pub typeattested: TpmuAttest,
}

named!( tpm2b_name<&[u8], Tpm2bName>,
    switch!(u16!(nom::Endianness::Big),
        0 => value!(Tpm2bName::None) |
        4 => map!(u32!(nom::Endianness::Big), Tpm2bName::Handle) |
        size => map!(take!(size), |d| Tpm2bName::Digest(d.to_vec()))
    )
);

named!( tpm2b_data<&[u8], Option<Vec<u8>>>,
    switch!(u16!(nom::Endianness::Big),
        0 => value!(None) |
        size => map!(take!(size), |d| Some(d.to_vec()))
    )
);

named! ( tpmuattestcertify<&[u8], TpmuAttest>,
    do_parse!(
        name: tpm2b_name >>
        qualified_name: tpm2b_name >>
        (
            TpmuAttest::AttestCertify(name, qualified_name)
        )
    )
);

named!( tpmsattest_parser<&[u8], TpmsAttest>,
    do_parse!(
        magic: verify!(u32!(nom::Endianness::Big), |x| x == TPM_GENERATED_VALUE) >>
        type_: map_opt!(u16!(nom::Endianness::Big), TpmSt::new) >>
        qualified_signer: tpm2b_name >>
        extra_data: tpm2b_data >>
        clock_info: tpmsclockinfo_parser >>
        firmware_version: u64!(nom::Endianness::Big) >>
        // we *could* try to parse this generically, BUT I can't work out how to amke nom
        // reach back to type_ to switch on the type. However, webauthn ONLY needs attestCertify
        // so we can blindly attempt to parse this as it is.
        typeattested: tpmuattestcertify >>
        /*
        typeattested: switch!(type_,
            TpmSt::AttestCertify => tpmuattestcertify |
            _ => value!(TpmuAttest::Invalid)
        ) >>
        */
        (TpmsAttest {
            magic, type_, qualified_signer, extra_data, clock_info, firmware_version, typeattested
        })
    )
);

impl TryFrom<&[u8]> for TpmsAttest {
    type Error = WebauthnError;

    fn try_from(data: &[u8]) -> Result<TpmsAttest, WebauthnError> {
        tpmsattest_parser(data)
            .map_err(|e| {
                log::debug!("{:?}", e);
                // eprintln!("{:?}", e);
                WebauthnError::ParseNOMFailure
            })
            .map(|(_, v)| v)
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(u16)]
/// The tpm cryptographic algorithm that may be in use.
pub enum TpmAlgId {
    /// Error occured
    Error = 0x0000,
    /// RSA
    Rsa = 0x0001,
    /// Insecure Sha1
    Sha1 = 0x0004,
    /// Hmac
    Hmac = 0x0005,
    /// Aes
    Aes = 0x0006,
    // Mgf1 = 0x0007,
    // KeyedHash = 0x0008,
    // Xor = 0x000A,
    /// Sha256
    Sha256 = 0x000B,
    /// Sha384
    Sha384 = 0x000C,
    /// Sha512
    Sha512 = 0x000D,
    /// Null (no algorithm)
    Null = 0x0010,
    // Sm3_256 = 0x0012,
    // Sm4 = 0x0013,
    /// Rsa SSA
    RsaSSA = 0x0014,
    // RsAes = 0x0015,
    /// Rsa PSS
    RsaPSS = 0x0016,
    // Oaep = 0x0017,
    /// Ecdsa
    Ecdsa = 0x0018,
    // Ecdh = 0x0019,
    /// Ecdaa
    Ecdaa = 0x001A,
    // Sm2 = 0x001B,
    // EcSchnorr = 0x001C,
    // EcMqv = 0x001D,
    // Kdf1Sp80056A = 0x0020,
    // Kdf2 = 0x0021,
    // Kdf1Sp800108 = 0x0022,
    /// Ecc
    Ecc = 0x0023,
    // Symcipher = 0x0025,
    // Camellia = 0x0026,
    // Ctr = 0x0040,
    // Ofb = 0x0041,
    // Cbc = 0x0042,
    // Cfb = 0x0043,
    // Ecb = 0x0044,
}

impl TpmAlgId {
    fn new(v: u16) -> Option<Self> {
        match v {
            0x0000 => Some(TpmAlgId::Error),
            0x0001 => Some(TpmAlgId::Rsa),
            0x0004 => Some(TpmAlgId::Sha1),
            0x0005 => Some(TpmAlgId::Hmac),
            0x0006 => Some(TpmAlgId::Aes),
            0x000B => Some(TpmAlgId::Sha256),
            0x000C => Some(TpmAlgId::Sha384),
            0x000D => Some(TpmAlgId::Sha512),
            0x0010 => Some(TpmAlgId::Null),
            0x0014 => Some(TpmAlgId::RsaSSA),
            0x0016 => Some(TpmAlgId::RsaPSS),
            0x0018 => Some(TpmAlgId::Ecdsa),
            0x001A => Some(TpmAlgId::Ecdaa),
            0x0023 => Some(TpmAlgId::Ecc),
            _ => None,
        }
    }
}

// Later, this probably would be rewritten interms of the chosen
// symetric algo, but for now it's always Null
#[derive(Debug)]
/// Symmetric crypto definition. Unused in webauthn
pub struct TpmtSymDefObject {
    algorithm: TpmAlgId,
    // keybits: Option<()>,
    // mode: Option<()>,
    // details
}

fn parse_tpmtsymdefobject(input: &[u8]) -> nom::IResult<&[u8], Option<TpmtSymDefObject>> {
    let (data, algorithm) = map_opt!(input, u16!(nom::Endianness::Big), TpmAlgId::new)?;
    match algorithm {
        TpmAlgId::Null => Ok((data, None)),
        _ => Err(nom::Err::Failure(nom::Context::Code(
            input,
            nom::ErrorKind::Custom(2),
        ))),
    }
}

#[derive(Debug)]
/// The Rsa Scheme. Unused in webauthn.
pub struct TpmtRsaScheme {
    algorithm: TpmAlgId,
    // details
}

fn parse_tpmtrsascheme(input: &[u8]) -> nom::IResult<&[u8], Option<TpmtRsaScheme>> {
    let (data, algorithm) = map_opt!(input, u16!(nom::Endianness::Big), TpmAlgId::new)?;
    match algorithm {
        TpmAlgId::Null => Ok((data, None)),
        _ => Err(nom::Err::Failure(nom::Context::Code(
            input,
            nom::ErrorKind::Custom(2),
        ))),
    }
}

#[derive(Debug)]
/// Rsa Parameters.
pub struct TpmsRsaParms {
    // TPMT_SYM_DEF_OBJECT + ALG_NULL
    symmetric: Option<TpmtSymDefObject>,
    // TPMT_RSA_SCHEME+ (rsapss, rsassa, null)
    scheme: Option<TpmtRsaScheme>,
    // TPMI_RSA_KEY_BITS
    keybits: u16,
    // u32
    /// The Rsa Exponent
    pub exponent: u32,
}

named!( tpmsrsaparms_parser<&[u8], TpmsRsaParms>,
    do_parse!(
        symmetric: parse_tpmtsymdefobject >>
        scheme: parse_tpmtrsascheme >>
        keybits: u16!(nom::Endianness::Big) >>
        exponent: u32!(nom::Endianness::Big) >>
        (TpmsRsaParms {
            symmetric, scheme, keybits, exponent
        })
    )
);

/*
#[derive(Debug)]
pub struct TpmsEccParms {
}
*/

#[derive(Debug)]
/// Asymetric Public Parameters
pub enum TpmuPublicParms {
    // KeyedHash
    // Symcipher
    /// Rsa
    Rsa(TpmsRsaParms),
    // Ecc(TpmsEccParms),
    // Asym
}

fn parse_tpmupublicparms(input: &[u8], alg: TpmAlgId) -> nom::IResult<&[u8], TpmuPublicParms> {
    // eprintln!("tpmupublicparms input -> {:?}", input);
    match alg {
        TpmAlgId::Rsa => {
            tpmsrsaparms_parser(input).map(|(data, inner)| (data, TpmuPublicParms::Rsa(inner)))
        }
        _ => Err(nom::Err::Failure(nom::Context::Code(
            input,
            nom::ErrorKind::Custom(2),
        ))),
    }
}

#[derive(Debug)]
/// Asymetric Public Key
pub enum TpmuPublicId {
    // KeyedHash
    // Symcipher
    /// Rsa
    Rsa(Vec<u8>),
    // Ecc(TpmsEccParms),
    // Asym
}

named!( tpmsrsapublickey_parser<&[u8], Vec<u8>>,
    switch!(u16!(nom::Endianness::Big),
        0 => value!(Vec::new()) |
        size => map!(take!(size), |d| d.to_vec())
    )
);

fn parse_tpmupublicid(input: &[u8], alg: TpmAlgId) -> nom::IResult<&[u8], TpmuPublicId> {
    // eprintln!("tpmupublicparms input -> {:?}", input);
    match alg {
        TpmAlgId::Rsa => {
            tpmsrsapublickey_parser(input).map(|(data, inner)| (data, TpmuPublicId::Rsa(inner)))
        }
        _ => Err(nom::Err::Failure(nom::Context::Code(
            input,
            nom::ErrorKind::Custom(2),
        ))),
    }
}

#[derive(Debug)]
/// Tpm Public Key Structure
pub struct TpmtPublic {
    /// The type of public parms and key IE Ecdsa or Rsa
    pub type_: TpmAlgId,
    /// The hash type over pubarea (webauthn specific)
    pub name_alg: TpmAlgId,
    // TPMA_OBJECT
    /// Unused in webauthn.
    pub object_attributes: u32,
    /// Unused in webauthn.
    pub auth_policy: Option<Vec<u8>>,
    //
    // TPMU_PUBLIC_PARMS
    /// Public Parameters
    pub parameters: TpmuPublicParms,
    // TPMU_PUBLIC_ID
    /// Public Key
    pub unique: TpmuPublicId,
}

impl TryFrom<&[u8]> for TpmtPublic {
    type Error = WebauthnError;

    fn try_from(data: &[u8]) -> Result<TpmtPublic, WebauthnError> {
        tpmtpublic_parser(data)
            .map_err(|e| {
                log::debug!("{:?}", e);
                // eprintln!("{:?}", e);
                WebauthnError::ParseNOMFailure
            })
            .map(|(_, v)| v)
    }
}

named!( tpm2b_digest<&[u8], Option<Vec<u8>>>,
    switch!(u16!(nom::Endianness::Big),
        0 => value!(None) |
        size => map!(take!(size), |d| Some(d.to_vec()))
    )
);

named!( tpmtpublic_parser<&[u8], TpmtPublic>,
    do_parse!(
        type_: map_opt!(u16!(nom::Endianness::Big), TpmAlgId::new) >>
        name_alg: map_opt!(u16!(nom::Endianness::Big), TpmAlgId::new) >>
        object_attributes: u32!(nom::Endianness::Big) >>
        auth_policy: tpm2b_digest >>
        parameters: call!(parse_tpmupublicparms, type_) >>
        unique: call!(parse_tpmupublicid, type_) >>
        (TpmtPublic {
            type_, name_alg, object_attributes, auth_policy, parameters, unique
        })
    )
);

#[derive(Debug)]
/// A TPM Signature.
pub enum TpmtSignature {
    // if sigAlg has a type, parse as:
    // signature - TPMU_SIGNATURE
    // Else, due to how this work if no alg, just pass the raw bytes back.
    /// A raw signature, verifyied by a cert + hash combination. May be implementation
    /// specific.
    RawSignature(Vec<u8>),
}

impl TryFrom<&[u8]> for TpmtSignature {
    type Error = WebauthnError;

    fn try_from(data: &[u8]) -> Result<TpmtSignature, WebauthnError> {
        tpmtsignature_parser(data)
            .map_err(|e| {
                log::debug!("{:?}", e);
                WebauthnError::ParseNOMFailure
            })
            .map(|(_, v)| v)
    }
}

fn tpmtsignature_parser(input: &[u8]) -> nom::IResult<&[u8], TpmtSignature> {
    let (_data, algorithm) = map!(input, u16!(nom::Endianness::Big), TpmAlgId::new)?;
    match algorithm {
        None => Ok((&[], TpmtSignature::RawSignature(Vec::from(input)))),
        _ => Err(nom::Err::Failure(nom::Context::Code(
            input,
            nom::ErrorKind::Custom(2),
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AttestationObject, RegisterPublicKeyCredential, TpmsAttest, TpmtPublic, TpmtSignature,
        TPM_GENERATED_VALUE,
    };
    use serde_json;
    use std::convert::TryFrom;

    #[test]
    fn deserialise_register_response() {
        let x = r#"
        {   "id":"4oiUggKcrpRIlB-cFzFbfkx_BNeM7UAnz3wO7ZpT4I2GL_n-g8TICyJTHg11l0wyc-VkQUVnJ0yM08-1D5oXnw",
            "rawId":"4oiUggKcrpRIlB-cFzFbfkx_BNeM7UAnz3wO7ZpT4I2GL_n-g8TICyJTHg11l0wyc-VkQUVnJ0yM08-1D5oXnw",
            "response":{
                "attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjEEsoXtJryKJQ28wPgFmAwoh5SXSZuIJJnQzgBqP1AcaBBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQOKIlIICnK6USJQfnBcxW35MfwTXjO1AJ898Du2aU-CNhi_5_oPEyAsiUx4NdZdMMnPlZEFFZydMjNPPtQ-aF5-lAQIDJiABIVggFo08FM4Je1yfCSuPsxP6h0zvlJSjfocUk75EvXw2oSMiWCArRwLD8doar0bACWS1PgVJKzp_wStyvOkTd4NlWHW8rQ",
                "clientDataJSON":"eyJjaGFsbGVuZ2UiOiJwZENXRDJWamRMSVkzN2VSYTVfazdhS3BqdkF2VmNOY04ycVozMjk0blpVIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovLzEyNy4wLjAuMTo4MDgwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9"
            },
            "type":"public-key"
        }
        "#;
        let _y: RegisterPublicKeyCredential = serde_json::from_str(x).unwrap();
    }

    #[test]
    fn deserialise_attestation_object() {
        let raw_ao = base64::decode(
            "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjEEsoXtJryKJQ28wPgFmAwoh5SXSZuIJJnQzgBqP1AcaBBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQCgxaVISCxE+DrcxP5/+aPM88CTI+04J+o61SK6mnepjGZYv062AbtydzWmbAxF00VSAyp0ImP94uoy+0y7w9yilAQIDJiABIVggGT9woA+UoX+jBxuiHQpdkm0kCVh75WTj3TXl4zLJuzoiWCBKiCneKgWJgWiwrZedNwl06GTaXyaGrYS4bPbBraInyg=="
        ).unwrap();

        let _ao = AttestationObject::try_from(raw_ao.as_slice()).unwrap();
    }
    // Add tests for when the objects are too short.
    //
    #[test]
    fn deserialise_tpms_attest() {
        let data: Vec<u8> = vec![
            255, 84, 67, 71, // magic
            128, 23, // type_
            0, 34, // 2b_name size
            0, 11, 174, 74, 152, 70, 1, 87, 191, 156, 96, 74, 177, 221, 37, 132, 6, 8, 101, 35,
            124, 216, 85, 173, 85, 195, 115, 137, 194, 247, 145, 61, 82, 40, // 2b_name data
            0, 20, // exdata size
            234, 98, 144, 49, 146, 39, 99, 47, 44, 82, 115, 48, 64, 40, 152, 224, 227, 42, 63,
            133, // ext data
            0, 0, 0, 2, 219, 215, 137, 38, // clock
            187, 106, 183, 8, // reset
            100, 145, 106, 200, // restart
            1,   // safe
            86, 5, 220, 81, 118, 234, 131, 141, // fw vers
            0, 34, // type attested.
            0, 11, 239, 53, 112, 255, 253, 12, 189, 168, 16, 253, 10, 149, 108, 7, 31, 212, 143,
            21, 153, 7, 7, 153, 99, 73, 205, 97, 90, 110, 182, 120, 4, 250, 0, 34, 0, 11, 249, 72,
            224, 84, 16, 96, 147, 197, 167, 195, 110, 181, 77, 207, 147, 16, 34, 64, 139, 185, 120,
            190, 196, 209, 213, 29, 1, 136, 76, 235, 223, 247,
        ];

        let tpms_attest = TpmsAttest::try_from(data.as_slice()).unwrap();
        println!("{:?}", tpms_attest);
        assert!(tpms_attest.magic == TPM_GENERATED_VALUE);
    }

    #[test]
    fn deserialise_tpmt_public() {
        // The TPMT_PUBLIC structure (see [TPMv2-Part2] section 12.2.4) used by the TPM to represent the credential public key.
        let data: Vec<u8> = vec![
            0, 1, 0, 11, 0, 6, 4, 114, 0, 32, 157, 255, 203, 243, 108, 56, 58, 230, 153, 251, 152,
            104, 220, 109, 203, 137, 215, 21, 56, 132, 190, 40, 3, 146, 44, 18, 65, 88, 191, 173,
            34, 174, 0, 16, 0, 16, 8, 0, 0, 0, 0, 0, 1, 0, 220, 20, 243, 114, 251, 142, 90, 236,
            17, 204, 181, 223, 8, 72, 230, 209, 122, 44, 90, 55, 96, 134, 69, 16, 125, 139, 112,
            81, 154, 230, 133, 211, 129, 37, 75, 208, 222, 70, 210, 239, 209, 188, 152, 93, 222,
            222, 154, 169, 217, 160, 90, 243, 135, 151, 25, 87, 240, 178, 106, 119, 150, 89, 23,
            223, 158, 88, 107, 72, 101, 61, 184, 132, 19, 110, 144, 107, 22, 178, 252, 206, 50,
            207, 11, 177, 137, 35, 139, 68, 212, 148, 121, 249, 50, 35, 89, 52, 47, 26, 23, 6, 15,
            115, 155, 127, 59, 168, 208, 196, 78, 125, 205, 0, 98, 43, 223, 233, 65, 137, 103, 2,
            227, 35, 81, 107, 247, 230, 186, 111, 27, 4, 57, 42, 220, 32, 29, 181, 159, 6, 176,
            182, 94, 191, 222, 212, 235, 60, 101, 83, 86, 217, 203, 151, 251, 254, 219, 204, 195,
            10, 74, 147, 5, 27, 167, 127, 117, 149, 245, 157, 92, 124, 2, 196, 214, 107, 246, 228,
            171, 229, 100, 212, 67, 88, 215, 75, 33, 183, 199, 51, 171, 210, 213, 65, 45, 96, 96,
            226, 29, 130, 254, 58, 92, 252, 133, 207, 105, 63, 156, 208, 149, 142, 9, 83, 1, 193,
            217, 244, 35, 137, 43, 138, 137, 140, 82, 231, 195, 145, 213, 230, 185, 245, 104, 105,
            62, 142, 124, 34, 9, 157, 167, 188, 243, 112, 104, 248, 63, 50, 19, 53, 173, 69, 12,
            39, 252, 9, 69, 223,
        ];
        let tpmt_public = TpmtPublic::try_from(data.as_slice()).unwrap();
        println!("{:?}", tpmt_public);
    }

    #[test]
    fn deserialise_tpmt_signature() {
        // The attestation signature, in the form of a TPMT_SIGNATURE structure as specified in [TPMv2-Part2] section 11.3.4.
        let data: Vec<u8> = vec![
            5, 3, 162, 216, 151, 57, 210, 103, 145, 121, 161, 186, 63, 232, 221, 255, 89, 37, 17,
            59, 155, 241, 77, 30, 35, 201, 30, 140, 84, 214, 250, 185, 47, 248, 58, 89, 177, 187,
            231, 202, 220, 45, 167, 126, 243, 194, 94, 33, 39, 205, 163, 51, 40, 171, 35, 118, 196,
            244, 247, 143, 166, 193, 223, 94, 244, 157, 121, 220, 22, 94, 163, 15, 151, 223, 214,
            131, 105, 202, 40, 16, 176, 11, 154, 102, 100, 212, 174, 103, 166, 92, 90, 154, 224,
            20, 165, 106, 127, 53, 91, 230, 217, 199, 172, 195, 203, 242, 41, 158, 64, 252, 65, 9,
            155, 160, 63, 40, 94, 94, 64, 145, 173, 71, 85, 173, 2, 199, 18, 148, 88, 223, 93, 154,
            203, 197, 170, 142, 35, 249, 146, 107, 146, 2, 14, 54, 39, 151, 181, 10, 176, 216, 117,
            25, 196, 2, 205, 159, 140, 155, 56, 89, 87, 31, 135, 93, 97, 78, 95, 176, 228, 72, 237,
            130, 171, 23, 66, 232, 35, 115, 218, 105, 168, 6, 253, 121, 161, 129, 44, 78, 252, 44,
            11, 23, 172, 66, 37, 214, 113, 128, 28, 33, 209, 66, 34, 32, 196, 153, 80, 87, 243,
            162, 7, 25, 62, 252, 243, 174, 31, 168, 98, 123, 100, 2, 143, 134, 36, 154, 236, 18,
            128, 175, 185, 189, 177, 51, 53, 216, 190, 43, 63, 35, 84, 14, 64, 249, 23, 9, 125,
            147, 160, 176, 137, 30, 174, 245, 148, 189,
        ];
        let tpmt_sig = TpmtSignature::try_from(data.as_slice()).unwrap();
        println!("{:?}", tpmt_sig);
    }
}

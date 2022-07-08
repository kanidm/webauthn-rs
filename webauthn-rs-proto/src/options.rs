//! Types that define options as to how an authenticator may interact with
//! with the server.

use base64urlsafedata::Base64UrlSafeData;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A credential ID type. At the moment this is a vector of bytes, but
/// it could also be a future change for this to be base64 string instead.
///
/// If changed, this would likely be a major library version change.
pub type CredentialID = Base64UrlSafeData;

/// Defines the User Authenticator Verification policy. This is documented
/// <https://w3c.github.io/webauthn/#enumdef-userverificationrequirement>, and each
/// variant lists it's effects.
///
/// To be clear, Verification means that the Authenticator perform extra or supplementary
/// interaction with the user to verify who they are. An example of this is Apple Touch Id
/// required a fingerprint to be verified, or a yubico device requiring a pin in addition to
/// a touch event.
///
/// An example of a non-verified interaction is a yubico device with no pin where touch is
/// the only interaction - we only verify a user is present, but we don't have extra details
/// to the legitimacy of that user.
///
/// As UserVerificationPolicy is *only* used in credential registration, this stores the
/// verification state of the credential in the persisted credential. These persisted
/// credentials define which UserVerificationPolicy is issued during authentications.
///
/// ⚠️  WARNING - discouraged is marked with a warning, as in some cases, some authenticators
/// will FORCE verification during registration but NOT during authentication. This means
/// that is is NOT possible assert verification has been bypassed or not from the server
/// viewpoint, and to the user it may create confusion about when verification is or is
/// not required.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
#[allow(non_camel_case_types)]
#[serde(rename_all = "lowercase")]
pub enum UserVerificationPolicy {
    /// Require User Verification bit to be set, and fail the registration or authentication
    /// if false. If the authenticator is not able to perform verification, it may not be
    /// usable with this policy.
    Required,
    /// TO FILL IN
    #[serde(rename = "preferred")]
    Preferred,
    /// TO FILL IN
    #[serde(rename = "discouraged")]
    Discouraged_DO_NOT_USE,
}

impl Default for UserVerificationPolicy {
    fn default() -> Self {
        UserVerificationPolicy::Preferred
    }
}

/// Relying Party Entity
#[derive(Debug, Serialize, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelyingParty {
    /// The name of the relying party.
    pub name: String,
    /// The id of the relying party.
    pub id: String,
}

/// User Entity
#[derive(Debug, Serialize, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct User {
    /// The user's id in base64 form. This MUST be a unique id, and
    /// must NOT contain personally identifying information, as this value can NEVER
    /// be changed. If in doubt, use a UUID.
    pub id: Base64UrlSafeData,
    /// The users preferred name for display.
    pub name: String,
    /// The users preferred name for display.
    pub display_name: String,
}

/// Public key cryptographic parameters
#[derive(Debug, Serialize, Clone, Deserialize)]
pub struct PubKeyCredParams {
    /// The type of public-key credential.
    #[serde(rename = "type")]
    pub type_: String,
    /// The algorithm in use defined by COSE.
    pub alg: i64,
}

/// <https://www.w3.org/TR/webauthn/#enumdef-attestationconveyancepreference>
#[derive(Debug, Serialize, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AttestationConveyancePreference {
    /// Do not request attestation.
    /// <https://www.w3.org/TR/webauthn/#dom-attestationconveyancepreference-none>
    None,

    /// Request attestation in a semi-anonymized form.
    /// <https://www.w3.org/TR/webauthn/#dom-attestationconveyancepreference-indirect>
    Indirect,

    /// Request attestation in a direct form.
    /// <https://www.w3.org/TR/webauthn/#dom-attestationconveyancepreference-direct>
    Direct,
}

/// <https://www.w3.org/TR/webauthn/#enumdef-authenticatortransport>
#[derive(Debug, Serialize, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
#[allow(unused)]
pub enum AuthenticatorTransport {
    /// <https://www.w3.org/TR/webauthn/#dom-authenticatortransport-usb>
    Usb,
    /// <https://www.w3.org/TR/webauthn/#dom-authenticatortransport-nfc>
    Nfc,
    /// <https://www.w3.org/TR/webauthn/#dom-authenticatortransport-ble>
    Ble,
    /// <https://www.w3.org/TR/webauthn/#dom-authenticatortransport-internal>
    Internal,
    // ///
    // Hybrid
}

/// <https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialdescriptor>
#[derive(Debug, Serialize, Clone, Deserialize)]
pub struct PublicKeyCredentialDescriptor {
    /// The type of credential
    #[serde(rename = "type")]
    pub type_: String,
    /// The credential id.
    pub id: Base64UrlSafeData,
    /// The allowed transports for this credential. Note this is a hint, and is NOT
    /// enforced.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<AuthenticatorTransport>>,
}

/// The authenticator attachment hint. This is NOT enforced, and is only used
/// to help a user select a relevant authenticator type.
///
/// <https://www.w3.org/TR/webauthn/#attachment>
#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq)]
pub enum AuthenticatorAttachment {
    /// Request a device that is part of the machine aka inseperable.
    /// <https://www.w3.org/TR/webauthn/#attachment>
    #[serde(rename = "platform")]
    Platform,
    /// Request a device that can be seperated from the machine aka an external token.
    /// <https://www.w3.org/TR/webauthn/#attachment>
    #[serde(rename = "cross-platform")]
    CrossPlatform,
}

/// <https://www.w3.org/TR/webauthn/#dictdef-authenticatorselectioncriteria>
#[derive(Debug, Serialize, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatorSelectionCriteria {
    /// How the authenticator should be attached to the client machine.
    /// Note this is only a hint. It is not enforced in anyway shape or form.
    /// <https://www.w3.org/TR/webauthn/#attachment>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticator_attachment: Option<AuthenticatorAttachment>,

    /// Hint to the credential to create a resident key. Note this can not be enforced
    /// or validated, so the authenticator may choose to ignore this parameter.
    /// <https://www.w3.org/TR/webauthn/#resident-credential>
    pub require_resident_key: bool,

    /// The user verification level to request during registration. Depending on if this
    /// authenticator provides verification may affect future interactions as this is
    /// associated to the credential during registration.
    pub user_verification: UserVerificationPolicy,
}

/// A descriptor of a credential that can be used.
#[derive(Debug, Serialize, Clone, Deserialize)]
pub struct AllowCredentials {
    #[serde(rename = "type")]
    /// The type of credential.
    pub type_: String,
    /// The id of the credential.
    pub id: Base64UrlSafeData,
    /// <https://www.w3.org/TR/webauthn/#transport>
    /// may be usb, nfc, ble, internal
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<AuthenticatorTransport>>,
}

/// The data collected and hashed in the operation.
/// <https://www.w3.org/TR/webauthn-2/#dictdef-collectedclientdata>
#[derive(Debug, Serialize, Clone, Deserialize)]
pub struct CollectedClientData {
    /// The credential type
    #[serde(rename = "type")]
    pub type_: String,
    /// The challenge.
    pub challenge: Base64UrlSafeData,
    /// The rp origin as the browser understood it.
    pub origin: url::Url,
    /// The inverse of the sameOriginWithAncestors argument value that was
    /// passed into the internal method.
    #[serde(rename = "crossOrigin", skip_serializing_if = "Option::is_none")]
    pub cross_origin: Option<bool>,
    /// tokenBinding.
    #[serde(rename = "tokenBinding")]
    pub token_binding: Option<TokenBinding>,
    /// This struct be extended, so it's important to be tolerant of unknown
    /// keys.
    #[serde(flatten)]
    pub unknown_keys: BTreeMap<String, serde_json::value::Value>,
}

/*
impl TryFrom<&[u8]> for CollectedClientData {
    type Error = WebauthnError;
    fn try_from(data: &[u8]) -> Result<CollectedClientData, WebauthnError> {
        let ccd: CollectedClientData =
            serde_json::from_slice(data).map_err(WebauthnError::ParseJSONFailure)?;
        Ok(ccd)
    }
}
*/

/// Token binding
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TokenBinding {
    /// status
    pub status: String,
    /// id
    pub id: Option<String>,
}

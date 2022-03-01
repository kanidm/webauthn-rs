//! Extensions allowing certain types of authenticators to provide supplemental information.

use base64urlsafedata::Base64UrlSafeData;
use serde::{Deserialize, Serialize};

/// Valid credential protection policies
#[derive(Debug, Serialize, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[repr(u8)]
pub enum CredentialProtectionPolicy {
    /// This reflects "FIDO_2_0" semantics. In this configuration, performing
    /// some form of user verification is optional with or without credentialID
    /// list. This is the default state of the credential if the extension is
    /// not specified.
    UserVerificationOptional = 0x1,
    /// In this configuration, credential is discovered only when its
    /// credentialID is provided by the platform or when some form of user
    /// verification is performed.
    UserVerificationOptionalWithCredentialIDList = 0x2,
    /// This reflects that discovery and usage of the credential MUST be
    /// preceded by some form of user verification.
    UserVerificationRequired = 0x3,
}

impl TryFrom<u8> for CredentialProtectionPolicy {
    type Error = &'static str;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        use CredentialProtectionPolicy::*;
        match v {
            0x1 => Ok(UserVerificationOptional),
            0x2 => Ok(UserVerificationOptionalWithCredentialIDList),
            0x3 => Ok(UserVerificationRequired),
            _ => Err("Invalid policy number"),
        }
    }
}

/// The desired options for the client's use of the `credProtect` extension
///
/// <https://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html#sctn-credProtect-extension>
#[derive(Debug, Serialize, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CredProtect {
    /// The credential policy to enact
    pub credential_protection_policy: CredentialProtectionPolicy,
    /// Whether it is better for the authenticator to fail to create a
    /// credential rather than ignore the protection policy
    /// If no value is provided, the client treats it as `false`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enforce_credential_protection_policy: Option<bool>,
}

/// Wrapper for an ArrayBuffer containing opaque data in an RP-specific format.
/// <https://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html#sctn-credBlob-extension>
#[derive(Debug, Serialize, Clone, Deserialize, PartialEq, Eq)]
pub struct CredBlobSet(pub Base64UrlSafeData);

impl From<Vec<u8>> for CredBlobSet {
    fn from(bytes: Vec<u8>) -> Self {
        CredBlobSet(Base64UrlSafeData(bytes))
    }
}

/// Extension option inputs for PublicKeyCredentialCreationOptions.
///
/// Implements \[AuthenticatorExtensionsClientInputs\] from the spec.
#[derive(Debug, Serialize, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestRegistrationExtensions {
    /// The `credProtect` extension options
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub cred_protect: Option<CredProtect>,

    /// The `credBlob` extension options
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cred_blob: Option<CredBlobSet>,
}

// ========== Auth exten ============

/// Wrapper for a boolean value to indicate that this extension is requested by
/// the Relying Party.
#[derive(Debug, Serialize, Clone, Deserialize, PartialEq, Eq)]
pub struct CredBlobGet(pub bool);

/// Extension option inputs for PublicKeyCredentialRequestOptions
///
/// Implements \[AuthenticatorExtensionsClientInputs\] from the spec
#[derive(Debug, Serialize, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestAuthenticationExtensions {
    /// The `credBlob` extension options
    #[serde(skip_serializing_if = "Option::is_none")]
    pub get_cred_blob: Option<CredBlobGet>,

    /// The `appid` extension options
    #[serde(skip_serializing_if = "Option::is_none")]
    pub appid: Option<String>,
}

/// <https://w3c.github.io/webauthn/#dictdef-authenticationextensionsclientoutputs>
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AuthenticationExtensionsClientOutputs {
    /// Indicates whether the client used the provided appid extension
    #[serde(default)]
    pub appid: bool,
}

#[cfg(feature = "wasm")]
impl From<web_sys::AuthenticationExtensionsClientOutputs>
    for AuthenticationExtensionsClientOutputs
{
    fn from(
        ext: web_sys::AuthenticationExtensionsClientOutputs,
    ) -> AuthenticationExtensionsClientOutputs {
        let appid = js_sys::Reflect::get(&ext, &"appid".into())
            .ok()
            .and_then(|jv| jv.as_bool())
            .unwrap_or(false);

        AuthenticationExtensionsClientOutputs { appid }
    }
}

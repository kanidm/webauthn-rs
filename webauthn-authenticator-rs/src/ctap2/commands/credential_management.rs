//! `authenticatorCredentialManagement` commands.
#[cfg(doc)]
use crate::stubs::*;

use serde::{Deserialize, Serialize};
use serde_cbor_2::{
    ser::to_vec_packed,
    value::{from_value, to_value},
    Value,
};
use std::fmt::Debug;
use webauthn_rs_core::proto::COSEKey;
use webauthn_rs_proto::CredentialProtectionPolicy;

use crate::crypto::{compute_sha256, SHA256Hash};

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
        /// * [CredSubCommand] for dynamically-constructed commands
        /// * [ENUMERATE_RPS_GET_NEXT][Self::ENUMERATE_RPS_GET_NEXT]
        /// * [ENUMERATE_CREDENTIALS_GET_NEXT][Self::ENUMERATE_CREDENTIALS_GET_NEXT]
        ///
        /// Reference: [CTAP protocol reference][ref]
        #[derive(Serialize, Debug, Clone, Default, PartialEq, Eq)]
        #[serde(into = "BTreeMap<u32, Value>")]
        pub struct $name {
            /// Action being requested
            sub_command: u8,
            /// Parameters for the [`sub_command`][Self::sub_command].
            ///
            /// **See also:** [CredSubCommand]
            sub_command_params: Option<BTreeMap<Value, Value>>,
            /// PIN / UV protocol version chosen by the platform
            pin_uv_protocol: Option<u32>,
            /// Output of calling "Authenticate" on some context specific to
            /// [`sub_command`][Self::sub_command].
            pin_uv_auth_param: Option<Vec<u8>>,
        }

        impl CBORCommand for $name {
            const CMD: u8 = $cmd;
            type Response = CredentialManagementResponse;
        }

        impl CredentialManagementRequestTrait for $name {
            const ENUMERATE_RPS_GET_NEXT: Self = Self {
                sub_command: 0x03,
                sub_command_params: None,
                pin_uv_protocol: None,
                pin_uv_auth_param: None,
            };

            const ENUMERATE_CREDENTIALS_GET_NEXT: Self = Self {
                sub_command: 0x05,
                sub_command_params: None,
                pin_uv_protocol: None,
                pin_uv_auth_param: None,
            };

            fn new(
                s: CredSubCommand,
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

        impl From<$name> for BTreeMap<u32, Value> {
            fn from(value: $name) -> Self {
                let $name {
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

    /// Command to get the next RP while enumerating RPs with discoverable
    /// credentials on the authenticator.
    ///
    /// **See also:** [`CredSubCommand::EnumerateRPsBegin`]
    const ENUMERATE_RPS_GET_NEXT: Self;

    /// Command to get the next credential while enumerating discoverable
    /// credentials on the authenticator for an RP.
    ///
    /// **See also:** [`CredSubCommand::EnumerateCredentialsBegin`]
    const ENUMERATE_CREDENTIALS_GET_NEXT: Self;
}

/// Wrapper for credential management command types, which can be passed to
/// [CredentialManagementRequestTrait::new].
///
/// Static commands (not requiring authentication) are declared as constants of
/// [CredentialManagementRequestTrait], see:
///
/// * [ENUMERATE_RPS_GET_NEXT][CredentialManagementRequestTrait::ENUMERATE_RPS_GET_NEXT]
/// * [ENUMERATE_CREDENTIALS_GET_NEXT][CredentialManagementRequestTrait::ENUMERATE_CREDENTIALS_GET_NEXT]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum CredSubCommand {
    #[default]
    Unknown,

    /// Gets metadata about the authenticator's discoverable credential storage.
    ///
    /// See [CredentialStorageMetadata] for more details.
    GetCredsMetadata,

    /// Starts enumerating all relying parties with discoverable credentials
    /// stored on this authenticator.
    ///
    /// To get the next relying party, use
    /// [ENUMERATE_RPS_GET_NEXT][CredentialManagementRequestTrait::ENUMERATE_RPS_GET_NEXT].
    EnumerateRPsBegin,

    /// Starts enumerating all credentials for a relying party, by the SHA-256
    /// hash of the relying party ID.
    ///
    /// To enumerate credentials by relying party ID (rather than its hash), use
    /// [`enumerate_credentials_by_rpid()`][0].
    ///
    /// To get the next credential, use [ENUMERATE_CREDENTIALS_GET_NEXT][1].
    ///
    /// [0]: CredSubCommand::enumerate_credentials_by_rpid
    /// [1]: CredentialManagementRequestTrait::ENUMERATE_CREDENTIALS_GET_NEXT
    EnumerateCredentialsBegin(/* rpIdHash */ SHA256Hash),

    /// Deletes a discoverable credential from the authenticator.
    DeleteCredential(PublicKeyCredentialDescriptorCM),

    /// Updates user information for a discoverable credential.
    ///
    /// This is only available on authenticators supporting CTAP 2.1 or later.
    UpdateUserInformation(PublicKeyCredentialDescriptorCM, UserCM),
}

impl From<&CredSubCommand> for u8 {
    fn from(c: &CredSubCommand) -> Self {
        use CredSubCommand::*;
        match c {
            Unknown => 0x00,
            GetCredsMetadata => 0x01,
            EnumerateRPsBegin => 0x02,
            // EnumerateRPsGetNextRP => 0x03,
            EnumerateCredentialsBegin(_) => 0x04,
            // EnumerateCredentialsGetNextCredential => 0x05,
            DeleteCredential(_) => 0x06,
            UpdateUserInformation(_, _) => 0x07,
        }
    }
}

impl From<CredSubCommand> for Option<BTreeMap<Value, Value>> {
    fn from(c: CredSubCommand) -> Self {
        use CredSubCommand::*;
        match c {
            Unknown | GetCredsMetadata | EnumerateRPsBegin => None,
            EnumerateCredentialsBegin(rp_id_hash) => Some(BTreeMap::from([(
                Value::Integer(0x01),
                Value::Bytes(rp_id_hash.to_vec()),
            )])),
            DeleteCredential(credential_id) => Some(BTreeMap::from([(
                Value::Integer(0x02),
                to_value(credential_id).ok()?,
            )])),
            UpdateUserInformation(credential_id, user) => Some(BTreeMap::from([
                (Value::Integer(0x02), to_value(credential_id).ok()?),
                (Value::Integer(0x03), to_value(user).ok()?),
            ])),
        }
    }
}

impl CredSubCommand {
    /// The [PRF (pseudo-random function)][prf] for [CredSubCommand], used to
    /// sign requests for PIN/UV authentication.
    ///
    /// [prf]: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#prfValues
    pub fn prf(&self) -> Vec<u8> {
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

    /// Creates an [EnumerateCredentialsBegin][0] for enumerating credentials by
    /// relying party ID.
    ///
    /// See [EnumerateCredentialsBegin][0] for enumerating credentials by the
    /// SHA-256 hash of the relying party ID.
    ///
    /// [0]: CredSubCommand::EnumerateCredentialsBegin
    #[inline]
    pub fn enumerate_credentials_by_rpid(rp_id: &str) -> Self {
        Self::EnumerateCredentialsBegin(compute_sha256(rp_id.as_bytes()))
    }
}

/// Potentially-abridged form of [RelyingParty][] for credential management.
///
/// Per [CTAP 2.1 specification §6.8.3: Enumerating RPs][2]:
///
/// > `PublicKeyCredentialRpEntity`, where the `id` field *should* be included,
/// > and other fields *may* be included. See
/// > [§6.8.7 Truncation of relying party identifiers][0] about possible
/// > truncation of the `id` field…
///
/// Most authenticators we've tested only store the `id` field. However, we've
/// observed authenticators from the same vendor, supporting the same CTAP
/// version sometimes *also* including the `name` and `icon` fields.
///
/// **Note:** [the `icon` field is deprecated][1], so this field is not
/// supported by this library.
///
/// [RelyingParty]: webauthn_rs_proto::RelyingParty
/// [0]: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#rpid-truncation
/// [1]: https://github.com/w3c/webauthn/pull/1337
/// [2]: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#enumeratingRPs
#[derive(Debug, Default, Serialize, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RelyingPartyCM {
    /// The name of the relying party.
    ///
    /// This might be omitted by the authenticator to save storage space.
    pub name: Option<String>,

    /// The relying party ID, typically a domain name.
    ///
    /// This *should* be included by all authenticators, but the value
    /// [may be truncated][0] (so [`hash`][Self::hash] might not be
    /// `sha256(id)`).
    ///
    /// [0]: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#rpid-truncation
    pub id: Option<String>,

    /// The SHA-256 hash of the [*untruncated*][0] [relying party ID][Self::id].
    ///
    /// [0]: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#rpid-truncation
    #[serde(skip)]
    pub hash: Option<SHA256Hash>,
}

/// User entity
///
/// **Note:** [the `icon` field is deprecated][1], so this field is not
/// supported by this library.
///
/// [1]: https://github.com/w3c/webauthn/pull/1337
#[derive(Debug, Serialize, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UserCM {
    /// The user ID.
    #[serde(with = "serde_bytes")]
    pub id: Vec<u8>,

    /// A human-palatable identifier for the account, such as a username, email
    /// address or phone number.
    ///
    /// This value **can** change, so **must not** be used as a primary key.
    pub name: Option<String>,

    /// Human-palatable display name for the user account.
    ///
    /// This value **can** change, so **must not** be used as a primary key.
    pub display_name: Option<String>,
}

#[derive(Debug, Serialize, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyCredentialDescriptorCM {
    /// The type of credential
    #[serde(rename = "type")]
    pub type_: String,
    /// The credential id.
    #[serde(with = "serde_bytes")]
    pub id: Vec<u8>,
}

impl From<Vec<u8>> for PublicKeyCredentialDescriptorCM {
    fn from(id: Vec<u8>) -> Self {
        Self {
            type_: "public-key".to_string(),
            id,
        }
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
    pub storage_metadata: Option<CredentialStorageMetadata>,
    pub rp: Option<RelyingPartyCM>,
    pub total_rps: Option<u32>,
    pub discoverable_credential: DiscoverableCredential,
    pub total_credentials: Option<u32>,
}

impl TryFrom<BTreeMap<u32, Value>> for CredentialManagementResponse {
    type Error = &'static str;
    fn try_from(mut raw: BTreeMap<u32, Value>) -> Result<Self, Self::Error> {
        trace!(?raw);

        // Parse the relying party field if present.
        let mut rp: Option<RelyingPartyCM> = if let Some(v) = raw.remove(&0x03) {
            Some(from_value(v).map_err(|e| {
                error!("parsing rp: {e:?}");
                "parsing rp"
            })?)
        } else {
            None
        };

        // Parse the relying party ID hash field if present.
        if let Some(rp_id_hash) = raw
            .remove(&0x04)
            .and_then(|v| value_to_vec_u8(v, "0x04"))
            .and_then(|v| v.try_into().ok())
        {
            if let Some(rp) = &mut rp {
                // Add the hash to the existing RelyingPartyCM
                rp.hash = Some(rp_id_hash);
            } else {
                rp = Some(RelyingPartyCM {
                    hash: Some(rp_id_hash),
                    ..Default::default()
                });
            }
        }

        Ok(Self {
            storage_metadata: CredentialStorageMetadata::try_from(&mut raw).ok(),
            rp,
            total_rps: raw.remove(&0x05).and_then(|v| value_to_u32(&v, "0x05")),
            total_credentials: raw.remove(&0x09).and_then(|v| value_to_u32(&v, "0x09")),
            discoverable_credential: DiscoverableCredential::try_from(&mut raw)?,
        })
    }
}

crate::deserialize_cbor!(CredentialManagementResponse);

/// Discoverable credential storage metadata, returned by
/// [`CredentialManagementAuthenticator::get_credentials_metadata()`][1].
///
/// [1]: crate::ctap2::ctap21_cred::CredentialManagementAuthenticator::get_credentials_metadata
#[derive(Deserialize, Debug, Default, PartialEq, Eq)]
pub struct CredentialStorageMetadata {
    /// Number of discoverable credentials present on the authenticator.
    pub existing_resident_credentials_count: u32,

    /// Estimated number of additional discoverable credentials which could be
    /// created on this authenticator, assuming *minimally-sized* fields for all
    /// requests (ie: errs high).
    ///
    /// This value may vary over time, depending on the size of individual
    /// discoverable credentials, and the token's storage allocation strategy.
    ///
    /// ## CTAP compatibility
    ///
    /// On authenticators supporting CTAP 2.1 or later, a pessimistic estimate
    /// (ie: presuming *maximally-sized* credentials) *might* be available
    /// *without* authentication in
    /// [`GetInfoResponse::remaining_discoverable_credentials`][0].
    ///
    /// [0]: super::GetInfoResponse::remaining_discoverable_credentials
    pub max_possible_remaining_resident_credentials_count: u32,
}

impl TryFrom<&mut BTreeMap<u32, Value>> for CredentialStorageMetadata {
    type Error = WebauthnCError;
    fn try_from(raw: &mut BTreeMap<u32, Value>) -> Result<Self, Self::Error> {
        Ok(Self {
            existing_resident_credentials_count: raw
                .remove(&0x01)
                .and_then(|v| value_to_u32(&v, "0x01"))
                .ok_or(WebauthnCError::MissingRequiredField)?,
            max_possible_remaining_resident_credentials_count: raw
                .remove(&0x02)
                .and_then(|v| value_to_u32(&v, "0x02"))
                .ok_or(WebauthnCError::MissingRequiredField)?,
        })
    }
}

#[derive(Deserialize, Debug, Default, PartialEq, Eq)]
pub struct DiscoverableCredential {
    pub user: Option<UserCM>,
    pub credential_id: Option<PublicKeyCredentialDescriptorCM>,
    pub public_key: Option<COSEKey>,
    pub cred_protect: Option<CredentialProtectionPolicy>,
    pub large_blob_key: Option<Vec<u8>>,
}

impl TryFrom<&mut BTreeMap<u32, Value>> for DiscoverableCredential {
    type Error = &'static str;
    fn try_from(raw: &mut BTreeMap<u32, Value>) -> Result<Self, Self::Error> {
        Ok(Self {
            user: if let Some(v) = raw.remove(&0x06) {
                Some(from_value(v).map_err(|e| {
                    error!("parsing user: {e:?}");
                    "parsing user"
                })?)
            } else {
                None
            },
            credential_id: if let Some(v) = raw.remove(&0x07) {
                Some(from_value(v).map_err(|e| {
                    error!("parsing credentialID: {e:?}");
                    "parsing credentialID"
                })?)
            } else {
                None
            },
            public_key: if let Some(v) = raw.remove(&0x08) {
                // publicKey is a Map<u32, Value>, need to use
                // `impl TryFrom<&Value> for COSEKey`
                Some(COSEKey::try_from(&v).map_err(|e| {
                    error!("parsing publicKey: {e:?}");
                    "parsing publicKey"
                })?)
            } else {
                None
            },
            cred_protect: raw
                .remove(&0x0A)
                .and_then(|v| value_to_u8(&v, "0x0A"))
                .and_then(|v| CredentialProtectionPolicy::try_from(v).ok()),
            large_blob_key: raw.remove(&0x0B).and_then(|v| value_to_vec_u8(v, "0x0B")),
        })
    }
}

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

#[cfg(test)]
mod test {
    use base64urlsafedata::Base64UrlSafeData;
    use webauthn_rs_core::proto::{COSEEC2Key, COSEKeyType, ECDSACurve};
    use webauthn_rs_proto::COSEAlgorithm;

    use super::*;
    const PIN_UV_AUTH_PARAM: [u8; 32] = [
        0x13, 0xd7, 0xf2, 0xe7, 0xa0, 0xb9, 0x61, 0x78, 0x39, 0xb3, 0xfb, 0xbf, 0xc2, 0xf9, 0x0c,
        0xec, 0x5e, 0xc0, 0xc6, 0xc0, 0x41, 0x54, 0x72, 0x74, 0x22, 0x56, 0xac, 0x6e, 0xd7, 0x9e,
        0xfa, 0x5d,
    ];

    #[test]
    fn get_cred_metadata() {
        let _ = tracing_subscriber::fmt::try_init();

        const SUBCOMMAND: CredSubCommand = CredSubCommand::GetCredsMetadata;
        assert_eq!(vec![0x01], SUBCOMMAND.prf());

        let c =
            CredentialManagementRequest::new(SUBCOMMAND, Some(2), Some(PIN_UV_AUTH_PARAM.to_vec()));

        assert_eq!(
            vec![
                0x0a, 0xa3, 0x01, 0x01, 0x03, 0x02, 0x04, 0x58, 0x20, 0x13, 0xd7, 0xf2, 0xe7, 0xa0,
                0xb9, 0x61, 0x78, 0x39, 0xb3, 0xfb, 0xbf, 0xc2, 0xf9, 0x0c, 0xec, 0x5e, 0xc0, 0xc6,
                0xc0, 0x41, 0x54, 0x72, 0x74, 0x22, 0x56, 0xac, 0x6e, 0xd7, 0x9e, 0xfa, 0x5d
            ],
            c.cbor().expect("encode error")
        );

        let c = PrototypeCredentialManagementRequest::new(
            SUBCOMMAND,
            Some(1),
            Some(PIN_UV_AUTH_PARAM.to_vec()),
        );

        assert_eq!(
            vec![
                0x41, 0xa3, 0x01, 0x01, 0x03, 0x01, 0x04, 0x58, 0x20, 0x13, 0xd7, 0xf2, 0xe7, 0xa0,
                0xb9, 0x61, 0x78, 0x39, 0xb3, 0xfb, 0xbf, 0xc2, 0xf9, 0x0c, 0xec, 0x5e, 0xc0, 0xc6,
                0xc0, 0x41, 0x54, 0x72, 0x74, 0x22, 0x56, 0xac, 0x6e, 0xd7, 0x9e, 0xfa, 0x5d
            ],
            c.cbor().expect("encode error")
        );

        let r = [0xa2, 0x01, 0x03, 0x02, 0x16];
        let a = <CredentialManagementResponse as CBORResponse>::try_from(r.as_slice())
            .expect("Failed to decode message");

        assert_eq!(
            CredentialManagementResponse {
                storage_metadata: Some(CredentialStorageMetadata {
                    existing_resident_credentials_count: 3,
                    max_possible_remaining_resident_credentials_count: 22,
                }),
                ..Default::default()
            },
            a
        )
    }

    #[test]
    fn enumerate_rps_begin() {
        let _ = tracing_subscriber::fmt::try_init();

        const SUBCOMMAND: CredSubCommand = CredSubCommand::EnumerateRPsBegin;
        assert_eq!(vec![0x02], SUBCOMMAND.prf());

        let c =
            CredentialManagementRequest::new(SUBCOMMAND, Some(2), Some(PIN_UV_AUTH_PARAM.to_vec()));

        assert_eq!(
            vec![
                0x0a, 0xa3, 0x01, 0x02, 0x03, 0x02, 0x04, 0x58, 0x20, 0x13, 0xd7, 0xf2, 0xe7, 0xa0,
                0xb9, 0x61, 0x78, 0x39, 0xb3, 0xfb, 0xbf, 0xc2, 0xf9, 0x0c, 0xec, 0x5e, 0xc0, 0xc6,
                0xc0, 0x41, 0x54, 0x72, 0x74, 0x22, 0x56, 0xac, 0x6e, 0xd7, 0x9e, 0xfa, 0x5d
            ],
            c.cbor().expect("encode error")
        );

        let c = PrototypeCredentialManagementRequest::new(
            SUBCOMMAND,
            Some(1),
            Some(PIN_UV_AUTH_PARAM.to_vec()),
        );

        assert_eq!(
            vec![
                0x41, 0xa3, 0x01, 0x02, 0x03, 0x01, 0x04, 0x58, 0x20, 0x13, 0xd7, 0xf2, 0xe7, 0xa0,
                0xb9, 0x61, 0x78, 0x39, 0xb3, 0xfb, 0xbf, 0xc2, 0xf9, 0x0c, 0xec, 0x5e, 0xc0, 0xc6,
                0xc0, 0x41, 0x54, 0x72, 0x74, 0x22, 0x56, 0xac, 0x6e, 0xd7, 0x9e, 0xfa, 0x5d
            ],
            c.cbor().expect("encode error")
        );

        // Response with RP ID and hash only
        let r = [
            0xa3, 0x03, 0xa1, 0x62, 0x69, 0x64, 0x78, 0x18, 0x77, 0x65, 0x62, 0x61, 0x75, 0x74,
            0x68, 0x6e, 0x2e, 0x66, 0x69, 0x72, 0x73, 0x74, 0x79, 0x65, 0x61, 0x72, 0x2e, 0x69,
            0x64, 0x2e, 0x61, 0x75, 0x04, 0x58, 0x20, 0x6a, 0xb9, 0xbb, 0xf0, 0xdf, 0x9a, 0x16,
            0xf9, 0x1d, 0xbb, 0x33, 0xbb, 0xb1, 0x32, 0xfa, 0xf9, 0xd1, 0x7c, 0x78, 0x2c, 0x48,
            0x26, 0xc6, 0xec, 0x70, 0xec, 0xee, 0x58, 0xd9, 0x7e, 0xf5, 0x2a, 0x05, 0x02,
        ];
        let a = <CredentialManagementResponse as CBORResponse>::try_from(r.as_slice())
            .expect("Failed to decode message");

        assert_eq!(
            CredentialManagementResponse {
                rp: Some(RelyingPartyCM {
                    name: None,
                    id: Some("webauthn.firstyear.id.au".to_string()),
                    hash: Some([
                        0x6a, 0xb9, 0xbb, 0xf0, 0xdf, 0x9a, 0x16, 0xf9, 0x1d, 0xbb, 0x33, 0xbb,
                        0xb1, 0x32, 0xfa, 0xf9, 0xd1, 0x7c, 0x78, 0x2c, 0x48, 0x26, 0xc6, 0xec,
                        0x70, 0xec, 0xee, 0x58, 0xd9, 0x7e, 0xf5, 0x2a
                    ]),
                }),
                total_rps: Some(2),
                ..Default::default()
            },
            a
        );

        // Response with RP ID, name, icon (ignored) and hash
        let r = [
            0xa3, 0x03, 0xa3, 0x62, 0x69, 0x64, 0x78, 0x1e, 0x77, 0x65, 0x62, 0x61, 0x75, 0x74,
            0x68, 0x6e, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x61, 0x7a, 0x75, 0x72, 0x65, 0x77, 0x65,
            0x62, 0x73, 0x69, 0x74, 0x65, 0x73, 0x2e, 0x6e, 0x65, 0x74, 0x64, 0x69, 0x63, 0x6f,
            0x6e, 0x78, 0x1e, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x65, 0x78, 0x61,
            0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x72, 0x70, 0x49, 0x63, 0x6f,
            0x6e, 0x2e, 0x70, 0x6e, 0x67, 0x64, 0x6e, 0x61, 0x6d, 0x65, 0x74, 0x57, 0x65, 0x62,
            0x41, 0x75, 0x74, 0x68, 0x6e, 0x20, 0x54, 0x65, 0x73, 0x74, 0x20, 0x53, 0x65, 0x72,
            0x76, 0x65, 0x72, 0x04, 0x58, 0x20, 0xe4, 0x53, 0x29, 0xd0, 0x3a, 0x20, 0x68, 0xd1,
            0xca, 0xf7, 0xf7, 0xbb, 0x0a, 0xe9, 0x54, 0xe6, 0xb0, 0xe6, 0x25, 0x97, 0x45, 0xf3,
            0x2f, 0x48, 0x29, 0xf7, 0x50, 0xf0, 0x50, 0x11, 0xf9, 0xc2, 0x05, 0x03,
        ];
        let a = <CredentialManagementResponse as CBORResponse>::try_from(r.as_slice())
            .expect("Failed to decode message");

        assert_eq!(
            CredentialManagementResponse {
                rp: Some(RelyingPartyCM {
                    name: Some("WebAuthn Test Server".to_string()),
                    id: Some("webauthntest.azurewebsites.net".to_string()),
                    hash: Some([
                        0xe4, 0x53, 0x29, 0xd0, 0x3a, 0x20, 0x68, 0xd1, 0xca, 0xf7, 0xf7, 0xbb,
                        0x0a, 0xe9, 0x54, 0xe6, 0xb0, 0xe6, 0x25, 0x97, 0x45, 0xf3, 0x2f, 0x48,
                        0x29, 0xf7, 0x50, 0xf0, 0x50, 0x11, 0xf9, 0xc2
                    ]),
                }),
                total_rps: Some(3),
                ..Default::default()
            },
            a
        );

        // Feitian keys with zero credentials give an empty CredentialManagementResponse
        let r = [];
        let a = <CredentialManagementResponse as CBORResponse>::try_from(r.as_slice())
            .expect("Failed to decode message");
        assert_eq!(
            CredentialManagementResponse {
                total_rps: None,
                ..Default::default()
            },
            a
        );

        // Yubikey 5 with zero credentials gives an explicit zero
        let r = [0xa1, 0x05, 0x00];
        let a = <CredentialManagementResponse as CBORResponse>::try_from(r.as_slice())
            .expect("Failed to decode message");

        assert_eq!(
            CredentialManagementResponse {
                total_rps: Some(0),
                ..Default::default()
            },
            a
        );
    }

    #[test]
    fn enumerate_rps_next() {
        let _ = tracing_subscriber::fmt::try_init();

        assert_eq!(
            vec![0x0a, 0xa1, 0x01, 0x03],
            CredentialManagementRequest::ENUMERATE_RPS_GET_NEXT
                .cbor()
                .expect("encode error")
        );

        assert_eq!(
            vec![0x41, 0xa1, 0x01, 0x03],
            PrototypeCredentialManagementRequest::ENUMERATE_RPS_GET_NEXT
                .cbor()
                .expect("encode error")
        );

        let r = [
            0xa2, 0x03, 0xa1, 0x62, 0x69, 0x64, 0x78, 0x21, 0x77, 0x65, 0x62, 0x61, 0x75, 0x74,
            0x68, 0x6e, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74,
            0x79, 0x73, 0x74, 0x61, 0x6e, 0x64, 0x61, 0x72, 0x64, 0x73, 0x2e, 0x69, 0x6f, 0x04,
            0x58, 0x20, 0x0b, 0x99, 0x7c, 0xcc, 0xeb, 0x3a, 0xeb, 0x29, 0xc5, 0x5c, 0x94, 0xa8,
            0x94, 0xb1, 0x1c, 0xf0, 0x1a, 0x24, 0xb4, 0xc8, 0xae, 0x70, 0x6f, 0x32, 0x8c, 0xc2,
            0xea, 0x8c, 0xeb, 0xc4, 0xad, 0x5c,
        ];
        let a = <CredentialManagementResponse as CBORResponse>::try_from(r.as_slice())
            .expect("Failed to decode message");

        assert_eq!(
            CredentialManagementResponse {
                rp: Some(RelyingPartyCM {
                    name: None,
                    id: Some("webauthntest.identitystandards.io".to_string()),
                    hash: Some([
                        0x0b, 0x99, 0x7c, 0xcc, 0xeb, 0x3a, 0xeb, 0x29, 0xc5, 0x5c, 0x94, 0xa8,
                        0x94, 0xb1, 0x1c, 0xf0, 0x1a, 0x24, 0xb4, 0xc8, 0xae, 0x70, 0x6f, 0x32,
                        0x8c, 0xc2, 0xea, 0x8c, 0xeb, 0xc4, 0xad, 0x5c
                    ]),
                }),
                ..Default::default()
            },
            a
        );
    }

    #[test]
    fn enumerate_credentials_begin() {
        let _ = tracing_subscriber::fmt::try_init();
        const SUBCOMMAND: CredSubCommand = CredSubCommand::EnumerateCredentialsBegin([
            0x0b, 0x99, 0x7c, 0xcc, 0xeb, 0x3a, 0xeb, 0x29, 0xc5, 0x5c, 0x94, 0xa8, 0x94, 0xb1,
            0x1c, 0xf0, 0x1a, 0x24, 0xb4, 0xc8, 0xae, 0x70, 0x6f, 0x32, 0x8c, 0xc2, 0xea, 0x8c,
            0xeb, 0xc4, 0xad, 0x5c,
        ]);

        assert_eq!(
            vec![
                0x04, 0xa1, 0x01, 0x58, 0x20, 0x0b, 0x99, 0x7c, 0xcc, 0xeb, 0x3a, 0xeb, 0x29, 0xc5,
                0x5c, 0x94, 0xa8, 0x94, 0xb1, 0x1c, 0xf0, 0x1a, 0x24, 0xb4, 0xc8, 0xae, 0x70, 0x6f,
                0x32, 0x8c, 0xc2, 0xea, 0x8c, 0xeb, 0xc4, 0xad, 0x5c
            ],
            SUBCOMMAND.prf()
        );

        assert_eq!(
            CredSubCommand::enumerate_credentials_by_rpid("webauthntest.identitystandards.io"),
            SUBCOMMAND
        );

        let c =
            CredentialManagementRequest::new(SUBCOMMAND, Some(2), Some(PIN_UV_AUTH_PARAM.to_vec()));

        assert_eq!(
            vec![
                0x0a, 0xa4, 0x01, 0x04, 0x02, 0xa1, 0x01, 0x58, 0x20, 0x0b, 0x99, 0x7c, 0xcc, 0xeb,
                0x3a, 0xeb, 0x29, 0xc5, 0x5c, 0x94, 0xa8, 0x94, 0xb1, 0x1c, 0xf0, 0x1a, 0x24, 0xb4,
                0xc8, 0xae, 0x70, 0x6f, 0x32, 0x8c, 0xc2, 0xea, 0x8c, 0xeb, 0xc4, 0xad, 0x5c, 0x03,
                0x02, 0x04, 0x58, 0x20, 0x13, 0xd7, 0xf2, 0xe7, 0xa0, 0xb9, 0x61, 0x78, 0x39, 0xb3,
                0xfb, 0xbf, 0xc2, 0xf9, 0x0c, 0xec, 0x5e, 0xc0, 0xc6, 0xc0, 0x41, 0x54, 0x72, 0x74,
                0x22, 0x56, 0xac, 0x6e, 0xd7, 0x9e, 0xfa, 0x5d
            ],
            c.cbor().expect("encode error")
        );

        let c = PrototypeCredentialManagementRequest::new(
            SUBCOMMAND,
            Some(1),
            Some(PIN_UV_AUTH_PARAM.to_vec()),
        );

        assert_eq!(
            vec![
                0x41, 0xa4, 0x01, 0x04, 0x02, 0xa1, 0x01, 0x58, 0x20, 0x0b, 0x99, 0x7c, 0xcc, 0xeb,
                0x3a, 0xeb, 0x29, 0xc5, 0x5c, 0x94, 0xa8, 0x94, 0xb1, 0x1c, 0xf0, 0x1a, 0x24, 0xb4,
                0xc8, 0xae, 0x70, 0x6f, 0x32, 0x8c, 0xc2, 0xea, 0x8c, 0xeb, 0xc4, 0xad, 0x5c, 0x03,
                0x01, 0x04, 0x58, 0x20, 0x13, 0xd7, 0xf2, 0xe7, 0xa0, 0xb9, 0x61, 0x78, 0x39, 0xb3,
                0xfb, 0xbf, 0xc2, 0xf9, 0x0c, 0xec, 0x5e, 0xc0, 0xc6, 0xc0, 0x41, 0x54, 0x72, 0x74,
                0x22, 0x56, 0xac, 0x6e, 0xd7, 0x9e, 0xfa, 0x5d
            ],
            c.cbor().expect("encode error")
        );

        let r = [
            0xa6, 0x06, 0xa3, 0x62, 0x69, 0x64, 0x51, 0x61, 0x6c, 0x69, 0x63, 0x65, 0x40, 0x65,
            0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x64, 0x6e, 0x61, 0x6d,
            0x65, 0x73, 0x61, 0x6c, 0x6c, 0x69, 0x73, 0x6f, 0x6e, 0x40, 0x65, 0x78, 0x61, 0x6d,
            0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x6b, 0x64, 0x69, 0x73, 0x70, 0x6c, 0x61,
            0x79, 0x4e, 0x61, 0x6d, 0x65, 0x6b, 0x41, 0x6c, 0x6c, 0x69, 0x73, 0x6f, 0x6e, 0x20,
            0x44, 0x6f, 0x65, 0x07, 0xa2, 0x62, 0x69, 0x64, 0x50, 0x39, 0x24, 0xdb, 0xf7, 0xba,
            0x5d, 0xe8, 0x82, 0x9c, 0x69, 0xee, 0x10, 0x15, 0x89, 0x76, 0xf1, 0x64, 0x74, 0x79,
            0x70, 0x65, 0x6a, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x2d, 0x6b, 0x65, 0x79, 0x08,
            0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20, 0x6f, 0xd0, 0x2c, 0xd1,
            0x31, 0x25, 0x1d, 0x12, 0xda, 0x03, 0x8a, 0x1b, 0xd2, 0xdb, 0xb6, 0x47, 0xe2, 0x45,
            0x4d, 0x71, 0x47, 0x7a, 0xd3, 0x1d, 0xbd, 0x7c, 0xdb, 0x15, 0xd2, 0x8d, 0xf8, 0xbf,
            0x22, 0x58, 0x20, 0x04, 0x42, 0x2c, 0xca, 0xa2, 0x61, 0xc1, 0x97, 0x92, 0x1a, 0xab,
            0xad, 0xa5, 0x57, 0x8e, 0x91, 0x55, 0xde, 0x56, 0xc4, 0xca, 0xd9, 0x1d, 0x8d, 0xd0,
            0x7e, 0xe3, 0x78, 0x71, 0xf9, 0xf1, 0xf5, 0x09, 0x02, 0x0a, 0x01, 0x0b, 0x58, 0x20,
            0xa3, 0x81, 0x0f, 0xaf, 0xc1, 0x2a, 0xe8, 0xa3, 0xf5, 0xdd, 0x47, 0x21, 0x2f, 0xf8,
            0x2a, 0x30, 0xd8, 0x2a, 0xd9, 0xf8, 0x6e, 0xdf, 0x06, 0x34, 0x71, 0x76, 0x5c, 0x85,
            0x3a, 0xa8, 0x0a, 0xe6,
        ];
        let a = <CredentialManagementResponse as CBORResponse>::try_from(r.as_slice())
            .expect("Failed to decode message");

        assert_eq!(
            CredentialManagementResponse {
                discoverable_credential: DiscoverableCredential {
                    user: Some(UserCM {
                        id: b"alice@example.com".to_vec(),
                        name: Some("allison@example.com".to_string()),
                        display_name: Some("Allison Doe".to_string()),
                    }),
                    credential_id: Some(
                        vec![
                            0x39, 0x24, 0xdb, 0xf7, 0xba, 0x5d, 0xe8, 0x82, 0x9c, 0x69, 0xee, 0x10,
                            0x15, 0x89, 0x76, 0xf1
                        ]
                        .into()
                    ),
                    public_key: Some(COSEKey {
                        type_: COSEAlgorithm::ES256,
                        key: COSEKeyType::EC_EC2(COSEEC2Key {
                            curve: ECDSACurve::SECP256R1,
                            x: Base64UrlSafeData::from(vec![
                                0x6f, 0xd0, 0x2c, 0xd1, 0x31, 0x25, 0x1d, 0x12, 0xda, 0x03, 0x8a,
                                0x1b, 0xd2, 0xdb, 0xb6, 0x47, 0xe2, 0x45, 0x4d, 0x71, 0x47, 0x7a,
                                0xd3, 0x1d, 0xbd, 0x7c, 0xdb, 0x15, 0xd2, 0x8d, 0xf8, 0xbf
                            ]),
                            y: Base64UrlSafeData::from(vec![
                                0x04, 0x42, 0x2c, 0xca, 0xa2, 0x61, 0xc1, 0x97, 0x92, 0x1a, 0xab,
                                0xad, 0xa5, 0x57, 0x8e, 0x91, 0x55, 0xde, 0x56, 0xc4, 0xca, 0xd9,
                                0x1d, 0x8d, 0xd0, 0x7e, 0xe3, 0x78, 0x71, 0xf9, 0xf1, 0xf5
                            ])
                        })
                    }),
                    cred_protect: Some(CredentialProtectionPolicy::UserVerificationOptional),
                    large_blob_key: Some(vec![
                        0xa3, 0x81, 0x0f, 0xaf, 0xc1, 0x2a, 0xe8, 0xa3, 0xf5, 0xdd, 0x47, 0x21,
                        0x2f, 0xf8, 0x2a, 0x30, 0xd8, 0x2a, 0xd9, 0xf8, 0x6e, 0xdf, 0x06, 0x34,
                        0x71, 0x76, 0x5c, 0x85, 0x3a, 0xa8, 0x0a, 0xe6
                    ]),
                },
                total_credentials: Some(2),
                ..Default::default()
            },
            a
        );
    }

    #[test]
    fn enumerate_credentials_next() {
        let _ = tracing_subscriber::fmt::try_init();

        assert_eq!(
            vec![0x0a, 0xa1, 0x01, 0x05],
            CredentialManagementRequest::ENUMERATE_CREDENTIALS_GET_NEXT
                .cbor()
                .expect("encode error")
        );

        assert_eq!(
            vec![0x41, 0xa1, 0x01, 0x05],
            PrototypeCredentialManagementRequest::ENUMERATE_CREDENTIALS_GET_NEXT
                .cbor()
                .expect("encode error")
        );

        let r = [
            0xa5, 0x06, 0xa3, 0x62, 0x69, 0x64, 0x51, 0x61, 0x6c, 0x69, 0x63, 0x65, 0x40, 0x65,
            0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x64, 0x6e, 0x61, 0x6d,
            0x65, 0x73, 0x61, 0x6c, 0x6c, 0x69, 0x73, 0x6f, 0x6e, 0x40, 0x65, 0x78, 0x61, 0x6d,
            0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x6b, 0x64, 0x69, 0x73, 0x70, 0x6c, 0x61,
            0x79, 0x4e, 0x61, 0x6d, 0x65, 0x6b, 0x41, 0x6c, 0x6c, 0x69, 0x73, 0x6f, 0x6e, 0x20,
            0x44, 0x6f, 0x65, 0x07, 0xa2, 0x62, 0x69, 0x64, 0x50, 0x39, 0x24, 0xdb, 0xf7, 0xba,
            0x5d, 0xe8, 0x82, 0x9c, 0x69, 0xee, 0x10, 0x15, 0x89, 0x76, 0xf1, 0x64, 0x74, 0x79,
            0x70, 0x65, 0x6a, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x2d, 0x6b, 0x65, 0x79, 0x08,
            0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20, 0x6f, 0xd0, 0x2c, 0xd1,
            0x31, 0x25, 0x1d, 0x12, 0xda, 0x03, 0x8a, 0x1b, 0xd2, 0xdb, 0xb6, 0x47, 0xe2, 0x45,
            0x4d, 0x71, 0x47, 0x7a, 0xd3, 0x1d, 0xbd, 0x7c, 0xdb, 0x15, 0xd2, 0x8d, 0xf8, 0xbf,
            0x22, 0x58, 0x20, 0x04, 0x42, 0x2c, 0xca, 0xa2, 0x61, 0xc1, 0x97, 0x92, 0x1a, 0xab,
            0xad, 0xa5, 0x57, 0x8e, 0x91, 0x55, 0xde, 0x56, 0xc4, 0xca, 0xd9, 0x1d, 0x8d, 0xd0,
            0x7e, 0xe3, 0x78, 0x71, 0xf9, 0xf1, 0xf5, 0x0a, 0x01, 0x0b, 0x58, 0x20, 0xa3, 0x81,
            0x0f, 0xaf, 0xc1, 0x2a, 0xe8, 0xa3, 0xf5, 0xdd, 0x47, 0x21, 0x2f, 0xf8, 0x2a, 0x30,
            0xd8, 0x2a, 0xd9, 0xf8, 0x6e, 0xdf, 0x06, 0x34, 0x71, 0x76, 0x5c, 0x85, 0x3a, 0xa8,
            0x0a, 0xe6,
        ];
        let a = <CredentialManagementResponse as CBORResponse>::try_from(r.as_slice())
            .expect("Failed to decode message");

        assert_eq!(
            CredentialManagementResponse {
                discoverable_credential: DiscoverableCredential {
                    user: Some(UserCM {
                        id: b"alice@example.com".to_vec(),
                        name: Some("allison@example.com".to_string()),
                        display_name: Some("Allison Doe".to_string()),
                    }),
                    credential_id: Some(
                        vec![
                            0x39, 0x24, 0xdb, 0xf7, 0xba, 0x5d, 0xe8, 0x82, 0x9c, 0x69, 0xee, 0x10,
                            0x15, 0x89, 0x76, 0xf1
                        ]
                        .into()
                    ),
                    public_key: Some(COSEKey {
                        type_: COSEAlgorithm::ES256,
                        key: COSEKeyType::EC_EC2(COSEEC2Key {
                            curve: ECDSACurve::SECP256R1,
                            x: Base64UrlSafeData::from(vec![
                                0x6f, 0xd0, 0x2c, 0xd1, 0x31, 0x25, 0x1d, 0x12, 0xda, 0x03, 0x8a,
                                0x1b, 0xd2, 0xdb, 0xb6, 0x47, 0xe2, 0x45, 0x4d, 0x71, 0x47, 0x7a,
                                0xd3, 0x1d, 0xbd, 0x7c, 0xdb, 0x15, 0xd2, 0x8d, 0xf8, 0xbf
                            ]),
                            y: Base64UrlSafeData::from(vec![
                                0x04, 0x42, 0x2c, 0xca, 0xa2, 0x61, 0xc1, 0x97, 0x92, 0x1a, 0xab,
                                0xad, 0xa5, 0x57, 0x8e, 0x91, 0x55, 0xde, 0x56, 0xc4, 0xca, 0xd9,
                                0x1d, 0x8d, 0xd0, 0x7e, 0xe3, 0x78, 0x71, 0xf9, 0xf1, 0xf5
                            ])
                        })
                    }),
                    cred_protect: Some(CredentialProtectionPolicy::UserVerificationOptional),
                    large_blob_key: Some(vec![
                        0xa3, 0x81, 0x0f, 0xaf, 0xc1, 0x2a, 0xe8, 0xa3, 0xf5, 0xdd, 0x47, 0x21,
                        0x2f, 0xf8, 0x2a, 0x30, 0xd8, 0x2a, 0xd9, 0xf8, 0x6e, 0xdf, 0x06, 0x34,
                        0x71, 0x76, 0x5c, 0x85, 0x3a, 0xa8, 0x0a, 0xe6
                    ]),
                },
                ..Default::default()
            },
            a
        );
    }

    #[test]
    fn update_user_information() {
        let _ = tracing_subscriber::fmt::try_init();

        let s = CredSubCommand::UpdateUserInformation(
            vec![
                0x39, 0x24, 0xdb, 0xf7, 0xba, 0x5d, 0xe8, 0x82, 0x9c, 0x69, 0xee, 0x10, 0x15, 0x89,
                0x76, 0xf1,
            ]
            .into(),
            UserCM {
                id: b"alice@example.com".to_vec(),
                name: Some("allison@example.com".to_string()),
                display_name: Some("Allison Doe".to_string()),
            },
        );
        assert_eq!(
            vec![
                0x07, 0xa2, 0x02, 0xa2, 0x62, 0x69, 0x64, 0x50, 0x39, 0x24, 0xdb, 0xf7, 0xba, 0x5d,
                0xe8, 0x82, 0x9c, 0x69, 0xee, 0x10, 0x15, 0x89, 0x76, 0xf1, 0x64, 0x74, 0x79, 0x70,
                0x65, 0x6a, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x2d, 0x6b, 0x65, 0x79, 0x03, 0xa3,
                0x62, 0x69, 0x64, 0x51, 0x61, 0x6c, 0x69, 0x63, 0x65, 0x40, 0x65, 0x78, 0x61, 0x6d,
                0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x64, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x61,
                0x6c, 0x6c, 0x69, 0x73, 0x6f, 0x6e, 0x40, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
                0x2e, 0x63, 0x6f, 0x6d, 0x6b, 0x64, 0x69, 0x73, 0x70, 0x6c, 0x61, 0x79, 0x4e, 0x61,
                0x6d, 0x65, 0x6b, 0x41, 0x6c, 0x6c, 0x69, 0x73, 0x6f, 0x6e, 0x20, 0x44, 0x6f, 0x65
            ],
            s.prf()
        );

        // UpdateUserInformation only supported in CTAP 2.1 (CredentialManagementRequest)
        let c = CredentialManagementRequest::new(s, Some(2), Some(PIN_UV_AUTH_PARAM.into()));

        assert_eq!(
            vec![
                0x0a, 0xa4, 0x01, 0x07, 0x02, 0xa2, 0x02, 0xa2, 0x62, 0x69, 0x64, 0x50, 0x39, 0x24,
                0xdb, 0xf7, 0xba, 0x5d, 0xe8, 0x82, 0x9c, 0x69, 0xee, 0x10, 0x15, 0x89, 0x76, 0xf1,
                0x64, 0x74, 0x79, 0x70, 0x65, 0x6a, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x2d, 0x6b,
                0x65, 0x79, 0x03, 0xa3, 0x62, 0x69, 0x64, 0x51, 0x61, 0x6c, 0x69, 0x63, 0x65, 0x40,
                0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x64, 0x6e, 0x61,
                0x6d, 0x65, 0x73, 0x61, 0x6c, 0x6c, 0x69, 0x73, 0x6f, 0x6e, 0x40, 0x65, 0x78, 0x61,
                0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x6b, 0x64, 0x69, 0x73, 0x70, 0x6c,
                0x61, 0x79, 0x4e, 0x61, 0x6d, 0x65, 0x6b, 0x41, 0x6c, 0x6c, 0x69, 0x73, 0x6f, 0x6e,
                0x20, 0x44, 0x6f, 0x65, 0x03, 0x02, 0x04, 0x58, 0x20, 0x13, 0xd7, 0xf2, 0xe7, 0xa0,
                0xb9, 0x61, 0x78, 0x39, 0xb3, 0xfb, 0xbf, 0xc2, 0xf9, 0x0c, 0xec, 0x5e, 0xc0, 0xc6,
                0xc0, 0x41, 0x54, 0x72, 0x74, 0x22, 0x56, 0xac, 0x6e, 0xd7, 0x9e, 0xfa, 0x5d,
            ],
            c.cbor().expect("encode error")
        );
    }
}

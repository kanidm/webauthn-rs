//! Webauthn-rs - Webauthn for Rust Server Applications
//!
//! Webauthn is a standard allowing communication between servers, browsers and authenticators
//! to allow strong, passwordless, cryptographic authentication to be performed. Webauthn
//! is able to operate with many authenticator types, such as U2F.
//!
//! This library aims to provide a secure Webauthn implementation that you can
//! plug into your application, so that you can provide Webauthn to your users.
//!
//! For examples, see our examples folder.
//!
//! To use this library yourself, you will want to reference the `WebauthnConfig` trait to
//! develop site specific policy and configuration, and the `Webauthn` struct for Webauthn
//! interactions.

#![warn(missing_docs)]

use rand::prelude::*;
use std::convert::TryFrom;

use crate::attestation::{
    verify_apple_anonymous_attestation, verify_fidou2f_attestation, verify_none_attestation,
    verify_packed_attestation, verify_tpm_attestation, AttestationFormat, AttestationType,
};
use crate::base64_data::Base64UrlSafeData;
use crate::constants::{AUTHENTICATOR_TIMEOUT, CHALLENGE_SIZE_BYTES};
use crate::crypto::compute_sha256;
use crate::error::WebauthnError;
use crate::proto::*;

/// The in progress state of a credential registration attempt. You must persist this associated
/// to the UserID requesting the registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationState {
    policy: UserVerificationPolicy,
    exclude_credentials: Vec<CredentialID>,
    challenge: Base64UrlSafeData,
}

/// The in progress state of an authentication attempt. You must persist this associated to the UserID
/// requesting the registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationState {
    credentials: Vec<Credential>,
    policy: UserVerificationPolicy,
    challenge: Base64UrlSafeData,
}

impl AuthenticationState {
    /// set which credentials the user is allowed to authenticate with
    pub fn set_allowed_credentials(&mut self, credentials: Vec<Credential>) {
        self.credentials = credentials;
    }
}

/// This is the core of the Webauthn operations. It provides 4 interfaces that you will likely
/// use the most:
/// * generate_challenge_response
/// * register_credential
/// * generate_challenge_authenticate
/// * authenticate_credential
///
/// Each of these is described in turn, but they will all map to routes in your application.
/// The generate functions return Json challenges that are intended to be processed by the client
/// browser, and the register and authenticate will receive Json that is processed and verified.
///
/// These functions return state that you must store and handle correctly for the authentication
/// or registration to proceed correctly.
///
/// As a result, it's very important you read the function descriptions to understand the process
/// as much as possible.
#[derive(Debug)]
pub struct Webauthn<T> {
    config: T,
    pkcp: Vec<PubKeyCredParams>,
    rp_id_hash: Vec<u8>,
}

impl<T> Webauthn<T> {
    /// Create a new Webauthn instance with the supplied configuration. The config type
    /// will receive and interact with various callbacks to allow the lifecycle and
    /// application handling of Credentials to be customised for your application.
    ///
    /// You should see the Documentation for WebauthnConfig, which is the main part of
    /// the code you will interact with for site-specific customisation.
    pub fn new(config: T) -> Self
    where
        T: WebauthnConfig,
    {
        let pkcp = config
            .get_credential_algorithms()
            .iter()
            .map(|a| PubKeyCredParams {
                type_: "public-key".to_string(),
                alg: a.into(),
            })
            .collect();
        let rp_id_hash = compute_sha256(config.get_relying_party_id().as_bytes());
        Webauthn {
            // Use a per-thread csprng
            config,
            pkcp,
            rp_id_hash,
        }
    }

    fn generate_challenge(&self) -> Challenge {
        let mut rng = rand::thread_rng();
        Challenge::new(rng.gen::<[u8; CHALLENGE_SIZE_BYTES]>().to_vec())
    }

    /// Generate a new challenge for client registration.
    /// Same as `generate_challenge_register_options` but default options
    pub fn generate_challenge_register(
        &self,
        user_name: &str,
        policy: Option<UserVerificationPolicy>,
    ) -> Result<(CreationChallengeResponse, RegistrationState), WebauthnError>
    where
        T: WebauthnConfig,
    {
        self.generate_challenge_register_options(
            user_name.as_bytes().to_vec(),
            user_name.to_string(),
            user_name.to_string(),
            None,
            policy,
            None,
        )
    }

    /// Generate a new challenge for client registration. This is the first step in
    /// the lifecycle of a credential. This function will return the
    /// CreationChallengeResponse which is suitable for Serde JSON serialisation
    /// to be sent to the client.
    /// The client (generally a web browser) will pass this JSON
    /// structure to the `navigator.credentials.create()` javascript function for registration.
    ///
    /// It also returns a RegistrationState, that you *must*
    /// persist. It is strongly advised you associate this RegistrationState with the
    /// UserId of the requester.
    pub fn generate_challenge_register_options(
        &self,
        user_id: UserId,
        user_name: String,
        user_display_name: String,
        exclude_credentials: Option<Vec<CredentialID>>,
        policy: Option<UserVerificationPolicy>,
        extensions: Option<RequestRegistrationExtensions>,
    ) -> Result<(CreationChallengeResponse, RegistrationState), WebauthnError>
    where
        T: WebauthnConfig,
    {
        let policy = policy.unwrap_or(UserVerificationPolicy::Preferred_DO_NOT_USE);

        if policy == UserVerificationPolicy::Preferred_DO_NOT_USE {
            log::warn!("UserVerificationPolicy::Preferred_DO_NOT_USE is misleading! You should select Discouraged or Required!");
        }

        if user_id.is_empty() {
            return Err(WebauthnError::InvalidUsername);
        }

        let challenge = self.generate_challenge();

        let c = CreationChallengeResponse {
            public_key: PublicKeyCredentialCreationOptions {
                rp: RelyingParty {
                    name: self.config.get_relying_party_name().to_owned(),
                    id: self.config.get_relying_party_id().to_owned(),
                },
                user: User {
                    id: Base64UrlSafeData(user_id),
                    name: user_name,
                    display_name: user_display_name,
                },
                challenge: challenge.clone().into(),
                pub_key_cred_params: self
                    .config
                    .get_credential_algorithms()
                    .into_iter()
                    .map(|alg| PubKeyCredParams {
                        type_: "public-key".to_string(),
                        alg: alg as i64,
                    })
                    .collect(),
                timeout: Some(self.config.get_authenticator_timeout()),
                attestation: Some(self.config.get_attestation_preference()),
                exclude_credentials: exclude_credentials.as_ref().map(|creds| {
                    creds
                        .iter()
                        .cloned()
                        .map(PublicKeyCredentialDescriptor::from_bytes)
                        .collect()
                }),
                authenticator_selection: Some(AuthenticatorSelectionCriteria {
                    authenticator_attachment: self.config.get_authenticator_attachment(),
                    require_resident_key: self.config.get_require_resident_key(),
                    user_verification: policy.clone(),
                }),
                extensions,
            },
        };

        let wr = RegistrationState {
            policy,
            exclude_credentials: exclude_credentials.unwrap_or_else(|| Vec::with_capacity(0)),
            challenge: challenge.into(),
        };

        // This should have an opaque type of username + chal + policy
        Ok((c, wr))
    }

    /// Process a credential registration response. This is the output of
    /// `navigator.credentials.create()` which is sent to the webserver from the client.
    ///
    /// Given the username you also must provide the associated RegistrationState for this
    /// operation to proceed.
    ///
    /// On success this returns a new Credential that you must persist and associate with the
    /// user.
    ///
    /// Optionally, you may provide a closure that is able to check if any credential of the
    /// same id has already been persisted by your server.
    pub fn register_credential(
        &self,
        reg: &RegisterPublicKeyCredential,
        state: &RegistrationState,
        does_exist_fn: impl Fn(&CredentialID) -> Result<bool, ()>,
    ) -> Result<(Credential, AuthenticatorData), WebauthnError>
    where
        T: WebauthnConfig,
    {
        // From the rfc https://w3c.github.io/webauthn/#registering-a-new-credential
        // get the challenge (it's username associated)
        // Policy should also come from the chal

        let RegistrationState {
            policy,
            exclude_credentials,
            challenge,
        } = state;
        let chal: &ChallengeRef = challenge.into();

        // TODO: check the req username matches? I think it's not possible, the caller needs to
        // create the linkage between the username and the state.

        // send to register_credential_internal
        let credential =
            self.register_credential_internal(reg, policy.clone(), chal, &exclude_credentials)?;

        // Check that the credentialId is not yet registered to any other user. If registration is
        // requested for a credential that is already registered to a different user, the Relying
        // Party SHOULD fail this registration ceremony, or it MAY decide to accept the registration,
        // e.g. while deleting the older registration.

        let cred_exist_result = does_exist_fn(&credential.0.cred_id)
            .map_err(|_| WebauthnError::CredentialExistCheckError)?;

        if cred_exist_result {
            return Err(WebauthnError::CredentialAlreadyExists);
        }

        Ok(credential)
    }

    pub(crate) fn register_credential_internal(
        &self,
        reg: &RegisterPublicKeyCredential,
        policy: UserVerificationPolicy,
        chal: &ChallengeRef,
        exclude_credentials: &[CredentialID],
    ) -> Result<(Credential, AuthenticatorData), WebauthnError>
    where
        T: WebauthnConfig,
    {
        // Let C, the client data claimed as collected during the credential creation, be the result
        // of running an implementation-specific JSON parser on JSONtext.
        //
        // Now, we actually do a much larger conversion in one shot
        // here, where we get the AuthenticatorAttestationResponse

        let data = AuthenticatorAttestationResponse::try_from(&reg.response)?;

        // println!("data: {:?}", data);

        // Verify that the value of C.type is webauthn.create.
        if data.client_data_json.type_ != "webauthn.create" {
            return Err(WebauthnError::InvalidClientDataType);
        }

        // Verify that the value of C.challenge matches the challenge that was sent to the
        // authenticator in the create() call.
        if data.client_data_json.challenge.0 != &**chal {
            return Err(WebauthnError::MismatchedChallenge);
        }

        // Verify that the value of C.origin matches the Relying Party's origin.
        if data.client_data_json.origin != self.config.get_origin() {
            log::debug!(
                "{} != {}",
                data.client_data_json.origin,
                self.config.get_origin()
            );
            return Err(WebauthnError::InvalidRPOrigin);
        }

        // Verify that the value of C.tokenBinding.status matches the state of Token Binding for the
        // TLS connection over which the assertion was obtained. If Token Binding was used on that
        // TLS connection, also verify that C.tokenBinding.id matches the base64url encoding of the
        // Token Binding ID for the connection.
        //
        //  This could be reasonably complex to do, given that we could be behind a load balancer
        // or we may not directly know the status of TLS inside this api. I'm open to creative
        // suggestions on this topic!
        //

        // 7. Compute the hash of response.clientDataJSON using SHA-256.
        //    This will be used in step 14.
        // First you have to decode this from base64!!! This really could just be implementation
        // specific though ...
        let client_data_json_hash = compute_sha256(data.client_data_json_bytes.as_slice());

        // Perform CBOR decoding on the attestationObject field of the AuthenticatorAttestationResponse
        // structure to obtain the attestation statement format fmt, the authenticator data authData,
        // and the attestation statement attStmt.
        //
        // Done as part of try_from

        // Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the
        // Relying Party.
        //
        //  NOW: Remember that RP ID https://w3c.github.io/webauthn/#rp-id is NOT THE SAME as the RP name
        // it's actually derived from the RP origin.
        if data.attestation_object.auth_data.rp_id_hash != self.rp_id_hash {
            return Err(WebauthnError::InvalidRPIDHash);
        }

        // Verify that the User Present bit of the flags in authData is set.
        if !data.attestation_object.auth_data.user_present {
            return Err(WebauthnError::UserNotPresent);
        }

        // TODO: Is it possible to verify the attachement policy and resident
        // key requirement here?

        // If user verification is required for this registration, verify that the User Verified bit
        // of the flags in authData is set.
        match policy {
            UserVerificationPolicy::Required => {
                if !data.attestation_object.auth_data.user_verified {
                    return Err(WebauthnError::UserNotVerified);
                }
            }
            UserVerificationPolicy::Preferred_DO_NOT_USE | UserVerificationPolicy::Discouraged => {}
        };

        // Verify that the "alg" parameter in the credential public key in authData matches the alg
        // attribute of one of the items in options.pubKeyCredParams.
        //
        // WARNING: This is actually done after attestation as the credential public key
        // is NOT available yet!

        // Verify that the values of the client extension outputs in clientExtensionResults and the
        // authenticator extension outputs in the extensions in authData are as expected,
        // considering the client extension input values that were given as the extensions option in
        // the create() call. In particular, any extension identifier values in the
        // clientExtensionResults and the extensions in authData MUST be also be present as
        // extension identifier values in the extensions member of options, i.e., no extensions are
        // present that were not requested. In the general case, the meaning of "are as expected" is
        // specific to the Relying Party and which extensions are in use.

        if let Some(ext) = &data.attestation_object.auth_data.extensions {
            log::debug!("ext: {:?}", ext);
        }

        // Determine the attestation statement format by performing a USASCII case-sensitive match on
        // fmt against the set of supported WebAuthn Attestation Statement Format Identifier values.
        // An up-to-date list of registered WebAuthn Attestation Statement Format Identifier values
        // is maintained in the IANA registry of the same name [WebAuthn-Registries].
        // ( https://tools.ietf.org/html/draft-hodges-webauthn-registries-02 )
        //
        //  https://w3c.github.io/webauthn/#packed-attestation
        //  https://w3c.github.io/webauthn/#tpm-attestation
        //  https://w3c.github.io/webauthn/#android-key-attestation
        //  https://w3c.github.io/webauthn/#android-safetynet-attestation
        //  https://w3c.github.io/webauthn/#fido-u2f-attestation
        //  https://w3c.github.io/webauthn/#none-attestation
        let attest_format = AttestationFormat::try_from(data.attestation_object.fmt.as_str())?;

        // 14. Verify that attStmt is a correct attestation statement, conveying a valid attestation
        // signature, by using the attestation statement format fmt’s verification procedure given
        // attStmt, authData and the hash of the serialized client data computed in step 7.

        let acd = data
            .attestation_object
            .auth_data
            .acd
            .as_ref()
            .ok_or(WebauthnError::MissingAttestationCredentialData)?;

        // Now, match based on the attest_format
        // This returns an AttestationType, containing all the metadata needed for
        // step 15.

        log::debug!("attestation is: {:?}", &attest_format);

        let attest_result = match attest_format {
            AttestationFormat::FIDOU2F => verify_fidou2f_attestation(
                acd,
                data.attestation_object.auth_data.counter,
                data.attestation_object.auth_data.user_verified,
                &data.attestation_object.att_stmt,
                &client_data_json_hash,
                &data.attestation_object.auth_data.rp_id_hash,
            ),
            AttestationFormat::Packed => verify_packed_attestation(
                acd,
                data.attestation_object.auth_data.counter,
                data.attestation_object.auth_data.user_verified,
                &data.attestation_object.att_stmt,
                &data.attestation_object.auth_data_bytes,
                &client_data_json_hash,
            ),
            AttestationFormat::TPM => verify_tpm_attestation(
                acd,
                data.attestation_object.auth_data.counter,
                data.attestation_object.auth_data.user_verified,
                &data.attestation_object.att_stmt,
                &data.attestation_object.auth_data_bytes,
                &client_data_json_hash,
            ),
            AttestationFormat::AppleAnonymous => verify_apple_anonymous_attestation(
                acd,
                data.attestation_object.auth_data.counter,
                data.attestation_object.auth_data.user_verified,
                &data.attestation_object.att_stmt,
                &data.attestation_object.auth_data_bytes,
                &client_data_json_hash,
            ),
            AttestationFormat::None => verify_none_attestation(
                acd,
                data.attestation_object.auth_data.counter,
                data.attestation_object.auth_data.user_verified,
            ),
            _ => {
                if self.config.ignore_unsupported_attestation_formats() {
                    let credential_public_key = COSEKey::try_from(&acd.credential_pk)?;
                    Ok(AttestationType::None(Credential::new(
                        acd,
                        credential_public_key,
                        data.attestation_object.auth_data.counter,
                        false,
                    )))
                } else {
                    // No other types are currently implemented
                    Err(WebauthnError::AttestationNotSupported)
                }
            }
        }?;

        // Now based on result ...

        // 15. If validation is successful, obtain a list of acceptable trust anchors (attestation
        // root certificates or ECDAA-Issuer public keys) for that attestation type and attestation
        // statement format fmt, from a trusted source or from policy. For example, the FIDO Metadata
        // Service [FIDOMetadataService] provides one way to obtain such information, using the
        // aaguid in the attestedCredentialData in authData.

        // 16: Assess the attestation trustworthiness using the outputs of the verification procedure
        // in step 14, as follows: (SEE RFC)
        // If the attestation statement attStmt successfully verified but is not trustworthy per step
        // 16 above, the Relying Party SHOULD fail the registration ceremony.

        let credential = self
            .config
            .policy_verify_trust(attest_result)
            .map_err(|_e| WebauthnError::AttestationTrustFailure)?;

        // Verify that the credential public key alg is one of the allowed algorithms.
        let alg_valid = self
            .config
            .get_credential_algorithms()
            .into_iter()
            .any(|alg| alg == credential.cred.type_);

        if !alg_valid {
            return Err(WebauthnError::CredentialAlteredAlgFromRequest);
        }

        // OUT OF SPEC - exclude any credential that is in our exclude list.
        let excluded = exclude_credentials
            .iter()
            .any(|credid| credid.as_slice() == credential.cred_id.as_slice());

        if excluded {
            return Err(WebauthnError::CredentialAlteredAlgFromRequest);
        }

        //  If the attestation statement attStmt verified successfully and is found to be trustworthy,
        // then register the new credential with the account that was denoted in the options.user
        // passed to create(), by associating it with the credentialId and credentialPublicKey in
        // the attestedCredentialData in authData, as appropriate for the Relying Party's system.

        // Already returned above if trust failed.

        // So we return the credential here, and the caller persists it.
        // We turn this into a "helper" and serialisable credential structure that
        // people can use a bit nicer.
        Ok((credential, data.attestation_object.auth_data))
    }

    // https://w3c.github.io/webauthn/#verifying-assertion
    pub(crate) fn verify_credential_internal(
        &self,
        rsp: &PublicKeyCredential,
        policy: UserVerificationPolicy,
        chal: &ChallengeRef,
        cred: &Credential,
    ) -> Result<AuthenticatorData, WebauthnError>
    where
        T: WebauthnConfig,
    {
        if policy == UserVerificationPolicy::Preferred_DO_NOT_USE {
            return Err(WebauthnError::InconsistentUserVerificationPolicy);
        }

        // Let cData, authData and sig denote the value of credential’s response's clientDataJSON,
        // authenticatorData, and signature respectively.
        // Let JSONtext be the result of running UTF-8 decode on the value of cData.
        let data = AuthenticatorAssertionResponse::try_from(&rsp.response).map_err(|e| {
            log::debug!("AuthenticatorAssertionResponse::try_from -> {:?}", e);
            e
        })?;

        let c = &data.client_data;

        // Let C, the client data claimed as used for the signature, be the result of running an
        // implementation-specific JSON parser on JSONtext.
        //     Note: C may be any implementation-specific data structure representation, as long as
        //     C’s components are referenceable, as required by this algorithm.

        // Verify that the value of C.type is the string webauthn.get.
        if c.type_ != "webauthn.get" {
            return Err(WebauthnError::InvalidClientDataType);
        }

        // Verify that the value of C.challenge matches the challenge that was sent to the
        // authenticator in the PublicKeyCredentialRequestOptions passed to the get() call.
        if c.challenge.0 != &**chal {
            return Err(WebauthnError::MismatchedChallenge);
        }

        // Verify that the value of C.origin matches the Relying Party's origin.
        if c.origin != self.config.get_origin() {
            log::debug!("{} != {}", c.origin, self.config.get_origin());
            return Err(WebauthnError::InvalidRPOrigin);
        }

        // Verify that the value of C.tokenBinding.status matches the state of Token Binding for the
        // TLS connection over which the attestation was obtained. If Token Binding was used on that
        // TLS connection, also verify that C.tokenBinding.id matches the base64url encoding of the
        // Token Binding ID for the connection.

        // Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party.
        if data.authenticator_data.rp_id_hash != self.rp_id_hash {
            return Err(WebauthnError::InvalidRPIDHash);
        }

        // Verify that the User Present bit of the flags in authData is set.
        if !data.authenticator_data.user_present {
            return Err(WebauthnError::UserNotPresent);
        }

        // If user verification is required for this assertion, verify that the User Verified bit of
        // the flags in authData is set.
        match policy {
            UserVerificationPolicy::Required => {
                if !data.authenticator_data.user_verified {
                    return Err(WebauthnError::UserNotVerified);
                }
            }
            UserVerificationPolicy::Preferred_DO_NOT_USE | UserVerificationPolicy::Discouraged => {}
        };

        // Verify that the values of the client extension outputs in clientExtensionResults and the
        // authenticator extension outputs in the extensions in authData are as expected, considering
        // the client extension input values that were given as the extensions option in the get()
        // call. In particular, any extension identifier values in the clientExtensionResults and
        // the extensions in authData MUST be also be present as extension identifier values in the
        // extensions member of options, i.e., no extensions are present that were not requested. In
        // the general case, the meaning of "are as expected" is specific to the Relying Party and
        // which extensions are in use.
        //
        // Note: Since all extensions are OPTIONAL for both the client and the authenticator, the
        // Relying Party MUST be prepared to handle cases where none or not all of the requested
        // extensions were acted upon.
        match &data.authenticator_data.extensions {
            Some(_) => {
                // we do not need to do any processing here
            }
            None => {}
        }

        // Let hash be the result of computing a hash over the cData using SHA-256.
        let client_data_json_hash = compute_sha256(data.client_data_bytes.as_slice());

        // Using the credential public key looked up in step 3, verify that sig is a valid signature
        // over the binary concatenation of authData and hash.
        // Note: This verification step is compatible with signatures generated by FIDO U2F
        // authenticators. See §6.1.2 FIDO U2F Signature Format Compatibility.

        let verification_data: Vec<u8> = data
            .authenticator_data_bytes
            .iter()
            .chain(client_data_json_hash.iter())
            .copied()
            .collect();

        let verified = cred
            .cred
            .verify_signature(&data.signature, &verification_data)?;

        if !verified {
            return Err(WebauthnError::AuthenticationFailure);
        }

        Ok(data.authenticator_data)
    }

    /// Convenience function for `generate_challenge_authenticate_extensions` without extensions
    pub fn generate_challenge_authenticate(
        &self,
        creds: Vec<Credential>,
    ) -> Result<(RequestChallengeResponse, AuthenticationState), WebauthnError>
    where
        T: WebauthnConfig,
    {
        self.generate_challenge_authenticate_options(creds, None)
    }

    /// Generate a challenge for an authenticate request for a user. You must supply the set of
    /// credentials that exist for the user that *may* be used in this authentication request. If
    /// an empty credential set is supplied, the authentication *will* fail.
    ///
    /// This challenge is supplied to
    /// to the client javascript function `navigator.credentials.get()`.
    ///
    /// You must persist the AuthenticationState that is returned. You should associate this by
    /// UserId. The AuthenticationState is required for the authenticate_credential function to
    /// operate correctly.
    ///
    /// NOTE: `WebauthnError::InconsistentUserVerificationPolicy`
    ///
    /// This error is returning when the set of credentials has a mix of verified
    /// and unverified credentials. This is due to an issue with the webauthn standard
    /// as noted at https://github.com/w3c/webauthn/issues/1510. What can occur is that
    /// when you *register* a credential, you set an expectation as to the verification
    /// policy of that credential, and if that credential can soley be a MFA on it's own
    /// or requires extra material to function as an MFA. However, when you mix credentials
    /// you can have unverified credentials require verification (register discouraged, or
    /// u2f on ctap1, then authenticate preferred and ctap2) or verified credentials NOT
    /// need verification.
    ///
    /// As a result, this means the set of credentials that is provided must be internally
    /// consistent so that the policy can be set to discouraged or required based on
    /// the credentials given. This means you *must* consider a UX to allow the user to
    /// choose if they wish to use a verified token or not as webauthn as a standard can
    /// not make this distinction.
    ///
    /// An alternate suggestion is that the policy is *always* preferred and then the
    /// authenticate_credential yields the verification bit to the caller, but this
    /// still causes issues with ctap1 / ctap2 interop, and credentials becoming verified
    /// when they should not be.
    pub fn generate_challenge_authenticate_options(
        &self,
        creds: Vec<Credential>,
        extensions: Option<RequestAuthenticationExtensions>,
    ) -> Result<(RequestChallengeResponse, AuthenticationState), WebauthnError>
    where
        T: WebauthnConfig,
    {
        let chal = self.generate_challenge();

        let verified = creds.iter().all(|cred| cred.verified);
        let unverified = creds.iter().all(|cred| !cred.verified);

        if !verified && !unverified {
            return Err(WebauthnError::InconsistentUserVerificationPolicy);
        }

        let policy = if verified {
            UserVerificationPolicy::Required
        } else {
            UserVerificationPolicy::Discouraged
        };

        // Get the user's existing creds if any.
        let ac = creds
            .iter()
            .map(|cred| AllowCredentials {
                type_: "public-key".to_string(),
                id: Base64UrlSafeData(cred.cred_id.clone()),
                transports: None,
            })
            .collect();

        // Store the chal associated to the user.
        // Now put that into the correct challenge format
        let r = RequestChallengeResponse::new(
            chal.clone(),
            self.config.get_authenticator_timeout(),
            self.config.get_relying_party_id().to_owned(),
            ac,
            policy.clone(),
            extensions,
        );
        let st = AuthenticationState {
            // username: username.clone(),
            credentials: creds,
            policy,
            challenge: chal.into(),
        };
        Ok((r, st))
    }

    /// Process an authenticate response from the authenticator and browser. This
    /// is the output of `navigator.credentials.get()`, which is processed by this
    /// function. If the authentication fails, appropriate errors will be returned.
    ///
    /// This requires the associated AuthenticationState that was created by
    /// generate_challenge_authenticate
    ///
    /// On successful authentication, an Ok result is returned. The Ok may contain the CredentialID
    /// and associated counter, which you *should* update for security purposes. If the Ok returns
    /// `None` then the credential does not have a counter.
    pub fn authenticate_credential<'a>(
        &self,
        rsp: &PublicKeyCredential,
        state: &'a AuthenticationState,
    ) -> Result<(&'a CredentialID, AuthenticatorData), WebauthnError>
    where
        T: WebauthnConfig,
    {
        // https://w3c.github.io/webauthn/#verifying-assertion
        // Lookup challenge

        let AuthenticationState {
            credentials: creds,
            policy,
            challenge: chal,
        } = state;
        let chal: &ChallengeRef = chal.into();

        // If the allowCredentials option was given when this authentication ceremony was initiated,
        // verify that credential.id identifies one of the public key credentials that were listed in allowCredentials.
        //
        // We always supply allowCredentials in this library, so we expect creds as a vec of credentials
        // that would be equivalent to what was allowed.
        // println!("rsp: {:?}", rsp);

        let cred = {
            // Identify the user being authenticated and verify that this user is the owner of the public
            // key credential source credentialSource identified by credential.id:
            //
            //  If the user was identified before the authentication ceremony was initiated, e.g., via a
            //  username or cookie,
            //      verify that the identified user is the owner of credentialSource. If
            //      credential.response.userHandle is present, let userHandle be its value. Verify that
            //      userHandle also maps to the same user.

            //  If the user was not identified before the authentication ceremony was initiated,
            //      verify that credential.response.userHandle is present, and that the user identified
            //      by this value is the owner of credentialSource.
            //
            //      Note: User-less mode is handled by calling `AuthenticationState::set_allowed_credentials`
            //      after the caller extracts the userHandle and verifies the credential Source

            // Using credential’s id attribute (or the corresponding rawId, if base64url encoding is
            // inappropriate for your use case), look up the corresponding credential public key.
            let mut found_cred: Option<&Credential> = None;
            for cred in creds {
                if cred.cred_id == rsp.raw_id.0 {
                    found_cred = Some(cred);
                    break;
                }
            }

            found_cred.ok_or(WebauthnError::CredentialNotFound)?
        };

        let auth_data = self.verify_credential_internal(rsp, policy.clone(), chal, &cred)?;
        let counter = auth_data.counter;

        // If the signature counter value authData.signCount is nonzero or the value stored in
        // conjunction with credential’s id attribute is nonzero, then run the following sub-step:
        if counter > 0 || cred.counter > 0 {
            // greater than the signature counter value stored in conjunction with credential’s id attribute.
            //       Update the stored signature counter value, associated with credential’s id attribute,
            //       to be the value of authData.signCount.
            // less than or equal to the signature counter value stored in conjunction with credential’s id attribute.
            //      This is a signal that the authenticator may be cloned, i.e. at least two copies
            //      of the credential private key may exist and are being used in parallel. Relying
            //      Parties should incorporate this information into their risk scoring. Whether the
            //      Relying Party updates the stored signature counter value in this case, or not,
            //      or fails the authentication ceremony or not, is Relying Party-specific.
            let counter_shows_compromise = auth_data.counter <= cred.counter;

            if self.config.require_valid_counter_value() && counter_shows_compromise {
                return Err(WebauthnError::CredentialPossibleCompromise);
            }
        }

        Ok((&cred.cred_id, auth_data))
    }
}

/// The WebauthnConfig type allows site-specific customisation of the Webauthn library.
/// This provides a set of callbacks which are used to supply data to various structures
/// and calls, as well as callbacks to manage data persistence and retrieval.
pub trait WebauthnConfig {
    /// Returns a copy of your relying parties name. This is generally any text identifier
    /// you wish, but should rarely if ever change. Changes to the relying party name may
    /// confuse authenticators and will cause their credentials to be lost.
    ///
    /// Examples of names could be "My Awesome Site", "https://my-awesome-site.com.au"
    fn get_relying_party_name(&self) -> &str;

    /// Returns a reference to your sites origin. The origin is the URL to your site with
    /// protocol and port. This should rarely, if ever change. In production usage this
    /// value must always be https://, however http://localhost is acceptable for testing
    /// only. We may add warnings or errors for non-https:// urls in the future. Changing this
    /// may cause associated authenticators to lose credentials.
    ///
    /// Examples of this value could be. "https://my-site.com.au", "https://my-site.com.au:8443"
    fn get_origin(&self) -> &str;

    /// Returns the relying party id. This should never change, and is used as an id
    /// in cryptographic operations and credential scoping. This is defined as the domain name
    /// of the service, minuse all protocol, port and location data. For example:
    ///   `https://name:port/path -> name`
    ///
    /// If changed, all associated credentials will be lost in all authenticators.
    ///
    /// Examples of this value for the site "https://my-site.com.au/auth" is "my-site.com.au"
    fn get_relying_party_id(&self) -> &str;

    /// Get the list of valid credential algorthims that this service can accept. Unless you have
    /// speific requirements around this, we advise you leave this function to the default
    /// implementation.
    fn get_credential_algorithms(&self) -> Vec<COSEContentType> {
        vec![COSEContentType::ECDSA_SHA256, COSEContentType::RS256]
    }

    /// Return a timeout on how long the authenticator has to respond to a challenge. This value
    /// defaults to 6000 milliseconds. You likely won't need to implement this function, and should
    /// rely on the defaults.
    fn get_authenticator_timeout(&self) -> u32 {
        AUTHENTICATOR_TIMEOUT
    }

    /// Returns the default attestation type. Options are `None`, `Direct` and `Indirect`.
    /// Defaults to `None`.
    ///
    /// DANGER: The client *may* alter this value, causing the registration to not contain
    /// an attestation. This is *not* a verified property.
    ///
    /// You *must* also implement policy_verify_trust if you change this from `None` else
    /// this can be BYPASSED.
    fn get_attestation_preference(&self) -> AttestationConveyancePreference {
        AttestationConveyancePreference::None
    }

    /// Get the preferred policy on authenticator attachment hint. Defaults to None (use
    /// any attachment method).
    ///
    /// Default of None allows any attachment method.
    ///
    /// WARNING: This is not enforced, as the client may modify the registration request to
    /// disregard this, and no part of the registration response indicates attachement. This
    /// is purely a hint, and is NOT a security enforcment.
    fn get_authenticator_attachment(&self) -> Option<AuthenticatorAttachment> {
        None
    }

    /// Get the site policy on if the registration should use a resident key so that
    /// username and other details can be embedded into the authenticator
    /// to allow bypassing that part of the interaction flow.
    ///
    /// Defaults to "false" aka non-resident keys.
    /// See also: https://www.w3.org/TR/webauthn/#resident-credential
    ///
    /// WARNING: This is not enforced as the client may modify the registration request
    /// to disregard this, and no part of the registration process indicates residence of
    /// the credentials. This is not a security enforcement.
    fn get_require_resident_key(&self) -> bool {
        false
    }

    /// If the attestation format is not supported, should we ignore verifying the attestation
    fn ignore_unsupported_attestation_formats(&self) -> bool {
        false
    }
    /// Decides the verifier must error on invalid counter values
    fn require_valid_counter_value(&self) -> bool {
        true
    }

    /// A callback to allow trust decisions to be made over the attestation of the
    /// credential. It's important for your implementation of this callback to follow
    /// the advice of the w3c standard, notably:
    ///
    /// 15. If validation is successful, obtain a list of acceptable trust anchors (attestation
    /// root certificates or ECDAA-Issuer public keys) for that attestation type and attestation
    /// statement format fmt, from a trusted source or from policy. For example, the FIDO Metadata
    /// Service \[FIDOMetadataService\] provides one way to obtain such information, using the
    /// aaguid in the attestedCredentialData in authData.
    ///
    /// 16: Assess the attestation trustworthiness using the outputs of the verification procedure
    /// in step 14, as follows: (SEE RFC)
    /// If the attestation statement attStmt successfully verified but is not trustworthy per step
    /// 16 above, the Relying Party SHOULD fail the registration ceremony.
    ///
    /// The default implementation of this method rejects Uncertain attestation, and
    /// will "blindly trust" self attestation and the other types as valid.
    /// If you have strict security requirements we strongly recommend you implement this function,
    /// and we may in the future provide a stronger default relying party policy.
    fn policy_verify_trust(&self, at: AttestationType) -> Result<Credential, ()> {
        log::debug!("policy_verify_trust -> {:?}", at);
        match at {
            AttestationType::Basic(credential, _attest_cert) => Ok(credential),
            AttestationType::Self_(credential) => Ok(credential),
            AttestationType::AttCa(credential, _attest_cert, _ca_chain) => Ok(credential),
            AttestationType::AnonCa(credential, _attest_cert, _ca_chain) => Ok(credential),
            AttestationType::None(credential) => Ok(credential),
            // TODO: trust is unimplemented here
            AttestationType::ECDAA => Err(()),
            // We don't trust Uncertain attestations
            AttestationType::Uncertain(_) => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::base64_data::Base64UrlSafeData;
    use crate::constants::CHALLENGE_SIZE_BYTES;
    use crate::core::{CreationChallengeResponse, RegistrationState, WebauthnError};
    use crate::ephemeral::WebauthnEphemeralConfig;
    use crate::proto::{
        AuthenticatorAssertionResponseRaw, AuthenticatorAttestationResponseRaw, Challenge,
        Credential, PublicKeyCredential, RegisterPublicKeyCredential, UserVerificationPolicy,
    };
    use crate::proto::{COSEContentType, COSEEC2Key, COSEKey, COSEKeyType, ECDSACurve};
    use crate::Webauthn;

    #[test]
    fn test_ephemeral() {}

    // Test the crypto operations of the webauthn impl

    #[test]
    fn test_registration() {
        let wan_c = WebauthnEphemeralConfig::new(
            "http://127.0.0.1:8080/auth",
            "http://127.0.0.1:8080",
            "127.0.0.1",
            None,
        );
        let wan = Webauthn::new(wan_c);
        // Generated by a yubico 5
        // Make a "fake" challenge, where we know what the values should be ....

        let zero_chal = Challenge::new((0..CHALLENGE_SIZE_BYTES).map(|_| 0).collect::<Vec<u8>>());

        // This is the json challenge this would generate in this case, with the rp etc.
        // {"publicKey":{"rp":{"name":"http://127.0.0.1:8080/auth"},"user":{"id":"xxx","name":"xxx","displayName":"xxx"},"challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","pubKeyCredParams":[{"type":"public-key","alg":-7}],"timeout":6000,"attestation":"direct"}}

        // And this is the response, from a real device. Let's register it!

        let rsp = r#"
        {
            "id":"0xYE4bQ_HZM51-XYwp7WHJu8RfeA2Oz3_9HnNIZAKqRTz9gsUlF3QO7EqcJ0pgLSwDcq6cL1_aQpTtKLeGu6Ig",
            "rawId":"0xYE4bQ_HZM51-XYwp7WHJu8RfeA2Oz3_9HnNIZAKqRTz9gsUlF3QO7EqcJ0pgLSwDcq6cL1_aQpTtKLeGu6Ig",
            "response":{
                 "attestationObject":"o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIhALjRb43YFcbJ3V9WiYPpIrZkhgzAM6KTR8KIjwCXejBCAiAO5Lvp1VW4dYBhBDv7HZIrxZb1SwKKYOLfFRXykRxMqGN4NWOBWQLBMIICvTCCAaWgAwIBAgIEGKxGwDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbjELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEnMCUGA1UEAwweWXViaWNvIFUyRiBFRSBTZXJpYWwgNDEzOTQzNDg4MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeeo7LHxJcBBiIwzSP-tg5SkxcdSD8QC-hZ1rD4OXAwG1Rs3Ubs_K4-PzD4Hp7WK9Jo1MHr03s7y-kqjCrutOOqNsMGowIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjcwEwYLKwYBBAGC5RwCAQEEBAMCBSAwIQYLKwYBBAGC5RwBAQQEEgQQy2lIHo_3QDmT7AonKaFUqDAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQCXnQOX2GD4LuFdMRx5brr7Ivqn4ITZurTGG7tX8-a0wYpIN7hcPE7b5IND9Nal2bHO2orh_tSRKSFzBY5e4cvda9rAdVfGoOjTaCW6FZ5_ta2M2vgEhoz5Do8fiuoXwBa1XCp61JfIlPtx11PXm5pIS2w3bXI7mY0uHUMGvxAzta74zKXLslaLaSQibSKjWKt9h-SsXy4JGqcVefOlaQlJfXL1Tga6wcO0QTu6Xq-Uw7ZPNPnrpBrLauKDd202RlN4SP7ohL3d9bG6V5hUz_3OusNEBZUn5W3VmPj1ZnFavkMB3RkRMOa58MZAORJT4imAPzrvJ0vtv94_y71C6tZ5aGF1dGhEYXRhWMQSyhe0mvIolDbzA-AWYDCiHlJdJm4gkmdDOAGo_UBxoEEAAAAAAAAAAAAAAAAAAAAAAAAAAABA0xYE4bQ_HZM51-XYwp7WHJu8RfeA2Oz3_9HnNIZAKqRTz9gsUlF3QO7EqcJ0pgLSwDcq6cL1_aQpTtKLeGu6IqUBAgMmIAEhWCCe1KvqpcVWN416_QZc8vJynt3uo3_WeJ2R4uj6kJbaiiJYIDC5ssxxummKviGgLoP9ZLFb836A9XfRO7op18QY3i5m",
                 "clientDataJSON":"eyJjaGFsbGVuZ2UiOiJBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovLzEyNy4wLjAuMTo4MDgwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9"
            },
            "type":"public-key"}
        "#;
        // turn it into our "deserialised struct"
        let rsp_d: RegisterPublicKeyCredential = serde_json::from_str(rsp).unwrap();

        // Now register, providing our fake challenge.
        let result = wan.register_credential_internal(
            &rsp_d,
            UserVerificationPolicy::Preferred_DO_NOT_USE,
            &zero_chal,
            &[],
        );
        println!("{:?}", result);
        assert!(result.is_ok());
    }

    // These are vectors from https://github.com/duo-labs/webauthn
    #[test]
    fn test_registration_duo_go() {
        let wan_c = WebauthnEphemeralConfig::new(
            "webauthn.io",         // name, whatever you want
            "https://webauthn.io", //must be url origin
            "webauthn.io",         // must be url minus proto + port
            None,
        );
        let wan = Webauthn::new(wan_c);

        let chal =
            Challenge::new(base64::decode("+Ri5NZTzJ8b6mvW3TVScLotEoALfgBa2Bn4YSaIObHc").unwrap());

        let rsp = r#"
        {
                "id": "FOxcmsqPLNCHtyILvbNkrtHMdKAeqSJXYZDbeFd0kc5Enm8Kl6a0Jp0szgLilDw1S4CjZhe9Z2611EUGbjyEmg",
                "rawId": "FOxcmsqPLNCHtyILvbNkrtHMdKAeqSJXYZDbeFd0kc5Enm8Kl6a0Jp0szgLilDw1S4CjZhe9Z2611EUGbjyEmg",
                "response": {
                        "attestationObject": "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEYwRAIgfyIhwZj-fkEVyT1GOK8chDHJR2chXBLSRg6bTCjODmwCIHH6GXI_BQrcR-GHg5JfazKVQdezp6_QWIFfT4ltTCO2Y3g1Y4FZAlMwggJPMIIBN6ADAgECAgQSNtF_MA0GCSqGSIb3DQEBCwUAMC4xLDAqBgNVBAMTI1l1YmljbyBVMkYgUm9vdCBDQSBTZXJpYWwgNDU3MjAwNjMxMCAXDTE0MDgwMTAwMDAwMFoYDzIwNTAwOTA0MDAwMDAwWjAxMS8wLQYDVQQDDCZZdWJpY28gVTJGIEVFIFNlcmlhbCAyMzkyNTczNDEwMzI0MTA4NzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNNlqR5emeDVtDnA2a-7h_QFjkfdErFE7bFNKzP401wVE-QNefD5maviNnGVk4HJ3CsHhYuCrGNHYgTM9zTWriGjOzA5MCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS41MBMGCysGAQQBguUcAgEBBAQDAgUgMA0GCSqGSIb3DQEBCwUAA4IBAQAiG5uzsnIk8T6-oyLwNR6vRklmo29yaYV8jiP55QW1UnXdTkEiPn8mEQkUac-Sn6UmPmzHdoGySG2q9B-xz6voVQjxP2dQ9sgbKd5gG15yCLv6ZHblZKkdfWSrUkrQTrtaziGLFSbxcfh83vUjmOhDLFC5vxV4GXq2674yq9F2kzg4nCS4yXrO4_G8YWR2yvQvE2ffKSjQJlXGO5080Ktptplv5XN4i5lS-AKrT5QRVbEJ3B4g7G0lQhdYV-6r4ZtHil8mF4YNMZ0-RaYPxAaYNWkFYdzOZCaIdQbXRZefgGfbMUiAC2gwWN7fiPHV9eu82NYypGU32OijG9BjhGt_aGF1dGhEYXRhWMR0puqSE8mcL3SyJJKzIM9AJiqUwalQoDl_KSULYIQe8EEAAAAAAAAAAAAAAAAAAAAAAAAAAABAFOxcmsqPLNCHtyILvbNkrtHMdKAeqSJXYZDbeFd0kc5Enm8Kl6a0Jp0szgLilDw1S4CjZhe9Z2611EUGbjyEmqUBAgMmIAEhWCD_ap3Q9zU8OsGe967t48vyRxqn8NfFTk307mC1WsH2ISJYIIcqAuW3MxhU0uDtaSX8-Ftf_zeNJLdCOEjZJGHsrLxH",
                        "clientDataJSON": "eyJjaGFsbGVuZ2UiOiItUmk1TlpUeko4YjZtdlczVFZTY0xvdEVvQUxmZ0JhMkJuNFlTYUlPYkhjIiwib3JpZ2luIjoiaHR0cHM6Ly93ZWJhdXRobi5pbyIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ"
                },
                "type": "public-key"
        }
        "#;
        let rsp_d: RegisterPublicKeyCredential = serde_json::from_str(rsp).unwrap();
        let result = wan.register_credential_internal(
            &rsp_d,
            UserVerificationPolicy::Preferred_DO_NOT_USE,
            chal.as_ref(),
            &[],
        );
        println!("{:?}", result);
        assert!(result.is_ok());
    }

    #[test]
    fn test_registration_packed_attestation() {
        let wan_c = WebauthnEphemeralConfig::new(
            "localhost:8443/auth",
            "https://localhost:8443",
            "localhost",
            None,
        );
        let wan = Webauthn::new(wan_c);

        let chal =
            Challenge::new(base64::decode("lP6mWNAtG+/Vv15iM7lb/XRkdWMvVQ+lTyKwZuOg1Vo=").unwrap());

        // Example generated using navigator.credentials.create on Chrome Version 77.0.3865.120
        // using Touch ID on MacBook running MacOS 10.15
        let rsp = r#"{
                        "id":"ATk_7QKbi_ntSdp16LXeU6RDf9YnRLIDTCqEjJFzc6rKBhbqoSYccxNa",
                        "rawId":"ATk_7QKbi_ntSdp16LXeU6RDf9YnRLIDTCqEjJFzc6rKBhbqoSYccxNa",
                        "response":{
                            "attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIgLXPjBtVEhBH3KdUDFFk3LAd9EtHogllIf48vjX4wgfECIQCXOymmfg12FPMXEdwpSjjtmrvki4K8y0uYxqWN5Bw6DGhhdXRoRGF0YViuSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFXaqejq3OAAI1vMYKZIsLJfHwVQMAKgE5P-0Cm4v57Unadei13lOkQ3_WJ0SyA0wqhIyRc3OqygYW6qEmHHMTWqUBAgMmIAEhWCDNRS_Gw52ow5PNrC9OdFTFNudDmZO6Y3wmM9N8e0tJICJYIC09iIH5_RrT5tbS0PIw3srdAxYDMGao7yWgu0JFIEzT",
                            "clientDataJSON":"eyJjaGFsbGVuZ2UiOiJsUDZtV05BdEctX1Z2MTVpTTdsYl9YUmtkV012VlEtbFR5S3dadU9nMVZvIiwiZXh0cmFfa2V5c19tYXlfYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb21wYXJlIGNsaWVudERhdGFKU09OIGFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ29vLmdsL3lhYlBleCIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0"
                            },
                        "type":"public-key"
                      }
        "#;
        let rsp_d: RegisterPublicKeyCredential = serde_json::from_str(rsp).unwrap();
        let result = wan.register_credential_internal(
            &rsp_d,
            UserVerificationPolicy::Preferred_DO_NOT_USE,
            &chal,
            &[],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_registration_packed_attestaion_fails_with_bad_cred_protect() {
        let wan_c = WebauthnEphemeralConfig::new(
            "localhost:8080/auth",
            "http://localhost:8080",
            "localhost",
            None,
        );
        let wan = Webauthn::new(wan_c);

        let chal = Challenge::new(vec![
            125, 119, 194, 67, 227, 22, 152, 134, 220, 143, 75, 119, 197, 165, 115, 149, 187, 153,
            211, 51, 215, 128, 225, 56, 110, 80, 52, 235, 149, 146, 101, 202,
        ]);

        let rsp = r#"{
            "id":"9KJylaUgVoWF2cF2qX5an7ZtPBFeRMXy-jMSGgNWCogxiyctVFtIcDKmkVmfKOgllffKJMyl4gFeDm8KaltrDw",
            "rawId":"9KJylaUgVoWF2cF2qX5an7ZtPBFeRMXy-jMSGgNWCogxiyctVFtIcDKmkVmfKOgllffKJMyl4gFeDm8KaltrDw",
            "response":{
                "attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEYwRAIgZEq9euYGkqTP4VMBs-5fruhwAPSyKjOlr2THNZGvZ3gCIHww2gAgZXvZcIwcSiUF3fHhaNL0uj8V5rOLHyGRJz81Y3g1Y4FZAsEwggK9MIIBpaADAgECAgQej4c0MA0GCSqGSIb3DQEBCwUAMC4xLDAqBgNVBAMTI1l1YmljbyBVMkYgUm9vdCBDQSBTZXJpYWwgNDU3MjAwNjMxMCAXDTE0MDgwMTAwMDAwMFoYDzIwNTAwOTA0MDAwMDAwWjBuMQswCQYDVQQGEwJTRTESMBAGA1UECgwJWXViaWNvIEFCMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMScwJQYDVQQDDB5ZdWJpY28gVTJGIEVFIFNlcmlhbCA1MTI3MjI3NDAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASoefgjOO0UlLrAcEvMf8Zj0bJxcVl2JDEBx2BRFdfBUp4oHBxnMi04S1zVXdPpgY1f2FwirzJuDGT8IK_jPyNmo2wwajAiBgkrBgEEAYLECgIEFTEuMy42LjEuNC4xLjQxNDgyLjEuNzATBgsrBgEEAYLlHAIBAQQEAwIEMDAhBgsrBgEEAYLlHAEBBAQSBBAvwFefgRNH6rEWu1qNuSAqMAwGA1UdEwEB_wQCMAAwDQYJKoZIhvcNAQELBQADggEBAIaT_2LfDVd51HSNf8jRAicxio5YDmo6V8EI6U4Dw4Vos2aJT85WJL5KPv1_NBGLPZk3Q_eSoZiRYMj8muCwTj357hXj6IwE_IKo3L9YGOEI3MKWhXeuef9mK5RzTj3sRZcwXXPm5V7ivrnNlnjKCTXlM-tjj44m-ruBfNpEH76YMYMq5fbirZkvnrvbTGIji4-NerSB1tMmO82_nkpXVQNwmIrVgTRA-gMsrbZyPK3Y-Ne6gJ91tDz_oKW5rdFCMu-dnhSBJjgjPEykqHO5-KyY4yuhkWdgbhWQn83bSi3_va5GICSfmmZGrIHkgy0RGf6_qnMaiC2iWneCfUbRkBdoYXV0aERhdGFY0kmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjxQAAAAEvwFefgRNH6rEWu1qNuSAqAED0onKVpSBWhYXZwXapflqftm08EV5ExfL6MxIaA1YKiDGLJy1UW0hwMqaRWZ8o6CWV98okzKXiAV4ObwpqW2sPpQECAyYgASFYIB_nQH-kBm4OmDfqezjFDr_t0Psz6JrylkEPWHFs2UB-Ilgg7xkwKc-IHHIwPI8EJ5ycM1zvWDnm4bCarn1LAWAU3Dqha2NyZWRQcm90ZWN0Aw",
                "clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiZlhmQ1EtTVdtSWJjajB0M3hhVnpsYnVaMHpQWGdPRTRibEEwNjVXU1pjbyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZSwib3RoZXJfa2V5c19jYW5fYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb21wYXJlIGNsaWVudERhdGFKU09OIGFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ29vLmdsL3lhYlBleCJ9"
            },
            "type":"public-key"
        }"#;
        let rsp_d: RegisterPublicKeyCredential = serde_json::from_str(rsp).unwrap();

        println!("{:?}", rsp_d);

        let result =
            wan.register_credential_internal(&rsp_d, UserVerificationPolicy::Required, &chal, &[]);
        println!("{:?}", result);
        assert!(result.is_ok());
    }

    #[test]
    fn test_authentication() {
        let wan_c = WebauthnEphemeralConfig::new(
            "http://localhost:8080/auth",
            "http://localhost:8080",
            "localhost",
            None,
        );

        // Generated by a yubico 5
        // Make a "fake" challenge, where we know what the values should be ....

        let zero_chal = Challenge::new(vec![
            90, 5, 243, 254, 68, 239, 221, 101, 20, 214, 76, 60, 134, 111, 142, 26, 129, 146, 225,
            144, 135, 95, 253, 219, 18, 161, 199, 216, 251, 213, 167, 195,
        ]);

        // Create the fake credential that we know is associated
        let cred = Credential {
            counter: 1,
            cred_id: vec![
                106, 223, 133, 124, 161, 172, 56, 141, 181, 18, 27, 66, 187, 181, 113, 251, 187,
                123, 20, 169, 41, 80, 236, 138, 92, 137, 4, 4, 16, 255, 188, 47, 158, 202, 111,
                192, 117, 110, 152, 245, 95, 22, 200, 172, 71, 154, 40, 181, 212, 64, 80, 17, 238,
                238, 21, 13, 27, 145, 140, 27, 208, 101, 166, 81,
            ],
            cred: COSEKey {
                type_: COSEContentType::ECDSA_SHA256,
                key: COSEKeyType::EC_EC2(COSEEC2Key {
                    curve: ECDSACurve::SECP256R1,
                    x: [
                        46, 121, 76, 233, 118, 208, 250, 74, 227, 182, 8, 145, 45, 46, 5, 9, 199,
                        186, 84, 83, 7, 237, 130, 73, 16, 90, 17, 54, 33, 255, 54, 56,
                    ],
                    y: [
                        117, 105, 1, 23, 253, 223, 67, 135, 253, 219, 253, 223, 17, 247, 91, 197,
                        205, 225, 143, 59, 47, 138, 70, 120, 74, 155, 177, 177, 166, 233, 48, 71,
                    ],
                }),
            },
            verified: false,
        };

        // Persist it to our fake db.
        let wan = Webauthn::new(wan_c);

        // Captured authentication attempt
        let rsp = r#"
        {
            "id":"at-FfKGsOI21EhtCu7Vx-7t7FKkpUOyKXIkEBBD_vC-eym_AdW6Y9V8WyKxHmii11EBQEe7uFQ0bkYwb0GWmUQ",
            "rawId":"at-FfKGsOI21EhtCu7Vx-7t7FKkpUOyKXIkEBBD_vC-eym_AdW6Y9V8WyKxHmii11EBQEe7uFQ0bkYwb0GWmUQ",
            "response":{
                "authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAFA",
                "clientDataJSON":"eyJjaGFsbGVuZ2UiOiJXZ1h6X2tUdjNXVVUxa3c4aG0tT0dvR1M0WkNIWF8zYkVxSEgyUHZWcDhNIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9",
                "signature":"MEYCIQDmLVOqv85cdRup4Fr8Pf9zC4AWO-XKBJqa8xPwYFCCMAIhAOiExLoyes0xipmUmq0BVlqJaCKLn_MFKG9GIDsCGq_-",
                "userHandle":null
            },
            "type":"public-key"
        }
        "#;
        let rsp_d: PublicKeyCredential = serde_json::from_str(rsp).unwrap();

        // Now verify it!
        let r = wan.verify_credential_internal(
            &rsp_d,
            UserVerificationPolicy::Discouraged,
            &zero_chal,
            &cred,
        );
        println!("RESULT: {:?}", r);
        assert!(r.is_ok());
    }

    #[test]
    fn test_registration_ipados_5ci() {
        let wan_c = WebauthnEphemeralConfig::new(
            "https://172.20.0.141:8443/auth",
            "https://172.20.0.141:8443",
            "172.20.0.141",
            None,
        );
        let wan = Webauthn::new(wan_c);

        let chal =
            Challenge::new(base64::decode("tvR1m+d/ohXrwVxQjMgH8KnovHZ7BRWhZmDN4TVMpNU=").unwrap());

        let rsp_d = RegisterPublicKeyCredential {
            id: "uZcVDBVS68E_MtAgeQpElJxldF_6cY9sSvbWqx_qRh8wiu42lyRBRmh5yFeD_r9k130dMbFHBHI9RTFgdJQIzQ".to_string(),
            raw_id: Base64UrlSafeData(
                base64::decode("uZcVDBVS68E/MtAgeQpElJxldF/6cY9sSvbWqx/qRh8wiu42lyRBRmh5yFeD/r9k130dMbFHBHI9RTFgdJQIzQ==").unwrap()
            ),
            response: AuthenticatorAttestationResponseRaw {
                attestation_object: Base64UrlSafeData(
                    base64::decode("o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIhAKAZODmj+uF5qXsDY2NFol3apRjld544KRUpHzwfk5cbAiBnp2gHmamr2xr46ilQuhzIR9BwMlwtxWd6IT2QEYeo7WN4NWOBWQLBMIICvTCCAaWgAwIBAgIEK/F8eDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbjELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEnMCUGA1UEAwweWXViaWNvIFUyRiBFRSBTZXJpYWwgNzM3MjQ2MzI4MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEdMLHhCPIcS6bSPJZWGb8cECuTN8H13fVha8Ek5nt+pI8vrSflxb59Vp4bDQlH8jzXj3oW1ZwUDjHC6EnGWB5i6NsMGowIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjcwEwYLKwYBBAGC5RwCAQEEBAMCAiQwIQYLKwYBBAGC5RwBAQQEEgQQxe9V/62aS5+1gK3rr+Am0DAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQCLbpN2nXhNbunZANJxAn/Cd+S4JuZsObnUiLnLLS0FPWa01TY8F7oJ8bE+aFa4kTe6NQQfi8+yiZrQ8N+JL4f7gNdQPSrH+r3iFd4SvroDe1jaJO4J9LeiFjmRdcVa+5cqNF4G1fPCofvw9W4lKnObuPakr0x/icdVq1MXhYdUtQk6Zr5mBnc4FhN9qi7DXqLHD5G7ZFUmGwfIcD2+0m1f1mwQS8yRD5+/aDCf3vutwddoi3crtivzyromwbKklR4qHunJ75LGZLZA8pJ/mXnUQ6TTsgRqPvPXgQPbSyGMf2z/DIPbQqCD/Bmc4dj9o6LozheBdDtcZCAjSPTAd/uiaGF1dGhEYXRhWMS3tF916xTswLEZrAO3fy8EzMmvvR8f5wWM7F5+4KJ0ikEAAAACxe9V/62aS5+1gK3rr+Am0ABAuZcVDBVS68E/MtAgeQpElJxldF/6cY9sSvbWqx/qRh8wiu42lyRBRmh5yFeD/r9k130dMbFHBHI9RTFgdJQIzaUBAgMmIAEhWCDCfn9t/BeDFfwG32Ms/owb5hFeBYUcaCmQRauVoRrI8yJYII97t5wYshX4dZ+iRas0vPwaOwYvZ1wTOnVn+QDbCF/E").unwrap()
                ),
                client_data_json: Base64UrlSafeData(
                    base64::decode("eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwib3JpZ2luIjoiaHR0cHM6XC9cLzE3Mi4yMC4wLjE0MTo4NDQzIiwiY2hhbGxlbmdlIjoidHZSMW0tZF9vaFhyd1Z4UWpNZ0g4S25vdkhaN0JSV2habURONFRWTXBOVSJ9").unwrap()
                ),
            },
            type_: "public-key".to_string(),
        };

        let result = wan.register_credential_internal(
            &rsp_d,
            UserVerificationPolicy::Preferred_DO_NOT_USE,
            &chal,
            &[],
        );
        println!("{:?}", result);
        assert!(result.is_ok());
    }

    fn test_credential_registration<T>(
        wan_c: T,
        chal: Challenge,
        rsp_d: &RegisterPublicKeyCredential,
    ) where
        T: crate::WebauthnConfig,
    {
        let _ = env_logger::builder().is_test(true).try_init();
        let wan = Webauthn::new(wan_c);

        let result =
            wan.register_credential_internal(rsp_d, UserVerificationPolicy::Required, &chal, &[]);
        println!("{:?}", result);
        assert!(result.is_ok());
    }

    #[test]
    fn test_win_hello_attest_none() {
        let _ = env_logger::builder().is_test(true).try_init();
        let wan_c = WebauthnEphemeralConfig::new(
            "https://etools-dev.example.com:8080/auth",
            "https://etools-dev.example.com:8080",
            "etools-dev.example.com",
            None,
        );
        let wan = Webauthn::new(wan_c);

        let chal = Challenge::new(vec![
            21, 9, 50, 208, 90, 167, 153, 94, 74, 98, 161, 84, 247, 161, 61, 104, 10, 82, 33, 27,
            99, 94, 34, 156, 84, 85, 31, 240, 9, 188, 136, 52,
        ]);

        let rsp_d = RegisterPublicKeyCredential {
            id: "KwlEDOBCBc9P1YU3NWihYLCeY-I9KGMhPap9vwHbVoI".to_string(),
            raw_id: Base64UrlSafeData(vec![
                43, 9, 68, 12, 224, 66, 5, 207, 79, 213, 133, 55, 53, 104, 161, 96, 176, 158, 99,
                226, 61, 40, 99, 33, 61, 170, 125, 191, 1, 219, 86, 130,
            ]),
            response: AuthenticatorAttestationResponseRaw {
                attestation_object: Base64UrlSafeData(vec![
                    163, 99, 102, 109, 116, 100, 110, 111, 110, 101, 103, 97, 116, 116, 83, 116,
                    109, 116, 160, 104, 97, 117, 116, 104, 68, 97, 116, 97, 89, 1, 103, 108, 41,
                    129, 232, 231, 178, 172, 146, 198, 102, 0, 255, 160, 250, 221, 227, 137, 40,
                    196, 142, 208, 221, 115, 246, 47, 198, 69, 45, 165, 107, 42, 27, 69, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 43, 9, 68, 12, 224,
                    66, 5, 207, 79, 213, 133, 55, 53, 104, 161, 96, 176, 158, 99, 226, 61, 40, 99,
                    33, 61, 170, 125, 191, 1, 219, 86, 130, 164, 1, 3, 3, 57, 1, 0, 32, 89, 1, 0,
                    166, 163, 131, 233, 97, 64, 136, 207, 111, 39, 80, 80, 230, 19, 46, 59, 12,
                    247, 151, 113, 167, 157, 140, 198, 227, 168, 159, 211, 232, 112, 116, 209, 54,
                    148, 26, 156, 56, 88, 56, 27, 116, 102, 237, 88, 99, 81, 65, 79, 133, 242, 192,
                    25, 28, 45, 116, 131, 129, 253, 185, 91, 35, 129, 35, 193, 44, 64, 86, 87, 137,
                    44, 19, 74, 239, 72, 178, 243, 11, 195, 135, 194, 216, 109, 62, 84, 172, 16,
                    182, 82, 140, 170, 1, 255, 91, 80, 73, 100, 1, 117, 61, 148, 179, 95, 199, 169,
                    228, 244, 174, 69, 54, 185, 15, 107, 5, 0, 110, 155, 28, 243, 114, 32, 176,
                    220, 93, 196, 172, 158, 22, 3, 154, 18, 148, 20, 132, 94, 166, 45, 24, 27, 8,
                    255, 108, 31, 230, 196, 122, 125, 240, 215, 219, 118, 80, 224, 146, 92, 80,
                    219, 91, 211, 88, 45, 28, 133, 135, 83, 244, 212, 29, 121, 132, 104, 189, 3,
                    98, 42, 180, 10, 249, 232, 59, 172, 204, 109, 64, 206, 139, 76, 247, 230, 40,
                    36, 71, 79, 11, 139, 84, 211, 153, 125, 108, 108, 55, 195, 205, 5, 90, 248, 72,
                    42, 94, 40, 136, 193, 89, 3, 102, 109, 30, 65, 117, 76, 103, 150, 4, 44, 155,
                    104, 207, 126, 92, 16, 161, 175, 223, 119, 246, 169, 127, 72, 13, 83, 129, 12,
                    164, 102, 42, 141, 173, 102, 140, 52, 57, 43, 115, 12, 238, 89, 33, 67, 1, 0,
                    1,
                ]),
                client_data_json: Base64UrlSafeData(vec![
                    123, 34, 116, 121, 112, 101, 34, 58, 34, 119, 101, 98, 97, 117, 116, 104, 110,
                    46, 99, 114, 101, 97, 116, 101, 34, 44, 34, 99, 104, 97, 108, 108, 101, 110,
                    103, 101, 34, 58, 34, 70, 81, 107, 121, 48, 70, 113, 110, 109, 86, 53, 75, 89,
                    113, 70, 85, 57, 54, 69, 57, 97, 65, 112, 83, 73, 82, 116, 106, 88, 105, 75,
                    99, 86, 70, 85, 102, 56, 65, 109, 56, 105, 68, 81, 34, 44, 34, 111, 114, 105,
                    103, 105, 110, 34, 58, 34, 104, 116, 116, 112, 115, 58, 47, 47, 101, 116, 111,
                    111, 108, 115, 45, 100, 101, 118, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99,
                    111, 109, 58, 56, 48, 56, 48, 34, 44, 34, 99, 114, 111, 115, 115, 79, 114, 105,
                    103, 105, 110, 34, 58, 102, 97, 108, 115, 101, 125,
                ]),
            },
            type_: "public-key".to_string(),
        };

        let result =
            wan.register_credential_internal(&rsp_d, UserVerificationPolicy::Required, &chal, &[]);
        println!("{:?}", result);
        assert!(result.is_ok());
        let cred = result.unwrap();

        let chal = Challenge::new(vec![
            189, 116, 126, 107, 74, 29, 210, 181, 99, 178, 173, 214, 166, 212, 124, 219, 29, 169,
            9, 58, 26, 27, 120, 246, 87, 173, 169, 210, 241, 153, 150, 189,
        ]);

        let rsp_d = PublicKeyCredential {
            id: "KwlEDOBCBc9P1YU3NWihYLCeY-I9KGMhPap9vwHbVoI".to_string(),
            raw_id: Base64UrlSafeData(vec![
                43, 9, 68, 12, 224, 66, 5, 207, 79, 213, 133, 55, 53, 104, 161, 96, 176, 158, 99,
                226, 61, 40, 99, 33, 61, 170, 125, 191, 1, 219, 86, 130,
            ]),
            response: AuthenticatorAssertionResponseRaw {
                authenticator_data: Base64UrlSafeData(vec![
                    108, 41, 129, 232, 231, 178, 172, 146, 198, 102, 0, 255, 160, 250, 221, 227,
                    137, 40, 196, 142, 208, 221, 115, 246, 47, 198, 69, 45, 165, 107, 42, 27, 5, 0,
                    0, 0, 1,
                ]),
                client_data_json: Base64UrlSafeData(vec![
                    123, 34, 116, 121, 112, 101, 34, 58, 34, 119, 101, 98, 97, 117, 116, 104, 110,
                    46, 103, 101, 116, 34, 44, 34, 99, 104, 97, 108, 108, 101, 110, 103, 101, 34,
                    58, 34, 118, 88, 82, 45, 97, 48, 111, 100, 48, 114, 86, 106, 115, 113, 51, 87,
                    112, 116, 82, 56, 50, 120, 50, 112, 67, 84, 111, 97, 71, 51, 106, 50, 86, 54,
                    50, 112, 48, 118, 71, 90, 108, 114, 48, 34, 44, 34, 111, 114, 105, 103, 105,
                    110, 34, 58, 34, 104, 116, 116, 112, 115, 58, 47, 47, 101, 116, 111, 111, 108,
                    115, 45, 100, 101, 118, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109,
                    58, 56, 48, 56, 48, 34, 44, 34, 99, 114, 111, 115, 115, 79, 114, 105, 103, 105,
                    110, 34, 58, 102, 97, 108, 115, 101, 125,
                ]),
                signature: Base64UrlSafeData(vec![
                    77, 253, 152, 83, 184, 198, 5, 16, 68, 51, 178, 5, 228, 20, 148, 168, 182, 3,
                    201, 59, 162, 181, 96, 221, 67, 136, 230, 61, 252, 0, 38, 244, 143, 98, 100,
                    14, 226, 223, 234, 58, 72, 9, 230, 190, 0, 189, 176, 101, 172, 176, 146, 25,
                    221, 117, 79, 13, 176, 99, 208, 211, 135, 15, 60, 245, 106, 232, 195, 215, 37,
                    70, 136, 198, 25, 186, 156, 226, 77, 216, 85, 100, 139, 73, 73, 173, 210, 244,
                    116, 84, 108, 180, 138, 115, 15, 187, 140, 198, 110, 218, 78, 238, 99, 131,
                    210, 229, 242, 184, 133, 219, 177, 235, 96, 187, 143, 82, 243, 88, 120, 214,
                    182, 118, 88, 198, 157, 233, 83, 206, 165, 187, 111, 83, 211, 68, 147, 137,
                    176, 28, 173, 36, 66, 87, 225, 252, 195, 101, 181, 44, 119, 198, 48, 210, 186,
                    188, 190, 20, 78, 14, 49, 67, 144, 131, 76, 85, 70, 95, 130, 137, 132, 168, 33,
                    196, 113, 83, 59, 38, 46, 1, 167, 107, 200, 168, 242, 6, 106, 141, 203, 123,
                    203, 50, 69, 173, 6, 183, 117, 118, 229, 188, 39, 120, 188, 48, 54, 117, 223,
                    15, 153, 122, 4, 24, 218, 56, 251, 173, 166, 113, 240, 231, 175, 21, 28, 228,
                    248, 10, 1, 73, 222, 52, 57, 72, 51, 44, 131, 206, 4, 243, 66, 100, 61, 113,
                    237, 221, 115, 182, 37, 187, 29, 250, 103, 178, 104, 69, 153, 47, 212, 76, 200,
                    242,
                ]),
                user_handle: Some(Base64UrlSafeData(vec![109, 99, 104, 97, 110])),
            },
            type_: "public-key".to_string(),
        };

        let r = wan.verify_credential_internal(
            &rsp_d,
            UserVerificationPolicy::Required,
            &chal,
            &cred.0,
        );
        println!("RESULT: {:?}", r);
        assert!(r.is_ok());
    }

    #[test]
    fn test_win_hello_attest_tpm() {
        let _ = env_logger::builder().is_test(true).try_init();
        let wan_c = WebauthnEphemeralConfig::new(
            "https://etools-dev.example.com:8080/auth",
            "https://etools-dev.example.com:8080",
            "etools-dev.example.com",
            None,
        );
        let wan = Webauthn::new(wan_c);

        let chal = Challenge::new(vec![
            34, 92, 189, 180, 54, 92, 96, 184, 1, 200, 155, 91, 42, 168, 156, 94, 254, 223, 49,
            169, 171, 179, 2, 71, 90, 123, 180, 244, 37, 182, 17, 52,
        ]);

        let rsp_d = RegisterPublicKeyCredential {
            id: "0_n4aTCbomLUQXr07c7Ea-J0iNvdYmW0bUGuN6-ceGA".to_string(),
            raw_id: Base64UrlSafeData(vec![
                211, 249, 248, 105, 48, 155, 162, 98, 212, 65, 122, 244, 237, 206, 196, 107, 226,
                116, 136, 219, 221, 98, 101, 180, 109, 65, 174, 55, 175, 156, 120, 96,
            ]),
            response: AuthenticatorAttestationResponseRaw {
                attestation_object: Base64UrlSafeData(vec![
                    163, 99, 102, 109, 116, 99, 116, 112, 109, 103, 97, 116, 116, 83, 116, 109,
                    116, 166, 99, 97, 108, 103, 57, 255, 254, 99, 115, 105, 103, 89, 1, 0, 5, 3,
                    162, 216, 151, 57, 210, 103, 145, 121, 161, 186, 63, 232, 221, 255, 89, 37, 17,
                    59, 155, 241, 77, 30, 35, 201, 30, 140, 84, 214, 250, 185, 47, 248, 58, 89,
                    177, 187, 231, 202, 220, 45, 167, 126, 243, 194, 94, 33, 39, 205, 163, 51, 40,
                    171, 35, 118, 196, 244, 247, 143, 166, 193, 223, 94, 244, 157, 121, 220, 22,
                    94, 163, 15, 151, 223, 214, 131, 105, 202, 40, 16, 176, 11, 154, 102, 100, 212,
                    174, 103, 166, 92, 90, 154, 224, 20, 165, 106, 127, 53, 91, 230, 217, 199, 172,
                    195, 203, 242, 41, 158, 64, 252, 65, 9, 155, 160, 63, 40, 94, 94, 64, 145, 173,
                    71, 85, 173, 2, 199, 18, 148, 88, 223, 93, 154, 203, 197, 170, 142, 35, 249,
                    146, 107, 146, 2, 14, 54, 39, 151, 181, 10, 176, 216, 117, 25, 196, 2, 205,
                    159, 140, 155, 56, 89, 87, 31, 135, 93, 97, 78, 95, 176, 228, 72, 237, 130,
                    171, 23, 66, 232, 35, 115, 218, 105, 168, 6, 253, 121, 161, 129, 44, 78, 252,
                    44, 11, 23, 172, 66, 37, 214, 113, 128, 28, 33, 209, 66, 34, 32, 196, 153, 80,
                    87, 243, 162, 7, 25, 62, 252, 243, 174, 31, 168, 98, 123, 100, 2, 143, 134, 36,
                    154, 236, 18, 128, 175, 185, 189, 177, 51, 53, 216, 190, 43, 63, 35, 84, 14,
                    64, 249, 23, 9, 125, 147, 160, 176, 137, 30, 174, 245, 148, 189, 99, 118, 101,
                    114, 99, 50, 46, 48, 99, 120, 53, 99, 130, 89, 5, 189, 48, 130, 5, 185, 48,
                    130, 3, 161, 160, 3, 2, 1, 2, 2, 16, 88, 191, 48, 69, 71, 45, 69, 233, 150,
                    144, 71, 177, 166, 190, 225, 202, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1,
                    1, 11, 5, 0, 48, 66, 49, 64, 48, 62, 6, 3, 85, 4, 3, 19, 55, 78, 67, 85, 45,
                    73, 78, 84, 67, 45, 75, 69, 89, 73, 68, 45, 54, 67, 65, 57, 68, 70, 54, 50, 65,
                    49, 65, 65, 69, 50, 51, 69, 48, 70, 69, 66, 55, 67, 51, 70, 53, 69, 66, 56, 69,
                    54, 49, 69, 67, 65, 67, 49, 55, 67, 66, 55, 48, 30, 23, 13, 50, 48, 48, 56, 49,
                    49, 49, 54, 50, 50, 49, 54, 90, 23, 13, 50, 53, 48, 51, 50, 49, 50, 48, 51, 48,
                    48, 50, 90, 48, 0, 48, 130, 1, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1,
                    1, 1, 5, 0, 3, 130, 1, 15, 0, 48, 130, 1, 10, 2, 130, 1, 1, 0, 197, 166, 58,
                    190, 204, 104, 240, 65, 135, 183, 96, 7, 143, 26, 55, 77, 107, 12, 171, 56, 2,
                    145, 240, 201, 220, 75, 161, 201, 223, 24, 207, 126, 10, 118, 48, 201, 191, 6,
                    187, 227, 178, 255, 229, 252, 127, 199, 215, 76, 221, 180, 123, 111, 178, 141,
                    58, 235, 87, 27, 29, 24, 52, 235, 235, 181, 241, 28, 109, 223, 48, 137, 54, 21,
                    113, 155, 105, 39, 210, 237, 238, 172, 146, 195, 173, 170, 137, 201, 36, 212,
                    77, 179, 246, 142, 19, 198, 242, 48, 161, 199, 209, 113, 228, 182, 205, 115, 8,
                    29, 255, 6, 29, 87, 118, 157, 115, 116, 171, 64, 105, 248, 91, 128, 220, 98,
                    209, 126, 157, 177, 227, 101, 26, 26, 239, 72, 162, 135, 177, 177, 130, 16,
                    239, 79, 140, 1, 29, 26, 38, 57, 7, 96, 218, 94, 110, 49, 251, 102, 130, 28,
                    128, 227, 105, 117, 184, 13, 29, 229, 137, 151, 164, 116, 179, 101, 134, 253,
                    159, 165, 90, 245, 195, 156, 105, 87, 147, 61, 219, 46, 29, 191, 252, 201, 117,
                    54, 207, 6, 157, 96, 161, 26, 39, 172, 229, 85, 225, 172, 220, 252, 242, 129,
                    34, 7, 227, 8, 7, 112, 42, 34, 73, 125, 6, 241, 100, 14, 214, 125, 179, 63,
                    106, 150, 111, 19, 235, 59, 24, 141, 217, 140, 125, 91, 73, 152, 206, 174, 0,
                    237, 72, 250, 207, 138, 119, 143, 203, 206, 115, 97, 89, 211, 219, 245, 2, 3,
                    1, 0, 1, 163, 130, 1, 235, 48, 130, 1, 231, 48, 14, 6, 3, 85, 29, 15, 1, 1,
                    255, 4, 4, 3, 2, 7, 128, 48, 12, 6, 3, 85, 29, 19, 1, 1, 255, 4, 2, 48, 0, 48,
                    109, 6, 3, 85, 29, 32, 1, 1, 255, 4, 99, 48, 97, 48, 95, 6, 9, 43, 6, 1, 4, 1,
                    130, 55, 21, 31, 48, 82, 48, 80, 6, 8, 43, 6, 1, 5, 5, 7, 2, 2, 48, 68, 30, 66,
                    0, 84, 0, 67, 0, 80, 0, 65, 0, 32, 0, 32, 0, 84, 0, 114, 0, 117, 0, 115, 0,
                    116, 0, 101, 0, 100, 0, 32, 0, 32, 0, 80, 0, 108, 0, 97, 0, 116, 0, 102, 0,
                    111, 0, 114, 0, 109, 0, 32, 0, 32, 0, 73, 0, 100, 0, 101, 0, 110, 0, 116, 0,
                    105, 0, 116, 0, 121, 48, 16, 6, 3, 85, 29, 37, 4, 9, 48, 7, 6, 5, 103, 129, 5,
                    8, 3, 48, 80, 6, 3, 85, 29, 17, 1, 1, 255, 4, 70, 48, 68, 164, 66, 48, 64, 49,
                    22, 48, 20, 6, 5, 103, 129, 5, 2, 1, 12, 11, 105, 100, 58, 52, 57, 52, 69, 53,
                    52, 52, 51, 49, 14, 48, 12, 6, 5, 103, 129, 5, 2, 2, 12, 3, 83, 80, 84, 49, 22,
                    48, 20, 6, 5, 103, 129, 5, 2, 3, 12, 11, 105, 100, 58, 48, 48, 48, 50, 48, 48,
                    48, 48, 48, 31, 6, 3, 85, 29, 35, 4, 24, 48, 22, 128, 20, 147, 147, 77, 66, 14,
                    183, 179, 161, 2, 110, 122, 113, 35, 6, 16, 82, 232, 88, 88, 179, 48, 29, 6, 3,
                    85, 29, 14, 4, 22, 4, 20, 168, 251, 63, 173, 250, 64, 138, 217, 186, 126, 231,
                    77, 242, 159, 198, 195, 60, 109, 251, 231, 48, 129, 179, 6, 8, 43, 6, 1, 5, 5,
                    7, 1, 1, 4, 129, 166, 48, 129, 163, 48, 129, 160, 6, 8, 43, 6, 1, 5, 5, 7, 48,
                    2, 134, 129, 147, 104, 116, 116, 112, 58, 47, 47, 97, 122, 99, 115, 112, 114,
                    111, 100, 110, 99, 117, 97, 105, 107, 112, 117, 98, 108, 105, 115, 104, 46, 98,
                    108, 111, 98, 46, 99, 111, 114, 101, 46, 119, 105, 110, 100, 111, 119, 115, 46,
                    110, 101, 116, 47, 110, 99, 117, 45, 105, 110, 116, 99, 45, 107, 101, 121, 105,
                    100, 45, 54, 99, 97, 57, 100, 102, 54, 50, 97, 49, 97, 97, 101, 50, 51, 101,
                    48, 102, 101, 98, 55, 99, 51, 102, 53, 101, 98, 56, 101, 54, 49, 101, 99, 97,
                    99, 49, 55, 99, 98, 55, 47, 100, 56, 101, 48, 50, 49, 56, 101, 45, 55, 55, 101,
                    98, 45, 52, 51, 98, 56, 45, 97, 57, 56, 49, 45, 51, 48, 53, 99, 101, 99, 99,
                    53, 99, 98, 97, 54, 46, 99, 101, 114, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13,
                    1, 1, 11, 5, 0, 3, 130, 2, 1, 0, 4, 128, 111, 190, 0, 94, 133, 167, 0, 61, 237,
                    232, 184, 182, 255, 238, 77, 189, 198, 248, 63, 5, 5, 202, 60, 98, 125, 121,
                    175, 177, 82, 252, 85, 154, 80, 32, 167, 198, 224, 128, 251, 145, 5, 32, 101,
                    218, 186, 38, 255, 178, 63, 167, 51, 205, 62, 195, 167, 219, 144, 6, 11, 70,
                    14, 59, 177, 178, 116, 254, 131, 199, 231, 75, 204, 62, 116, 231, 40, 47, 112,
                    138, 24, 194, 154, 46, 30, 25, 149, 75, 139, 119, 164, 65, 187, 215, 24, 139,
                    160, 76, 210, 124, 16, 77, 27, 225, 70, 251, 137, 3, 176, 229, 248, 51, 108,
                    163, 125, 36, 240, 181, 104, 49, 102, 42, 44, 172, 14, 255, 46, 131, 47, 7,
                    180, 126, 84, 104, 151, 134, 42, 81, 159, 58, 126, 37, 224, 145, 122, 27, 111,
                    213, 236, 124, 97, 181, 112, 75, 29, 33, 34, 7, 210, 170, 139, 63, 18, 193, 98,
                    94, 186, 138, 225, 215, 44, 242, 91, 77, 201, 60, 66, 4, 27, 22, 85, 228, 223,
                    59, 42, 242, 163, 164, 219, 75, 174, 91, 118, 115, 29, 216, 53, 37, 124, 161,
                    194, 15, 117, 147, 50, 98, 205, 196, 137, 1, 244, 26, 124, 236, 181, 184, 5,
                    98, 64, 191, 209, 189, 64, 0, 11, 214, 153, 64, 2, 36, 116, 237, 238, 124, 47,
                    47, 182, 246, 20, 105, 12, 168, 188, 192, 215, 26, 228, 86, 69, 212, 42, 69,
                    121, 238, 73, 155, 154, 133, 203, 30, 108, 94, 184, 214, 91, 67, 79, 22, 118,
                    63, 100, 249, 23, 90, 142, 72, 94, 238, 91, 154, 32, 191, 51, 192, 44, 197,
                    212, 173, 119, 159, 156, 71, 96, 239, 37, 68, 73, 247, 102, 88, 203, 172, 113,
                    250, 74, 247, 129, 79, 19, 235, 145, 95, 158, 214, 44, 38, 28, 244, 218, 86,
                    202, 93, 73, 196, 209, 133, 138, 77, 42, 58, 221, 99, 112, 13, 73, 47, 22, 108,
                    162, 144, 47, 36, 208, 114, 146, 87, 77, 24, 78, 66, 148, 86, 91, 169, 104,
                    104, 106, 137, 126, 172, 10, 213, 37, 25, 179, 175, 253, 243, 212, 175, 240,
                    103, 8, 180, 190, 108, 198, 199, 40, 171, 227, 161, 232, 53, 147, 109, 244, 93,
                    113, 237, 64, 179, 160, 78, 35, 34, 8, 136, 179, 185, 176, 219, 4, 198, 38,
                    175, 6, 12, 227, 55, 168, 192, 122, 115, 119, 95, 205, 244, 105, 116, 238, 137,
                    228, 32, 4, 9, 219, 246, 49, 131, 190, 64, 37, 85, 108, 239, 164, 173, 90, 254,
                    146, 255, 252, 188, 232, 40, 184, 108, 69, 153, 81, 182, 17, 174, 194, 52, 246,
                    178, 77, 47, 50, 167, 56, 17, 83, 31, 65, 119, 143, 160, 113, 254, 71, 33, 166,
                    88, 53, 128, 195, 6, 193, 50, 144, 78, 242, 155, 234, 231, 20, 144, 132, 177,
                    159, 161, 94, 154, 205, 133, 78, 20, 214, 141, 230, 33, 115, 192, 148, 87, 151,
                    95, 71, 175, 89, 6, 240, 48, 130, 6, 236, 48, 130, 4, 212, 160, 3, 2, 1, 2, 2,
                    19, 51, 0, 0, 2, 113, 82, 34, 55, 131, 10, 123, 56, 174, 0, 0, 0, 0, 2, 113,
                    48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0, 48, 129, 140, 49, 11,
                    48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83, 49, 19, 48, 17, 6, 3, 85, 4, 8, 19, 10,
                    87, 97, 115, 104, 105, 110, 103, 116, 111, 110, 49, 16, 48, 14, 6, 3, 85, 4, 7,
                    19, 7, 82, 101, 100, 109, 111, 110, 100, 49, 30, 48, 28, 6, 3, 85, 4, 10, 19,
                    21, 77, 105, 99, 114, 111, 115, 111, 102, 116, 32, 67, 111, 114, 112, 111, 114,
                    97, 116, 105, 111, 110, 49, 54, 48, 52, 6, 3, 85, 4, 3, 19, 45, 77, 105, 99,
                    114, 111, 115, 111, 102, 116, 32, 84, 80, 77, 32, 82, 111, 111, 116, 32, 67,
                    101, 114, 116, 105, 102, 105, 99, 97, 116, 101, 32, 65, 117, 116, 104, 111,
                    114, 105, 116, 121, 32, 50, 48, 49, 52, 48, 30, 23, 13, 49, 57, 48, 51, 50, 49,
                    50, 48, 51, 48, 48, 50, 90, 23, 13, 50, 53, 48, 51, 50, 49, 50, 48, 51, 48, 48,
                    50, 90, 48, 66, 49, 64, 48, 62, 6, 3, 85, 4, 3, 19, 55, 78, 67, 85, 45, 73, 78,
                    84, 67, 45, 75, 69, 89, 73, 68, 45, 54, 67, 65, 57, 68, 70, 54, 50, 65, 49, 65,
                    65, 69, 50, 51, 69, 48, 70, 69, 66, 55, 67, 51, 70, 53, 69, 66, 56, 69, 54, 49,
                    69, 67, 65, 67, 49, 55, 67, 66, 55, 48, 130, 2, 34, 48, 13, 6, 9, 42, 134, 72,
                    134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 2, 15, 0, 48, 130, 2, 10, 2, 130, 2, 1, 0,
                    152, 43, 107, 173, 177, 53, 163, 163, 93, 154, 248, 108, 222, 80, 5, 122, 87,
                    236, 252, 225, 50, 52, 121, 17, 29, 232, 18, 63, 7, 156, 177, 34, 151, 214, 92,
                    55, 149, 204, 232, 129, 50, 154, 105, 128, 221, 190, 157, 193, 52, 48, 65, 151,
                    90, 250, 48, 160, 25, 134, 46, 36, 77, 126, 48, 129, 230, 125, 172, 189, 156,
                    247, 147, 31, 239, 20, 230, 78, 4, 146, 123, 54, 173, 175, 211, 248, 18, 125,
                    83, 110, 37, 67, 147, 152, 0, 121, 176, 166, 87, 248, 31, 3, 155, 235, 53, 134,
                    8, 105, 212, 244, 239, 170, 41, 94, 183, 81, 143, 34, 193, 123, 125, 187, 48,
                    149, 59, 99, 240, 15, 38, 108, 172, 200, 222, 70, 62, 98, 80, 163, 32, 19, 26,
                    181, 191, 156, 139, 248, 190, 110, 129, 56, 196, 50, 16, 89, 143, 150, 41, 172,
                    239, 136, 65, 145, 0, 93, 222, 226, 117, 208, 183, 116, 85, 166, 93, 247, 23,
                    39, 167, 130, 47, 73, 113, 26, 102, 197, 100, 212, 176, 34, 143, 98, 105, 5,
                    206, 194, 120, 190, 201, 49, 102, 199, 25, 161, 230, 11, 189, 87, 188, 102,
                    171, 44, 55, 193, 180, 208, 172, 250, 214, 194, 36, 148, 113, 206, 80, 159,
                    124, 135, 247, 246, 51, 10, 194, 204, 232, 44, 33, 64, 183, 63, 209, 225, 72,
                    195, 193, 71, 101, 174, 241, 42, 217, 92, 214, 117, 199, 101, 75, 42, 145, 145,
                    187, 113, 150, 138, 28, 61, 122, 159, 86, 152, 41, 83, 65, 80, 158, 165, 195,
                    96, 255, 135, 34, 90, 161, 69, 173, 74, 198, 147, 96, 85, 40, 100, 128, 191,
                    135, 11, 27, 86, 149, 149, 18, 103, 182, 110, 255, 71, 47, 227, 240, 14, 66,
                    137, 251, 211, 221, 191, 34, 157, 152, 230, 121, 195, 41, 148, 176, 219, 134,
                    62, 178, 181, 89, 7, 166, 111, 81, 85, 222, 85, 218, 96, 48, 120, 135, 99, 119,
                    60, 170, 236, 34, 41, 173, 19, 91, 140, 28, 220, 20, 140, 71, 236, 117, 13,
                    209, 248, 147, 130, 77, 125, 11, 109, 142, 43, 95, 221, 245, 154, 72, 250, 152,
                    36, 107, 77, 175, 133, 247, 233, 77, 225, 123, 53, 217, 16, 39, 218, 44, 7, 97,
                    89, 15, 241, 7, 15, 186, 204, 227, 132, 181, 120, 62, 216, 232, 84, 45, 142,
                    241, 86, 209, 254, 255, 208, 45, 88, 242, 239, 198, 31, 54, 159, 135, 142, 17,
                    52, 142, 58, 126, 81, 118, 231, 23, 209, 48, 11, 80, 194, 124, 248, 205, 80,
                    187, 12, 166, 123, 89, 175, 201, 212, 239, 172, 77, 151, 107, 127, 92, 161, 37,
                    246, 209, 253, 166, 8, 230, 153, 14, 54, 111, 173, 212, 8, 42, 60, 177, 191,
                    97, 130, 28, 51, 178, 40, 129, 46, 179, 24, 45, 26, 25, 59, 61, 94, 4, 145,
                    149, 42, 63, 49, 247, 136, 126, 5, 206, 102, 177, 28, 26, 86, 148, 35, 2, 3, 1,
                    0, 1, 163, 130, 1, 142, 48, 130, 1, 138, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255,
                    4, 4, 3, 2, 2, 132, 48, 27, 6, 3, 85, 29, 37, 4, 20, 48, 18, 6, 9, 43, 6, 1, 4,
                    1, 130, 55, 21, 36, 6, 5, 103, 129, 5, 8, 3, 48, 22, 6, 3, 85, 29, 32, 4, 15,
                    48, 13, 48, 11, 6, 9, 43, 6, 1, 4, 1, 130, 55, 21, 31, 48, 18, 6, 3, 85, 29,
                    19, 1, 1, 255, 4, 8, 48, 6, 1, 1, 255, 2, 1, 0, 48, 29, 6, 3, 85, 29, 14, 4,
                    22, 4, 20, 147, 147, 77, 66, 14, 183, 179, 161, 2, 110, 122, 113, 35, 6, 16,
                    82, 232, 88, 88, 179, 48, 31, 6, 3, 85, 29, 35, 4, 24, 48, 22, 128, 20, 122,
                    140, 10, 206, 47, 72, 98, 23, 226, 148, 209, 174, 85, 193, 82, 236, 113, 116,
                    164, 86, 48, 112, 6, 3, 85, 29, 31, 4, 105, 48, 103, 48, 101, 160, 99, 160, 97,
                    134, 95, 104, 116, 116, 112, 58, 47, 47, 119, 119, 119, 46, 109, 105, 99, 114,
                    111, 115, 111, 102, 116, 46, 99, 111, 109, 47, 112, 107, 105, 111, 112, 115,
                    47, 99, 114, 108, 47, 77, 105, 99, 114, 111, 115, 111, 102, 116, 37, 50, 48,
                    84, 80, 77, 37, 50, 48, 82, 111, 111, 116, 37, 50, 48, 67, 101, 114, 116, 105,
                    102, 105, 99, 97, 116, 101, 37, 50, 48, 65, 117, 116, 104, 111, 114, 105, 116,
                    121, 37, 50, 48, 50, 48, 49, 52, 46, 99, 114, 108, 48, 125, 6, 8, 43, 6, 1, 5,
                    5, 7, 1, 1, 4, 113, 48, 111, 48, 109, 6, 8, 43, 6, 1, 5, 5, 7, 48, 2, 134, 97,
                    104, 116, 116, 112, 58, 47, 47, 119, 119, 119, 46, 109, 105, 99, 114, 111, 115,
                    111, 102, 116, 46, 99, 111, 109, 47, 112, 107, 105, 111, 112, 115, 47, 99, 101,
                    114, 116, 115, 47, 77, 105, 99, 114, 111, 115, 111, 102, 116, 37, 50, 48, 84,
                    80, 77, 37, 50, 48, 82, 111, 111, 116, 37, 50, 48, 67, 101, 114, 116, 105, 102,
                    105, 99, 97, 116, 101, 37, 50, 48, 65, 117, 116, 104, 111, 114, 105, 116, 121,
                    37, 50, 48, 50, 48, 49, 52, 46, 99, 114, 116, 48, 13, 6, 9, 42, 134, 72, 134,
                    247, 13, 1, 1, 11, 5, 0, 3, 130, 2, 1, 0, 73, 235, 166, 7, 16, 89, 131, 50, 67,
                    31, 113, 176, 9, 16, 209, 146, 232, 124, 220, 236, 23, 249, 16, 213, 246, 244,
                    231, 147, 248, 141, 93, 158, 160, 222, 177, 160, 115, 201, 16, 11, 228, 151,
                    21, 209, 62, 191, 38, 153, 95, 178, 20, 202, 150, 24, 170, 85, 100, 155, 108,
                    120, 203, 242, 149, 237, 71, 252, 71, 149, 245, 18, 222, 155, 246, 56, 226,
                    116, 245, 175, 196, 187, 121, 2, 212, 117, 193, 222, 154, 201, 133, 16, 232,
                    171, 149, 255, 214, 198, 212, 197, 65, 34, 27, 55, 16, 54, 91, 251, 95, 52,
                    141, 113, 235, 119, 147, 78, 1, 254, 195, 123, 240, 11, 79, 183, 139, 167, 223,
                    99, 172, 242, 229, 252, 48, 126, 146, 1, 170, 111, 216, 195, 26, 9, 183, 178,
                    32, 197, 94, 57, 33, 1, 165, 51, 121, 63, 4, 53, 36, 195, 106, 69, 23, 244, 74,
                    0, 52, 93, 45, 232, 15, 144, 228, 162, 61, 32, 73, 156, 147, 11, 69, 235, 123,
                    172, 207, 162, 228, 234, 160, 234, 193, 35, 189, 70, 229, 126, 3, 63, 178, 15,
                    224, 235, 103, 203, 74, 37, 37, 146, 94, 43, 123, 179, 63, 216, 150, 144, 199,
                    224, 255, 121, 132, 38, 60, 0, 171, 31, 236, 168, 254, 171, 146, 116, 99, 43,
                    235, 186, 249, 176, 135, 195, 160, 51, 39, 252, 205, 76, 22, 189, 141, 240,
                    196, 2, 116, 193, 211, 79, 70, 63, 14, 37, 53, 170, 224, 243, 135, 251, 85,
                    142, 154, 99, 122, 59, 0, 96, 215, 6, 202, 198, 137, 50, 122, 35, 194, 17, 128,
                    215, 129, 249, 220, 85, 224, 26, 24, 8, 200, 198, 13, 105, 32, 81, 8, 34, 198,
                    33, 222, 79, 161, 60, 167, 105, 246, 195, 242, 5, 126, 69, 23, 54, 78, 166,
                    185, 253, 107, 152, 165, 14, 8, 158, 205, 81, 113, 18, 61, 101, 94, 9, 36, 203,
                    232, 130, 211, 230, 45, 209, 3, 100, 5, 159, 67, 152, 26, 95, 188, 125, 92,
                    141, 251, 62, 72, 40, 203, 116, 89, 14, 141, 8, 120, 232, 19, 235, 85, 35, 101,
                    24, 247, 149, 197, 215, 100, 22, 37, 144, 62, 173, 79, 123, 198, 63, 136, 236,
                    81, 242, 90, 231, 189, 41, 204, 131, 14, 150, 67, 108, 88, 123, 210, 157, 216,
                    251, 32, 193, 91, 82, 3, 107, 199, 180, 155, 243, 12, 23, 77, 162, 231, 227,
                    120, 72, 35, 94, 105, 168, 102, 35, 27, 0, 203, 104, 19, 212, 75, 177, 173, 38,
                    68, 156, 147, 228, 80, 215, 121, 250, 163, 49, 245, 155, 2, 15, 160, 49, 117,
                    74, 100, 43, 119, 37, 26, 23, 96, 188, 144, 155, 211, 185, 166, 123, 250, 211,
                    242, 193, 122, 67, 159, 35, 66, 33, 153, 122, 233, 160, 181, 188, 114, 250, 70,
                    165, 98, 31, 165, 84, 126, 45, 106, 164, 221, 57, 100, 151, 23, 81, 46, 118,
                    251, 43, 100, 201, 204, 121, 103, 112, 117, 98, 65, 114, 101, 97, 89, 1, 54, 0,
                    1, 0, 11, 0, 6, 4, 114, 0, 32, 157, 255, 203, 243, 108, 56, 58, 230, 153, 251,
                    152, 104, 220, 109, 203, 137, 215, 21, 56, 132, 190, 40, 3, 146, 44, 18, 65,
                    88, 191, 173, 34, 174, 0, 16, 0, 16, 8, 0, 0, 0, 0, 0, 1, 0, 220, 20, 243, 114,
                    251, 142, 90, 236, 17, 204, 181, 223, 8, 72, 230, 209, 122, 44, 90, 55, 96,
                    134, 69, 16, 125, 139, 112, 81, 154, 230, 133, 211, 129, 37, 75, 208, 222, 70,
                    210, 239, 209, 188, 152, 93, 222, 222, 154, 169, 217, 160, 90, 243, 135, 151,
                    25, 87, 240, 178, 106, 119, 150, 89, 23, 223, 158, 88, 107, 72, 101, 61, 184,
                    132, 19, 110, 144, 107, 22, 178, 252, 206, 50, 207, 11, 177, 137, 35, 139, 68,
                    212, 148, 121, 249, 50, 35, 89, 52, 47, 26, 23, 6, 15, 115, 155, 127, 59, 168,
                    208, 196, 78, 125, 205, 0, 98, 43, 223, 233, 65, 137, 103, 2, 227, 35, 81, 107,
                    247, 230, 186, 111, 27, 4, 57, 42, 220, 32, 29, 181, 159, 6, 176, 182, 94, 191,
                    222, 212, 235, 60, 101, 83, 86, 217, 203, 151, 251, 254, 219, 204, 195, 10, 74,
                    147, 5, 27, 167, 127, 117, 149, 245, 157, 92, 124, 2, 196, 214, 107, 246, 228,
                    171, 229, 100, 212, 67, 88, 215, 75, 33, 183, 199, 51, 171, 210, 213, 65, 45,
                    96, 96, 226, 29, 130, 254, 58, 92, 252, 133, 207, 105, 63, 156, 208, 149, 142,
                    9, 83, 1, 193, 217, 244, 35, 137, 43, 138, 137, 140, 82, 231, 195, 145, 213,
                    230, 185, 245, 104, 105, 62, 142, 124, 34, 9, 157, 167, 188, 243, 112, 104,
                    248, 63, 50, 19, 53, 173, 69, 12, 39, 252, 9, 69, 223, 104, 99, 101, 114, 116,
                    73, 110, 102, 111, 88, 161, 255, 84, 67, 71, 128, 23, 0, 34, 0, 11, 174, 74,
                    152, 70, 1, 87, 191, 156, 96, 74, 177, 221, 37, 132, 6, 8, 101, 35, 124, 216,
                    85, 173, 85, 195, 115, 137, 194, 247, 145, 61, 82, 40, 0, 20, 234, 98, 144, 49,
                    146, 39, 99, 47, 44, 82, 115, 48, 64, 40, 152, 224, 227, 42, 63, 133, 0, 0, 0,
                    2, 219, 215, 137, 38, 187, 106, 183, 8, 100, 145, 106, 200, 1, 86, 5, 220, 81,
                    118, 234, 131, 141, 0, 34, 0, 11, 239, 53, 112, 255, 253, 12, 189, 168, 16,
                    253, 10, 149, 108, 7, 31, 212, 143, 21, 153, 7, 7, 153, 99, 73, 205, 97, 90,
                    110, 182, 120, 4, 250, 0, 34, 0, 11, 249, 72, 224, 84, 16, 96, 147, 197, 167,
                    195, 110, 181, 77, 207, 147, 16, 34, 64, 139, 185, 120, 190, 196, 209, 213, 29,
                    1, 136, 76, 235, 223, 247, 104, 97, 117, 116, 104, 68, 97, 116, 97, 89, 1, 103,
                    108, 41, 129, 232, 231, 178, 172, 146, 198, 102, 0, 255, 160, 250, 221, 227,
                    137, 40, 196, 142, 208, 221, 115, 246, 47, 198, 69, 45, 165, 107, 42, 27, 69,
                    0, 0, 0, 0, 8, 152, 112, 88, 202, 220, 75, 129, 182, 225, 48, 222, 80, 220,
                    190, 150, 0, 32, 211, 249, 248, 105, 48, 155, 162, 98, 212, 65, 122, 244, 237,
                    206, 196, 107, 226, 116, 136, 219, 221, 98, 101, 180, 109, 65, 174, 55, 175,
                    156, 120, 96, 164, 1, 3, 3, 57, 1, 0, 32, 89, 1, 0, 220, 20, 243, 114, 251,
                    142, 90, 236, 17, 204, 181, 223, 8, 72, 230, 209, 122, 44, 90, 55, 96, 134, 69,
                    16, 125, 139, 112, 81, 154, 230, 133, 211, 129, 37, 75, 208, 222, 70, 210, 239,
                    209, 188, 152, 93, 222, 222, 154, 169, 217, 160, 90, 243, 135, 151, 25, 87,
                    240, 178, 106, 119, 150, 89, 23, 223, 158, 88, 107, 72, 101, 61, 184, 132, 19,
                    110, 144, 107, 22, 178, 252, 206, 50, 207, 11, 177, 137, 35, 139, 68, 212, 148,
                    121, 249, 50, 35, 89, 52, 47, 26, 23, 6, 15, 115, 155, 127, 59, 168, 208, 196,
                    78, 125, 205, 0, 98, 43, 223, 233, 65, 137, 103, 2, 227, 35, 81, 107, 247, 230,
                    186, 111, 27, 4, 57, 42, 220, 32, 29, 181, 159, 6, 176, 182, 94, 191, 222, 212,
                    235, 60, 101, 83, 86, 217, 203, 151, 251, 254, 219, 204, 195, 10, 74, 147, 5,
                    27, 167, 127, 117, 149, 245, 157, 92, 124, 2, 196, 214, 107, 246, 228, 171,
                    229, 100, 212, 67, 88, 215, 75, 33, 183, 199, 51, 171, 210, 213, 65, 45, 96,
                    96, 226, 29, 130, 254, 58, 92, 252, 133, 207, 105, 63, 156, 208, 149, 142, 9,
                    83, 1, 193, 217, 244, 35, 137, 43, 138, 137, 140, 82, 231, 195, 145, 213, 230,
                    185, 245, 104, 105, 62, 142, 124, 34, 9, 157, 167, 188, 243, 112, 104, 248, 63,
                    50, 19, 53, 173, 69, 12, 39, 252, 9, 69, 223, 33, 67, 1, 0, 1,
                ]),
                client_data_json: Base64UrlSafeData(vec![
                    123, 34, 116, 121, 112, 101, 34, 58, 34, 119, 101, 98, 97, 117, 116, 104, 110,
                    46, 99, 114, 101, 97, 116, 101, 34, 44, 34, 99, 104, 97, 108, 108, 101, 110,
                    103, 101, 34, 58, 34, 73, 108, 121, 57, 116, 68, 90, 99, 89, 76, 103, 66, 121,
                    74, 116, 98, 75, 113, 105, 99, 88, 118, 55, 102, 77, 97, 109, 114, 115, 119,
                    74, 72, 87, 110, 117, 48, 57, 67, 87, 50, 69, 84, 81, 34, 44, 34, 111, 114,
                    105, 103, 105, 110, 34, 58, 34, 104, 116, 116, 112, 115, 58, 47, 47, 101, 116,
                    111, 111, 108, 115, 45, 100, 101, 118, 46, 101, 120, 97, 109, 112, 108, 101,
                    46, 99, 111, 109, 58, 56, 48, 56, 48, 34, 44, 34, 99, 114, 111, 115, 115, 79,
                    114, 105, 103, 105, 110, 34, 58, 102, 97, 108, 115, 101, 125,
                ]),
            },
            type_: "public-key".to_string(),
        };

        let result =
            wan.register_credential_internal(&rsp_d, UserVerificationPolicy::Required, &chal, &[]);
        println!("{:?}", result);
        assert!(result.is_ok());
    }

    fn register_userid(
        user_name: &str,
    ) -> Result<(CreationChallengeResponse, RegistrationState), WebauthnError> {
        let wan_c = WebauthnEphemeralConfig::new(
            "https://etools-dev.example.com:8080/auth",
            "https://etools-dev.example.com:8080",
            "etools-dev.example.com",
            None,
        );
        let wan = Webauthn::new(wan_c);

        let policy = Some(UserVerificationPolicy::Required);

        wan.generate_challenge_register(user_name, policy)
    }

    #[test]
    fn test_registration_empty_userid() {
        let result = register_userid("");
        assert!(matches!(result, Err(WebauthnError::InvalidUsername)));
    }

    #[test]
    fn test_registration_nonempty_userid() {
        let result = register_userid("fizzbuzz");
        assert!(result.is_ok());
    }

    #[test]
    fn test_touchid_attest_apple_anonymous() {
        let wan_c = WebauthnEphemeralConfig::new(
            "https://spectral.local:8443/auth",
            "https://spectral.local:8443",
            "spectral.local",
            None,
        );

        let chal = Challenge::new(vec![
            37, 54, 228, 239, 39, 164, 32, 163, 153, 67, 12, 29, 25, 110, 205, 120, 50, 31, 198,
            182, 10, 208, 251, 238, 99, 27, 46, 123, 239, 134, 244, 210,
        ]);

        let rsp_d = RegisterPublicKeyCredential {
            id: "u_tliFf-aXRLg9XIz-SuQ0XBlbE".to_string(),
            raw_id: Base64UrlSafeData(vec![
                187, 251, 101, 136, 87, 254, 105, 116, 75, 131, 213, 200, 207, 228, 174, 67, 69,
                193, 149, 177,
            ]),
            response: AuthenticatorAttestationResponseRaw {
                attestation_object: Base64UrlSafeData(vec![
                    163, 99, 102, 109, 116, 101, 97, 112, 112, 108, 101, 103, 97, 116, 116, 83,
                    116, 109, 116, 162, 99, 97, 108, 103, 38, 99, 120, 53, 99, 130, 89, 2, 71, 48,
                    130, 2, 67, 48, 130, 1, 201, 160, 3, 2, 1, 2, 2, 6, 1, 118, 69, 82, 254, 167,
                    48, 10, 6, 8, 42, 134, 72, 206, 61, 4, 3, 2, 48, 72, 49, 28, 48, 26, 6, 3, 85,
                    4, 3, 12, 19, 65, 112, 112, 108, 101, 32, 87, 101, 98, 65, 117, 116, 104, 110,
                    32, 67, 65, 32, 49, 49, 19, 48, 17, 6, 3, 85, 4, 10, 12, 10, 65, 112, 112, 108,
                    101, 32, 73, 110, 99, 46, 49, 19, 48, 17, 6, 3, 85, 4, 8, 12, 10, 67, 97, 108,
                    105, 102, 111, 114, 110, 105, 97, 48, 30, 23, 13, 50, 48, 49, 50, 48, 56, 48,
                    50, 50, 55, 49, 53, 90, 23, 13, 50, 48, 49, 50, 49, 49, 48, 50, 50, 55, 49, 53,
                    90, 48, 129, 145, 49, 73, 48, 71, 6, 3, 85, 4, 3, 12, 64, 57, 97, 97, 57, 48,
                    99, 55, 99, 57, 51, 54, 97, 52, 101, 49, 98, 98, 56, 54, 56, 57, 54, 53, 102,
                    49, 52, 55, 97, 52, 51, 57, 57, 102, 49, 52, 48, 99, 102, 52, 48, 57, 98, 52,
                    51, 52, 102, 57, 48, 53, 57, 98, 50, 100, 52, 102, 53, 97, 51, 99, 102, 99, 48,
                    57, 50, 49, 26, 48, 24, 6, 3, 85, 4, 11, 12, 17, 65, 65, 65, 32, 67, 101, 114,
                    116, 105, 102, 105, 99, 97, 116, 105, 111, 110, 49, 19, 48, 17, 6, 3, 85, 4,
                    10, 12, 10, 65, 112, 112, 108, 101, 32, 73, 110, 99, 46, 49, 19, 48, 17, 6, 3,
                    85, 4, 8, 12, 10, 67, 97, 108, 105, 102, 111, 114, 110, 105, 97, 48, 89, 48,
                    19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61, 3, 1, 7, 3,
                    66, 0, 4, 212, 248, 99, 135, 245, 78, 94, 245, 231, 22, 62, 226, 45, 40, 215,
                    4, 251, 188, 180, 125, 22, 236, 133, 161, 234, 78, 251, 105, 11, 119, 148, 144,
                    105, 249, 199, 167, 152, 173, 94, 147, 57, 2, 250, 21, 5, 51, 116, 174, 217,
                    39, 160, 35, 12, 249, 120, 237, 52, 148, 171, 134, 138, 205, 26, 173, 163, 85,
                    48, 83, 48, 12, 6, 3, 85, 29, 19, 1, 1, 255, 4, 2, 48, 0, 48, 14, 6, 3, 85, 29,
                    15, 1, 1, 255, 4, 4, 3, 2, 4, 240, 48, 51, 6, 9, 42, 134, 72, 134, 247, 99,
                    100, 8, 2, 4, 38, 48, 36, 161, 34, 4, 32, 168, 226, 160, 197, 61, 146, 15, 234,
                    100, 124, 22, 29, 34, 18, 171, 91, 253, 122, 81, 241, 182, 105, 240, 209, 130,
                    176, 179, 61, 84, 183, 78, 190, 48, 10, 6, 8, 42, 134, 72, 206, 61, 4, 3, 2, 3,
                    104, 0, 48, 101, 2, 48, 14, 242, 134, 73, 12, 48, 2, 103, 184, 132, 187, 132,
                    124, 204, 63, 148, 168, 78, 225, 227, 161, 240, 147, 187, 90, 216, 65, 159, 90,
                    106, 102, 249, 56, 156, 201, 214, 182, 15, 173, 187, 167, 243, 127, 234, 138,
                    41, 50, 62, 2, 49, 0, 198, 15, 10, 182, 142, 103, 84, 7, 18, 0, 231, 130, 214,
                    26, 64, 58, 17, 118, 66, 14, 198, 244, 58, 211, 2, 97, 236, 163, 116, 124, 73,
                    166, 69, 69, 112, 107, 228, 83, 104, 91, 205, 20, 203, 250, 126, 29, 190, 42,
                    89, 2, 56, 48, 130, 2, 52, 48, 130, 1, 186, 160, 3, 2, 1, 2, 2, 16, 86, 37, 83,
                    149, 199, 167, 251, 64, 235, 226, 40, 216, 38, 8, 83, 182, 48, 10, 6, 8, 42,
                    134, 72, 206, 61, 4, 3, 3, 48, 75, 49, 31, 48, 29, 6, 3, 85, 4, 3, 12, 22, 65,
                    112, 112, 108, 101, 32, 87, 101, 98, 65, 117, 116, 104, 110, 32, 82, 111, 111,
                    116, 32, 67, 65, 49, 19, 48, 17, 6, 3, 85, 4, 10, 12, 10, 65, 112, 112, 108,
                    101, 32, 73, 110, 99, 46, 49, 19, 48, 17, 6, 3, 85, 4, 8, 12, 10, 67, 97, 108,
                    105, 102, 111, 114, 110, 105, 97, 48, 30, 23, 13, 50, 48, 48, 51, 49, 56, 49,
                    56, 51, 56, 48, 49, 90, 23, 13, 51, 48, 48, 51, 49, 51, 48, 48, 48, 48, 48, 48,
                    90, 48, 72, 49, 28, 48, 26, 6, 3, 85, 4, 3, 12, 19, 65, 112, 112, 108, 101, 32,
                    87, 101, 98, 65, 117, 116, 104, 110, 32, 67, 65, 32, 49, 49, 19, 48, 17, 6, 3,
                    85, 4, 10, 12, 10, 65, 112, 112, 108, 101, 32, 73, 110, 99, 46, 49, 19, 48, 17,
                    6, 3, 85, 4, 8, 12, 10, 67, 97, 108, 105, 102, 111, 114, 110, 105, 97, 48, 118,
                    48, 16, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 5, 43, 129, 4, 0, 34, 3, 98, 0, 4,
                    131, 46, 135, 47, 38, 20, 145, 129, 2, 37, 185, 245, 252, 214, 187, 99, 120,
                    181, 245, 95, 63, 203, 4, 91, 199, 53, 153, 52, 117, 253, 84, 144, 68, 223,
                    155, 254, 25, 33, 23, 101, 198, 154, 29, 218, 5, 11, 56, 212, 80, 131, 64, 26,
                    67, 79, 178, 77, 17, 45, 86, 195, 225, 207, 191, 203, 152, 145, 254, 192, 105,
                    96, 129, 190, 249, 108, 188, 119, 200, 141, 221, 175, 70, 165, 174, 225, 221,
                    81, 91, 90, 250, 171, 147, 190, 156, 11, 38, 145, 163, 102, 48, 100, 48, 18, 6,
                    3, 85, 29, 19, 1, 1, 255, 4, 8, 48, 6, 1, 1, 255, 2, 1, 0, 48, 31, 6, 3, 85,
                    29, 35, 4, 24, 48, 22, 128, 20, 38, 215, 100, 217, 197, 120, 194, 90, 103, 209,
                    167, 222, 107, 18, 208, 27, 99, 241, 198, 215, 48, 29, 6, 3, 85, 29, 14, 4, 22,
                    4, 20, 235, 174, 130, 196, 255, 161, 172, 91, 81, 212, 207, 36, 97, 5, 0, 190,
                    99, 189, 119, 136, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 1, 6, 48,
                    10, 6, 8, 42, 134, 72, 206, 61, 4, 3, 3, 3, 104, 0, 48, 101, 2, 49, 0, 221,
                    139, 26, 52, 129, 165, 250, 217, 219, 180, 231, 101, 123, 132, 30, 20, 76, 39,
                    183, 91, 135, 106, 65, 134, 194, 177, 71, 87, 80, 51, 114, 39, 239, 229, 84,
                    69, 126, 246, 72, 149, 12, 99, 46, 92, 72, 62, 112, 193, 2, 48, 44, 138, 96,
                    68, 220, 32, 31, 207, 229, 155, 195, 77, 41, 48, 193, 72, 120, 81, 217, 96,
                    237, 106, 117, 241, 235, 74, 202, 190, 56, 205, 37, 184, 151, 208, 200, 5, 190,
                    240, 199, 247, 139, 7, 165, 113, 198, 232, 14, 7, 104, 97, 117, 116, 104, 68,
                    97, 116, 97, 88, 152, 218, 20, 177, 242, 169, 30, 45, 223, 21, 45, 254, 74, 34,
                    125, 188, 96, 11, 1, 71, 41, 58, 94, 252, 180, 169, 243, 209, 21, 231, 138,
                    182, 91, 69, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20,
                    187, 251, 101, 136, 87, 254, 105, 116, 75, 131, 213, 200, 207, 228, 174, 67,
                    69, 193, 149, 177, 165, 1, 2, 3, 38, 32, 1, 33, 88, 32, 212, 248, 99, 135, 245,
                    78, 94, 245, 231, 22, 62, 226, 45, 40, 215, 4, 251, 188, 180, 125, 22, 236,
                    133, 161, 234, 78, 251, 105, 11, 119, 148, 144, 34, 88, 32, 105, 249, 199, 167,
                    152, 173, 94, 147, 57, 2, 250, 21, 5, 51, 116, 174, 217, 39, 160, 35, 12, 249,
                    120, 237, 52, 148, 171, 134, 138, 205, 26, 173,
                ]),
                client_data_json: Base64UrlSafeData(vec![
                    123, 34, 116, 121, 112, 101, 34, 58, 34, 119, 101, 98, 97, 117, 116, 104, 110,
                    46, 99, 114, 101, 97, 116, 101, 34, 44, 34, 99, 104, 97, 108, 108, 101, 110,
                    103, 101, 34, 58, 34, 74, 84, 98, 107, 55, 121, 101, 107, 73, 75, 79, 90, 81,
                    119, 119, 100, 71, 87, 55, 78, 101, 68, 73, 102, 120, 114, 89, 75, 48, 80, 118,
                    117, 89, 120, 115, 117, 101, 45, 45, 71, 57, 78, 73, 34, 44, 34, 111, 114, 105,
                    103, 105, 110, 34, 58, 34, 104, 116, 116, 112, 115, 58, 47, 47, 115, 112, 101,
                    99, 116, 114, 97, 108, 46, 108, 111, 99, 97, 108, 58, 56, 52, 52, 51, 34, 125,
                ]),
            },
            type_: "public-key".to_string(),
        };

        test_credential_registration(wan_c, chal, &rsp_d);
    }
}

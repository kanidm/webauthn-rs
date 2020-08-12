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

extern crate base64;
extern crate lru;
#[macro_use]
extern crate serde_derive;
// extern crate byteorder;
extern crate openssl;
#[macro_use]
extern crate nom;

pub mod attestation;
mod base64_data;
mod constants;
pub mod crypto;
pub mod ephemeral;
pub mod error;
pub mod proto;

use rand::prelude::*;
use std::convert::TryFrom;

use crate::attestation::{
    verify_fidou2f_attestation, verify_none_attestation, verify_packed_attestation,
    AttestationFormat, AttestationType,
};
use crate::base64_data::Base64UrlSafeData;
use crate::constants::{AUTHENTICATOR_TIMEOUT, CHALLENGE_SIZE_BYTES};
use crate::crypto::{compute_sha256, COSEContentType};
use crate::error::WebauthnError;
use crate::proto::{
    AllowCredentials, AttestationConveyancePreference, AuthenticatorAssertionResponse,
    AuthenticatorAttachment, AuthenticatorAttestationResponse, AuthenticatorSelectionCriteria,
    Challenge, Counter, CreationChallengeResponse, Credential, CredentialID, JSONExtensions,
    PubKeyCredParams, PublicKeyCredential, PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor, RegisterPublicKeyCredential, RelyingParty,
    RequestChallengeResponse, User, UserId, UserVerificationPolicy,
};

/// The in progress state of a credential registration attempt. You must persist this associated
/// to the UserID requesting the registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationState {
    policy: UserVerificationPolicy,
    challenge: Base64UrlSafeData,
}

/// The in progress state of an authentication attempt. You must persist this associated to the UserID
/// requesting the registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationState {
    // Allowed credentials?
    // username: UserId,
    credentials: Vec<Credential>,
    policy: UserVerificationPolicy,
    challenge: Base64UrlSafeData,
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
/// browser, and the register and authenticate will recieve Json that is processed and verified.
///
/// These functions return state that you must store and handle correctly for the authentication
/// or registration to proceed correctly.
///
/// As a result, it's very important you read the function descriptions to understand the process
/// as much as possible.
#[derive(Debug)]
pub struct Webauthn<T> {
    rng: ThreadRng,
    config: T,
    pkcp: Vec<PubKeyCredParams>,
    rp_id_hash: Vec<u8>,
}

impl<T> Webauthn<T> {
    /// Create a new Webauthn instance with the supplied configuration. The config type
    /// will recieve and interact with various callbacks to allow the lifecycle and
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
            rng: rand::thread_rng(),
            config: config,
            pkcp: pkcp,
            rp_id_hash: rp_id_hash,
        }
    }

    fn generate_challenge(&mut self) -> Challenge {
        Challenge(self.rng.gen::<[u8; CHALLENGE_SIZE_BYTES]>().to_vec())
    }

    /// Generate a new challenge for client registration.
    /// Same as `generate_challenge_register_options` but default options
    pub fn generate_challenge_register(
        &mut self,
        user_name: &String,
        policy: Option<UserVerificationPolicy>,
    ) -> Result<(CreationChallengeResponse, RegistrationState), WebauthnError>
    where
        T: WebauthnConfig,
    {
        self.generate_challenge_register_options(
            user_name.as_bytes().to_vec(),
            user_name.clone(),
            user_name.clone(),
            None,
            policy,
        )
    }

    /// Generate a new challenge for client registration. This is the first step in
    /// the lifecycle of a credential. This function will return the
    /// CreationChallengeResponse which is suitable for Serde JSON serialisation
    /// to be sent to the client.
    /// The client (generally a webbrowser) will pass this JSON
    /// structure to the `navigator.credentials.create()` javascript function for registration.
    ///
    /// It also returns a RegistratationState, that you *must*
    /// persist. It is strongly advised you associate this RegistrationState with the
    /// UserId of the requestor.
    ///
    /// At this time we deviate from the standard and base64 some fields, but we are
    /// investigating how to avoid this (https://github.com/Firstyear/webauthn-rs/issues/5)
    pub fn generate_challenge_register_options(
        &mut self,
        user_id: UserId,
        user_name: String,
        user_display_name: String,
        exclude_credentials: Option<Vec<CredentialID>>,
        policy: Option<UserVerificationPolicy>,
    ) -> Result<(CreationChallengeResponse, RegistrationState), WebauthnError>
    where
        T: WebauthnConfig,
    {
        let policy = policy.unwrap_or(UserVerificationPolicy::Preferred);
        let challenge = self.generate_challenge();
        let c = CreationChallengeResponse {
            public_key: PublicKeyCredentialCreationOptions {
                rp: RelyingParty {
                    name: self.config.get_relying_party_name(),
                    id: self.config.get_relying_party_id(),
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
                exclude_credentials: exclude_credentials.map(|creds| {
                    creds
                        .into_iter()
                        .map(PublicKeyCredentialDescriptor::from_bytes)
                        .collect()
                }),
                authenticator_selection: Some(AuthenticatorSelectionCriteria {
                    authenticator_attachment: self.config.get_authenticator_attachment(),
                    require_resident_key: self.config.get_require_resident_key(),
                    user_verification: policy.clone(),
                }),
                extensions: None,
            },
        };

        let wr = RegistrationState {
            policy,
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
    ///
    /// At this time we deviate from the standard and base64 some fields, but we are
    /// investigating how to avoid this (https://github.com/Firstyear/webauthn-rs/issues/5)
    pub fn register_credential(
        &self,
        reg: RegisterPublicKeyCredential,
        state: RegistrationState,
        does_exist_fn: impl Fn(&CredentialID) -> Result<bool, ()>,
    ) -> Result<Credential, WebauthnError>
    where
        T: WebauthnConfig,
    {
        // From the rfc https://w3c.github.io/webauthn/#registering-a-new-credential
        // get the challenge (it's username associated)
        // Policy should also come from the chal

        let RegistrationState { policy, challenge } = state;

        // TODO: check the req username matches? I think it's not possible, the caller needs to
        // create the linkage between the username and the state.

        // send to register_credential_internal
        let credential = self.register_credential_internal(reg, policy, challenge.into())?;

        // Check that the credentialId is not yet registered to any other user. If registration is
        // requested for a credential that is already registered to a different user, the Relying
        // Party SHOULD fail this registration ceremony, or it MAY decide to accept the registration,
        // e.g. while deleting the older registration.

        let cred_exist_result = does_exist_fn(&credential.cred_id)
            .map_err(|_| WebauthnError::CredentialExistCheckError)?;

        if cred_exist_result {
            return Err(WebauthnError::CredentialAlreadyExists);
        }

        Ok(credential)
    }

    pub(crate) fn register_credential_internal(
        &self,
        reg: RegisterPublicKeyCredential,
        policy: UserVerificationPolicy,
        chal: Challenge,
    ) -> Result<Credential, WebauthnError>
    where
        T: WebauthnConfig,
    {
        // println!("reg: {:?}", reg);

        // Let JSONtext be the result of running UTF-8 decode on the value of response.clientDataJSON.
        //  ^-- this is done in the actix extractors.

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
        if data.client_data_json.challenge.0 != chal.0 {
            return Err(WebauthnError::MismatchedChallenge);
        }

        // Verify that the value of C.origin matches the Relying Party's origin.
        if &data.client_data_json.origin != self.config.get_origin() {
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
            UserVerificationPolicy::Preferred => {}
            UserVerificationPolicy::Discouraged => {
                if data.attestation_object.auth_data.user_verified {
                    return Err(WebauthnError::UserVerifiedWhenDiscouraged);
                }
            }
        };

        // Verify that the values of the client extension outputs in clientExtensionResults and the
        // authenticator extension outputs in the extensions in authData are as expected,
        // considering the client extension input values that were given as the extensions option in
        // the create() call. In particular, any extension identifier values in the
        // clientExtensionResults and the extensions in authData MUST be also be present as
        // extension identifier values in the extensions member of options, i.e., no extensions are
        // present that were not requested. In the general case, the meaning of "are as expected" is
        // specific to the Relying Party and which extensions are in use.

        // TODO: Today we send NO EXTENSIONS, so we'll never have a case where the extensions
        // are present! But because extensions are possible from the config we WILL need to manage
        // this situation eventually!!!
        match &data.attestation_object.auth_data.extensions {
            Some(_ex) => {
                // We don't know how to handle client extensions yet!!!
                return Err(WebauthnError::InvalidExtensions);
            }
            None => {}
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

        let acd = &data
            .attestation_object
            .auth_data
            .acd
            .ok_or(WebauthnError::MissingAttestationCredentialData)?;

        // Now, match based on the attest_format
        // This returns an AttestationType, containing all the metadata needed for
        // step 15.

        log::debug!("attestation is: {:?}", &attest_format);

        let attest_result = match attest_format {
            AttestationFormat::FIDOU2F => verify_fidou2f_attestation(
                &data.attestation_object.att_stmt,
                acd,
                &client_data_json_hash,
                &data.attestation_object.auth_data.rp_id_hash,
                data.attestation_object.auth_data.counter,
            ),
            AttestationFormat::Packed => verify_packed_attestation(
                &data.attestation_object.att_stmt,
                acd,
                data.attestation_object.auth_data_bytes,
                &client_data_json_hash,
                data.attestation_object.auth_data.counter,
            ),
            AttestationFormat::None => verify_none_attestation(
                // &data.attestation_object.att_stmt,
                acd,
                data.attestation_object.auth_data.counter,
            ),
            _ => {
                // No other types are currently implemented
                Err(WebauthnError::AttestationNotSupported)
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

        //  If the attestation statement attStmt verified successfully and is found to be trustworthy,
        // then register the new credential with the account that was denoted in the options.user
        // passed to create(), by associating it with the credentialId and credentialPublicKey in
        // the attestedCredentialData in authData, as appropriate for the Relying Party's system.

        // Already returned above if trust failed.

        // So we return the credential here, and the caller persists it.
        // We turn this into a "helper" and serialisable credential structure that
        // people can use a bit nicer.
        Ok(credential)
    }

    // https://w3c.github.io/webauthn/#verifying-assertion
    pub(crate) fn verify_credential_internal(
        &self,
        rsp: PublicKeyCredential,
        policy: UserVerificationPolicy,
        chal: Challenge,
        cred: &Credential,
    ) -> Result<u32, WebauthnError>
    where
        T: WebauthnConfig,
    {
        // Let cData, authData and sig denote the value of credential’s response's clientDataJSON,
        // authenticatorData, and signature respectively.
        // Let JSONtext be the result of running UTF-8 decode on the value of cData.
        let data = AuthenticatorAssertionResponse::try_from(&rsp.response)?;

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
        if c.challenge.0 != chal.0 {
            return Err(WebauthnError::MismatchedChallenge);
        }

        // Verify that the value of C.origin matches the Relying Party's origin.
        if &c.origin != self.config.get_origin() {
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
            UserVerificationPolicy::Preferred => {}
            UserVerificationPolicy::Discouraged => {
                if data.authenticator_data.user_verified {
                    return Err(WebauthnError::UserVerifiedWhenDiscouraged);
                }
            }
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
            Some(_ex) => {
                // pass
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
            .map(|b| *b)
            .collect();

        let verified = cred
            .cred
            .verify_signature(&data.signature, &verification_data)?;

        if !verified {
            return Err(WebauthnError::AuthenticationFailure);
        }

        Ok(data.authenticator_data.counter)
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
    /// At this time we deviate from the standard and base64 some fields, but we are
    /// investigating how to avoid this (https://github.com/Firstyear/webauthn-rs/issues/5)
    pub fn generate_challenge_authenticate(
        &mut self,
        creds: Vec<Credential>,
        policy: Option<UserVerificationPolicy>,
    ) -> Result<(RequestChallengeResponse, AuthenticationState), WebauthnError>
    where
        T: WebauthnConfig,
    {
        let chal = self.generate_challenge();

        let policy = policy.unwrap_or(UserVerificationPolicy::Preferred);

        // Get the user's existing creds if any.
        let ac = creds
            .iter()
            .map(|cred| AllowCredentials {
                type_: "public-key".to_string(),
                id: base64::encode(cred.cred_id.as_slice()),
                transports: None,
            })
            .collect();

        // Store the chal associated to the user.
        // Now put that into the correct challenge format
        let r = RequestChallengeResponse::new(
            chal.clone(),
            self.config.get_authenticator_timeout(),
            self.config.get_relying_party_id(),
            ac,
            policy.clone(),
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
    /// This requireds the associated AuthenticationState that was created by
    /// generate_challenge_authenticate
    ///
    /// On successful authentication, an Ok result is returned. The Ok may contain the credentialid
    /// and associated counter, which you *should* update for security purposes. If the Ok returns
    /// `None` then the credential does not have a counter.
    ///
    /// At this time we deviate from the standard and base64 some fields, but we are
    /// investigating how to avoid this (https://github.com/Firstyear/webauthn-rs/issues/5)
    pub fn authenticate_credential(
        &mut self,
        rsp: PublicKeyCredential,
        state: AuthenticationState,
    ) -> Result<Option<(CredentialID, Counter)>, WebauthnError>
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
            // TODO: support webauthn in user-less mode -- i.e. the authenticator tells us the userhandle
            // TODO: and we must see if this userhandle is allowed entry

            // Using credential’s id attribute (or the corresponding rawId, if base64url encoding is
            // inappropriate for your use case), look up the corresponding credential public key.
            let mut found_cred: Option<Credential> = None;
            for cred in creds {
                if cred.cred_id == rsp.raw_id.0 {
                    found_cred = Some(cred);
                    break;
                }
            }

            found_cred.ok_or(WebauthnError::CredentialNotFound)?
        };

        let counter = self.verify_credential_internal(rsp, policy, chal.into(), &cred)?;

        // If the signature counter value authData.signCount is nonzero or the value stored in
        // conjunction with credential’s id attribute is nonzero, then run the following sub-step:
        if counter > 0 {
            // If the signature counter value authData.signCount is
            if counter > cred.counter {
                // greater than the signature counter value stored in conjunction with credential’s id attribute.
                //       Update the stored signature counter value, associated with credential’s id attribute,
                //       to be the value of authData.signCount.
                Ok(Some((cred.cred_id.clone(), counter)))
            // If all the above steps are successful, continue with the authentication ceremony as
            // appropriate. Otherwise, fail the authentication ceremony.
            } else {
                // less than or equal to the signature counter value stored in conjunction with credential’s id attribute.
                //      This is a signal that the authenticator may be cloned, i.e. at least two copies
                //      of the credential private key may exist and are being used in parallel. Relying
                //      Parties should incorporate this information into their risk scoring. Whether the
                //      Relying Party updates the stored signature counter value in this case, or not,
                //      or fails the authentication ceremony or not, is Relying Party-specific.
                Err(WebauthnError::CredentialPossibleCompromise)
            }
        } else {
            // If all the above steps are successful, continue with the authentication ceremony as
            // appropriate. Otherwise, fail the authentication ceremony.
            Ok(None)
        }
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
    fn get_relying_party_name(&self) -> String;

    /// Returns a reference to your sites origin. The origin is the URL to your site with
    /// protocol and port. This should rarely, if ever change. In production usage this
    /// value must always be https://, however http://localhost is acceptable for testing
    /// only. We may add warnings or errors for non-https:// urls in the future. Changing this
    /// may cause associated authenticators to lose credentials.
    ///
    /// Examples of this value could be. "https://my-site.com.au", "https://my-site.com.au:8443"
    fn get_origin(&self) -> &String;

    /// Returns the relying party id. This should never change, and is used as an id
    /// in cryptographic operations and credential scoping. This is defined as the domain name
    /// of the service, minuse all protocol, port and location data. For example:
    ///   `https://name:port/path -> name`
    ///
    /// If changed, all associated credentials will be lost in all authenticators.
    ///
    /// Examples of this value for the site "https://my-site.com.au/auth" is "my-site.com.au"
    fn get_relying_party_id(&self) -> String;

    /// Get the list of valid credential algorthims that this servie will accept. Unless you have
    /// speific requirements around this, we advise you leave this function to the default
    /// implementation.
    fn get_credential_algorithms(&self) -> Vec<COSEContentType> {
        vec![COSEContentType::ECDSA_SHA256]
    }

    /// Return a timeout on how long the authenticator has to respond to a challenge. This value
    /// defaults to 6000 milliseconds. You likely won't need to implement this function, and should
    /// rely on the defaults.
    fn get_authenticator_timeout(&self) -> u32 {
        AUTHENTICATOR_TIMEOUT
    }

    /// Returns the default attestation type. Options are `None`, `Direct` and `Indirect`.
    /// Defaults to `None`
    fn get_attestation_preference(&self) -> AttestationConveyancePreference {
        AttestationConveyancePreference::None
    }

    /// Get the preferred policy on authenticator attachement. Defaults to None (allowing
    /// any attachment method).
    ///
    /// NOTE: This is not enforced, as the client may modify the registration request to
    /// disregard this, and no part of the registration response indicates attachement. This
    /// is purely a hint, and is NOT a security enforcment.
    ///
    /// Default of None allows any attachment method.
    fn get_authenticator_attachment(&self) -> Option<AuthenticatorAttachment> {
        None
    }

    /// Get the site policy on if the registration should use a resident key so that
    /// username and other details can be embedded into the authenticator
    /// to allow bypassing that part of the workflow.
    ///
    /// NOTE: This is not enforced as the client may modify the registration request
    /// to disregard this, and no part of the registration process indicates residence of
    /// the credentials. This is not a security enforcement.
    ///
    /// Defaults to "false" aka non-resident keys.
    /// See also: https://www.w3.org/TR/webauthn/#resident-credential
    fn get_require_resident_key(&self) -> bool {
        false
    }

    /// Return a list of site-requested extensions to be sent to Authenticators during
    /// registration and authentication. Currently this is not implemented. Please see:
    /// https://github.com/Firstyear/webauthn-rs/issues/8
    /// https://w3c.github.io/webauthn/#extensions
    fn get_extensions(&self) -> Option<JSONExtensions> {
        None
    }

    /// A callback to allow trust decisions to be made over the attestation of the
    /// credential. It's important for your implementation of this callback to follow
    /// the advice of the w3c standard, notably:
    ///
    /// 15. If validation is successful, obtain a list of acceptable trust anchors (attestation
    /// root certificates or ECDAA-Issuer public keys) for that attestation type and attestation
    /// statement format fmt, from a trusted source or from policy. For example, the FIDO Metadata
    /// Service [FIDOMetadataService] provides one way to obtain such information, using the
    /// aaguid in the attestedCredentialData in authData.
    ///
    /// 16: Assess the attestation trustworthiness using the outputs of the verification procedure
    /// in step 14, as follows: (SEE RFC)
    /// If the attestation statement attStmt successfully verified but is not trustworthy per step
    /// 16 above, the Relying Party SHOULD fail the registration ceremony.
    ///
    /// The default implementation of this method rejects None and Uncertain attestation, and
    /// will "blindly trust" self attestation and the other types as valid.
    /// If you have strict security requirements we strongly recommend you implement this function,
    /// and we may in the future provide a stronger default relying party policy.
    fn policy_verify_trust(&self, at: AttestationType) -> Result<Credential, ()> {
        match at {
            AttestationType::Basic(credential, _ca) => Ok(credential),
            AttestationType::Self_(credential) => Ok(credential),
            AttestationType::None(credential) => Ok(credential),
            _ => {
                // We don't know how to assert trust in this yet, or we just
                // don't trust it at all (Uncertain, None).
                Err(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::base64_data::Base64UrlSafeData;
    use crate::constants::CHALLENGE_SIZE_BYTES;
    use crate::crypto::{COSEContentType, COSEEC2Key, COSEKey, COSEKeyType, ECDSACurve};
    use crate::ephemeral::WebauthnEphemeralConfig;
    use crate::proto::{
        AuthenticatorAttestationResponseRaw, Challenge, Credential, PublicKeyCredential,
        RegisterPublicKeyCredential, UserVerificationPolicy,
    };
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
        );
        let wan = Webauthn::new(wan_c);
        // Generated by a yubico 5
        // Make a "fake" challenge, where we know what the values should be ....

        let zero_chal = Challenge((0..CHALLENGE_SIZE_BYTES).map(|_| 0).collect::<Vec<u8>>());

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
        let result =
            wan.register_credential_internal(rsp_d, UserVerificationPolicy::Preferred, zero_chal);
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
        );
        let wan = Webauthn::new(wan_c);

        let chal =
            Challenge(base64::decode("+Ri5NZTzJ8b6mvW3TVScLotEoALfgBa2Bn4YSaIObHc").unwrap());

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
        let result =
            wan.register_credential_internal(rsp_d, UserVerificationPolicy::Preferred, chal);
        println!("{:?}", result);
        assert!(result.is_ok());
    }

    #[test]
    fn test_registration_packed_attestation() {
        let wan_c = WebauthnEphemeralConfig::new(
            "localhost:8443/auth",
            "https://localhost:8443",
            "localhost",
        );
        let wan = Webauthn::new(wan_c);

        let chal =
            Challenge(base64::decode("lP6mWNAtG+/Vv15iM7lb/XRkdWMvVQ+lTyKwZuOg1Vo=").unwrap());

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
        let result =
            wan.register_credential_internal(rsp_d, UserVerificationPolicy::Preferred, chal);
        assert!(result.is_ok());
    }

    #[test]
    fn test_authentication() {
        let wan_c = WebauthnEphemeralConfig::new(
            "http://localhost:8080/auth",
            "http://localhost:8080",
            "localhost",
        );

        // Generated by a yubico 5
        // Make a "fake" challenge, where we know what the values should be ....

        let zero_chal = Challenge(vec![
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
            rsp_d,
            UserVerificationPolicy::Preferred,
            zero_chal,
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
        );
        let wan = Webauthn::new(wan_c);

        let chal =
            Challenge(base64::decode("tvR1m+d/ohXrwVxQjMgH8KnovHZ7BRWhZmDN4TVMpNU=").unwrap());

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

        let result =
            wan.register_credential_internal(rsp_d, UserVerificationPolicy::Preferred, chal);
        println!("{:?}", result);
        assert!(result.is_ok());
    }
}

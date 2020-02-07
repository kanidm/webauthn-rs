//! Webauthn-rs - Webauthn for Rust Server Applications
//!
//! Webauthn is a standard allowing communication between servers, browsers and authenticators
//! to allow strong, passwordless, cryptographic authentication to be performed. Webauthn
//! is able to operate with many authenticator types, such as U2F.
//!
//! This library aims to provide a secure black-box Webauthn implementation that you can
//! plug into your application, so that you can provide Webauthn to your users.
//!
//! For examples, see our examples folder.
//!
//! To use this library yourself, you will want to reference the `WebauthnConfig` trait to
//! develop site specific policy and configuration, and the `Webauthn` struct for Webauthn
//! interactions.

// :(
// #![feature(vec_remove_item)]

#![warn(missing_docs)]

extern crate base64;
extern crate lru;
#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_derive;
// extern crate byteorder;
extern crate openssl;
#[macro_use]
extern crate nom;

pub mod attestation;
mod constants;
pub mod crypto;
pub mod ephemeral;
pub mod error;
pub mod proto;

use rand::prelude::*;
use std::convert::TryFrom;

use crate::attestation::{
    verify_fidou2f_attestation, verify_packed_attestation, AttestationFormat, AttestationType,
};
use crate::constants::{AUTHENTICATOR_TIMEOUT, CHALLENGE_SIZE_BYTES};
use crate::crypto::{compute_sha256, COSEContentType};
use crate::error::WebauthnError;
use crate::proto::{
    AllowCredentials, AuthenticatorAssertionResponse, AuthenticatorAttestationResponse, Challenge,
    CreationChallengeResponse, Credential, JSONExtensions, PubKeyCredParams, PublicKeyCredential,
    RegisterPublicKeyCredential, RequestChallengeResponse, UserId, UserVerificationPolicy,
};

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
/// During this processing, callbacks are initiated, which you can provide by implementing
/// WebauthnConfig for a type. The ephemeral module contains an example, in memory only
/// implementation of these callbacks as an example, or for testing.
///
/// As a result of this design, you will either need to provide thread safety around the
/// Webauthn type (due to the &mut requirements in some callbacks), or you can use many
/// Webauthn types, where each WebauthnConfig you have is able to use interior mutability
/// to protect and synchronise values.
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
            // We use stdrng because unlike thread_rng, it's a csprng, which given
            // this is a cryptographic operation, we kind of want!
            rng: rand::thread_rng();
            config: config,
            pkcp: pkcp,
            rp_id_hash: rp_id_hash,
        }
    }

    fn generate_challenge(&mut self) -> Challenge {
        Challenge((0..CHALLENGE_SIZE_BYTES).map(|_| self.rng.gen()).collect())
    }

    /// Generate a new challenge suitable for Serde JSON serialisation which can be
    /// sent to the client. The client (generally a webbrowser) will pass this JSON
    /// structure to the `navigator.credentials.create()` javascript function.
    ///
    /// At this time we deviate from the standard and base64 some fields, but we are
    /// investigating how to avoid this (https://github.com/Firstyear/webauthn-rs/issues/5)
    pub fn generate_challenge_register(
        &mut self,
        username: UserId,
    ) -> Result<CreationChallengeResponse, WebauthnError>
    where
        T: WebauthnConfig,
    {
        let policy = self.config.policy_user_verification(&username);
        let chal = self.generate_challenge();
        let c = CreationChallengeResponse::new(
            self.config.get_relying_party_name(),
            username.clone(),
            username.clone(),
            username.clone(),
            chal.to_string(),
            self.pkcp.clone(),
            self.config.get_authenticator_timeout(),
            policy,
        );

        self.config
            .persist_challenge(username, chal)
            .map_err(|_| WebauthnError::ChallengePersistenceError)?;
        Ok(c)
    }

    /// Process a credential registration response. This is the output of
    /// `navigator.credentials.create()` which is sent to the webserver. If the registration
    /// is valid, the credential will be sent to the appropriate callbacks, or an error
    /// will be returned to help identify why the registration failed.
    ///
    /// At this time we deviate from the standard and base64 some fields, but we are
    /// investigating how to avoid this (https://github.com/Firstyear/webauthn-rs/issues/5)
    pub fn register_credential(
        &mut self,
        reg: RegisterPublicKeyCredential,
        username: UserId,
    ) -> Result<(), WebauthnError>
    where
        T: WebauthnConfig,
    {
        // From the rfc https://w3c.github.io/webauthn/#registering-a-new-credential
        // get the challenge (it's username associated)
        let chal = self
            .config
            .retrieve_challenge(&username)
            .ok_or(WebauthnError::ChallengeNotFound)?;

        let policy = self.config.policy_user_verification(&username);

        // send to register_credential_internal
        let credential = self.register_credential_internal(reg, policy, chal)?;

        // Check that the credentialId is not yet registered to any other user. If registration is
        // requested for a credential that is already registered to a different user, the Relying
        // Party SHOULD fail this registration ceremony, or it MAY decide to accept the registration,
        // e.g. while deleting the older registration.

        let cred_exist_result = self
            .config
            .does_exist_credential(&username, &credential)
            .map_err(|_| WebauthnError::CredentialExistCheckError)?;

        if cred_exist_result {
            return Err(WebauthnError::CredentialAlreadyExists);
        }

        // match res, if good, save cred.
        self.config
            .persist_credential(username, credential)
            .map_err(|_| WebauthnError::CredentialPersistenceError)
    }

    pub(crate) fn register_credential_internal(
        &mut self,
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
        if data.client_data_json.challenge != chal.0 {
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
        if data.attestation_object.authData.rp_id_hash != self.rp_id_hash {
            return Err(WebauthnError::InvalidRPIDHash);
        }

        // Verify that the User Present bit of the flags in authData is set.
        if !data.attestation_object.authData.user_present {
            return Err(WebauthnError::UserNotPresent);
        }

        // If user verification is required for this registration, verify that the User Verified bit
        // of the flags in authData is set.
        match policy {
            UserVerificationPolicy::Required => {
                if !data.attestation_object.authData.user_verified {
                    return Err(WebauthnError::UserNotVerified);
                }
            }
            UserVerificationPolicy::Preferred => {}
            UserVerificationPolicy::Discouraged => {
                if data.attestation_object.authData.user_verified {
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
        match &data.attestation_object.authData.extensions {
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
            .authData
            .acd
            .ok_or(WebauthnError::MissingAttestationCredentialData)?;

        // Now, match based on the attest_format
        // This returns an AttestationType, containing all the metadata needed for
        // step 15.

        // let rp_hash = compute_sha256(self.config.get_relying_party_name().as_bytes());

        let attest_result = match attest_format {
            AttestationFormat::FIDOU2F => verify_fidou2f_attestation(
                &data.attestation_object.attStmt,
                acd,
                // &attest_data.authDataBytes,
                &client_data_json_hash,
                &data.attestation_object.authData.rp_id_hash,
                // &rp_hash,
                data.attestation_object.authData.counter,
            ),
            AttestationFormat::Packed => verify_packed_attestation(
                &data.attestation_object.attStmt,
                acd,
                data.attestation_object.authDataBytes,
                &client_data_json_hash,
                data.attestation_object.authData.counter,
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
        // We turn this into  a"helper" and serialisable credential structure that
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
        // println!("data: {:?}", data);

        let c = &data.clientDataJSON;

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
        if c.challenge != chal.0 {
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
        if data.authenticatorData.rp_id_hash != self.rp_id_hash {
            /*
            println!("rp_id_hash from authenitcatorData does not match our rp_id_hash");
            let a: String = base64::encode(&data.authenticatorData.rp_id_hash);
            let b: String = base64::encode(&self.rp_id_hash);
            println!("{:?} != {:?}", a, b);
            */
            return Err(WebauthnError::InvalidRPIDHash);
        }

        // Verify that the User Present bit of the flags in authData is set.
        if !data.authenticatorData.user_present {
            return Err(WebauthnError::UserNotPresent);
        }

        // If user verification is required for this assertion, verify that the User Verified bit of
        // the flags in authData is set.
        match policy {
            UserVerificationPolicy::Required => {
                if !data.authenticatorData.user_verified {
                    return Err(WebauthnError::UserNotVerified);
                }
            }
            UserVerificationPolicy::Preferred => {}
            UserVerificationPolicy::Discouraged => {
                if data.authenticatorData.user_verified {
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
        match &data.authenticatorData.extensions {
            Some(_ex) => {
                // pass
            }
            None => {}
        }

        // Let hash be the result of computing a hash over the cData using SHA-256.
        let client_data_json_hash = compute_sha256(data.clientDataJSONBytes.as_slice());

        // Using the credential public key looked up in step 3, verify that sig is a valid signature
        // over the binary concatenation of authData and hash.
        // Note: This verification step is compatible with signatures generated by FIDO U2F
        // authenticators. See §6.1.2 FIDO U2F Signature Format Compatibility.

        let verification_data: Vec<u8> = data
            .authenticatorDataBytes
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

        Ok(data.authenticatorData.counter)
    }

    /// Process an authenticate response from the authenticator and browser. This
    /// is the output of `navigator.credentials.get()`, which is processed by this
    /// function. If the authentication fails, appropriate errors will be returned.
    /// On success, an Ok(()) is returned.
    ///
    /// At this time we deviate from the standard and base64 some fields, but we are
    /// investigating how to avoid this (https://github.com/Firstyear/webauthn-rs/issues/5)
    pub fn authenticate_credential(
        &mut self,
        rsp: PublicKeyCredential,
        username: String,
    ) -> Result<(), WebauthnError>
    where
        T: WebauthnConfig,
    {
        // https://w3c.github.io/webauthn/#verifying-assertion
        // Lookup challenge
        let chal = self
            .config
            .retrieve_challenge(&username)
            .ok_or(WebauthnError::ChallengeNotFound)?;

        // If the allowCredentials option was given when this authentication ceremony was initiated,
        // verify that credential.id identifies one of the public key credentials that were listed in allowCredentials.
        //
        // We always supply allowCredentials in this library, so we expect creds as a vec of credentials
        // that would be equivalent to what was allowed.
        // println!("rsp: {:?}", rsp);

        let raw_id = base64::decode_mode(&rsp.rawId, base64::Base64Mode::Standard)
            .or(base64::decode_mode(&rsp.rawId, base64::Base64Mode::UrlSafe))
            .map_err(|e| WebauthnError::ParseBase64Failure(e))?;

        let cred = {
            // Identify the user being authenticated and verify that this user is the owner of the public
            // key credential source credentialSource identified by credential.id:
            //
            //  If the user was identified before the authentication ceremony was initiated, e.g., via a
            //  username or cookie,
            //      verify that the identified user is the owner of credentialSource. If
            //      credential.response.userHandle is present, let userHandle be its value. Verify that
            //      userHandle also maps to the same user.
            let creds = self
                .config
                .retrieve_credentials(&username)
                .ok_or(WebauthnError::CredentialRetrievalError)?;
            //  If the user was not identified before the authentication ceremony was initiated,
            //      verify that credential.response.userHandle is present, and that the user identified
            //      by this value is the owner of credentialSource.
            //
            // TODO: Not done yet

            // Using credential’s id attribute (or the corresponding rawId, if base64url encoding is
            // inappropriate for your use case), look up the corresponding credential public key.

            let cred_opt: Option<Credential> = creds.iter().fold(None, |acc, c| {
                if acc.is_none() && c.cred_id == raw_id {
                    Some((*c).clone())
                } else {
                    acc
                }
            });

            cred_opt.ok_or(WebauthnError::CredentialNotFound)?
        };

        let policy = self.config.policy_user_verification(&username);

        let counter = self.verify_credential_internal(rsp, policy, chal, &cred)?;

        // If the signature counter value authData.signCount is nonzero or the value stored in
        // conjunction with credential’s id attribute is nonzero, then run the following sub-step:
        if counter > 0 {
            // If the signature counter value authData.signCount is
            if counter > cred.counter {
                // greater than the signature counter value stored in conjunction with credential’s id attribute.
                //       Update the stored signature counter value, associated with credential’s id attribute,
                //       to be the value of authData.signCount.
                self.config
                    .credential_update_counter(&username, &cred, counter)
                    .map_err(|_| WebauthnError::CredentialCounterUpdateFailure)
            // If all the above steps are successful, continue with the authentication ceremony as
            // appropriate. Otherwise, fail the authentication ceremony.
            } else {
                // less than or equal to the signature counter value stored in conjunction with credential’s id attribute.
                //      This is a signal that the authenticator may be cloned, i.e. at least two copies
                //      of the credential private key may exist and are being used in parallel. Relying
                //      Parties should incorporate this information into their risk scoring. Whether the
                //      Relying Party updates the stored signature counter value in this case, or not,
                //      or fails the authentication ceremony or not, is Relying Party-specific.
                self.config
                    .credential_report_invalid_counter(&username, &cred, counter)
                    .map_err(|_| WebauthnError::CredentialCounterUpdateFailure)?;
                Err(WebauthnError::CredentialPossibleCompromise)
            }
        } else {
            // If all the above steps are successful, continue with the authentication ceremony as
            // appropriate. Otherwise, fail the authentication ceremony.
            Ok(())
        }
    }

    /// Generate a challenge for an authenticate request for a user. Given the userId, their
    /// AllowedCredential Ids will be added to the challenge. This challenge is supplied to
    /// to the javascript function `navigator.credentials.get()`.
    ///
    /// At this time we deviate from the standard and base64 some fields, but we are
    /// investigating how to avoid this (https://github.com/Firstyear/webauthn-rs/issues/5)
    pub fn generate_challenge_authenticate(
        &mut self,
        username: UserId,
    ) -> Result<RequestChallengeResponse, WebauthnError>
    where
        T: WebauthnConfig,
    {
        let chal = self.generate_challenge();

        // Get the user's existing creds if any.

        let uc = self.config.retrieve_credentials(&username);

        // println!("login_challenge: {:?}", uc);

        let ac = match uc {
            Some(creds) => creds
                .iter()
                .map(|cred| AllowCredentials {
                    type_: "public-key".to_string(),
                    id: base64::encode(cred.cred_id.as_slice()),
                })
                .collect(),
            None => Vec::new(),
        };

        let policy = self.config.policy_user_verification(&username);

        // Store the chal associated to the user.
        // Now put that into the correct challenge format
        let r = RequestChallengeResponse::new(
            chal.to_string(),
            self.config.get_authenticator_timeout(),
            self.config.get_relying_party_id(),
            ac,
            policy,
        );
        self.config
            .persist_challenge(username, chal)
            .map_err(|_| WebauthnError::ChallengePersistenceError)?;
        Ok(r)
    }
}

/// The WebauthnConfig type allows site-specific customisation of the Webauthn library.
/// This provides a set of callbacks which are used to supply data to various structures
/// and calls, as well as callbacks to manage data persistence and retrieval.
pub trait WebauthnConfig {
    /// Returns a copy of your relying parties name. This is generally any text identifier
    /// you wish, but should rarely if ever change. Changes to the relying party name may
    /// confuse authenticators and causes their credentials to be lost.
    ///
    /// Examples of names could be "My Awesome Site", "https://my-awesome-site.com.au"
    fn get_relying_party_name(&self) -> String;

    /// Returns a reference to your sites origin. The origin is the URL to your site with
    /// protocol and port. This should rarely, if ever change. In production usage this
    /// value must always be https://, however http://localhost is acceptable for testing
    /// only. We may add warnings or errors for non-https:// urls in the future.
    ///
    /// Examples of this value could be. "https://my-site.com.au", "https://my-site.com.au:8443"
    fn get_origin(&self) -> &String;

    /// Returs the relying party id. This should rarely if ever change, and is used as an id
    /// in cryptographic operations and credential scoping. This is defined as the domain name
    /// of the service, minuse all protocol, port and location data. For example:
    ///   `https://name:port/path -> name`
    ///
    /// Examples of this value for the site "https://my-site.com.au/auth" is "my-site.com.au"
    fn get_relying_party_id(&self) -> String;

    /// Given a UserId and Challenge, persist these to a temporary storage system. It is implementation
    /// specific if this challenge is distributed to other servires via a system like memcached
    /// or if these are persisted-per server. In the per-server case, you should use sticky
    /// sessions on your load balancer to ensure clients contact the server that issued the challenge
    ///
    /// The UserId and Challenge are both serialisable with serde for storage in a database or
    /// structure of some kind.
    fn persist_challenge(&mut self, userid: UserId, challenge: Challenge) -> Result<(), ()>;

    /// Given a UserId, return the challenge if one is present. If not challenge is found return
    /// None (which will cause the client operation to fail with correct error messages). It's important
    /// to note here the use of `Option<Challenge>` - you should remove the Challenge from the
    /// datastore as part of this request to prevent challenge re-use or bruteforce attacks from
    /// occuring.
    fn retrieve_challenge(&mut self, userid: &UserId) -> Option<Challenge>;

    /// Given a userId and a Credential, determine if this credential already exists and is
    /// registered to the user. It may be of benefit to determine if the credential belongs to
    /// *any* other user in your system to prevent credential re-use.
    fn does_exist_credential(&self, userid: &UserId, cred: &Credential) -> Result<bool, ()>;

    /// On a sucessful registration, persist this Credential associated to UserId.
    fn persist_credential(&mut self, userid: UserId, credential: Credential) -> Result<(), ()>;

    /// Given a userId, retrieve the set of all Credentials that the UserId has associated.
    fn retrieve_credentials(&self, userid: &UserId) -> Option<Vec<&Credential>>;

    /// Given a userId and Credential, update it's authentication counter to "counter". This
    /// helps to minimise threats from replay or reuse attacks by ensuring the counter is always
    /// advancing.
    fn credential_update_counter(
        &mut self,
        userid: &UserId,
        cred: &Credential,
        counter: u32,
    ) -> Result<(), ()>;

    /// Given a userId and Credential, if the counter value has gone backwards or is replayed
    /// this callback is called to allow reporting of a possible compromise of the Credential.
    /// You should take site appropriate action, ranging from audit-logging of the possible
    /// compromise, disabling of the Credential, disabling the account, or other appropriate
    /// actions.
    fn credential_report_invalid_counter(
        &mut self,
        userid: &UserId,
        cred: &Credential,
        counter: u32,
    ) -> Result<(), ()>;

    /// Get the list of valid credential algorthims that this servie will accept. Unless you have
    /// speific requirements around this, we advise you leave this function to the default
    /// implementation.
    fn get_credential_algorithms(&self) -> Vec<COSEContentType> {
        vec![COSEContentType::ECDSA_SHA256]
    }

    /// Return a timeout on how long the authenticator has to respond to a challenge. This value
    /// defaults to 6000 milliseconds. You likely won't need to implemented this function, and should
    /// rely on the defaults.
    fn get_authenticator_timeout(&self) -> u32 {
        AUTHENTICATOR_TIMEOUT
    }

    /// Returns a site policy on if user verification of the authenticator is required. This currently
    /// defaults to "false" due to implementation limitations, as per:
    /// https://github.com/Firstyear/webauthn-rs/issues/7
    fn get_user_verification_required(&self) -> bool {
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
            _ => {
                // We don't know how to assert trust in this yet, or we just
                // don't trust it at all (Uncertain, None).
                Err(())
            }
        }
    }

    /// A callback allowing you to specify a per-user credential verification
    /// policy. Given the user and credential id, determine if the user verification
    /// policy for this operation. This can be used to ensure that users with certain
    /// security levels must have verified credentials, while others merely need any
    /// credential. This also applies to registration. For more details, see UserVerificationPolicy
    ///
    /// Note this is not per credential, because as a policy it only makes sense per user.
    /// Changing this value for a user may cause existing credentials to fail as they may
    /// not support verification - arguably a good thing if their requirements have become
    /// stricter.
    ///
    /// The default policy returns "preffered" for all credentials.
    fn policy_user_verification(&self, _userid: &UserId) -> UserVerificationPolicy {
        UserVerificationPolicy::Preferred
    }
}

#[cfg(test)]
mod tests {
    use crate::constants::CHALLENGE_SIZE_BYTES;
    use crate::crypto::{COSEContentType, COSEEC2Key, COSEKey, COSEKeyType, ECDSACurve};
    use crate::ephemeral::WebauthnEphemeralConfig;
    use crate::proto::{
        Challenge, Credential, PublicKeyCredential, RegisterPublicKeyCredential,
        UserVerificationPolicy,
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
        let mut wan = Webauthn::new(wan_c);
        // Generated by a yubico 5
        // Make a "fake" challenge, where we know what the values should be ....

        let zero_chal = Challenge((0..CHALLENGE_SIZE_BYTES).map(|_| 0).collect::<Vec<u8>>());

        // This is the json challenge this would generate in this case, with the rp etc.
        // {"publicKey":{"rp":{"name":"http://127.0.0.1:8080/auth"},"user":{"id":"xxx","name":"xxx","displayName":"xxx"},"challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","pubKeyCredParams":[{"type":"public-key","alg":-7}],"timeout":6000,"attestation":"direct"}}

        // And this is the response, from a real device. Let's register it!

        let rsp = r#"
        {"id":"0xYE4bQ_HZM51-XYwp7WHJu8RfeA2Oz3_9HnNIZAKqRTz9gsUlF3QO7EqcJ0pgLSwDcq6cL1_aQpTtKLeGu6Ig","rawId":"0xYE4bQ/HZM51+XYwp7WHJu8RfeA2Oz3/9HnNIZAKqRTz9gsUlF3QO7EqcJ0pgLSwDcq6cL1/aQpTtKLeGu6Ig==","response":{"attestationObject":"o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIhALjRb43YFcbJ3V9WiYPpIrZkhgzAM6KTR8KIjwCXejBCAiAO5Lvp1VW4dYBhBDv7HZIrxZb1SwKKYOLfFRXykRxMqGN4NWOBWQLBMIICvTCCAaWgAwIBAgIEGKxGwDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbjELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEnMCUGA1UEAwweWXViaWNvIFUyRiBFRSBTZXJpYWwgNDEzOTQzNDg4MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeeo7LHxJcBBiIwzSP+tg5SkxcdSD8QC+hZ1rD4OXAwG1Rs3Ubs/K4+PzD4Hp7WK9Jo1MHr03s7y+kqjCrutOOqNsMGowIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjcwEwYLKwYBBAGC5RwCAQEEBAMCBSAwIQYLKwYBBAGC5RwBAQQEEgQQy2lIHo/3QDmT7AonKaFUqDAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQCXnQOX2GD4LuFdMRx5brr7Ivqn4ITZurTGG7tX8+a0wYpIN7hcPE7b5IND9Nal2bHO2orh/tSRKSFzBY5e4cvda9rAdVfGoOjTaCW6FZ5/ta2M2vgEhoz5Do8fiuoXwBa1XCp61JfIlPtx11PXm5pIS2w3bXI7mY0uHUMGvxAzta74zKXLslaLaSQibSKjWKt9h+SsXy4JGqcVefOlaQlJfXL1Tga6wcO0QTu6Xq+Uw7ZPNPnrpBrLauKDd202RlN4SP7ohL3d9bG6V5hUz/3OusNEBZUn5W3VmPj1ZnFavkMB3RkRMOa58MZAORJT4imAPzrvJ0vtv94/y71C6tZ5aGF1dGhEYXRhWMQSyhe0mvIolDbzA+AWYDCiHlJdJm4gkmdDOAGo/UBxoEEAAAAAAAAAAAAAAAAAAAAAAAAAAABA0xYE4bQ/HZM51+XYwp7WHJu8RfeA2Oz3/9HnNIZAKqRTz9gsUlF3QO7EqcJ0pgLSwDcq6cL1/aQpTtKLeGu6IqUBAgMmIAEhWCCe1KvqpcVWN416/QZc8vJynt3uo3/WeJ2R4uj6kJbaiiJYIDC5ssxxummKviGgLoP9ZLFb836A9XfRO7op18QY3i5m","clientDataJSON":"eyJjaGFsbGVuZ2UiOiJBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovLzEyNy4wLjAuMTo4MDgwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9"},"type":"public-key"}
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
        let mut wan = Webauthn::new(wan_c);

        let chal = Challenge(
            base64::decode_mode(
                "+Ri5NZTzJ8b6mvW3TVScLotEoALfgBa2Bn4YSaIObHc",
                base64::Base64Mode::Standard,
            )
            .unwrap(),
        );

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
        let mut wan = Webauthn::new(wan_c);

        let chal = Challenge(
            base64::decode_mode(
                "lP6mWNAtG+/Vv15iM7lb/XRkdWMvVQ+lTyKwZuOg1Vo=",
                base64::Base64Mode::Standard,
            )
            .unwrap(),
        );

        // Example generated using navigator.credentials.create on Chrome Version 77.0.3865.120
        // using Touch ID on MacBook running MacOS 10.15
        let rsp = r#"{"id":"ATk_7QKbi_ntSdp16LXeU6RDf9YnRLIDTCqEjJFzc6rKBhbqoSYccxNa","rawId":"ATk/7QKbi/ntSdp16LXeU6RDf9YnRLIDTCqEjJFzc6rKBhbqoSYccxNa","response":{"attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIgLXPjBtVEhBH3KdUDFFk3LAd9EtHogllIf48vjX4wgfECIQCXOymmfg12FPMXEdwpSjjtmrvki4K8y0uYxqWN5Bw6DGhhdXRoRGF0YViuSZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NFXaqejq3OAAI1vMYKZIsLJfHwVQMAKgE5P+0Cm4v57Unadei13lOkQ3/WJ0SyA0wqhIyRc3OqygYW6qEmHHMTWqUBAgMmIAEhWCDNRS/Gw52ow5PNrC9OdFTFNudDmZO6Y3wmM9N8e0tJICJYIC09iIH5/RrT5tbS0PIw3srdAxYDMGao7yWgu0JFIEzT","clientDataJSON":"eyJjaGFsbGVuZ2UiOiJsUDZtV05BdEctX1Z2MTVpTTdsYl9YUmtkV012VlEtbFR5S3dadU9nMVZvIiwiZXh0cmFfa2V5c19tYXlfYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb21wYXJlIGNsaWVudERhdGFKU09OIGFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ29vLmdsL3lhYlBleCIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0="},"type":"public-key"}
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
        // wan_c.persist_credential("xxx".to_string(), cred);

        let wan = Webauthn::new(wan_c);

        // Captured authentication attempt

        let rsp = r#"
        {"id":"at-FfKGsOI21EhtCu7Vx-7t7FKkpUOyKXIkEBBD_vC-eym_AdW6Y9V8WyKxHmii11EBQEe7uFQ0bkYwb0GWmUQ","rawId":"at+FfKGsOI21EhtCu7Vx+7t7FKkpUOyKXIkEBBD/vC+eym/AdW6Y9V8WyKxHmii11EBQEe7uFQ0bkYwb0GWmUQ==","response":{"authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2MBAAAAFA==","clientDataJSON":"eyJjaGFsbGVuZ2UiOiJXZ1h6X2tUdjNXVVUxa3c4aG0tT0dvR1M0WkNIWF8zYkVxSEgyUHZWcDhNIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9","signature":"MEYCIQDmLVOqv85cdRup4Fr8Pf9zC4AWO+XKBJqa8xPwYFCCMAIhAOiExLoyes0xipmUmq0BVlqJaCKLn/MFKG9GIDsCGq/+","userHandle":null},"type":"public-key"}
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
}

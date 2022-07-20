//! Webauthn-rs - Webauthn for Rust Server Applications
//!
//! Webauthn is a standard allowing communication between servers, browsers and authenticators
//! to allow strong, passwordless, cryptographic authentication to be performed. Webauthn
//! is able to operate with many authenticator types, such as U2F.
//!
//! ⚠️  ⚠️  ⚠️  THIS IS UNSAFE. AVOID USING THIS DIRECTLY ⚠️  ⚠️  ⚠️
//!
//! If possible, use the `webauthn-rs` crate, and it's safe wrapper instead!
//!
//! Webauthn as a standard has many traps that in the worst cases, may lead to
//! bypasses and full account compromises. Many of the features of webauthn are
//! NOT security policy, but user interface hints. Many options can NOT be
//! enforced. `webauthn-rs` handles these correctly. USE `webauthn-rs` INSTEAD.

#![warn(missing_docs)]

use rand::prelude::*;
use std::convert::TryFrom;
use url::Url;

use crate::attestation::{
    verify_android_key_attestation, verify_android_safetynet_attestation,
    verify_apple_anonymous_attestation, verify_attestation_ca_chain, verify_fidou2f_attestation,
    verify_packed_attestation, verify_tpm_attestation, AttestationFormat,
};
use crate::constants::{AUTHENTICATOR_TIMEOUT, CHALLENGE_SIZE_BYTES};
use crate::crypto::compute_sha256;
use crate::error::WebauthnError;
use crate::internals::*;
use crate::proto::*;
use base64urlsafedata::Base64UrlSafeData;

/// This is the core of the Webauthn operations. It provides 4 interfaces that you will likely
/// use the most:
/// * generate_challenge_register
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
pub struct WebauthnCore {
    rp_name: String,
    rp_id: String,
    rp_id_hash: [u8; 32],
    rp_origin: Url,
    authenticator_timeout: u32,
    require_valid_counter_value: bool,
    #[allow(unused)]
    ignore_unsupported_attestation_formats: bool,
    allow_cross_origin: bool,
    allow_subdomains_origin: bool,
    allow_any_port: bool,
}

impl WebauthnCore {
    /// ⚠️  ⚠️  ⚠️  THIS IS UNSAFE. AVOID USING THIS DIRECTLY ⚠️  ⚠️  ⚠️
    ///
    /// If possible, use the `webauthn-rs` crate, and it's safe wrapper instead!
    ///
    /// Webauthn as a standard has many traps that in the worst cases, may lead to
    /// bypasses and full account compromises. Many of the features of webauthn are
    /// NOT security policy, but user interface hints. Many options can NOT be
    /// enforced. `webauthn-rs` handles these correctly. USE `webauthn-rs` INSTEAD.
    ///
    /// If you still choose to continue, and use this directly, be aware that:
    ///
    /// * This function signature MAY change WITHOUT NOTICE and WITHIN MINOR VERSIONS
    /// * That you are responsible for UPHOLDING many invariants within webauthn that are NOT DOCUMENTED
    /// * You MUST understand the webauthn specification in excruciating detail to understand the traps within it
    ///
    /// Seriously. Use `webauthn-rs` instead.
    pub fn new_unsafe_experts_only(
        rp_name: &str,
        rp_id: &str,
        rp_origin: &Url,
        authenticator_timeout: Option<u32>,
        allow_subdomains_origin: Option<bool>,
        allow_any_port: Option<bool>,
    ) -> Self {
        let rp_id_hash = compute_sha256(rp_id.as_bytes());
        WebauthnCore {
            rp_name: rp_name.to_string(),
            rp_id: rp_id.to_string(),
            rp_id_hash,
            rp_origin: rp_origin.clone(),
            authenticator_timeout: authenticator_timeout.unwrap_or(AUTHENTICATOR_TIMEOUT),
            require_valid_counter_value: true,
            ignore_unsupported_attestation_formats: true,
            allow_cross_origin: false,
            allow_subdomains_origin: allow_subdomains_origin.unwrap_or(false),
            allow_any_port: allow_any_port.unwrap_or(false),
        }
    }

    /// Get the currently configured origin
    pub fn get_origin(&self) -> &Url {
        &self.rp_origin
    }

    fn generate_challenge(&self) -> Challenge {
        let mut rng = rand::thread_rng();
        Challenge::new(rng.gen::<[u8; CHALLENGE_SIZE_BYTES]>().to_vec())
    }

    /// Generate a new challenge for client registration.
    /// Same as `generate_challenge_register_options` but with simple, default options
    pub fn generate_challenge_register(
        &self,
        user_unique_id: &[u8],
        user_name: &str,
        user_display_name: &str,
        user_verification_required: bool,
    ) -> Result<(CreationChallengeResponse, RegistrationState), WebauthnError> {
        let policy = if user_verification_required {
            Some(UserVerificationPolicy::Required)
        } else {
            // I'm so mad about ctap2.0 you have no idea.
            Some(UserVerificationPolicy::Preferred)
        };

        let attestation = AttestationConveyancePreference::None;
        let exclude_credentials = None;
        let extensions = None;
        let credential_algorithms = COSEAlgorithm::secure_algs();
        let require_resident_key = false;
        let authenticator_attachment = None;

        self.generate_challenge_register_options(
            user_unique_id,
            user_name,
            user_display_name,
            attestation,
            policy,
            exclude_credentials,
            extensions,
            credential_algorithms,
            require_resident_key,
            authenticator_attachment,
            false,
        )
    }

    /// Generate a new challenge for client registration. This is the first step in
    /// the lifecycle of a credential. This function will return the
    /// creationchallengeresponse which is suitable for serde json serialisation
    /// to be sent to the client.
    /// The client (generally a web browser) will pass this JSON
    /// structure to the `navigator.credentials.create()` javascript function for registration.
    ///
    /// It also returns a RegistrationState, that you *must*
    /// persist. It is strongly advised you associate this RegistrationState with the
    /// UserId of the requester.
    #[allow(clippy::too_many_arguments)]
    pub fn generate_challenge_register_options(
        &self,
        user_unique_id: &[u8],
        user_name: &str,
        user_display_name: &str,
        attestation: AttestationConveyancePreference,
        policy: Option<UserVerificationPolicy>,
        exclude_credentials: Option<Vec<CredentialID>>,

        extensions: Option<RequestRegistrationExtensions>,

        credential_algorithms: Vec<COSEAlgorithm>,
        require_resident_key: bool,
        authenticator_attachment: Option<AuthenticatorAttachment>,
        experimental_reject_passkeys: bool,
    ) -> Result<(CreationChallengeResponse, RegistrationState), WebauthnError> {
        let policy = policy.unwrap_or(UserVerificationPolicy::Preferred);
        if policy == UserVerificationPolicy::Discouraged_DO_NOT_USE {
            warn!("UserVerificationPolicy::Discouraged_DO_NOT_USE is misleading! You should select Preferred or Required!");
        }

        if user_unique_id.is_empty() || user_display_name.is_empty() || user_name.is_empty() {
            return Err(WebauthnError::InvalidUsername);
        }

        let user_id: UserId = user_unique_id.to_vec();

        // Setup our extensions.
        // unimplemented!();

        // resident key needs cred props

        // user verification needs credProtect (?)

        // Have a UV strict?

        // CredBlob needs to limit to 32 bytes.

        // minPinLength

        // hmacSecret

        // credProps

        // userVerificationMethod

        //

        let challenge = self.generate_challenge();

        let c = CreationChallengeResponse {
            public_key: PublicKeyCredentialCreationOptions {
                rp: RelyingParty {
                    name: self.rp_name.clone(),
                    id: self.rp_id.clone(),
                },
                user: User {
                    id: Base64UrlSafeData(user_id),
                    name: user_name.to_string(),
                    display_name: user_display_name.to_string(),
                },
                challenge: challenge.clone().into(),
                pub_key_cred_params: credential_algorithms
                    .iter()
                    .map(|alg| PubKeyCredParams {
                        type_: "public-key".to_string(),
                        alg: *alg as i64,
                    })
                    .collect(),
                timeout: Some(self.authenticator_timeout),
                attestation: Some(attestation),
                exclude_credentials: exclude_credentials.as_ref().map(|creds| {
                    creds
                        .iter()
                        .cloned()
                        .map(|id| PublicKeyCredentialDescriptor {
                            type_: "public-key".to_string(),
                            id,
                            transports: None,
                        })
                        .collect()
                }),
                authenticator_selection: Some(AuthenticatorSelectionCriteria {
                    authenticator_attachment,
                    require_resident_key,
                    user_verification: policy,
                }),
                extensions: extensions.clone(),
            },
        };

        let wr = RegistrationState {
            policy,
            exclude_credentials: exclude_credentials.unwrap_or_else(|| Vec::with_capacity(0)),
            challenge: challenge.into(),
            credential_algorithms,
            // We can potentially enforce these!
            require_resident_key,
            authenticator_attachment,
            extensions: extensions.unwrap_or_default(),
            experimental_allow_passkeys: !experimental_reject_passkeys,
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
    /// You need to provide a closure that is able to check if any credential of the
    /// same id has already been persisted by your server.
    pub fn register_credential(
        &self,
        reg: &RegisterPublicKeyCredential,
        state: &RegistrationState,
        attestation_cas: Option<&AttestationCaList>,
        // does_exist_fn: impl Fn(&CredentialID) -> Result<bool, ()>,
    ) -> Result<Credential, WebauthnError> {
        // Decompose our registration state which contains everything we need to proceed.
        trace!(?state);
        trace!(?reg);

        let RegistrationState {
            policy,
            exclude_credentials,
            challenge,
            credential_algorithms,
            require_resident_key: _,
            authenticator_attachment: _,
            extensions,
            experimental_allow_passkeys,
        } = state;
        let chal: &ChallengeRef = challenge.into();

        // send to register_credential_internal
        let credential = self.register_credential_internal(
            reg,
            *policy,
            chal,
            exclude_credentials,
            credential_algorithms,
            attestation_cas,
            false,
            extensions,
            *experimental_allow_passkeys,
        )?;

        // Check that the credentialId is not yet registered to any other user. If registration is
        // requested for a credential that is already registered to a different user, the Relying
        // Party SHOULD fail this registration ceremony, or it MAY decide to accept the registration,
        // e.g. while deleting the older registration.

        /*
        let cred_exist_result = does_exist_fn(&credential.0.cred_id)
            .map_err(|_| WebauthnError::CredentialExistCheckError)?;

        if cred_exist_result {
            return Err(WebauthnError::CredentialAlreadyExists);
        }
        */

        Ok(credential)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn register_credential_internal(
        &self,
        reg: &RegisterPublicKeyCredential,
        policy: UserVerificationPolicy,
        chal: &ChallengeRef,
        exclude_credentials: &[CredentialID],
        credential_algorithms: &[COSEAlgorithm],
        attestation_cas: Option<&AttestationCaList>,
        danger_disable_certificate_time_checks: bool,
        req_extn: &RequestRegistrationExtensions,
        experimental_allow_passkeys: bool,
    ) -> Result<Credential, WebauthnError> {
        // Internal management - if the attestation ca list is some, but is empty, we need to fail!
        if attestation_cas
            .as_ref()
            .map(|l| l.is_empty())
            .unwrap_or(false)
        {
            return Err(WebauthnError::MissingAttestationCaList);
        }

        // ======================================================================
        // References:
        // Level 2: https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential

        // Steps 1 through 4 are performed by the Client, not the RP.

        // Let JSONtext be the result of running UTF-8 decode on the value of response.clientDataJSON.
        //
        //   This is done by the calling webserver to give us reg aka JSONText in this case.
        //
        // Let C, the client data claimed as collected during the credential creation, be the result
        // of running an implementation-specific JSON parser on JSONtext.
        //
        // Now, we actually do a much larger conversion in one shot
        // here, where we get the AuthenticatorAttestationResponse

        let data = AuthenticatorAttestationResponse::try_from(&reg.response)?;

        // trace!("data: {:?}", data);

        // Verify that the value of C.type is webauthn.create.
        if data.client_data_json.type_ != "webauthn.create" {
            return Err(WebauthnError::InvalidClientDataType);
        }

        // Verify that the value of C.challenge matches the challenge that was sent to the
        // authenticator in the create() call.
        if data.client_data_json.challenge.0 != chal.as_ref() {
            return Err(WebauthnError::MismatchedChallenge);
        }

        // Verify that the value of C.origin matches the Relying Party's origin.
        Self::validate_origin(
            self.allow_subdomains_origin,
            self.allow_any_port,
            &data.client_data_json.origin,
            &self.rp_origin,
        )?;

        // ATM most browsers do not send this value, so we must default to
        // `false`. See [WebauthnConfig::allow_cross_origin] doc-comment for
        // more.
        if !self.allow_cross_origin && data.client_data_json.cross_origin.unwrap_or(false) {
            return Err(WebauthnError::CredentialCrossOrigin);
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

        // Let hash be the result of computing a hash over response.clientDataJSON using SHA-256
        //
        //   clarifying point - this is the hash of bytes.
        //
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
        if matches!(policy, UserVerificationPolicy::Required)
            && !data.attestation_object.auth_data.user_verified
        {
            return Err(WebauthnError::UserNotVerified);
        }

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

        debug!(
            "extensions: {:?}",
            data.attestation_object.auth_data.extensions
        );

        // Only packed, tpm and apple allow extensions to be verified!

        // Determine the attestation statement format by performing a USASCII case-sensitive match on
        // fmt against the set of supported WebAuthn Attestation Statement Format Identifier values.
        // An up-to-date list of registered WebAuthn Attestation Statement Format Identifier values
        // is maintained in the IANA registry of the same name [WebAuthn-Registries].
        // ( https://www.rfc-editor.org/rfc/rfc8809 )
        //
        //  https://w3c.github.io/webauthn-3/#packed-attestation
        //  https://w3c.github.io/webauthn-3/#tpm-attestation
        //  https://w3c.github.io/webauthn-3/#android-key-attestation
        //  https://w3c.github.io/webauthn-3/#android-safetynet-attestation
        //  https://w3c.github.io/webauthn-3/#fido-u2f-attestation
        //  https://w3c.github.io/webauthn-3/#none-attestation
        //  https://www.w3.org/TR/webauthn-3/#sctn-apple-anonymous-attestation
        //
        let attest_format = AttestationFormat::try_from(data.attestation_object.fmt.as_str())?;

        // Verify that attStmt is a correct attestation statement, conveying a valid attestation
        // signature, by using the attestation statement format fmt’s verification procedure given
        // attStmt, authData and the hash of the serialized client data.

        let acd = data
            .attestation_object
            .auth_data
            .acd
            .as_ref()
            .ok_or(WebauthnError::MissingAttestationCredentialData)?;

        // Now, match based on the attest_format
        debug!("attestation is: {:?}", &attest_format);
        debug!("attested credential data is: {:?}", &acd);

        let (attestation_data, attestation_metadata) = match attest_format {
            AttestationFormat::FIDOU2F => (
                verify_fidou2f_attestation(acd, &data.attestation_object, &client_data_json_hash)?,
                AttestationMetadata::None,
            ),
            AttestationFormat::Packed => {
                verify_packed_attestation(acd, &data.attestation_object, &client_data_json_hash)?
            }
            // AttestationMetadata::None,
            AttestationFormat::Tpm => {
                verify_tpm_attestation(acd, &data.attestation_object, &client_data_json_hash)?
            }
            // AttestationMetadata::None,
            AttestationFormat::AppleAnonymous => verify_apple_anonymous_attestation(
                acd,
                &data.attestation_object,
                &client_data_json_hash,
            )?,
            // AttestationMetadata::None,
            AttestationFormat::AndroidKey => verify_android_key_attestation(
                acd,
                &data.attestation_object,
                &client_data_json_hash,
            )?,
            AttestationFormat::AndroidSafetyNet => verify_android_safetynet_attestation(
                acd,
                &data.attestation_object,
                &client_data_json_hash,
                danger_disable_certificate_time_checks,
            )?,
            AttestationFormat::None => (ParsedAttestationData::None, AttestationMetadata::None),
        };

        let credential: Credential = Credential::new(
            acd,
            &data.attestation_object.auth_data,
            COSEKey::try_from(&acd.credential_pk)?,
            policy,
            ParsedAttestation {
                data: attestation_data,
                metadata: attestation_metadata,
            },
            req_extn,
            &reg.extensions,
            attest_format,
            &data.transports,
        );

        // Now based on result ...

        // If validation is successful, obtain a list of acceptable trust anchors (attestation
        // root certificates or ECDAA-Issuer public keys) for that attestation type and attestation
        // statement format fmt, from a trusted source or from policy. For example, the FIDO Metadata
        // Service [FIDOMetadataService] provides one way to obtain such information, using the
        // aaguid in the attestedCredentialData in authData.
        //
        // Assess the attestation trustworthiness using the outputs of the verification procedure in step 19, as follows:
        //
        // * If no attestation was provided, verify that None attestation is acceptable under Relying Party policy.
        // * If self attestation was used, verify that self attestation is acceptable under Relying Party policy.
        // * Otherwise, use the X.509 certificates returned as the attestation trust path from the verification
        //     procedure to verify that the attestation public key either correctly chains up to an acceptable
        //     root certificate, or is itself an acceptable certificate (i.e., it and the root certificate
        //     obtained in Step 20 may be the same).

        // If the attestation statement attStmt successfully verified but is not trustworthy per step 21 above,
        // the Relying Party SHOULD fail the registration ceremony.

        let attested_ca_crt = if let Some(ca_list) = attestation_cas {
            // If given a set of ca's assert that our attestation actually matched one.
            let ca_crt = verify_attestation_ca_chain(
                &credential.attestation.data,
                ca_list,
                danger_disable_certificate_time_checks,
            )?;

            // It may seem odd to unwrap the option and make this not verified at this point,
            // but in this case because we have the ca_list and none was the result (which happens)
            // in some cases, we need to map that through. But we need verify_attesation_ca_chain
            // to still return these option types due to re-attestation in the future.
            let ca_crt = ca_crt.ok_or(WebauthnError::AttestationNotVerifiable)?;
            Some(ca_crt)
        } else {
            None
        };

        debug!("attested_ca_crt = {:?}", attested_ca_crt);

        // Verify that the credential public key alg is one of the allowed algorithms.
        let alg_valid = credential_algorithms
            .iter()
            .any(|alg| alg == &credential.cred.type_);

        if !alg_valid {
            error!(
                "Authenticator ignored requested algorithm set - {:?} - {:?}",
                credential.cred.type_, credential_algorithms
            );
            return Err(WebauthnError::CredentialAlteredAlgFromRequest);
        }

        // OUT OF SPEC - Allow rejection of passkeys if desired by the caller.
        if !experimental_allow_passkeys && credential.backup_eligible {
            error!("Credential counter is 0 - may indicate that it is a passkey and not bound to hardware.");
            return Err(WebauthnError::CredentialMayNotBeHardwareBound);
        }

        // OUT OF SPEC - It is invalid for a credential to indicate it is backed up
        // but not that it is elligible for backup
        if credential.backup_state && !credential.backup_eligible {
            error!("Credential indicates it is backed up, but has not declared valid backup elligibility");
            return Err(WebauthnError::CredentialMayNotBeHardwareBound);
        }

        // OUT OF SPEC - exclude any credential that is in our exclude list.
        let excluded = exclude_credentials
            .iter()
            .any(|credid| credid.0.as_slice() == credential.cred_id.0.as_slice());

        if excluded {
            return Err(WebauthnError::CredentialAlteredAlgFromRequest);
        }

        // If the attestation statement attStmt verified successfully and is found to be trustworthy,
        // then register the new credential with the account that was denoted in options.user:
        //
        // For us, we return the credential for the caller to persist.
        // If trust failed, we have already returned an Err before this point.

        // TODO: Associate the credentialId with the transport hints returned by calling
        // credential.response.getTransports(). This value SHOULD NOT be modified before or after
        // storing it. It is RECOMMENDED to use this value to populate the transports of the
        // allowCredentials option in future get() calls to help the client know how to find a
        // suitable authenticator.

        Ok(credential)
    }

    // https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion
    pub(crate) fn verify_credential_internal(
        &self,
        rsp: &PublicKeyCredential,
        policy: UserVerificationPolicy,
        chal: &ChallengeRef,
        cred: &Credential,
        appid: &Option<String>,
    ) -> Result<AuthenticatorData<Authentication>, WebauthnError> {
        // Steps 1 through 7 are performed by the caller of this fn.

        // Let cData, authData and sig denote the value of credential’s response's clientDataJSON,
        // authenticatorData, and signature respectively.
        //
        // Let JSONtext be the result of running UTF-8 decode on the value of cData.
        let data = AuthenticatorAssertionResponse::try_from(&rsp.response).map_err(|e| {
            debug!("AuthenticatorAssertionResponse::try_from -> {:?}", e);
            e
        })?;

        let c = &data.client_data;

        /*
        Let C, the client data claimed as used for the signature, be the result of running an
        implementation-specific JSON parser on JSONtext.
            Note: C may be any implementation-specific data structure representation, as long as
            C’s components are referenceable, as required by this algorithm.
        */

        // Verify that the value of C.type is the string webauthn.get.
        if c.type_ != "webauthn.get" {
            return Err(WebauthnError::InvalidClientDataType);
        }

        // Verify that the value of C.challenge matches the challenge that was sent to the
        // authenticator in the PublicKeyCredentialRequestOptions passed to the get() call.
        if c.challenge.0 != chal.as_ref() {
            return Err(WebauthnError::MismatchedChallenge);
        }

        // Verify that the value of C.origin matches the Relying Party's origin.
        Self::validate_origin(
            self.allow_subdomains_origin,
            self.allow_any_port,
            &c.origin,
            &self.rp_origin,
        )?;

        // Verify that the value of C.tokenBinding.status matches the state of Token Binding for the
        // TLS connection over which the attestation was obtained. If Token Binding was used on that
        // TLS connection, also verify that C.tokenBinding.id matches the base64url encoding of the
        // Token Binding ID for the connection.

        // Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party.
        // Note that if we have an appid stored in the state and the client indicates it has used the appid extension,
        // we also check the hash against this appid in addition to the Relying Party
        let has_appid_enabled = rsp.extensions.appid.unwrap_or(false);

        let appid_hash = if has_appid_enabled {
            appid.as_ref().map(|id| compute_sha256(id.as_bytes()))
        } else {
            None
        };

        if !(data.authenticator_data.rp_id_hash == self.rp_id_hash
            || Some(&data.authenticator_data.rp_id_hash) == appid_hash.as_ref())
        {
            return Err(WebauthnError::InvalidRPIDHash);
        }

        // Verify that the User Present bit of the flags in authData is set.
        if !data.authenticator_data.user_present {
            return Err(WebauthnError::UserNotPresent);
        }

        // If user verification is required for this assertion, verify that the User Verified bit of
        // the flags in authData is set.
        //
        // We also check the historical policy too. See designs/authentication-use-cases.md

        match (&policy, &cred.registration_policy) {
            (_, UserVerificationPolicy::Required) | (UserVerificationPolicy::Required, _) => {
                // If we requested required at registration or now, enforce that.
                if !data.authenticator_data.user_verified {
                    return Err(WebauthnError::UserNotVerified);
                }
            }
            (_, UserVerificationPolicy::Preferred) => {
                // If we asked for Preferred at registration, we MAY have established to the user
                // that they are required to enter a pin, so we SHOULD enforce this.
                if cred.user_verified && !data.authenticator_data.user_verified {
                    debug!("Token registered UV=preferred, enforcing UV policy.");
                    return Err(WebauthnError::UserNotVerified);
                }
            }
            // Pass - we can not know if verification was requested to the client in the past correctly.
            // This means we can't know what it's behaviour is at the moment.
            // We must allow unverified tokens now.
            _ => {}
        }

        // OUT OF SPEC - if the backup elligibility of this device has changed, this may represent
        // a compromise of the credential, tampering with the device, or some other change to its
        // risk profile from when it was originally enrolled. Reject the authentication if this
        // situation occurs.
        if cred.backup_eligible != data.authenticator_data.backup_elligible {
            debug!("Credential backup elligibility has changed!");
            return Err(WebauthnError::CredentialBackupElligibilityInconsistent);
        }

        // OUT OF SPEC - It is invalid for a credential to indicate it is backed up
        // but not that it is elligible for backup
        if data.authenticator_data.backup_state && !cred.backup_eligible {
            error!("Credential indicates it is backed up, but has not declared valid backup elligibility");
            return Err(WebauthnError::CredentialMayNotBeHardwareBound);
        }

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
        debug!("extensions: {:?}", data.authenticator_data.extensions);

        // Let hash be the result of computing a hash over the cData using SHA-256.
        let client_data_json_hash = compute_sha256(data.client_data_bytes.as_slice());

        // Using the credential public key, verify that sig is a valid signature
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
    ) -> Result<(RequestChallengeResponse, AuthenticationState), WebauthnError> {
        self.generate_challenge_authenticate_options(creds, None)
    }

    /// Authenticate a single credential, with the ability to override the userVerification
    /// policy requested, or extensions in use. If userVerification is `None`, the policy from
    /// registration is used.
    ///
    /// NOTE: Over-riding the UserVerificationPolicy may have SECURITY consequences. You should
    /// understand how this interacts with the single credential in use, and how that may impact
    /// your system security.
    ///
    /// If in doubt, do NOT use this function!
    pub fn generate_challenge_authenticate_credential(
        &self,
        cred: Credential,
        policy: Option<UserVerificationPolicy>,
        extensions: Option<RequestAuthenticationExtensions>,
    ) -> Result<(RequestChallengeResponse, AuthenticationState), WebauthnError> {
        let policy = policy.unwrap_or(cred.registration_policy);
        self.generate_challenge_authenticate_inner(vec![cred], policy, extensions)
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
    /// This error is returning when the set of credentials has a mix of registration
    /// user verification policies.
    /// This is due to an issue with the webauthn standard
    /// as noted at <https://github.com/w3c/webauthn/issues/1510>. What can occur is that
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
    pub fn generate_challenge_authenticate_options(
        &self,
        creds: Vec<Credential>,
        extensions: Option<RequestAuthenticationExtensions>,
    ) -> Result<(RequestChallengeResponse, AuthenticationState), WebauthnError> {
        // Should this filter on cred.verified instead rather than the policy?
        // Or do we need to send Preferred instead of Discouraged due to ctap2.0?
        //
        // https://github.com/kanidm/webauthn-rs/issues/91
        //
        let (verified, unverified): (Vec<Credential>, Vec<Credential>) = creds
            .into_iter()
            .partition(|cred| cred.registration_policy == UserVerificationPolicy::Required);

        match (verified.len(), unverified.len()) {
            (_, 0) => self.generate_challenge_authenticate_inner(
                verified,
                UserVerificationPolicy::Required,
                extensions,
            ),
            (0, _) => self.generate_challenge_authenticate_inner(
                unverified,
                UserVerificationPolicy::Preferred,
                extensions,
            ),
            (_, _) => Err(WebauthnError::InconsistentUserVerificationPolicy),
        }
    }

    /// Begin a discoverable authentication session.
    pub fn generate_challenge_authenticate_discoverable(
        &self,
        policy: UserVerificationPolicy,
        extensions: Option<RequestAuthenticationExtensions>,
    ) -> Result<(RequestChallengeResponse, AuthenticationState), WebauthnError> {
        self.generate_challenge_authenticate_inner(vec![], policy, extensions)
    }

    fn generate_challenge_authenticate_inner(
        &self,
        creds: Vec<Credential>,
        policy: UserVerificationPolicy,
        extensions: Option<RequestAuthenticationExtensions>,
    ) -> Result<(RequestChallengeResponse, AuthenticationState), WebauthnError> {
        let chal = self.generate_challenge();

        // Get the user's existing creds if any.
        let ac = creds
            .iter()
            .map(|cred| AllowCredentials {
                type_: "public-key".to_string(),
                id: cred.cred_id.clone(),
                transports: cred.transports.clone(),
            })
            .collect();

        // Extract the appid from the extensions to store it in the AuthenticationState
        let appid = extensions.as_ref().and_then(|e| e.appid.clone());

        // Store the chal associated to the user.
        // Now put that into the correct challenge format
        let r = RequestChallengeResponse {
            public_key: PublicKeyCredentialRequestOptions {
                challenge: chal.clone().into(),
                timeout: Some(self.authenticator_timeout),
                rp_id: self.rp_id.clone(),
                allow_credentials: ac,
                user_verification: policy,
                extensions,
            },
            mediation: Mediation::None,
        };
        let st = AuthenticationState {
            credentials: creds,
            policy,
            challenge: chal.into(),
            appid,
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
        // ) -> Result<(&'a CredentialID, AuthenticatorData<Authentication>), WebauthnError> {
    ) -> Result<AuthenticationResult, WebauthnError> {
        // Steps 1 through 4 are client side.

        // https://w3c.github.io/webauthn/#verifying-assertion
        // Lookup challenge

        let AuthenticationState {
            credentials: creds,
            policy,
            challenge: chal,
            appid,
        } = state;
        let chal: &ChallengeRef = chal.into();

        // If the allowCredentials option was given when this authentication ceremony was initiated,
        // verify that credential.id identifies one of the public key credentials that were listed in allowCredentials.
        //
        // We always supply allowCredentials in this library, so we expect creds as a vec of credentials
        // that would be equivalent to what was allowed.
        // trace!("rsp: {:?}", rsp);

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
                if cred.cred_id.0 == rsp.raw_id.0 {
                    found_cred = Some(cred);
                    break;
                }
            }

            found_cred.ok_or(WebauthnError::CredentialNotFound)?
        };

        // Identify the user being authenticated and verify that this user is the owner of the public
        // key credential source credentialSource identified by credential.id:

        //  - If the user was identified before the authentication ceremony was initiated, e.g.,
        //  via a username or cookie,
        //      verify that the identified user is the owner of credentialSource. If
        //      response.userHandle is present, let userHandle be its value. Verify that
        //      userHandle also maps to the same user.

        // - If the user was not identified before the authentication ceremony was initiated,
        //      verify that response.userHandle is present, and that the user identified by this
        //      value is the owner of credentialSource.

        // Using credential.id (or credential.rawId, if base64url encoding is inappropriate for your
        // use case), look up the corresponding credential public key and let credentialPublicKey be
        // that credential public key.

        // * Due to the design of this library, in the majority of workflows the user MUST be known
        // before we begin, else we would not have the allowed Credentials list. When we proceed to
        // allowing resident keys (client side discoverable) such as username-less, then we will need
        // to consider how to proceed here. For now, username-less is such a hot-mess due to RK handling
        // being basicly non-existant, that there is no point. As a result, we have already enforced
        // these conditions.

        let auth_data = self.verify_credential_internal(rsp, *policy, chal, cred, appid)?;
        let mut needs_update = false;
        let counter = auth_data.counter;
        let user_verified = auth_data.user_verified;
        let backup_state = auth_data.backup_state;

        let extensions = process_authentication_extensions(&auth_data.extensions);

        if backup_state != cred.backup_state {
            needs_update = true;
        }

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

            if counter > cred.counter {
                needs_update = true;
            }

            if self.require_valid_counter_value && counter_shows_compromise {
                return Err(WebauthnError::CredentialPossibleCompromise);
            }
        }

        Ok(AuthenticationResult {
            cred_id: cred.cred_id.clone(),
            needs_update,
            user_verified,
            backup_state,
            counter,
            extensions,
        })
    }

    fn validate_origin(
        allow_subdomains_origin: bool,
        allow_any_port: bool,
        ccd_url: &url::Url,
        cnf_url: &url::Url,
    ) -> Result<(), WebauthnError> {
        if allow_subdomains_origin {
            match (ccd_url.origin(), cnf_url.origin()) {
                (
                    url::Origin::Tuple(ccd_scheme, ccd_host, ccd_port),
                    url::Origin::Tuple(cnf_scheme, cnf_host, cnf_port),
                ) => {
                    if ccd_scheme != cnf_scheme {
                        debug!("{} != {}", ccd_url, cnf_url);
                        return Err(WebauthnError::InvalidRPOrigin);
                    }

                    if !allow_any_port && ccd_port != cnf_port {
                        debug!("{} != {}", ccd_url, cnf_url);
                        return Err(WebauthnError::InvalidRPOrigin);
                    }

                    let valid = match (ccd_host, cnf_host) {
                        (url::Host::Domain(ccd_domain), url::Host::Domain(cnf_domain)) => {
                            ccd_domain.ends_with(&cnf_domain)
                        }
                        (a, b) => a == b,
                    };

                    if valid {
                        Ok(())
                    } else {
                        debug!("Domain/IP in origin do not match");
                        Err(WebauthnError::InvalidRPOrigin)
                    }
                }
                _ => {
                    debug!("Origin is opaque");
                    Err(WebauthnError::InvalidRPOrigin)
                }
            }
        } else if ccd_url.origin() != cnf_url.origin() || !ccd_url.origin().is_tuple() {
            if ccd_url.host() == cnf_url.host()
                && ccd_url.scheme() == cnf_url.scheme()
                && allow_any_port
            {
                Ok(())
            } else {
                debug!("{} != {}", ccd_url, cnf_url);
                Err(WebauthnError::InvalidRPOrigin)
            }
        } else {
            Ok(())
        }
    }
}

/*
/// The WebauthnConfig type allows site-specific customisation of the Webauthn library.
/// This provides a set of callbacks which are used to supply data to various structures
/// and calls, as well as callbacks to manage data persistence and retrieval.
pub trait WebauthnConfig {
    /// Returns a reference to your relying parties name. This is generally any text identifier
    /// you wish, but should rarely if ever change. Changes to the relying party name may
    /// confuse authenticators and will cause their credentials to be lost.
    ///
    /// Examples of names could be `My Awesome Site`, `https://my-awesome-site.com.au`
    fn get_relying_party_name(&self) -> &str;

    /// Returns a reference to your sites origin. The origin is the URL to your site with
    /// protocol and port. This should rarely, if ever change. In production usage this
    /// value must always be https://, however http://localhost is acceptable for testing
    /// only. We may add warnings or errors for non-https:// urls in the future. Changing this
    /// may cause associated authenticators to lose credentials.
    ///
    /// Examples of this value could be. `https://my-site.com.au`, `https://my-site.com.au:8443`
    fn get_origin(&self) -> &url::Url;

    /// Returns the relying party id. This should never change, and is used as an id
    /// in cryptographic operations and credential scoping. This is defined as the domain name
    /// of the service, minus all protocol, port and location data. For example:
    ///   `https://name:port/path -> name`
    ///
    /// If changed, all associated credentials will be lost in all authenticators.
    ///
    /// Examples of this value for the site `https://my-site.com.au/auth` is `my-site.com.au`
    fn get_relying_party_id(&self) -> &str;

    /// Get the list of valid credential algorithms that this service can accept. Unless you have
    /// speific requirements around this, we advise you leave this function to the default
    /// implementation.
    fn get_credential_algorithms(&self) -> Vec<COSEAlgorithm> {
        vec![COSEAlgorithm::ES256, COSEAlgorithm::RS256]
    }

    /// Return a timeout on how long the authenticator has to respond to a challenge. This value
    /// defaults to 60000 milliseconds. You likely won't need to implement this function, and should
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
    /// See also: <https://www.w3.org/TR/webauthn/#resident-credential>
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
    /// Assess the attestation trustworthiness using the outputs of the verification procedure in step 19, as follows:
    /// * If no attestation was provided, verify that None attestation is acceptable under Relying Party policy.
    /// * If self attestation was used, verify that self attestation is acceptable under Relying Party policy.
    /// * Otherwise, use the X.509 certificates returned as the attestation trust path from the verification
    ///   procedure to verify that the attestation public key either correctly chains up to an acceptable
    ///   root certificate, or is itself an acceptable certificate (i.e., it and the root certificate
    ///   obtained previously may be the same).
    ///
    /// The default implementation of this method rejects Uncertain attestation, and
    /// will "blindly trust" self attestation and the other types as valid.
    /// If you have strict security requirements we strongly recommend you implement this function,
    /// and we may in the future provide a stronger default relying party policy.
    fn policy_verify_trust(&self, pad: ParsedAttestationData) -> Result<(), ()> {
        debug!("policy_verify_trust -> {:?}", pad);
        match pad {
            ParsedAttestationData::Basic(_attest_cert) => Ok(()),
            ParsedAttestationData::Self_ => Ok(()),
            ParsedAttestationData::AttCa(_attest_cert, _ca_chain) => Ok(()),
            ParsedAttestationData::AnonCa(_attest_cert, _ca_chain) => Ok(()),
            ParsedAttestationData::None => Ok(()),
            // TODO: trust is unimplemented here
            ParsedAttestationData::ECDAA => Err(()),
            // We don't trust Uncertain attestations
            ParsedAttestationData::Uncertain => Err(()),
        }
    }

    /// Get the site policy on whether cross origin credentials are allowed.
    ///
    /// A credential is cross origin if the ECMAScript context in which the
    /// credential creation functions were invoked belonged to a different
    /// origin than that of the RP the credential is being created for.
    ///
    /// WARNING: Most browsers do not currently send the `crossOrigin` value so
    /// we assume where the key is absent that the credential was not created in
    /// a cross-origin context.
    fn allow_cross_origin(&self) -> bool {
        false
    }

    /// Allow subdomains of origin to be valid to use credentils from the parent origin. This
    /// exists due to a subtle confusion in the webauthn specification. In
    /// https://www.w3.org/TR/webauthn-2/#scope we see that the relying party ID is intended
    /// to allow effective domains to be validated by the client for the origin that we are
    /// using, however in https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential step
    /// 9 it is requested that origin *equality* is performed. This would disallow subdomains
    /// of the effective domain from being use.
    ///
    /// By default we take the "strict" behaviour to only allow exact origin matches, but some
    /// applications may wish subdomains of origin to valid. Consider idm.example.com and
    /// host.idm.example.com where a credential should be valid for either.
    ///
    /// In most cases you DO NOT need to enable this option.
    fn allow_subdomains_origin(&self) -> bool {
        false
    }
}
*/

#[cfg(test)]
mod tests {
    use crate::constants::CHALLENGE_SIZE_BYTES;
    use crate::core::{CreationChallengeResponse, RegistrationState, WebauthnError};
    use crate::proto::*;
    use crate::WebauthnCore as Webauthn;
    use crate::{internals::*, AttestationFormat};
    use base64urlsafedata::Base64UrlSafeData;
    use url::Url;

    // Test the crypto operations of the webauthn impl

    #[test]
    fn test_registration_yk() {
        let _ = tracing_subscriber::fmt::try_init();
        let wan = Webauthn::new_unsafe_experts_only(
            "http://127.0.0.1:8080/auth",
            "127.0.0.1",
            &Url::parse("http://127.0.0.1:8080").unwrap(),
            None,
            None,
            None,
        );
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
            UserVerificationPolicy::Preferred,
            &zero_chal,
            &[],
            &[COSEAlgorithm::ES256],
            Some(&AttestationCaList {
                cas: vec![AttestationCa::yubico_u2f_root_ca_serial_457200631()],
            }),
            false,
            &RequestRegistrationExtensions::default(),
            true,
        );
        trace!("{:?}", result);
        assert!(result.is_ok());
    }

    // These are vectors from https://github.com/duo-labs/webauthn
    #[test]
    fn test_registration_duo_go() {
        let _ = tracing_subscriber::fmt::try_init();
        let wan = Webauthn::new_unsafe_experts_only(
            "webauthn.io",
            "webauthn.io",
            &Url::parse("https://webauthn.io").unwrap(),
            None,
            None,
            None,
        );

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
            UserVerificationPolicy::Preferred,
            chal.as_ref(),
            &[],
            &[COSEAlgorithm::ES256],
            None,
            false,
            &RequestRegistrationExtensions::default(),
            true,
        );
        trace!("{:?}", result);
        assert!(result.is_ok());
    }

    #[test]
    fn test_registration_packed_attestation() {
        let _ = tracing_subscriber::fmt::try_init();
        let wan = Webauthn::new_unsafe_experts_only(
            "localhost:8443/auth",
            "localhost",
            &Url::parse("https://localhost:8443").unwrap(),
            None,
            None,
            None,
        );

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
            UserVerificationPolicy::Preferred,
            &chal,
            &[],
            &[COSEAlgorithm::ES256],
            None,
            false,
            &RequestRegistrationExtensions::default(),
            false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_registration_packed_attestaion_fails_with_bad_cred_protect() {
        let _ = tracing_subscriber::fmt::try_init();
        let wan = Webauthn::new_unsafe_experts_only(
            "localhost:8080/auth",
            "localhost",
            &Url::parse("http://localhost:8080").unwrap(),
            None,
            None,
            None,
        );

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

        trace!("{:?}", rsp_d);

        let result = wan.register_credential_internal(
            &rsp_d,
            UserVerificationPolicy::Required,
            &chal,
            &[],
            &[COSEAlgorithm::ES256],
            None,
            false,
            &RequestRegistrationExtensions::default(),
            false,
        );
        trace!("{:?}", result);
        assert!(result.is_ok());
    }

    #[test]
    fn test_registration_packed_attestaion_works_with_valid_fido_aaguid_extension() {
        let _ = tracing_subscriber::fmt::try_init();
        let wan = Webauthn::new_unsafe_experts_only(
            "webauthn.firstyear.id.au",
            "webauthn.firstyear.id.au",
            &Url::parse("https://webauthn.firstyear.id.au/compat_test").unwrap(),
            None,
            None,
            None,
        );

        let chal: Base64UrlSafeData =
            serde_json::from_str("\"qabSCYW_PPKKBAW5_qEsPF3Q3prQeYBORfDMArsoKdg\"").unwrap();
        let chal = Challenge::from(chal);

        let rsp = r#"{
            "id": "eKSmfhLUwwmJpuD2IKaTopbbWKFv-qZAE4LXa2FGmTtRpvioMpeFhI8RqdsOGlBoQxJehEQyWyu7ECwPkVL5Hg",
            "rawId": "eKSmfhLUwwmJpuD2IKaTopbbWKFv-qZAE4LXa2FGmTtRpvioMpeFhI8RqdsOGlBoQxJehEQyWyu7ECwPkVL5Hg",
            "response": {
            "attestationObject": "o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIgW2gYNWvUDgxl8LB7rflbuJw_zvJCT5ddfDZNROTy0JYCIQDxuy3JLSHDIrEFYqDifFA_ZHttNfRqJAPgH4hedttVIWN4NWOBWQLBMIICvTCCAaWgAwIBAgIEHo-HNDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbjELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEnMCUGA1UEAwweWXViaWNvIFUyRiBFRSBTZXJpYWwgNTEyNzIyNzQwMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqHn4IzjtFJS6wHBLzH_GY9GycXFZdiQxAcdgURXXwVKeKBwcZzItOEtc1V3T6YGNX9hcIq8ybgxk_CCv4z8jZqNsMGowIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjcwEwYLKwYBBAGC5RwCAQEEBAMCBDAwIQYLKwYBBAGC5RwBAQQEEgQQL8BXn4ETR-qxFrtajbkgKjAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQCGk_9i3w1XedR0jX_I0QInMYqOWA5qOlfBCOlOA8OFaLNmiU_OViS-Sj79fzQRiz2ZN0P3kqGYkWDI_JrgsE49-e4V4-iMBPyCqNy_WBjhCNzCloV3rnn_ZiuUc0497EWXMF1z5uVe4r65zZZ4ygk15TPrY4-OJvq7gXzaRB--mDGDKuX24q2ZL56720xiI4uPjXq0gdbTJjvNv55KV1UDcJiK1YE0QPoDLK22cjyt2PjXuoCfdbQ8_6Clua3RQjLvnZ4UgSY4IzxMpKhzufismOMroZFnYG4VkJ_N20ot_72uRiAkn5pmRqyB5IMtERn-v6pzGogtolp3gn1G0ZAXaGF1dGhEYXRhWMRqubvw35oW-R27M7uxMvr50Xx4LEgmxuxw7O5Y2X71KkUAAAACL8BXn4ETR-qxFrtajbkgKgBAeKSmfhLUwwmJpuD2IKaTopbbWKFv-qZAE4LXa2FGmTtRpvioMpeFhI8RqdsOGlBoQxJehEQyWyu7ECwPkVL5HqUBAgMmIAEhWCBT_WnxT3SKAIGfnEKUi7xtZmnlcZRV-63N21154_r-xyJYIGuwu6BK1zp6D6EQ94VOcK1DuFWr58xI_PbeP5F1Nfe6",
            "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJxYWJTQ1lXX1BQS0tCQVc1X3FFc1BGM1EzcHJRZVlCT1JmRE1BcnNvS2RnIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cHM6Ly93ZWJhdXRobi5maXJzdHllYXIuaWQuYXUiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0"
            },
            "type": "public-key"
        }"#;

        let rsp_d: RegisterPublicKeyCredential = serde_json::from_str(rsp).unwrap();

        trace!("{:?}", rsp_d);

        let result = wan.register_credential_internal(
            &rsp_d,
            UserVerificationPolicy::Required,
            &chal,
            &[],
            &[COSEAlgorithm::ES256],
            None,
            false,
            &RequestRegistrationExtensions::default(),
            false,
        );
        trace!("{:?}", result);
        assert!(result.is_ok());
    }

    #[test]
    fn test_registration_packed_attestaion_fails_with_invalid_fido_aaguid_extension() {
        let _ = tracing_subscriber::fmt::try_init();
        let wan = Webauthn::new_unsafe_experts_only(
            "webauthn.firstyear.id.au",
            "webauthn.firstyear.id.au",
            &Url::parse("https://webauthn.firstyear.id.au/compat_test").unwrap(),
            None,
            None,
            None,
        );

        let chal: Base64UrlSafeData =
            serde_json::from_str("\"qabSCYW_PPKKBAW5_qEsPF3Q3prQeYBORfDMArsoKdg\"").unwrap();
        let chal = Challenge::from(chal);

        let rsp = r#"{
            "id": "eKSmfhLUwwmJpuD2IKaTopbbWKFv-qZAE4LXa2FGmTtRpvioMpeFhI8RqdsOGlBoQxJehEQyWyu7ECwPkVL5Hg",
            "rawId": "eKSmfhLUwwmJpuD2IKaTopbbWKFv-qZAE4LXa2FGmTtRpvioMpeFhI8RqdsOGlBoQxJehEQyWyu7ECwPkVL5Hg",
            "response": {
            "attestationObject": "o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIgW2gYNWvUDgxl8LB7rflbuJw_zvJCT5ddfDZNROTy0JYCIQDxuy3JLSHDIrEFYqDifFA_ZHttNfRqJAPgH4hedttVIWN4NWOBWQLBMIICvTCCAaWgAwIBAgIEHo-HNDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbjELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEnMCUGA1UEAwweWXViaWNvIFUyRiBFRSBTZXJpYWwgNTEyNzIyNzQwMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqHn4IzjtFJS6wHBLzH_GY9GycXFZdiQxAcdgURXXwVKeKBwcZzItOEtc1V3T6YGNX9hcIq8ybgxk_CCv4z8jZqNsMGowIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjcwEwYLKwYBBAGC5RwCAQEEBAMCBDAwIQYLKwYBBAGC5RwBAQQEEgQQXXXXXXXXXXXXXXXXXXXXXjAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQCGk_9i3w1XedR0jX_I0QInMYqOWA5qOlfBCOlOA8OFaLNmiU_OViS-Sj79fzQRiz2ZN0P3kqGYkWDI_JrgsE49-e4V4-iMBPyCqNy_WBjhCNzCloV3rnn_ZiuUc0497EWXMF1z5uVe4r65zZZ4ygk15TPrY4-OJvq7gXzaRB--mDGDKuX24q2ZL56720xiI4uPjXq0gdbTJjvNv55KV1UDcJiK1YE0QPoDLK22cjyt2PjXuoCfdbQ8_6Clua3RQjLvnZ4UgSY4IzxMpKhzufismOMroZFnYG4VkJ_N20ot_72uRiAkn5pmRqyB5IMtERn-v6pzGogtolp3gn1G0ZAXaGF1dGhEYXRhWMRqubvw35oW-R27M7uxMvr50Xx4LEgmxuxw7O5Y2X71KkUAAAACL8BXn4ETR-qxFrtajbkgKgBAeKSmfhLUwwmJpuD2IKaTopbbWKFv-qZAE4LXa2FGmTtRpvioMpeFhI8RqdsOGlBoQxJehEQyWyu7ECwPkVL5HqUBAgMmIAEhWCBT_WnxT3SKAIGfnEKUi7xtZmnlcZRV-63N21154_r-xyJYIGuwu6BK1zp6D6EQ94VOcK1DuFWr58xI_PbeP5F1Nfe6",
            "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJxYWJTQ1lXX1BQS0tCQVc1X3FFc1BGM1EzcHJRZVlCT1JmRE1BcnNvS2RnIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cHM6Ly93ZWJhdXRobi5maXJzdHllYXIuaWQuYXUiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0"
            },
            "type": "public-key"
        }"#;

        let rsp_d: RegisterPublicKeyCredential = serde_json::from_str(rsp).unwrap();

        trace!("{:?}", rsp_d);

        let result = wan.register_credential_internal(
            &rsp_d,
            UserVerificationPolicy::Required,
            &chal,
            &[],
            &[COSEAlgorithm::ES256],
            None,
            false,
            &RequestRegistrationExtensions::default(),
            false,
        );
        trace!("{:?}", result);
        assert!(matches!(
            result,
            Err(WebauthnError::AttestationCertificateAAGUIDMismatch)
        ));
    }

    #[test]
    fn test_authentication() {
        let _ = tracing_subscriber::fmt::try_init();
        let wan = Webauthn::new_unsafe_experts_only(
            "localhost:8080/auth",
            "localhost",
            &Url::parse("http://localhost:8080").unwrap(),
            None,
            None,
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
            cred_id: Base64UrlSafeData(vec![
                106, 223, 133, 124, 161, 172, 56, 141, 181, 18, 27, 66, 187, 181, 113, 251, 187,
                123, 20, 169, 41, 80, 236, 138, 92, 137, 4, 4, 16, 255, 188, 47, 158, 202, 111,
                192, 117, 110, 152, 245, 95, 22, 200, 172, 71, 154, 40, 181, 212, 64, 80, 17, 238,
                238, 21, 13, 27, 145, 140, 27, 208, 101, 166, 81,
            ]),
            cred: COSEKey {
                type_: COSEAlgorithm::ES256,
                key: COSEKeyType::EC_EC2(COSEEC2Key {
                    curve: ECDSACurve::SECP256R1,
                    x: [
                        46, 121, 76, 233, 118, 208, 250, 74, 227, 182, 8, 145, 45, 46, 5, 9, 199,
                        186, 84, 83, 7, 237, 130, 73, 16, 90, 17, 54, 33, 255, 54, 56,
                    ]
                    .to_vec()
                    .into(),
                    y: [
                        117, 105, 1, 23, 253, 223, 67, 135, 253, 219, 253, 223, 17, 247, 91, 197,
                        205, 225, 143, 59, 47, 138, 70, 120, 74, 155, 177, 177, 166, 233, 48, 71,
                    ]
                    .to_vec()
                    .into(),
                }),
            },
            counter: 1,
            transports: None,
            user_verified: false,
            backup_eligible: false,
            backup_state: false,
            registration_policy: UserVerificationPolicy::Discouraged_DO_NOT_USE,
            extensions: RegisteredExtensions::none(),
            attestation: ParsedAttestation {
                data: ParsedAttestationData::None,
                metadata: AttestationMetadata::None,
            },
            attestation_format: AttestationFormat::None,
        };

        // Persist it to our fake db.

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
            UserVerificationPolicy::Discouraged_DO_NOT_USE,
            &zero_chal,
            &cred,
            &None,
        );
        trace!("RESULT: {:?}", r);
        assert!(r.is_ok());

        // Captured authentication attempt, this mentions the appid extension has been used, but we still provide a valid RPID
        let rsp = r#"
        {
            "id":"at-FfKGsOI21EhtCu7Vx-7t7FKkpUOyKXIkEBBD_vC-eym_AdW6Y9V8WyKxHmii11EBQEe7uFQ0bkYwb0GWmUQ",
            "rawId":"at-FfKGsOI21EhtCu7Vx-7t7FKkpUOyKXIkEBBD_vC-eym_AdW6Y9V8WyKxHmii11EBQEe7uFQ0bkYwb0GWmUQ",
            "extensions": {
                "appid": true
            }, 
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

        // Now verify it, as the RPID is valid, the appid should be ignored
        let r = wan.verify_credential_internal(
            &rsp_d,
            UserVerificationPolicy::Discouraged_DO_NOT_USE,
            &zero_chal,
            &cred,
            &Some(String::from("https://unused.local")),
        );
        trace!("RESULT: {:?}", r);
        assert!(r.is_ok());
    }

    #[test]
    fn test_authentication_appid() {
        let _ = tracing_subscriber::fmt::try_init();
        let wan = Webauthn::new_unsafe_experts_only(
            "https://testing.local",
            "testing.local",
            &Url::parse("https://testing.local").unwrap(),
            None,
            None,
            None,
        );

        // Generated by a yubico 5
        // Make a "fake" challenge, where we know what the values should be ....

        let zero_chal = Challenge::new(vec![
            160, 127, 213, 174, 150, 36, 228, 190, 41, 61, 216, 14, 171, 191, 75, 203, 99, 59, 4,
            252, 49, 90, 235, 36, 220, 165, 159, 201, 58, 225, 248, 142,
        ]);

        // Create the fake credential that we know is associated
        let cred = Credential {
            counter: 1,
            transports: None,
            cred_id: Base64UrlSafeData(vec![
                179, 64, 237, 0, 28, 248, 197, 30, 213, 228, 250, 139, 28, 11, 156, 130, 69, 242,
                21, 48, 84, 77, 103, 163, 66, 204, 167, 147, 82, 214, 212,
            ]),
            cred: COSEKey {
                type_: COSEAlgorithm::ES256,
                key: COSEKeyType::EC_EC2(COSEEC2Key {
                    curve: ECDSACurve::SECP256R1,
                    x: [
                        187, 71, 18, 101, 166, 110, 166, 38, 116, 119, 74, 4, 183, 104, 24, 46,
                        245, 24, 227, 143, 161, 136, 37, 186, 140, 221, 228, 115, 81, 175, 50, 51,
                    ]
                    .to_vec()
                    .into(),
                    y: [
                        13, 59, 59, 158, 149, 197, 116, 228, 99, 12, 235, 185, 190, 110, 251, 154,
                        226, 143, 75, 26, 44, 136, 244, 245, 243, 4, 40, 223, 22, 253, 224, 95,
                    ]
                    .to_vec()
                    .into(),
                }),
            },
            user_verified: false,
            backup_eligible: false,
            backup_state: false,
            registration_policy: UserVerificationPolicy::Discouraged_DO_NOT_USE,
            extensions: RegisteredExtensions::none(),
            attestation: ParsedAttestation {
                data: ParsedAttestationData::None,
                metadata: AttestationMetadata::None,
            },
            attestation_format: AttestationFormat::None,
        };

        // Persist it to our fake db.

        // Captured authentication attempt, this client has used the appid extension
        let rsp = r#"
        {
            "id": "z077A6SzdvA3rDRG6tfnTf9TMFVtfLYe1mh27mRXgBZU6TXA_nCJAi6WnLLq1p3d0yj3n62_4yJMu80o4O8kkw",
            "rawId": "z077A6SzdvA3rDRG6tfnTf9TMFVtfLYe1mh27mRXgBZU6TXA_nCJAi6WnLLq1p3d0yj3n62_4yJMu80o4O8kkw",
            "type": "public-key",
            "extensions": {
                "appid": true
            },
            "response": {
                "authenticatorData": "UN6WJxNDzSGdqrQoPbqYbsZdIxtC9vfU9iGe5i1pCTYBAAAAuQ",
                "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJvSF9WcnBZazVMNHBQZGdPcTc5THkyTTdCUHd4V3VzazNLV2Z5VHJoLUk0IiwiY2xpZW50RXh0ZW5zaW9ucyI6eyJhcHBpZCI6Imh0dHBzOi8vdGVzdGluZy5sb2NhbC9hcHAtaWQuanNvbiJ9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vdGVzdGluZy5sb2NhbCIsInR5cGUiOiJ3ZWJhdXRobi5nZXQifQ",
                "signature": "MEUCIEw2O8LYZj6IKbjP6FuvdcL2MoDBY6LqJWuhteje3H7eAiEAvzRLSg70tkrGnZqpQIZyv-zaizNpCtyr4U3SZ-E2-f4"
            }
        }
        "#;
        let rsp_d: PublicKeyCredential = serde_json::from_str(rsp).unwrap();

        // Now verify it!
        let r = wan.verify_credential_internal(
            &rsp_d,
            UserVerificationPolicy::Discouraged_DO_NOT_USE,
            &zero_chal,
            &cred,
            &Some(String::from("https://testing.local/app-id.json")),
        );
        trace!("RESULT: {:?}", r);
        assert!(r.is_ok());

        // Captured authentication attempt, this client has NOT used the appid extension, but is providing the appid anyway
        let rsp = r#"
        {
            "id": "z077A6SzdvA3rDRG6tfnTf9TMFVtfLYe1mh27mRXgBZU6TXA_nCJAi6WnLLq1p3d0yj3n62_4yJMu80o4O8kkw",
            "rawId": "z077A6SzdvA3rDRG6tfnTf9TMFVtfLYe1mh27mRXgBZU6TXA_nCJAi6WnLLq1p3d0yj3n62_4yJMu80o4O8kkw",
            "type": "public-key",
            "extensions": {
                "appid": false
            },
            "response": {
                "authenticatorData": "UN6WJxNDzSGdqrQoPbqYbsZdIxtC9vfU9iGe5i1pCTYBAAAAuQ",
                "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJvSF9WcnBZazVMNHBQZGdPcTc5THkyTTdCUHd4V3VzazNLV2Z5VHJoLUk0IiwiY2xpZW50RXh0ZW5zaW9ucyI6eyJhcHBpZCI6Imh0dHBzOi8vdGVzdGluZy5sb2NhbC9hcHAtaWQuanNvbiJ9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vdGVzdGluZy5sb2NhbCIsInR5cGUiOiJ3ZWJhdXRobi5nZXQifQ",
                "signature": "MEUCIEw2O8LYZj6IKbjP6FuvdcL2MoDBY6LqJWuhteje3H7eAiEAvzRLSg70tkrGnZqpQIZyv-zaizNpCtyr4U3SZ-E2-f4"
            }
        }
        "#;
        let rsp_d: PublicKeyCredential = serde_json::from_str(rsp).unwrap();

        // This will verify against the RPID while the client provided an appid, so it should fail
        let r = wan.verify_credential_internal(
            &rsp_d,
            UserVerificationPolicy::Discouraged_DO_NOT_USE,
            &zero_chal,
            &cred,
            &None,
        );
        trace!("RESULT: {:?}", r);
        assert!(r.is_err());
    }

    #[test]
    fn test_registration_ipados_5ci() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .try_init();
        let wan = Webauthn::new_unsafe_experts_only(
            "https://172.20.0.141:8443/auth",
            "172.20.0.141",
            &Url::parse("https://172.20.0.141:8443").unwrap(),
            None,
            None,
            None,
        );

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
                transports: None,
            },
            type_: "public-key".to_string(),
            extensions: RegistrationExtensionsClientOutputs::default(),
        };

        // Assert this fails when the attestaion is missing.
        let result = wan.register_credential_internal(
            &rsp_d,
            UserVerificationPolicy::Preferred,
            &chal,
            &[],
            &[COSEAlgorithm::ES256],
            Some(&AttestationCaList {
                // This is what introduces the failure!
                cas: Vec::with_capacity(0),
            }),
            false,
            &RequestRegistrationExtensions::default(),
            false,
        );
        trace!("{:?}", result);
        assert!(matches!(
            result,
            Err(WebauthnError::MissingAttestationCaList)
        ));

        let result = wan.register_credential_internal(
            &rsp_d,
            UserVerificationPolicy::Preferred,
            &chal,
            &[],
            &[COSEAlgorithm::ES256],
            Some(&AttestationCaList {
                cas: vec![
                    AttestationCa::apple_webauthn_root_ca(),
                    // Exclude the matching CA!
                    // AttestationCa::yubico_u2f_root_ca_serial_457200631(),
                    AttestationCa::microsoft_tpm_root_certificate_authority_2014(),
                ],
            }),
            false,
            &RequestRegistrationExtensions::default(),
            false,
        );
        trace!("{:?}", result);
        assert!(matches!(
            result,
            Err(WebauthnError::AttestationChainNotTrusted(_))
        ));

        let result = wan.register_credential_internal(
            &rsp_d,
            UserVerificationPolicy::Preferred,
            &chal,
            &[],
            &[COSEAlgorithm::ES256],
            Some(&AttestationCaList {
                cas: vec![
                    AttestationCa::apple_webauthn_root_ca(),
                    AttestationCa::yubico_u2f_root_ca_serial_457200631(),
                    AttestationCa::microsoft_tpm_root_certificate_authority_2014(),
                ],
            }),
            false,
            &RequestRegistrationExtensions::default(),
            false,
        );
        trace!("{:?}", result);
        assert!(result.is_ok());
    }

    #[test]
    fn test_deserialise_ipados_5ci() {
        // This is to test migration between the x/y byte array to base64 format.
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .try_init();
        let ser_cred = r#"{"cred_id":"uZcVDBVS68E_MtAgeQpElJxldF_6cY9sSvbWqx_qRh8wiu42lyRBRmh5yFeD_r9k130dMbFHBHI9RTFgdJQIzQ","cred":{"type_":"ES256","key":{"EC_EC2":{"curve":"SECP256R1","x":[194,126,127,109,252,23,131,21,252,6,223,99,44,254,140,27,230,17,94,5,133,28,104,41,144,69,171,149,161,26,200,243],"y":[143,123,183,156,24,178,21,248,117,159,162,69,171,52,188,252,26,59,6,47,103,92,19,58,117,103,249,0,219,8,95,196]}}},"counter":2,"user_verified":false,"backup_eligible":false,"backup_state":false,"registration_policy":"preferred","extensions":{"cred_protect":"NotRequested","hmac_create_secret":"NotRequested"},"attestation":{"data":{"Basic":["MIICvTCCAaWgAwIBAgIEK_F8eDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbjELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEnMCUGA1UEAwweWXViaWNvIFUyRiBFRSBTZXJpYWwgNzM3MjQ2MzI4MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEdMLHhCPIcS6bSPJZWGb8cECuTN8H13fVha8Ek5nt-pI8vrSflxb59Vp4bDQlH8jzXj3oW1ZwUDjHC6EnGWB5i6NsMGowIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjcwEwYLKwYBBAGC5RwCAQEEBAMCAiQwIQYLKwYBBAGC5RwBAQQEEgQQxe9V_62aS5-1gK3rr-Am0DAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQCLbpN2nXhNbunZANJxAn_Cd-S4JuZsObnUiLnLLS0FPWa01TY8F7oJ8bE-aFa4kTe6NQQfi8-yiZrQ8N-JL4f7gNdQPSrH-r3iFd4SvroDe1jaJO4J9LeiFjmRdcVa-5cqNF4G1fPCofvw9W4lKnObuPakr0x_icdVq1MXhYdUtQk6Zr5mBnc4FhN9qi7DXqLHD5G7ZFUmGwfIcD2-0m1f1mwQS8yRD5-_aDCf3vutwddoi3crtivzyromwbKklR4qHunJ75LGZLZA8pJ_mXnUQ6TTsgRqPvPXgQPbSyGMf2z_DIPbQqCD_Bmc4dj9o6LozheBdDtcZCAjSPTAd_ui"]},"metadata":"None"},"attestation_format":"Packed"}"#;
        let cred: Credential = serde_json::from_str(ser_cred).unwrap();
        trace!("{:?}", cred);
    }

    #[test]
    fn test_win_hello_attest_none() {
        let _ = tracing_subscriber::fmt::try_init();
        let wan = Webauthn::new_unsafe_experts_only(
            "https://etools-dev.example.com:8080/auth",
            "etools-dev.example.com",
            &Url::parse("https://etools-dev.example.com:8080").unwrap(),
            None,
            None,
            None,
        );
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
                transports: None,
            },
            type_: "public-key".to_string(),
            extensions: RegistrationExtensionsClientOutputs::default(),
        };

        let result = wan.register_credential_internal(
            &rsp_d,
            UserVerificationPolicy::Required,
            &chal,
            &[],
            &[COSEAlgorithm::RS256],
            None,
            false,
            &RequestRegistrationExtensions::default(),
            true,
        );
        trace!("{:?}", result);
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
            extensions: AuthenticationExtensionsClientOutputs::default(),
            type_: "public-key".to_string(),
        };

        let r = wan.verify_credential_internal(
            &rsp_d,
            UserVerificationPolicy::Required,
            &chal,
            &cred,
            &None,
        );
        trace!("RESULT: {:?}", r);
        assert!(r.is_ok());
    }

    #[test]
    fn test_win_hello_attest_tpm() {
        let _ = tracing_subscriber::fmt::try_init();
        let wan = Webauthn::new_unsafe_experts_only(
            "https://etools-dev.example.com:8080/auth",
            "etools-dev.example.com",
            &Url::parse("https://etools-dev.example.com:8080").unwrap(),
            None,
            None,
            None,
        );

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
                transports: None,
            },
            type_: "public-key".to_string(),
            extensions: RegistrationExtensionsClientOutputs::default(),
        };

        let result = wan.register_credential_internal(
            &rsp_d,
            UserVerificationPolicy::Required,
            &chal,
            &[],
            &[COSEAlgorithm::RS256],
            Some(&AttestationCaList {
                cas: vec![AttestationCa::microsoft_tpm_root_certificate_authority_2014()],
            }),
            false,
            &RequestRegistrationExtensions::default(),
            true,
        );
        trace!("{:?}", result);
        if cfg!(feature = "insecure_rs1") {
            assert!(result.is_ok());
        } else {
            assert!(matches!(
                result,
                Err(WebauthnError::CredentialInsecureCryptography)
            ))
        }
    }

    fn register_userid(
        user_unique_id: &[u8],
        name: &str,
        display_name: &str,
    ) -> Result<(CreationChallengeResponse, RegistrationState), WebauthnError> {
        let wan = Webauthn::new_unsafe_experts_only(
            "https://etools-dev.example.com:8080/auth",
            "etools-dev.example.com",
            &Url::parse("https://etools-dev.example.com:8080").unwrap(),
            None,
            None,
            None,
        );

        let policy = true;

        wan.generate_challenge_register(user_unique_id, name, display_name, policy)
    }

    #[test]
    fn test_registration_userid_states() {
        assert!(matches!(
            register_userid(&[], "an name", "an name"),
            Err(WebauthnError::InvalidUsername)
        ));
        assert!(matches!(
            register_userid(&[0, 1, 2, 3], "an name", ""),
            Err(WebauthnError::InvalidUsername)
        ));
        assert!(matches!(
            register_userid(&[0, 1, 2, 3], "", "an_name"),
            Err(WebauthnError::InvalidUsername)
        ));
        assert!(register_userid(&[0, 1, 2, 3], "fizzbuzz", "an name").is_ok());
    }

    #[test]
    fn test_touchid_attest_apple_anonymous() {
        let _ = tracing_subscriber::fmt::try_init();
        let wan = Webauthn::new_unsafe_experts_only(
            "https://spectral.local:8443/auth",
            "spectral.local",
            &Url::parse("https://spectral.local:8443").unwrap(),
            None,
            None,
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
                transports: None,
            },
            type_: "public-key".to_string(),
            extensions: RegistrationExtensionsClientOutputs::default(),
        };

        let result = wan.register_credential_internal(
            &rsp_d,
            UserVerificationPolicy::Required,
            &chal,
            &[],
            &[
                COSEAlgorithm::ES256,
                COSEAlgorithm::ES384,
                COSEAlgorithm::ES512,
                COSEAlgorithm::RS256,
                COSEAlgorithm::RS384,
                COSEAlgorithm::RS512,
                COSEAlgorithm::PS256,
                COSEAlgorithm::PS384,
                COSEAlgorithm::PS512,
                COSEAlgorithm::EDDSA,
            ],
            Some(&AttestationCaList {
                cas: vec![AttestationCa::apple_webauthn_root_ca()],
            }),
            // Must disable time checks because the submission is limited to 5 days.
            true,
            &RequestRegistrationExtensions::default(),
            // Don't allow passkeys
            false,
        );
        debug!("{:?}", result);
        assert!(result.is_ok());

        let result = wan.register_credential_internal(
            &rsp_d,
            UserVerificationPolicy::Required,
            &chal,
            &[],
            &[
                COSEAlgorithm::ES256,
                COSEAlgorithm::ES384,
                COSEAlgorithm::ES512,
                COSEAlgorithm::RS256,
                COSEAlgorithm::RS384,
                COSEAlgorithm::RS512,
                COSEAlgorithm::PS256,
                COSEAlgorithm::PS384,
                COSEAlgorithm::PS512,
                COSEAlgorithm::EDDSA,
            ],
            Some(&AttestationCaList {
                cas: vec![AttestationCa::apple_webauthn_root_ca()],
            }),
            // Must disable time checks because the submission is limited to 5 days.
            true,
            &RequestRegistrationExtensions::default(),
            // Allow them.
            true,
        );
        debug!("{:?}", result);
        assert!(result.is_ok());
    }

    #[test]
    fn test_touchid_attest_apple_anonymous_fails_with_invalid_nonce_extension() {
        let _ = tracing_subscriber::fmt::try_init();
        let wan = Webauthn::new_unsafe_experts_only(
            "https://spectral.local:8443/auth",
            "spectral.local",
            &Url::parse("https://spectral.local:8443").unwrap(),
            None,
            None,
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
                    100, 8, 2, 4, 38, 48, 36, 161, 34, 4, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 48, 10, 6, 8, 42,
                    134, 72, 206, 61, 4, 3, 2, 3, 104, 0, 48, 101, 2, 48, 14, 242, 134, 73, 12, 48,
                    2, 103, 184, 132, 187, 132, 124, 204, 63, 148, 168, 78, 225, 227, 161, 240,
                    147, 187, 90, 216, 65, 159, 90, 106, 102, 249, 56, 156, 201, 214, 182, 15, 173,
                    187, 167, 243, 127, 234, 138, 41, 50, 62, 2, 49, 0, 198, 15, 10, 182, 142, 103,
                    84, 7, 18, 0, 231, 130, 214, 26, 64, 58, 17, 118, 66, 14, 198, 244, 58, 211, 2,
                    97, 236, 163, 116, 124, 73, 166, 69, 69, 112, 107, 228, 83, 104, 91, 205, 20,
                    203, 250, 126, 29, 190, 42, 89, 2, 56, 48, 130, 2, 52, 48, 130, 1, 186, 160, 3,
                    2, 1, 2, 2, 16, 86, 37, 83, 149, 199, 167, 251, 64, 235, 226, 40, 216, 38, 8,
                    83, 182, 48, 10, 6, 8, 42, 134, 72, 206, 61, 4, 3, 3, 48, 75, 49, 31, 48, 29,
                    6, 3, 85, 4, 3, 12, 22, 65, 112, 112, 108, 101, 32, 87, 101, 98, 65, 117, 116,
                    104, 110, 32, 82, 111, 111, 116, 32, 67, 65, 49, 19, 48, 17, 6, 3, 85, 4, 10,
                    12, 10, 65, 112, 112, 108, 101, 32, 73, 110, 99, 46, 49, 19, 48, 17, 6, 3, 85,
                    4, 8, 12, 10, 67, 97, 108, 105, 102, 111, 114, 110, 105, 97, 48, 30, 23, 13,
                    50, 48, 48, 51, 49, 56, 49, 56, 51, 56, 48, 49, 90, 23, 13, 51, 48, 48, 51, 49,
                    51, 48, 48, 48, 48, 48, 48, 90, 48, 72, 49, 28, 48, 26, 6, 3, 85, 4, 3, 12, 19,
                    65, 112, 112, 108, 101, 32, 87, 101, 98, 65, 117, 116, 104, 110, 32, 67, 65,
                    32, 49, 49, 19, 48, 17, 6, 3, 85, 4, 10, 12, 10, 65, 112, 112, 108, 101, 32,
                    73, 110, 99, 46, 49, 19, 48, 17, 6, 3, 85, 4, 8, 12, 10, 67, 97, 108, 105, 102,
                    111, 114, 110, 105, 97, 48, 118, 48, 16, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6,
                    5, 43, 129, 4, 0, 34, 3, 98, 0, 4, 131, 46, 135, 47, 38, 20, 145, 129, 2, 37,
                    185, 245, 252, 214, 187, 99, 120, 181, 245, 95, 63, 203, 4, 91, 199, 53, 153,
                    52, 117, 253, 84, 144, 68, 223, 155, 254, 25, 33, 23, 101, 198, 154, 29, 218,
                    5, 11, 56, 212, 80, 131, 64, 26, 67, 79, 178, 77, 17, 45, 86, 195, 225, 207,
                    191, 203, 152, 145, 254, 192, 105, 96, 129, 190, 249, 108, 188, 119, 200, 141,
                    221, 175, 70, 165, 174, 225, 221, 81, 91, 90, 250, 171, 147, 190, 156, 11, 38,
                    145, 163, 102, 48, 100, 48, 18, 6, 3, 85, 29, 19, 1, 1, 255, 4, 8, 48, 6, 1, 1,
                    255, 2, 1, 0, 48, 31, 6, 3, 85, 29, 35, 4, 24, 48, 22, 128, 20, 38, 215, 100,
                    217, 197, 120, 194, 90, 103, 209, 167, 222, 107, 18, 208, 27, 99, 241, 198,
                    215, 48, 29, 6, 3, 85, 29, 14, 4, 22, 4, 20, 235, 174, 130, 196, 255, 161, 172,
                    91, 81, 212, 207, 36, 97, 5, 0, 190, 99, 189, 119, 136, 48, 14, 6, 3, 85, 29,
                    15, 1, 1, 255, 4, 4, 3, 2, 1, 6, 48, 10, 6, 8, 42, 134, 72, 206, 61, 4, 3, 3,
                    3, 104, 0, 48, 101, 2, 49, 0, 221, 139, 26, 52, 129, 165, 250, 217, 219, 180,
                    231, 101, 123, 132, 30, 20, 76, 39, 183, 91, 135, 106, 65, 134, 194, 177, 71,
                    87, 80, 51, 114, 39, 239, 229, 84, 69, 126, 246, 72, 149, 12, 99, 46, 92, 72,
                    62, 112, 193, 2, 48, 44, 138, 96, 68, 220, 32, 31, 207, 229, 155, 195, 77, 41,
                    48, 193, 72, 120, 81, 217, 96, 237, 106, 117, 241, 235, 74, 202, 190, 56, 205,
                    37, 184, 151, 208, 200, 5, 190, 240, 199, 247, 139, 7, 165, 113, 198, 232, 14,
                    7, 104, 97, 117, 116, 104, 68, 97, 116, 97, 88, 152, 218, 20, 177, 242, 169,
                    30, 45, 223, 21, 45, 254, 74, 34, 125, 188, 96, 11, 1, 71, 41, 58, 94, 252,
                    180, 169, 243, 209, 21, 231, 138, 182, 91, 69, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20, 187, 251, 101, 136, 87, 254, 105, 116, 75,
                    131, 213, 200, 207, 228, 174, 67, 69, 193, 149, 177, 165, 1, 2, 3, 38, 32, 1,
                    33, 88, 32, 212, 248, 99, 135, 245, 78, 94, 245, 231, 22, 62, 226, 45, 40, 215,
                    4, 251, 188, 180, 125, 22, 236, 133, 161, 234, 78, 251, 105, 11, 119, 148, 144,
                    34, 88, 32, 105, 249, 199, 167, 152, 173, 94, 147, 57, 2, 250, 21, 5, 51, 116,
                    174, 217, 39, 160, 35, 12, 249, 120, 237, 52, 148, 171, 134, 138, 205, 26, 173,
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
                transports: None,
            },
            type_: "public-key".to_string(),
            extensions: RegistrationExtensionsClientOutputs::default(),
        };

        let result = wan.register_credential_internal(
            &rsp_d,
            UserVerificationPolicy::Required,
            &chal,
            &[],
            &[
                COSEAlgorithm::ES256,
                COSEAlgorithm::ES384,
                COSEAlgorithm::ES512,
                COSEAlgorithm::RS256,
                COSEAlgorithm::RS384,
                COSEAlgorithm::RS512,
                COSEAlgorithm::PS256,
                COSEAlgorithm::PS384,
                COSEAlgorithm::PS512,
                COSEAlgorithm::EDDSA,
            ],
            Some(&AttestationCaList {
                cas: vec![AttestationCa::apple_webauthn_root_ca()],
            }),
            // Must disable time checks because the submission is limited to 5 days.
            true,
            &RequestRegistrationExtensions::default(),
            false,
        );
        debug!("{:?}", result);
        assert!(matches!(
            result,
            Err(WebauthnError::AttestationCertificateNonceMismatch)
        ));
    }

    #[test]
    fn test_uv_consistency() {
        let _ = tracing_subscriber::fmt::try_init();
        let wan = Webauthn::new_unsafe_experts_only(
            "http://127.0.0.1:8080/auth",
            "127.0.0.1",
            &Url::parse("http://127.0.0.1:8080").unwrap(),
            None,
            None,
            None,
        );

        // Given two credentials with differening policy
        let mut creds = vec![
            Credential {
                cred_id: Base64UrlSafeData(vec![
                    205, 198, 18, 130, 133, 220, 73, 23, 199, 211, 240, 143, 220, 154, 172, 117,
                    91, 18, 164, 211, 24, 147, 16, 203, 118, 76, 33, 65, 31, 92, 236, 211, 79, 67,
                    240, 30, 65, 247, 46, 134, 19, 136, 170, 209, 11, 115, 37, 12, 88, 244, 244,
                    240, 148, 132, 191, 165, 150, 166, 252, 39, 97, 137, 21, 186,
                ]),
                cred: COSEKey {
                    type_: COSEAlgorithm::ES256,
                    key: COSEKeyType::EC_EC2(COSEEC2Key {
                        curve: ECDSACurve::SECP256R1,
                        x: [
                            131, 160, 173, 103, 102, 41, 186, 183, 60, 175, 136, 103, 167, 145,
                            239, 235, 216, 80, 109, 26, 218, 187, 146, 77, 5, 173, 143, 33, 126,
                            119, 197, 116,
                        ]
                        .to_vec()
                        .into(),
                        y: [
                            59, 202, 240, 192, 92, 25, 186, 100, 135, 111, 53, 194, 234, 134, 249,
                            249, 30, 22, 70, 58, 81, 250, 141, 38, 217, 9, 44, 121, 162, 230, 197,
                            87,
                        ]
                        .to_vec()
                        .into(),
                    }),
                },
                counter: 0,
                transports: None,
                user_verified: false,
                backup_eligible: false,
                backup_state: false,
                registration_policy: UserVerificationPolicy::Discouraged_DO_NOT_USE,
                extensions: RegisteredExtensions::none(),
                attestation: ParsedAttestation {
                    data: ParsedAttestationData::None,
                    metadata: AttestationMetadata::None,
                },
                attestation_format: AttestationFormat::None,
            },
            Credential {
                cred_id: Base64UrlSafeData(vec![
                    211, 204, 163, 253, 101, 149, 83, 136, 242, 175, 211, 104, 215, 131, 122, 175,
                    187, 84, 13, 3, 21, 24, 11, 138, 50, 137, 55, 225, 180, 109, 49, 28, 98, 8, 28,
                    181, 149, 241, 106, 124, 110, 149, 154, 198, 23, 8, 8, 4, 41, 69, 236, 203,
                    122, 120, 204, 174, 28, 58, 171, 43, 218, 81, 195, 177,
                ]),
                cred: COSEKey {
                    type_: COSEAlgorithm::ES256,
                    key: COSEKeyType::EC_EC2(COSEEC2Key {
                        curve: ECDSACurve::SECP256R1,
                        x: [
                            87, 236, 127, 24, 222, 164, 79, 139, 67, 77, 159, 33, 76, 155, 161,
                            155, 234, 151, 203, 142, 136, 87, 77, 177, 27, 67, 248, 104, 233, 156,
                            15, 51,
                        ]
                        .to_vec()
                        .into(),
                        y: [
                            21, 29, 94, 187, 68, 148, 156, 253, 117, 226, 40, 88, 53, 61, 209, 227,
                            12, 164, 136, 185, 148, 125, 86, 21, 22, 52, 195, 192, 6, 6, 176, 179,
                        ]
                        .to_vec()
                        .into(),
                    }),
                },
                counter: 1,
                transports: None,
                user_verified: true,
                backup_eligible: false,
                backup_state: false,
                registration_policy: UserVerificationPolicy::Required,
                extensions: RegisteredExtensions::none(),
                attestation: ParsedAttestation {
                    data: ParsedAttestationData::None,
                    metadata: AttestationMetadata::None,
                },
                attestation_format: AttestationFormat::None,
            },
        ];
        // Ensure we get a bad result.

        assert!(
            wan.generate_challenge_authenticate(creds.clone())
                .unwrap_err()
                == WebauthnError::InconsistentUserVerificationPolicy
        );

        // now mutate to different states to check.
        // cred 0 verified + uv::req
        // cred 1 verified + uv::req
        {
            creds
                .get_mut(0)
                .map(|cred| {
                    cred.user_verified = true;
                    cred.registration_policy = UserVerificationPolicy::Required;
                })
                .unwrap();
            creds
                .get_mut(1)
                .map(|cred| {
                    cred.user_verified = true;
                    cred.registration_policy = UserVerificationPolicy::Required;
                })
                .unwrap();
        }

        let r = wan.generate_challenge_authenticate(creds.clone());
        debug!("{:?}", r);
        assert!(r.is_ok());

        // now mutate to different states to check.
        // cred 0 verified + uv::dc
        // cred 1 verified + uv::dc
        {
            creds
                .get_mut(0)
                .map(|cred| {
                    cred.user_verified = true;
                    cred.registration_policy = UserVerificationPolicy::Discouraged_DO_NOT_USE;
                })
                .unwrap();
            creds
                .get_mut(1)
                .map(|cred| {
                    cred.user_verified = false;
                    cred.registration_policy = UserVerificationPolicy::Discouraged_DO_NOT_USE;
                })
                .unwrap();
        }

        let r = wan.generate_challenge_authenticate(creds.clone());
        debug!("{:?}", r);
        assert!(r.is_ok());
    }

    #[test]
    fn test_subdomain_origin() {
        let _ = tracing_subscriber::fmt::try_init();
        let wan = Webauthn::new_unsafe_experts_only(
            "rp_name",
            "idm.example.com",
            &Url::parse("https://idm.example.com:8080").unwrap(),
            None,
            Some(true),
            None,
        );

        let id =
            "zIQDbMsgDg89LbWHAMLrpgI4w5Bz5Hy8U6F-gaUmda1fgwgn6NzhXQFJwEDfowsiY0NTgdU2jjAG2PmzaD5aWA".to_string();
        let raw_id = Base64UrlSafeData(vec![
            204, 132, 3, 108, 203, 32, 14, 15, 61, 45, 181, 135, 0, 194, 235, 166, 2, 56, 195, 144,
            115, 228, 124, 188, 83, 161, 126, 129, 165, 38, 117, 173, 95, 131, 8, 39, 232, 220,
            225, 93, 1, 73, 192, 64, 223, 163, 11, 34, 99, 67, 83, 129, 213, 54, 142, 48, 6, 216,
            249, 179, 104, 62, 90, 88,
        ]);

        let chal = Challenge::new(vec![
            174, 237, 157, 66, 159, 70, 216, 148, 130, 184, 54, 89, 38, 149, 217, 32, 161, 42, 99,
            227, 50, 124, 208, 164, 221, 38, 202, 210, 140, 102, 116, 84,
        ]);

        let rsp_d = RegisterPublicKeyCredential {
            id: id.clone(),
            raw_id: raw_id.clone(),
            response: AuthenticatorAttestationResponseRaw {
                attestation_object: Base64UrlSafeData(vec![
                    163, 99, 102, 109, 116, 104, 102, 105, 100, 111, 45, 117, 50, 102, 103, 97,
                    116, 116, 83, 116, 109, 116, 162, 99, 115, 105, 103, 88, 70, 48, 68, 2, 32,
                    125, 195, 114, 22, 37, 221, 215, 19, 15, 177, 53, 167, 63, 179, 235, 152, 8,
                    204, 65, 203, 37, 196, 223, 76, 226, 35, 234, 182, 102, 156, 93, 50, 2, 32, 20,
                    177, 103, 196, 47, 107, 19, 76, 35, 2, 14, 186, 197, 229, 113, 38, 83, 252, 17,
                    164, 221, 19, 27, 34, 193, 155, 205, 220, 133, 53, 47, 223, 99, 120, 53, 99,
                    129, 89, 2, 193, 48, 130, 2, 189, 48, 130, 1, 165, 160, 3, 2, 1, 2, 2, 4, 24,
                    172, 70, 192, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0, 48, 46,
                    49, 44, 48, 42, 6, 3, 85, 4, 3, 19, 35, 89, 117, 98, 105, 99, 111, 32, 85, 50,
                    70, 32, 82, 111, 111, 116, 32, 67, 65, 32, 83, 101, 114, 105, 97, 108, 32, 52,
                    53, 55, 50, 48, 48, 54, 51, 49, 48, 32, 23, 13, 49, 52, 48, 56, 48, 49, 48, 48,
                    48, 48, 48, 48, 90, 24, 15, 50, 48, 53, 48, 48, 57, 48, 52, 48, 48, 48, 48, 48,
                    48, 90, 48, 110, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 83, 69, 49, 18, 48, 16,
                    6, 3, 85, 4, 10, 12, 9, 89, 117, 98, 105, 99, 111, 32, 65, 66, 49, 34, 48, 32,
                    6, 3, 85, 4, 11, 12, 25, 65, 117, 116, 104, 101, 110, 116, 105, 99, 97, 116,
                    111, 114, 32, 65, 116, 116, 101, 115, 116, 97, 116, 105, 111, 110, 49, 39, 48,
                    37, 6, 3, 85, 4, 3, 12, 30, 89, 117, 98, 105, 99, 111, 32, 85, 50, 70, 32, 69,
                    69, 32, 83, 101, 114, 105, 97, 108, 32, 52, 49, 51, 57, 52, 51, 52, 56, 56, 48,
                    89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61, 3, 1,
                    7, 3, 66, 0, 4, 121, 234, 59, 44, 124, 73, 112, 16, 98, 35, 12, 210, 63, 235,
                    96, 229, 41, 49, 113, 212, 131, 241, 0, 190, 133, 157, 107, 15, 131, 151, 3, 1,
                    181, 70, 205, 212, 110, 207, 202, 227, 227, 243, 15, 129, 233, 237, 98, 189,
                    38, 141, 76, 30, 189, 55, 179, 188, 190, 146, 168, 194, 174, 235, 78, 58, 163,
                    108, 48, 106, 48, 34, 6, 9, 43, 6, 1, 4, 1, 130, 196, 10, 2, 4, 21, 49, 46, 51,
                    46, 54, 46, 49, 46, 52, 46, 49, 46, 52, 49, 52, 56, 50, 46, 49, 46, 55, 48, 19,
                    6, 11, 43, 6, 1, 4, 1, 130, 229, 28, 2, 1, 1, 4, 4, 3, 2, 5, 32, 48, 33, 6, 11,
                    43, 6, 1, 4, 1, 130, 229, 28, 1, 1, 4, 4, 18, 4, 16, 203, 105, 72, 30, 143,
                    247, 64, 57, 147, 236, 10, 39, 41, 161, 84, 168, 48, 12, 6, 3, 85, 29, 19, 1,
                    1, 255, 4, 2, 48, 0, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0,
                    3, 130, 1, 1, 0, 151, 157, 3, 151, 216, 96, 248, 46, 225, 93, 49, 28, 121, 110,
                    186, 251, 34, 250, 167, 224, 132, 217, 186, 180, 198, 27, 187, 87, 243, 230,
                    180, 193, 138, 72, 55, 184, 92, 60, 78, 219, 228, 131, 67, 244, 214, 165, 217,
                    177, 206, 218, 138, 225, 254, 212, 145, 41, 33, 115, 5, 142, 94, 225, 203, 221,
                    107, 218, 192, 117, 87, 198, 160, 232, 211, 104, 37, 186, 21, 158, 127, 181,
                    173, 140, 218, 248, 4, 134, 140, 249, 14, 143, 31, 138, 234, 23, 192, 22, 181,
                    92, 42, 122, 212, 151, 200, 148, 251, 113, 215, 83, 215, 155, 154, 72, 75, 108,
                    55, 109, 114, 59, 153, 141, 46, 29, 67, 6, 191, 16, 51, 181, 174, 248, 204,
                    165, 203, 178, 86, 139, 105, 36, 34, 109, 34, 163, 88, 171, 125, 135, 228, 172,
                    95, 46, 9, 26, 167, 21, 121, 243, 165, 105, 9, 73, 125, 114, 245, 78, 6, 186,
                    193, 195, 180, 65, 59, 186, 94, 175, 148, 195, 182, 79, 52, 249, 235, 164, 26,
                    203, 106, 226, 131, 119, 109, 54, 70, 83, 120, 72, 254, 232, 132, 189, 221,
                    245, 177, 186, 87, 152, 84, 207, 253, 206, 186, 195, 68, 5, 149, 39, 229, 109,
                    213, 152, 248, 245, 102, 113, 90, 190, 67, 1, 221, 25, 17, 48, 230, 185, 240,
                    198, 64, 57, 18, 83, 226, 41, 128, 63, 58, 239, 39, 75, 237, 191, 222, 63, 203,
                    189, 66, 234, 214, 121, 104, 97, 117, 116, 104, 68, 97, 116, 97, 88, 196, 239,
                    115, 241, 111, 91, 226, 27, 23, 185, 145, 15, 75, 208, 190, 109, 73, 186, 119,
                    107, 122, 2, 224, 117, 140, 139, 132, 92, 21, 148, 105, 187, 55, 65, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 204, 132, 3, 108,
                    203, 32, 14, 15, 61, 45, 181, 135, 0, 194, 235, 166, 2, 56, 195, 144, 115, 228,
                    124, 188, 83, 161, 126, 129, 165, 38, 117, 173, 95, 131, 8, 39, 232, 220, 225,
                    93, 1, 73, 192, 64, 223, 163, 11, 34, 99, 67, 83, 129, 213, 54, 142, 48, 6,
                    216, 249, 179, 104, 62, 90, 88, 165, 1, 2, 3, 38, 32, 1, 33, 88, 32, 169, 47,
                    103, 25, 132, 175, 84, 4, 152, 225, 66, 5, 83, 201, 162, 184, 13, 204, 129,
                    162, 225, 184, 248, 76, 21, 9, 140, 51, 233, 28, 21, 189, 34, 88, 32, 152, 216,
                    30, 49, 240, 214, 59, 66, 44, 67, 110, 41, 126, 83, 131, 50, 13, 175, 237, 57,
                    225, 87, 38, 132, 17, 54, 52, 22, 0, 142, 54, 255,
                ]),
                client_data_json: Base64UrlSafeData(vec![
                    123, 34, 116, 121, 112, 101, 34, 58, 34, 119, 101, 98, 97, 117, 116, 104, 110,
                    46, 99, 114, 101, 97, 116, 101, 34, 44, 34, 99, 104, 97, 108, 108, 101, 110,
                    103, 101, 34, 58, 34, 114, 117, 50, 100, 81, 112, 57, 71, 50, 74, 83, 67, 117,
                    68, 90, 90, 74, 112, 88, 90, 73, 75, 69, 113, 89, 45, 77, 121, 102, 78, 67,
                    107, 51, 83, 98, 75, 48, 111, 120, 109, 100, 70, 81, 34, 44, 34, 111, 114, 105,
                    103, 105, 110, 34, 58, 34, 104, 116, 116, 112, 115, 58, 47, 47, 105, 100, 109,
                    46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 58, 56, 48, 56, 48, 34,
                    44, 34, 99, 114, 111, 115, 115, 79, 114, 105, 103, 105, 110, 34, 58, 102, 97,
                    108, 115, 101, 125,
                ]),
                transports: None,
            },
            type_: "public-key".to_string(),
            extensions: RegistrationExtensionsClientOutputs::default(),
        };

        let cred = wan
            .register_credential_internal(
                &rsp_d,
                UserVerificationPolicy::Discouraged_DO_NOT_USE,
                &chal,
                &[],
                &[COSEAlgorithm::ES256],
                None,
                false,
                &RequestRegistrationExtensions::default(),
                true,
            )
            .expect("Failed to register credential");

        // In this we visit from "https://sub.idm.example.com:8080" which is an effective domain
        // of the origin.

        let chal = Challenge::new(vec![
            127, 52, 208, 243, 214, 88, 79, 34, 12, 226, 145, 217, 217, 241, 99, 228, 171, 232,
            226, 26, 191, 32, 122, 4, 164, 217, 49, 134, 85, 161, 116, 32,
        ]);

        let rsp_d = PublicKeyCredential {
            id,
            raw_id,
            response: AuthenticatorAssertionResponseRaw {
                authenticator_data: Base64UrlSafeData(vec![
                    239, 115, 241, 111, 91, 226, 27, 23, 185, 145, 15, 75, 208, 190, 109, 73, 186,
                    119, 107, 122, 2, 224, 117, 140, 139, 132, 92, 21, 148, 105, 187, 55, 1, 0, 0,
                    3, 237,
                ]),
                client_data_json: Base64UrlSafeData(vec![
                    123, 34, 116, 121, 112, 101, 34, 58, 34, 119, 101, 98, 97, 117, 116, 104, 110,
                    46, 103, 101, 116, 34, 44, 34, 99, 104, 97, 108, 108, 101, 110, 103, 101, 34,
                    58, 34, 102, 122, 84, 81, 56, 57, 90, 89, 84, 121, 73, 77, 52, 112, 72, 90, 50,
                    102, 70, 106, 53, 75, 118, 111, 52, 104, 113, 95, 73, 72, 111, 69, 112, 78,
                    107, 120, 104, 108, 87, 104, 100, 67, 65, 34, 44, 34, 111, 114, 105, 103, 105,
                    110, 34, 58, 34, 104, 116, 116, 112, 115, 58, 47, 47, 115, 117, 98, 46, 105,
                    100, 109, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 58, 56, 48,
                    56, 48, 34, 44, 34, 99, 114, 111, 115, 115, 79, 114, 105, 103, 105, 110, 34,
                    58, 102, 97, 108, 115, 101, 125,
                ]),
                signature: Base64UrlSafeData(vec![
                    48, 69, 2, 32, 113, 175, 47, 74, 251, 87, 115, 175, 144, 222, 52, 128, 21, 250,
                    35, 239, 213, 162, 75, 45, 110, 28, 15, 103, 138, 234, 106, 219, 34, 198, 74,
                    74, 2, 33, 0, 204, 144, 147, 62, 250, 6, 11, 19, 239, 90, 108, 6, 126, 165,
                    157, 41, 223, 251, 81, 22, 202, 121, 126, 133, 192, 81, 71, 193, 220, 208, 25,
                    127,
                ]),
                user_handle: Some(Base64UrlSafeData(vec![])),
            },
            extensions: AuthenticationExtensionsClientOutputs::default(),
            type_: "public-key".to_string(),
        };

        let r = wan.verify_credential_internal(
            &rsp_d,
            UserVerificationPolicy::Discouraged_DO_NOT_USE,
            &chal,
            &cred,
            &None,
        );
        trace!("RESULT: {:?}", r);
        assert!(r.is_ok());
    }

    #[test]
    fn test_yk5bio_fallback_alg_attest_none() {
        let _ = tracing_subscriber::fmt::try_init();
        let wan = Webauthn::new_unsafe_experts_only(
            "http://localhost:8080/auth",
            "localhost",
            &Url::parse("http://localhost:8080").unwrap(),
            None,
            None,
            None,
        );

        let chal: Base64UrlSafeData =
            serde_json::from_str("\"NE6dm0mgUe47-X0Yf5nRdhYokY3A8XAzs10KBLGlVY0\"").unwrap();
        let chal = Challenge::from(chal);

        let rsp_d: RegisterPublicKeyCredential = serde_json::from_str(r#"{
            "id": "k8-N3sbgQe_ze58s5b955iLRrqcizmms-YOqFQTQbBbbJLStt9CaR3vUYXEajy4O22fAgdyY1aOvc6HW9o1ikqiSWee2CxXXJe2DE40byI4-m4oesHfmz4urfMxkIrAd_4i8pgWHNLVlTSMtAzhCXH16Yw4uUsdsntv1HpYiu94",
            "rawId": "k8-N3sbgQe_ze58s5b955iLRrqcizmms-YOqFQTQbBbbJLStt9CaR3vUYXEajy4O22fAgdyY1aOvc6HW9o1ikqiSWee2CxXXJe2DE40byI4-m4oesHfmz4urfMxkIrAd_4i8pgWHNLVlTSMtAzhCXH16Yw4uUsdsntv1HpYiu94",
            "response": {
                "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjhSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAQAAAAAAAAAAAAAAAAAAAAAAgJPPjd7G4EHv83ufLOW_eeYi0a6nIs5prPmDqhUE0GwW2yS0rbfQmkd71GFxGo8uDttnwIHcmNWjr3Oh1vaNYpKoklnntgsV1yXtgxONG8iOPpuKHrB35s-Lq3zMZCKwHf-IvKYFhzS1ZU0jLQM4Qlx9emMOLlLHbJ7b9R6WIrvepAEBAycgBiFYICgd3qEI_iQqhYAi0y47WqeU2Bf2kVY4Mq02t1zgTzkV",
                "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiTkU2ZG0wbWdVZTQ3LVgwWWY1blJkaFlva1kzQThYQXpzMTBLQkxHbFZZMCIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0"
            },
            "type": "public-key"
        }"#).unwrap();

        debug!("{:?}", rsp_d);

        let result = wan.register_credential_internal(
            &rsp_d,
            UserVerificationPolicy::Discouraged_DO_NOT_USE,
            &chal,
            &[],
            &[COSEAlgorithm::EDDSA],
            None,
            false,
            &RequestRegistrationExtensions::default(),
            false,
        );
        debug!("{:?}", result);
        // Currently UNSUPPORTED as openssl doesn't have eddsa management utils that we need.
        assert!(result.is_err());
    }

    #[test]
    fn test_solokey_fallback_alg_attest_none() {
        let _ = tracing_subscriber::fmt::try_init();
        let wan = Webauthn::new_unsafe_experts_only(
            "https://webauthn.firstyear.id.au",
            "webauthn.firstyear.id.au",
            &Url::parse("https://webauthn.firstyear.id.au").unwrap(),
            None,
            None,
            None,
        );

        let chal: Base64UrlSafeData =
            serde_json::from_str("\"rRPXQ7lps3xBQzX3dDAor9fHwH_ff55gUU-8wwZVK-g\"").unwrap();
        let chal = Challenge::from(chal);

        let rsp_d: RegisterPublicKeyCredential = serde_json::from_str(r#"{
            "id": "owBY6NCpGj_5nAM427VzsWjmifVdW10z3Ov8fyN5BPX5cxyR2umlVN5h7oGUos-9RPeoYBuCRBkSyAK6jM0gkZ0RLrHrCGRTwfk5p1NQ2ucX_cAh0uel-TkBpyWE-dxqXyk-WLlhSA4LKEdlmyTVqiDAGG7CRHdDn0oAufgq0za7-Crt6cWPKwzmkTGHsMAaEqEaQzHjo1D-pb_WkJJfYp5SZ52ZdTj5eKx7htT5QIogb70lwTKv82ix8PZskqiV-L4j5EroU-xXl7sxKlVtmkS8tSlHpyU-h8fZcFmmW4lr6cBOACd5aNEgR88BTFqQQZ97RORZ7J9sagJQJ63Jj-CZTqGBewVu2jazgA",
            "rawId": "owBY6NCpGj_5nAM427VzsWjmifVdW10z3Ov8fyN5BPX5cxyR2umlVN5h7oGUos-9RPeoYBuCRBkSyAK6jM0gkZ0RLrHrCGRTwfk5p1NQ2ucX_cAh0uel-TkBpyWE-dxqXyk-WLlhSA4LKEdlmyTVqiDAGG7CRHdDn0oAufgq0za7-Crt6cWPKwzmkTGHsMAaEqEaQzHjo1D-pb_WkJJfYp5SZ52ZdTj5eKx7htT5QIogb70lwTKv82ix8PZskqiV-L4j5EroU-xXl7sxKlVtmkS8tSlHpyU-h8fZcFmmW4lr6cBOACd5aNEgR88BTFqQQZ97RORZ7J9sagJQJ63Jj-CZTqGBewVu2jazgA",
            "response": {
                "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVkBbWq5u_Dfmhb5Hbszu7Ey-vnRfHgsSCbG7HDs7ljZfvUqRQAAAEoAAAAAAAAAAAAAAAAAAAAAAQyjAFjo0KkaP_mcAzjbtXOxaOaJ9V1bXTPc6_x_I3kE9flzHJHa6aVU3mHugZSiz71E96hgG4JEGRLIArqMzSCRnREusesIZFPB-TmnU1Da5xf9wCHS56X5OQGnJYT53GpfKT5YuWFIDgsoR2WbJNWqIMAYbsJEd0OfSgC5-CrTNrv4Ku3pxY8rDOaRMYewwBoSoRpDMeOjUP6lv9aQkl9inlJnnZl1OPl4rHuG1PlAiiBvvSXBMq_zaLHw9mySqJX4viPkSuhT7FeXuzEqVW2aRLy1KUenJT6Hx9lwWaZbiWvpwE4AJ3lo0SBHzwFMWpBBn3tE5Fnsn2xqAlAnrcmP4JlOoYF7BW7aNrOApAEBAycgBiFYIKfpbghX95Ey_8DV4Ots95iyCRWa7OElliqsg9tdnRur",
                "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiclJQWFE3bHBzM3hCUXpYM2REQW9yOWZId0hfZmY1NWdVVS04d3daVkstZyIsIm9yaWdpbiI6Imh0dHBzOi8vd2ViYXV0aG4uZmlyc3R5ZWFyLmlkLmF1IiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ"
            },
            "type": "public-key"
        }"#).unwrap();

        debug!("{:?}", rsp_d);

        let result = wan.register_credential_internal(
            &rsp_d,
            UserVerificationPolicy::Discouraged_DO_NOT_USE,
            &chal,
            &[],
            &[COSEAlgorithm::EDDSA],
            None,
            false,
            &RequestRegistrationExtensions::default(),
            false,
        );
        debug!("{:?}", result);
        // Currently UNSUPPORTED as openssl doesn't have eddsa management utils that we need.
        assert!(result.is_err());
    }

    // ⚠️  Currently IGNORED as it appears that pixel 3a send INVALID attestation requests.
    #[test]
    #[ignore]
    fn test_google_pixel_3a_direct_attestation() {
        let _ = tracing_subscriber::fmt::try_init();
        let wan = Webauthn::new_unsafe_experts_only(
            "https://webauthn.firstyear.id.au",
            "webauthn.firstyear.id.au",
            &Url::parse("https://webauthn.firstyear.id.au").unwrap(),
            None,
            None,
            None,
        );
        let chal: Base64UrlSafeData =
            serde_json::from_str("\"Y0j5PX0VXeKb2150k6sAh1QNRBJ3iTv8WBsUfgn_pRs\"").unwrap();
        let chal = Challenge::from(chal);

        let rsp_d: RegisterPublicKeyCredential = serde_json::from_str(r#"{
            "id": "Afx3PxBAXAercQxfFjvHGt3OnTHtXjfNcuCxI-XVaeAtLkohnHQ_mJ2Ocgj2Bhhkv3neczncwaH1nkVpwitUxyQ",
            "rawId": "Afx3PxBAXAercQxfFjvHGt3OnTHtXjfNcuCxI-XVaeAtLkohnHQ_mJ2Ocgj2Bhhkv3neczncwaH1nkVpwitUxyQ",
            "response": {
                "attestationObject": "o2NmbXRxYW5kcm9pZC1zYWZldHluZXRnYXR0U3RtdKJjdmVyaTIxNDgxNTA0NGhyZXNwb25zZVkgcmV5SmhiR2NpT2lKU1V6STFOaUlzSW5nMVl5STZXeUpOU1VsR1dVUkRRMEpGYVdkQmQwbENRV2RKVWtGT2FHTkhiRGN3UWpWaFNVTlJRVUZCUVVWQ2JpOUZkMFJSV1VwTGIxcEphSFpqVGtGUlJVeENVVUYzVW1wRlRFMUJhMGRCTVZWRlFtaE5RMVpXVFhoSmFrRm5RbWRPVmtKQmIxUkhWV1IyWWpKa2MxcFRRbFZqYmxaNlpFTkNWRnBZU2pKaFYwNXNZM2xDVFZSRlRYaEZla0ZTUW1kT1ZrSkJUVlJEYTJSVlZYbENSRkZUUVhoU1JGRjNTR2hqVGsxcVNYZE5WRWt4VFZSQmQwMUVUVEJYYUdOT1RXcEpkMDVFU1RGTlZFRjNUVVJOZWxkcVFXUk5Vbk4zUjFGWlJGWlJVVVJGZUVwb1pFaFNiR016VVhWWlZ6VnJZMjA1Y0ZwRE5XcGlNakIzWjJkRmFVMUJNRWREVTNGSFUwbGlNMFJSUlVKQlVWVkJRVFJKUWtSM1FYZG5aMFZMUVc5SlFrRlJRMWsxYkhwR1kwaHNaVEZFVEd4MFRrcG9iRk5qYm5GV1VuTllRMWQ2TmpGR2J5OUdSMHRzWW0wMGJHSTVZemR5V1hwWlRtOU1UV3hVV0d0YWFVczBSMUpGZG5acVozZE1kMk0zVEVNNFRUWjZiM0pHY1dFNWFqTjZORzB2VFhWa1EyRkdWblIzTUVGVmJtVnFhbFpTYUZSaVdrVkthV3M0VVVWaWFIZzFZWHBDVGxOd00yZ3JSemcyTlV4YUszbG5SR1JrTUZaYVMyUnhOVE5MUWpscU1FWTRlV0pyWkhaVlkxTnpMMjB6UjAxcVYwVkJhWEEwVjI1eVJGazVSa3hhWm5ncmNFTndRVTVQUVdKVVRuWmphV2xMUVhkUGExRkhSRVZKTVVaeFZFTjFTVzVhYVVoU2RtMXBaazlSYzA5dVUwVjRTWFV6YzFjM2RsRmpSWFJVWWtZclZWcDRhR3BpU0RWRmRtSmtiMFZ1WVV4Tk5sUkNTbmwxYkRkMGVsZDFhalJaTkZoVVkydDJaRk5EYm5KQlUzZHpaM2xST1hWT09YZG9VSFpCVm01NFIxWkNXRWxGVkVWMFZVRTRiWGxRTkROVVMzTktRV2ROUWtGQlIycG5aMHAzVFVsSlEySkVRVTlDWjA1V1NGRTRRa0ZtT0VWQ1FVMURRbUZCZDBWM1dVUldVakJzUWtGM2QwTm5XVWxMZDFsQ1FsRlZTRUYzUlhkRVFWbEVWbEl3VkVGUlNDOUNRVWwzUVVSQlpFSm5UbFpJVVRSRlJtZFJWWEZXVFRKVlRWcFdRVXMxUTNsUldUWkdSM0owVTBrM01YTXliM2RJZDFsRVZsSXdha0pDWjNkR2IwRlZTbVZKV1VSeVNsaHJXbEZ4TldSU1pHaHdRMFF6YkU5NmRVcEpkMkpSV1VsTGQxbENRbEZWU0VGUlJVVlpWRUptVFVOdlIwTkRjMGRCVVZWR1FucEJRbWhvTlc5a1NGSjNUMms0ZG1JeVRucGpRelYzWVRKcmRWb3lPWFphZVRsdVpFaE5lRnBFVW5CaWJsRjNUVkZaU1V0M1dVSkNVVlZJVFVGTFIwcFhhREJrU0VFMlRIazVkMkV5YTNWYU1qbDJXbms1ZVZwWVFuWk1NazVzWTI1U2Vrd3laREJqZWtaclRrTTFhMXBZU1hkSVVWbEVWbEl3VWtKQ1dYZEdTVWxUV1ZoU01GcFlUakJNYlVaMVdraEtkbUZYVVhWWk1qbDBUVU5GUjBFeFZXUkpRVkZoVFVKbmQwTkJXVWRhTkVWTlFWRkpRazFCZDBkRGFYTkhRVkZSUWpGdWEwTkNVVTEzVUhkWlJGWlNNR1pDUkdkM1RtcEJNRzlFUzJkTlNWbDFZVWhTTUdORWIzWk1NazU1WWtoTmRXTkhkSEJNYldSMllqSmpkbG96VW5wTlYxRXdZVmMxTUV3eFNUTlBSMWt4WldwT2NVNHpiRzVNYlU1NVlrUkRRMEZSVFVkRGFYTkhRVkZSUWpGdWEwTkNRVWxGWjJaUlJXZG1SVUUzZDBJeFFVWkhhbk5RV0RsQldHMWpWbTB5TkU0emFWQkVTMUkyZWtKemJua3ZaV1ZwUlV0aFJHWTNWV2wzV0d4QlFVRkNabkJFYkVSQlNVRkJRVkZFUVVWWmQxSkJTV2RKTkRWc1VIRXdOVmRXZUVsNmJ6RlZiR2hvVTBWMmNrbHZRVlkxUlhGME1DdHNWa1Z1YVd4WWNUaFZRMGxEVjNCSFJrZzVSQzlFZVdabllXZFhNeTh5WjBWMVNGcGFPRXRIU3psQ09VcGFla0pEU2l0Q2RsTmxRVWhaUVV0WWJTczRTalExVDFOSWQxWnVUMlpaTmxZek5XSTFXR1phZUdkRGRtbzFWRll3YlZoRFZtUjRORkZCUVVGR0sydFBWVXcwWjBGQlFrRk5RVko2UWtaQmFVVkJiMk50Vm1SamJFTkVNbUpHVUU5T2IxWXlNWFJpT0VkelpWZGtNa1p0TTFkVFIzRlhUVEIzUkRCQ2MwTkpSV1YwUkhsd05YcGpialU0YWpob1VrUlNieTlXVlVkMFp6TnRkaklyV1RaS1JqUnFibnBDVWt0RlVVMUJNRWREVTNGSFUwbGlNMFJSUlVKRGQxVkJRVFJKUWtGUlFVbHViSGh1U1VsMlEwdHJWbWxLWlRWaWRFVTJUVkJaUVdwNE0wZElXakZMTDNwc2RIQnpaVTFTVVRoaVJsVkxUVVpNVTFOeE4zVk9SbEJSY2pkUFZ6Tm9RMmhuVEVORFZtOUZla2MwWW5GR2RVMTRWMklyU0hRNVVFaDBSbmhXV0hwaVowcDVhbUoyUkRkSVUwOVVjV3M0UVZreFlTOU9VVFYxYW5ORFRGTktORVJtTmxKa2FFZ3ZUM1p3ZEdWUU0wNW1iRlZYVGsxSlFrVjJNRlYyTVhSMlRFVm1VVWRYTUdoVFltYzJUQzlJUjJkQlkxZDFURGRzTmk5UVdFbEZkVEpsVERkcllVZEdVbWhKTW1KcU5FcE9PVmxGU0VkdWRtaGpSM0ExTlhsQ016ZG9TWGd4YkRoVk56VllPV2hJTVU4MlRVMXRlblpLTURWeGRGaERjMVJZVVdsbGFrUXdWSFI0VkdwSFZpdFdTM1J3VEZoSlEzQlVabmhPYzNCQ2VrTk1hRGt4U1V4dE1uQkhORlk1Wkd0dFJWWnZPVEIwU25wS1NTOUJTelpoVUdadloyTktiMEpuYm5CVE9GVlpkMEZPYlZORElpd2lUVWxKUm1wRVEwTkJNMU5uUVhkSlFrRm5TVTVCWjBOUGMyZEplazV0VjB4YVRUTmliWHBCVGtKbmEzRm9hMmxIT1hjd1FrRlJjMFpCUkVKSVRWRnpkME5SV1VSV1VWRkhSWGRLVmxWNlJXbE5RMEZIUVRGVlJVTm9UVnBTTWpsMldqSjRiRWxHVW5sa1dFNHdTVVpPYkdOdVduQlpNbFo2U1VWNFRWRjZSVlZOUWtsSFFURlZSVUY0VFV4U01WSlVTVVpLZG1JelVXZFZha1YzU0doalRrMXFRWGRQUkVWNlRVUkJkMDFFVVhsWGFHTk9UV3BqZDA5VVRYZE5SRUYzVFVSUmVWZHFRa2ROVVhOM1ExRlpSRlpSVVVkRmQwcFdWWHBGYVUxRFFVZEJNVlZGUTJoTldsSXlPWFphTW5oc1NVWlNlV1JZVGpCSlJrNXNZMjVhY0ZreVZucEpSWGhOVVhwRlZFMUNSVWRCTVZWRlFYaE5TMUl4VWxSSlJVNUNTVVJHUlU1RVEwTkJVMGwzUkZGWlNrdHZXa2xvZG1OT1FWRkZRa0pSUVVSblowVlFRVVJEUTBGUmIwTm5aMFZDUVV0MlFYRnhVRU5GTWpkc01IYzVla000WkZSUVNVVTRPV0pCSzNoVWJVUmhSemQ1TjFabVVUUmpLMjFQVjJoc1ZXVmlWVkZ3U3pCNWRqSnlOamM0VWtwRmVFc3dTRmRFYW1WeEsyNU1TVWhPTVVWdE5XbzJja0ZTV21sNGJYbFNVMnBvU1ZJd1MwOVJVRWRDVFZWc1pITmhlblJKU1VvM1R6Qm5Memd5Y1dvdmRrZEViQzh2TTNRMGRGUnhlR2xTYUV4UmJsUk1XRXBrWlVJck1rUm9hMlJWTmtsSlozZzJkMDQzUlRWT1kxVklNMUpqYzJWcVkzRnFPSEExVTJveE9YWkNiVFpwTVVab2NVeEhlVzFvVFVaeWIxZFdWVWRQTTNoMFNVZzVNV1J6WjNrMFpVWkxZMlpMVmt4WFN6TnZNakU1TUZFd1RHMHZVMmxMYlV4aVVrbzFRWFUwZVRGbGRVWktiVEpLVFRsbFFqZzBSbXR4WVROcGRuSllWMVZsVm5SNVpUQkRVV1JMZG5OWk1rWnJZWHAyZUhSNGRuVnpURXA2VEZkWlNHczFOWHBqVWtGaFkwUkJNbE5sUlhSQ1lsRm1SREZ4YzBOQmQwVkJRV0ZQUTBGWVdYZG5aMFo1VFVFMFIwRXhWV1JFZDBWQ0wzZFJSVUYzU1VKb2FrRmtRbWRPVmtoVFZVVkdha0ZWUW1kbmNrSm5SVVpDVVdORVFWRlpTVXQzV1VKQ1VWVklRWGRKZDBWbldVUldVakJVUVZGSUwwSkJaM2RDWjBWQ0wzZEpRa0ZFUVdSQ1owNVdTRkUwUlVablVWVktaVWxaUkhKS1dHdGFVWEUxWkZKa2FIQkRSRE5zVDNwMVNrbDNTSGRaUkZaU01HcENRbWQzUm05QlZUVkxPSEpLYmtWaFN6Qm5ibWhUT1ZOYWFYcDJPRWxyVkdOVU5IZGhRVmxKUzNkWlFrSlJWVWhCVVVWRldFUkNZVTFEV1VkRFEzTkhRVkZWUmtKNlFVSm9hSEJ2WkVoU2QwOXBPSFppTWs1NlkwTTFkMkV5YTNWYU1qbDJXbms1Ym1SSVRubE5WRUYzUW1kbmNrSm5SVVpDVVdOM1FXOVphMkZJVWpCalJHOTJURE5DY21GVE5XNWlNamx1VEROS2JHTkhPSFpaTWxaNVpFaE5kbG96VW5wamFrVjFXa2RXZVUxRVVVZEJNVlZrU0hkUmRFMURjM2RMWVVGdWIwTlhSMGt5YURCa1NFRTJUSGs1YW1OdGQzVmpSM1J3VEcxa2RtSXlZM1phTTFKNlkycEZkbG96VW5wamFrVjFXVE5LYzAxRk1FZEJNVlZrU1VGU1IwMUZVWGREUVZsSFdqUkZUVUZSU1VKTlJHZEhRMmx6UjBGUlVVSXhibXREUWxGTmQwdHFRVzlDWjJkeVFtZEZSa0pSWTBOQlVsbGpZVWhTTUdOSVRUWk1lVGwzWVRKcmRWb3lPWFphZVRsNVdsaENkbU15YkRCaU0wbzFUSHBCVGtKbmEzRm9hMmxIT1hjd1FrRlJjMFpCUVU5RFFXZEZRVWxXVkc5NU1qUnFkMWhWY2pCeVFWQmpPVEkwZG5WVFZtSkxVWFZaZHpOdVRHWnNUR1pNYURWQldWZEZaVlpzTDBSMU1UaFJRVmRWVFdSalNqWnZMM0ZHV21Kb1dHdENTREJRVG1OM09UZDBhR0ZtTWtKbGIwUlpXVGxEYXk5aUsxVkhiSFZvZURBMmVtUTBSVUptTjBnNVVEZzBibTV5ZDNCU0t6UkhRa1JhU3l0WWFETkpNSFJ4U25reWNtZFBjVTVFWm14eU5VbE5VVGhhVkZkQk0zbHNkR0ZyZWxOQ1MxbzJXSEJHTUZCd2NYbERVblp3TDA1RFIzWXlTMWd5VkhWUVEwcDJjMk53TVM5dE1uQldWSFI1UW1wWlVGSlJLMUYxUTFGSFFVcExhblJPTjFJMVJFWnlabFJ4VFZkMldXZFdiSEJEU2tKcmQyeDFOeXMzUzFrelkxUkpabnBGTjJOdFFVeHphMDFMVGt4MVJIb3JVbnBEWTNOWlZITldZVlUzVm5BemVFdzJNRTlaYUhGR2EzVkJUMDk0UkZvMmNFaFBhamtyVDBwdFdXZFFiVTlVTkZnekt6ZE1OVEZtV0VwNVVrZzVTMlpNVWxBMmJsUXpNVVExYm0xelIwRlBaMW95Tmk4NFZEbG9jMEpYTVhWdk9XcDFOV1phVEZwWVZsWlROVWd3U0hsSlFrMUZTM2xIVFVsUWFFWlhjbXgwTDJoR1V6STRUakY2WVV0Sk1GcENSMFF6WjFsblJFeGlhVVJVT1daSFdITjBjR3NyUm0xak5HOXNWbXhYVUhwWVpUZ3hkbVJ2Ulc1R1luSTFUVEkzTWtoa1owcFhieXRYYUZRNVFsbE5NRXBwSzNka1ZtMXVVbVptV0dkc2IwVnZiSFZVVG1OWGVtTTBNV1JHY0dkS2RUaG1Sak5NUnpCbmJESnBZbE5aYVVOcE9XRTJhSFpWTUZSd2NHcEtlVWxYV0doclNsUmpUVXBzVUhKWGVERldlWFJGVlVkeVdESnNNRXBFZDFKcVZ5ODJOVFp5TUV0V1FqQXllRWhTUzNadE1scExTVEF6Vkdkc1RFbHdiVlpEU3pOclFrdHJTMDV3UWs1clJuUTRjbWhoWm1ORFMwOWlPVXA0THpsMGNFNUdiRkZVYkRkQ016bHlTbXhLVjJ0U01UZFJibHB4Vm5CMFJtVlFSazlTYjFwdFJucE5QU0lzSWsxSlNVWlpha05EUWtWeFowRjNTVUpCWjBsUlpEY3dUbUpPY3pJclVuSnhTVkV2UlRoR2FsUkVWRUZPUW1kcmNXaHJhVWM1ZHpCQ1FWRnpSa0ZFUWxoTlVYTjNRMUZaUkZaUlVVZEZkMHBEVWxSRldrMUNZMGRCTVZWRlEyaE5VVkl5ZUhaWmJVWnpWVEpzYm1KcFFuVmthVEY2V1ZSRlVVMUJORWRCTVZWRlEzaE5TRlZ0T1haa1EwSkVVVlJGWWsxQ2EwZEJNVlZGUVhoTlUxSXllSFpaYlVaelZUSnNibUpwUWxOaU1qa3dTVVZPUWsxQ05GaEVWRWwzVFVSWmVFOVVRWGROUkVFd1RXeHZXRVJVU1RSTlJFVjVUMFJCZDAxRVFUQk5iRzkzVW5wRlRFMUJhMGRCTVZWRlFtaE5RMVpXVFhoSmFrRm5RbWRPVmtKQmIxUkhWV1IyWWpKa2MxcFRRbFZqYmxaNlpFTkNWRnBZU2pKaFYwNXNZM2xDVFZSRlRYaEdSRUZUUW1kT1ZrSkJUVlJETUdSVlZYbENVMkl5T1RCSlJrbDRUVWxKUTBscVFVNUNaMnR4YUd0cFJ6bDNNRUpCVVVWR1FVRlBRMEZuT0VGTlNVbERRMmRMUTBGblJVRjBhRVZEYVhnM2FtOVlaV0pQT1hrdmJFUTJNMnhoWkVGUVMwZzVaM1pzT1UxbllVTmpabUl5YWtndk56Wk9kVGhoYVRaWWJEWlBUVk12YTNJNWNrZzFlbTlSWkhObWJrWnNPVGQyZFdaTGFqWmlkMU5wVmpadWNXeExjaXREVFc1NU5sTjRia2RRWWpFMWJDczRRWEJsTmpKcGJUbE5XbUZTZHpGT1JVUlFhbFJ5UlZSdk9HZFpZa1YyY3k5QmJWRXpOVEZyUzFOVmFrSTJSekF3YWpCMVdVOUVVREJuYlVoMU9ERkpPRVV6UTNkdWNVbHBjblUyZWpGcldqRnhLMUJ6UVdWM2JtcEllR2R6U0VFemVUWnRZbGQzV2tSeVdGbG1hVmxoVWxGTk9YTkliV3RzUTJsMFJETTRiVFZoWjBrdmNHSnZVRWRwVlZVck5rUlBiMmR5UmxwWlNuTjFRalpxUXpVeE1YQjZjbkF4V210cU5WcFFZVXMwT1d3NFMwVnFPRU00VVUxQlRGaE1NekpvTjAweFlrdDNXVlZJSzBVMFJYcE9hM1JOWnpaVVR6aFZjRzEyVFhKVmNITjVWWEYwUldvMVkzVklTMXBRWm0xbmFFTk9Oa296UTJsdmFqWlBSMkZMTDBkUU5VRm1iRFF2V0hSalpDOXdNbWd2Y25Nek4wVlBaVnBXV0hSTU1HMDNPVmxDTUdWelYwTnlkVTlETjFoR2VGbHdWbkU1VDNNMmNFWk1TMk4zV25CRVNXeFVhWEo0V2xWVVVVRnpObkY2YTIwd05uQTVPR2MzUWtGbEsyUkVjVFprYzI4ME9UbHBXVWcyVkV0WUx6RlpOMFI2YTNabmRHUnBlbXByV0ZCa2MwUjBVVU4yT1ZWM0szZHdPVlUzUkdKSFMyOW5VR1ZOWVROTlpDdHdkbVY2TjFjek5VVnBSWFZoS3l0MFoza3ZRa0pxUmtaR2VUTnNNMWRHY0U4NVMxZG5lamQ2Y0cwM1FXVkxTblE0VkRFeFpHeGxRMlpsV0d0clZVRkxTVUZtTlhGdlNXSmhjSE5hVjNkd1ltdE9SbWhJWVhneWVFbFFSVVJuWm1jeFlYcFdXVGd3V21OR2RXTjBURGRVYkV4dVRWRXZNR3hWVkdKcFUzY3hia2cyT1UxSE5ucFBNR0k1WmpaQ1VXUm5RVzFFTURaNVN6VTJiVVJqV1VKYVZVTkJkMFZCUVdGUFEwRlVaM2RuWjBVd1RVRTBSMEV4VldSRWQwVkNMM2RSUlVGM1NVSm9ha0ZRUW1kT1ZraFNUVUpCWmpoRlFsUkJSRUZSU0M5TlFqQkhRVEZWWkVSblVWZENRbFJyY25semJXTlNiM0pUUTJWR1RERktiVXhQTDNkcFVrNTRVR3BCWmtKblRsWklVMDFGUjBSQlYyZENVbWRsTWxsaFVsRXlXSGx2YkZGTU16QkZlbFJUYnk4dmVqbFRla0puUW1kbmNrSm5SVVpDVVdOQ1FWRlNWVTFHU1hkS1VWbEpTM2RaUWtKUlZVaE5RVWRIUjFkb01HUklRVFpNZVRsMldUTk9kMHh1UW5KaFV6VnVZakk1Ymt3eVpIcGpha1YzUzFGWlNVdDNXVUpDVVZWSVRVRkxSMGhYYURCa1NFRTJUSGs1ZDJFeWEzVmFNamwyV25rNWJtTXpTWGhNTW1SNlkycEZkVmt6U2pCTlJFbEhRVEZWWkVoM1VYSk5RMnQzU2paQmJHOURUMGRKVjJnd1pFaEJOa3g1T1dwamJYZDFZMGQwY0V4dFpIWmlNbU4yV2pOT2VVMVRPVzVqTTBsNFRHMU9lV0pFUVRkQ1owNVdTRk5CUlU1RVFYbE5RV2RIUW0xbFFrUkJSVU5CVkVGSlFtZGFibWRSZDBKQlowbDNSRkZaVEV0M1dVSkNRVWhYWlZGSlJrRjNTWGRFVVZsTVMzZFpRa0pCU0ZkbFVVbEdRWGROZDBSUldVcExiMXBKYUhaalRrRlJSVXhDVVVGRVoyZEZRa0ZFVTJ0SWNrVnZiemxETUdSb1pXMU5XRzlvTm1SR1UxQnphbUprUWxwQ2FVeG5PVTVTTTNRMVVDdFVORlo0Wm5FM2RuRm1UUzlpTlVFelVta3habmxLYlRsaWRtaGtSMkZLVVROaU1uUTJlVTFCV1U0dmIyeFZZWHB6WVV3cmVYbEZiamxYY0hKTFFWTlBjMmhKUVhKQmIzbGFiQ3QwU21GdmVERXhPR1psYzNOdFdHNHhhRWxXZHpReGIyVlJZVEYyTVhabk5FWjJOelI2VUd3MkwwRm9VM0ozT1ZVMWNFTmFSWFEwVjJrMGQxTjBlalprVkZvdlEweEJUbmc0VEZwb01VbzNVVXBXYWpKbWFFMTBabFJLY2psM05Ib3pNRm95TURsbVQxVXdhVTlOZVN0eFpIVkNiWEIyZGxsMVVqZG9Xa3cyUkhWd2MzcG1ibmN3VTJ0bWRHaHpNVGhrUnpsYVMySTFPVlZvZG0xaFUwZGFVbFppVGxGd2MyY3pRbHBzZG1sa01HeEpTMDh5WkRGNGIzcGpiRTk2WjJwWVVGbHZka3BLU1hWc2RIcHJUWFV6TkhGUllqbFRlaTk1YVd4eVlrTm5hamc5SWwxOS5leUp1YjI1alpTSTZJbko1VFZZMVRpdEpTVzlPYzBnNE9YTk1NbXhCWkRKRWIxaEVUMFZaVFRsQlZGQjJSblJuZW1KVGIwMDlJaXdpZEdsdFpYTjBZVzF3VFhNaU9qRTJORFEzTXpnek9EVTNPVFFzSW1Gd2ExQmhZMnRoWjJWT1lXMWxJam9pWTI5dExtZHZiMmRzWlM1aGJtUnliMmxrTG1kdGN5SXNJbUZ3YTBScFoyVnpkRk5vWVRJMU5pSTZJbVpaUlVSV2VVbHFPRFJ4V2xkd1dXazBRMUJ6VlU4MlN6aHVZbU5RWWs0dlkwczJXREl3UTJSM09GVTlJaXdpWTNSelVISnZabWxzWlUxaGRHTm9JanAwY25WbExDSmhjR3REWlhKMGFXWnBZMkYwWlVScFoyVnpkRk5vWVRJMU5pSTZXeUk0VURGelZ6QkZVRXBqYzJ4M04xVjZVbk5wV0V3Mk5IY3JUelV3UldRclVrSkpRM1JoZVRGbk1qUk5QU0pkTENKaVlYTnBZMGx1ZEdWbmNtbDBlU0k2ZEhKMVpTd2laWFpoYkhWaGRHbHZibFI1Y0dVaU9pSkNRVk5KUXl4SVFWSkVWMEZTUlY5Q1FVTkxSVVFpZlEuYXZwSHpzT2VCUlEydUVLLXdNc2oyam5BX19iY19nd2dWYTladlAxMGhrbC1fYVZYb2I5aF9PN2JwTlpZRWR6VjI1VVR4X1BQRzFPMHpiNG9oLUo0TDZwam0yMGZZclRXTndZeGJaLWxYamRZcW1YWmsybkxLMnJTWkZNOWxyVTJGOXJvOUdSOEtsN3JzenpxazBQa3N1NkFybzgtRTRlWGoxQ3ZGYnB6cEQ1VUVZeXp0M0JaUE9KWTZYVVU1LXd2azV1UFl2OWhCeG5jNEdPYXdRelJiY3l3Ukh6N2g1NWMwV2dqVUNpOFc2SD04xVjZVbk5wV0V3Mk5IY3JUelV3UldRclVrSkpRM1JoZVRGbk1qUk5QU0pkTENKaVlYTnBZMGx1ZEdWbmNtbDBlU0k2ZEhKMVpTd2laWFpoYkhWaGRHbHZibFI1Y0dVaU9pSkNRVk5KUXl4SVFWSkVWMEZTUlY5Q1FVTkxSVVFpZlEuYXZwSHpzT2VCUlEydUVLLXdNc2oyam5BX19iY19nd2dWYTladlAxMGhrbC1fYVZYb2I5aF9PN2JwTlpZRWR6VjI1VVR4X1BQRzFPMHpiNG9oLUo0TDZwam0yMGZZclRXTndZeGJaLWxYamRZcW1YWmsybkxLMnJTWkZNOWxyVTJGOXJvOUdSOEtsN3JzenpxazBQa3N1NkFybzgtRTRlWGoxQ3ZGYnB6cEQ1VUVZeXp0M0JaUE9KWTZYVVU1LXd2azV1UFl2OWhCeG5jNEdPYXdRelJiY3l3Ukh6N2g1NWMwV2dqVUNpOFc2SD04xVjZVbk5wV0V3Mk5IY3JUelV3UldRclVrSkpRM1JoZjhXQnNVZmduX3BScyIsIm9yaWdpbiI6Imh0dHBzOlwvXC93ZWJhdXRobi5maXJzdHllYXIuaWQuYXUiLCJhbmRyb2lkUGFja2FnZU5hbWUiOiJjb20uYW5kcm9pZC5jaHJvbWUifQ"
            },
            "type": "public-key"
        }"#).unwrap();

        debug!("{:?}", rsp_d);

        let result = wan.register_credential_internal(
            &rsp_d,
            UserVerificationPolicy::Discouraged_DO_NOT_USE,
            &chal,
            &[],
            &[COSEAlgorithm::ES256],
            None,
            false,
            &RequestRegistrationExtensions::default(),
            false,
        );
        debug!("{:?}", result);
        // Currently UNSUPPORTED as openssl doesn't have eddsa management utils that we need.
        assert!(result.is_err());
    }

    // https://w3c.github.io/webauthn/#sctn-android-safetynet-attestation

    #[test]
    fn test_google_pixel_3a_indirect_attestation() {
        let _ = tracing_subscriber::fmt::try_init();
        let wan = Webauthn::new_unsafe_experts_only(
            "https://webauthn.firstyear.id.au",
            "webauthn.firstyear.id.au",
            &Url::parse("https://webauthn.firstyear.id.au").unwrap(),
            None,
            None,
            None,
        );
        let chal: Base64UrlSafeData =
            serde_json::from_str("\"CxQSmkUusCl8ig6qyA0Cp4qFU4Y960OAYGX1c24G-fo\"").unwrap();
        let chal = Challenge::from(chal);

        let rsp_d: RegisterPublicKeyCredential = serde_json::from_str(r#"{
        "id": "ARyDDvKaBEFvDCuXalasRT97rY-Akdim8kK03QK3EP3gJHq4ddYvvWvgkd_FwoR4zrfstbILRWCpT4Xy9j44c8w",
        "rawId": "ARyDDvKaBEFvDCuXalasRT97rY-Akdim8kK03QK3EP3gJHq4ddYvvWvgkd_FwoR4zrfstbILRWCpT4Xy9j44c8w",
        "response": {
          "attestationObject": "o2NmbXRxYW5kcm9pZC1zYWZldHluZXRnYXR0U3RtdKJjdmVyaTIxNDgxNTA0NGhyZXNwb25zZVkgcmV5SmhiR2NpT2lKU1V6STFOaUlzSW5nMVl5STZXeUpOU1VsR1dVUkRRMEpGYVdkQmQwbENRV2RKVWtGT2FHTkhiRGN3UWpWaFNVTlJRVUZCUVVWQ2JpOUZkMFJSV1VwTGIxcEphSFpqVGtGUlJVeENVVUYzVW1wRlRFMUJhMGRCTVZWRlFtaE5RMVpXVFhoSmFrRm5RbWRPVmtKQmIxUkhWV1IyWWpKa2MxcFRRbFZqYmxaNlpFTkNWRnBZU2pKaFYwNXNZM2xDVFZSRlRYaEZla0ZTUW1kT1ZrSkJUVlJEYTJSVlZYbENSRkZUUVhoU1JGRjNTR2hqVGsxcVNYZE5WRWt4VFZSQmQwMUVUVEJYYUdOT1RXcEpkMDVFU1RGTlZFRjNUVVJOZWxkcVFXUk5Vbk4zUjFGWlJGWlJVVVJGZUVwb1pFaFNiR016VVhWWlZ6VnJZMjA1Y0ZwRE5XcGlNakIzWjJkRmFVMUJNRWREVTNGSFUwbGlNMFJSUlVKQlVWVkJRVFJKUWtSM1FYZG5aMFZMUVc5SlFrRlJRMWsxYkhwR1kwaHNaVEZFVEd4MFRrcG9iRk5qYm5GV1VuTllRMWQ2TmpGR2J5OUdSMHRzWW0wMGJHSTVZemR5V1hwWlRtOU1UV3hVV0d0YWFVczBSMUpGZG5acVozZE1kMk0zVEVNNFRUWjZiM0pHY1dFNWFqTjZORzB2VFhWa1EyRkdWblIzTUVGVmJtVnFhbFpTYUZSaVdrVkthV3M0VVVWaWFIZzFZWHBDVGxOd00yZ3JSemcyTlV4YUszbG5SR1JrTUZaYVMyUnhOVE5MUWpscU1FWTRlV0pyWkhaVlkxTnpMMjB6UjAxcVYwVkJhWEEwVjI1eVJGazVSa3hhWm5ncmNFTndRVTVQUVdKVVRuWmphV2xMUVhkUGExRkhSRVZKTVVaeFZFTjFTVzVhYVVoU2RtMXBaazlSYzA5dVUwVjRTWFV6YzFjM2RsRmpSWFJVWWtZclZWcDRhR3BpU0RWRmRtSmtiMFZ1WVV4Tk5sUkNTbmwxYkRkMGVsZDFhalJaTkZoVVkydDJaRk5EYm5KQlUzZHpaM2xST1hWT09YZG9VSFpCVm01NFIxWkNXRWxGVkVWMFZVRTRiWGxRTkROVVMzTktRV2ROUWtGQlIycG5aMHAzVFVsSlEySkVRVTlDWjA1V1NGRTRRa0ZtT0VWQ1FVMURRbUZCZDBWM1dVUldVakJzUWtGM2QwTm5XVWxMZDFsQ1FsRlZTRUYzUlhkRVFWbEVWbEl3VkVGUlNDOUNRVWwzUVVSQlpFSm5UbFpJVVRSRlJtZFJWWEZXVFRKVlRWcFdRVXMxUTNsUldUWkdSM0owVTBrM01YTXliM2RJZDFsRVZsSXdha0pDWjNkR2IwRlZTbVZKV1VSeVNsaHJXbEZ4TldSU1pHaHdRMFF6YkU5NmRVcEpkMkpSV1VsTGQxbENRbEZWU0VGUlJVVlpWRUptVFVOdlIwTkRjMGRCVVZWR1FucEJRbWhvTlc5a1NGSjNUMms0ZG1JeVRucGpRelYzWVRKcmRWb3lPWFphZVRsdVpFaE5lRnBFVW5CaWJsRjNUVkZaU1V0M1dVSkNVVlZJVFVGTFIwcFhhREJrU0VFMlRIazVkMkV5YTNWYU1qbDJXbms1ZVZwWVFuWk1NazVzWTI1U2Vrd3laREJqZWtaclRrTTFhMXBZU1hkSVVWbEVWbEl3VWtKQ1dYZEdTVWxUV1ZoU01GcFlUakJNYlVaMVdraEtkbUZYVVhWWk1qbDBUVU5GUjBFeFZXUkpRVkZoVFVKbmQwTkJXVWRhTkVWTlFWRkpRazFCZDBkRGFYTkhRVkZSUWpGdWEwTkNVVTEzVUhkWlJGWlNNR1pDUkdkM1RtcEJNRzlFUzJkTlNWbDFZVWhTTUdORWIzWk1NazU1WWtoTmRXTkhkSEJNYldSMllqSmpkbG96VW5wTlYxRXdZVmMxTUV3eFNUTlBSMWt4WldwT2NVNHpiRzVNYlU1NVlrUkRRMEZSVFVkRGFYTkhRVkZSUWpGdWEwTkNRVWxGWjJaUlJXZG1SVUUzZDBJeFFVWkhhbk5RV0RsQldHMWpWbTB5TkU0emFWQkVTMUkyZWtKemJua3ZaV1ZwUlV0aFJHWTNWV2wzV0d4QlFVRkNabkJFYkVSQlNVRkJRVkZFUVVWWmQxSkJTV2RKTkRWc1VIRXdOVmRXZUVsNmJ6RlZiR2hvVTBWMmNrbHZRVlkxUlhGME1DdHNWa1Z1YVd4WWNUaFZRMGxEVjNCSFJrZzVSQzlFZVdabllXZFhNeTh5WjBWMVNGcGFPRXRIU3psQ09VcGFla0pEU2l0Q2RsTmxRVWhaUVV0WWJTczRTalExVDFOSWQxWnVUMlpaTmxZek5XSTFXR1phZUdkRGRtbzFWRll3YlZoRFZtUjRORkZCUVVGR0sydFBWVXcwWjBGQlFrRk5RVko2UWtaQmFVVkJiMk50Vm1SamJFTkVNbUpHVUU5T2IxWXlNWFJpT0VkelpWZGtNa1p0TTFkVFIzRlhUVEIzUkRCQ2MwTkpSV1YwUkhsd05YcGpialU0YWpob1VrUlNieTlXVlVkMFp6TnRkaklyV1RaS1JqUnFibnBDVWt0RlVVMUJNRWREVTNGSFUwbGlNMFJSUlVKRGQxVkJRVFJKUWtGUlFVbHViSGh1U1VsMlEwdHJWbWxLWlRWaWRFVTJUVkJaUVdwNE0wZElXakZMTDNwc2RIQnpaVTFTVVRoaVJsVkxUVVpNVTFOeE4zVk9SbEJSY2pkUFZ6Tm9RMmhuVEVORFZtOUZla2MwWW5GR2RVMTRWMklyU0hRNVVFaDBSbmhXV0hwaVowcDVhbUoyUkRkSVUwOVVjV3M0UVZreFlTOU9VVFYxYW5ORFRGTktORVJtTmxKa2FFZ3ZUM1p3ZEdWUU0wNW1iRlZYVGsxSlFrVjJNRlYyTVhSMlRFVm1VVWRYTUdoVFltYzJUQzlJUjJkQlkxZDFURGRzTmk5UVdFbEZkVEpsVERkcllVZEdVbWhKTW1KcU5FcE9PVmxGU0VkdWRtaGpSM0ExTlhsQ016ZG9TWGd4YkRoVk56VllPV2hJTVU4MlRVMXRlblpLTURWeGRGaERjMVJZVVdsbGFrUXdWSFI0VkdwSFZpdFdTM1J3VEZoSlEzQlVabmhPYzNCQ2VrTk1hRGt4U1V4dE1uQkhORlk1Wkd0dFJWWnZPVEIwU25wS1NTOUJTelpoVUdadloyTktiMEpuYm5CVE9GVlpkMEZPYlZORElpd2lUVWxKUm1wRVEwTkJNMU5uUVhkSlFrRm5TVTVCWjBOUGMyZEplazV0VjB4YVRUTmliWHBCVGtKbmEzRm9hMmxIT1hjd1FrRlJjMFpCUkVKSVRWRnpkME5SV1VSV1VWRkhSWGRLVmxWNlJXbE5RMEZIUVRGVlJVTm9UVnBTTWpsMldqSjRiRWxHVW5sa1dFNHdTVVpPYkdOdVduQlpNbFo2U1VWNFRWRjZSVlZOUWtsSFFURlZSVUY0VFV4U01WSlVTVVpLZG1JelVXZFZha1YzU0doalRrMXFRWGRQUkVWNlRVUkJkMDFFVVhsWGFHTk9UV3BqZDA5VVRYZE5SRUYzVFVSUmVWZHFRa2ROVVhOM1ExRlpSRlpSVVVkRmQwcFdWWHBGYVUxRFFVZEJNVlZGUTJoTldsSXlPWFphTW5oc1NVWlNlV1JZVGpCSlJrNXNZMjVhY0ZreVZucEpSWGhOVVhwRlZFMUNSVWRCTVZWRlFYaE5TMUl4VWxSSlJVNUNTVVJHUlU1RVEwTkJVMGwzUkZGWlNrdHZXa2xvZG1OT1FWRkZRa0pSUVVSblowVlFRVVJEUTBGUmIwTm5aMFZDUVV0MlFYRnhVRU5GTWpkc01IYzVla000WkZSUVNVVTRPV0pCSzNoVWJVUmhSemQ1TjFabVVUUmpLMjFQVjJoc1ZXVmlWVkZ3U3pCNWRqSnlOamM0VWtwRmVFc3dTRmRFYW1WeEsyNU1TVWhPTVVWdE5XbzJja0ZTV21sNGJYbFNVMnBvU1ZJd1MwOVJVRWRDVFZWc1pITmhlblJKU1VvM1R6Qm5Memd5Y1dvdmRrZEViQzh2TTNRMGRGUnhlR2xTYUV4UmJsUk1XRXBrWlVJck1rUm9hMlJWTmtsSlozZzJkMDQzUlRWT1kxVklNMUpqYzJWcVkzRnFPSEExVTJveE9YWkNiVFpwTVVab2NVeEhlVzFvVFVaeWIxZFdWVWRQTTNoMFNVZzVNV1J6WjNrMFpVWkxZMlpMVmt4WFN6TnZNakU1TUZFd1RHMHZVMmxMYlV4aVVrbzFRWFUwZVRGbGRVWktiVEpLVFRsbFFqZzBSbXR4WVROcGRuSllWMVZsVm5SNVpUQkRVV1JMZG5OWk1rWnJZWHAyZUhSNGRuVnpURXA2VEZkWlNHczFOWHBqVWtGaFkwUkJNbE5sUlhSQ1lsRm1SREZ4YzBOQmQwVkJRV0ZQUTBGWVdYZG5aMFo1VFVFMFIwRXhWV1JFZDBWQ0wzZFJSVUYzU1VKb2FrRmtRbWRPVmtoVFZVVkdha0ZWUW1kbmNrSm5SVVpDVVdORVFWRlpTVXQzV1VKQ1VWVklRWGRKZDBWbldVUldVakJVUVZGSUwwSkJaM2RDWjBWQ0wzZEpRa0ZFUVdSQ1owNVdTRkUwUlVablVWVktaVWxaUkhKS1dHdGFVWEUxWkZKa2FIQkRSRE5zVDNwMVNrbDNTSGRaUkZaU01HcENRbWQzUm05QlZUVkxPSEpLYmtWaFN6Qm5ibWhUT1ZOYWFYcDJPRWxyVkdOVU5IZGhRVmxKUzNkWlFrSlJWVWhCVVVWRldFUkNZVTFEV1VkRFEzTkhRVkZWUmtKNlFVSm9hSEJ2WkVoU2QwOXBPSFppTWs1NlkwTTFkMkV5YTNWYU1qbDJXbms1Ym1SSVRubE5WRUYzUW1kbmNrSm5SVVpDVVdOM1FXOVphMkZJVWpCalJHOTJURE5DY21GVE5XNWlNamx1VEROS2JHTkhPSFpaTWxaNVpFaE5kbG96VW5wamFrVjFXa2RXZVUxRVVVZEJNVlZrU0hkUmRFMURjM2RMWVVGdWIwTlhSMGt5YURCa1NFRTJUSGs1YW1OdGQzVmpSM1J3VEcxa2RtSXlZM1phTTFKNlkycEZkbG96VW5wamFrVjFXVE5LYzAxRk1FZEJNVlZrU1VGU1IwMUZVWGREUVZsSFdqUkZUVUZSU1VKTlJHZEhRMmx6UjBGUlVVSXhibXREUWxGTmQwdHFRVzlDWjJkeVFtZEZSa0pSWTBOQlVsbGpZVWhTTUdOSVRUWk1lVGwzWVRKcmRWb3lPWFphZVRsNVdsaENkbU15YkRCaU0wbzFUSHBCVGtKbmEzRm9hMmxIT1hjd1FrRlJjMFpCUVU5RFFXZEZRVWxXVkc5NU1qUnFkMWhWY2pCeVFWQmpPVEkwZG5WVFZtSkxVWFZaZHpOdVRHWnNUR1pNYURWQldWZEZaVlpzTDBSMU1UaFJRVmRWVFdSalNqWnZMM0ZHV21Kb1dHdENTREJRVG1OM09UZDBhR0ZtTWtKbGIwUlpXVGxEYXk5aUsxVkhiSFZvZURBMmVtUTBSVUptTjBnNVVEZzBibTV5ZDNCU0t6UkhRa1JhU3l0WWFETkpNSFJ4U25reWNtZFBjVTVFWm14eU5VbE5VVGhhVkZkQk0zbHNkR0ZyZWxOQ1MxbzJXSEJHTUZCd2NYbERVblp3TDA1RFIzWXlTMWd5VkhWUVEwcDJjMk53TVM5dE1uQldWSFI1UW1wWlVGSlJLMUYxUTFGSFFVcExhblJPTjFJMVJFWnlabFJ4VFZkMldXZFdiSEJEU2tKcmQyeDFOeXMzUzFrelkxUkpabnBGTjJOdFFVeHphMDFMVGt4MVJIb3JVbnBEWTNOWlZITldZVlUzVm5BemVFdzJNRTlaYUhGR2EzVkJUMDk0UkZvMmNFaFBhamtyVDBwdFdXZFFiVTlVTkZnekt6ZE1OVEZtV0VwNVVrZzVTMlpNVWxBMmJsUXpNVVExYm0xelIwRlBaMW95Tmk4NFZEbG9jMEpYTVhWdk9XcDFOV1phVEZwWVZsWlROVWd3U0hsSlFrMUZTM2xIVFVsUWFFWlhjbXgwTDJoR1V6STRUakY2WVV0Sk1GcENSMFF6WjFsblJFeGlhVVJVT1daSFdITjBjR3NyUm0xak5HOXNWbXhYVUhwWVpUZ3hkbVJ2Ulc1R1luSTFUVEkzTWtoa1owcFhieXRYYUZRNVFsbE5NRXBwSzNka1ZtMXVVbVptV0dkc2IwVnZiSFZVVG1OWGVtTTBNV1JHY0dkS2RUaG1Sak5NUnpCbmJESnBZbE5aYVVOcE9XRTJhSFpWTUZSd2NHcEtlVWxYV0doclNsUmpUVXBzVUhKWGVERldlWFJGVlVkeVdESnNNRXBFZDFKcVZ5ODJOVFp5TUV0V1FqQXllRWhTUzNadE1scExTVEF6Vkdkc1RFbHdiVlpEU3pOclFrdHJTMDV3UWs1clJuUTRjbWhoWm1ORFMwOWlPVXA0THpsMGNFNUdiRkZVYkRkQ016bHlTbXhLVjJ0U01UZFJibHB4Vm5CMFJtVlFSazlTYjFwdFJucE5QU0lzSWsxSlNVWlpha05EUWtWeFowRjNTVUpCWjBsUlpEY3dUbUpPY3pJclVuSnhTVkV2UlRoR2FsUkVWRUZPUW1kcmNXaHJhVWM1ZHpCQ1FWRnpSa0ZFUWxoTlVYTjNRMUZaUkZaUlVVZEZkMHBEVWxSRldrMUNZMGRCTVZWRlEyaE5VVkl5ZUhaWmJVWnpWVEpzYm1KcFFuVmthVEY2V1ZSRlVVMUJORWRCTVZWRlEzaE5TRlZ0T1haa1EwSkVVVlJGWWsxQ2EwZEJNVlZGUVhoTlUxSXllSFpaYlVaelZUSnNibUpwUWxOaU1qa3dTVVZPUWsxQ05GaEVWRWwzVFVSWmVFOVVRWGROUkVFd1RXeHZXRVJVU1RSTlJFVjVUMFJCZDAxRVFUQk5iRzkzVW5wRlRFMUJhMGRCTVZWRlFtaE5RMVpXVFhoSmFrRm5RbWRPVmtKQmIxUkhWV1IyWWpKa2MxcFRRbFZqYmxaNlpFTkNWRnBZU2pKaFYwNXNZM2xDVFZSRlRYaEdSRUZUUW1kT1ZrSkJUVlJETUdSVlZYbENVMkl5T1RCSlJrbDRUVWxKUTBscVFVNUNaMnR4YUd0cFJ6bDNNRUpCVVVWR1FVRlBRMEZuT0VGTlNVbERRMmRMUTBGblJVRjBhRVZEYVhnM2FtOVlaV0pQT1hrdmJFUTJNMnhoWkVGUVMwZzVaM1pzT1UxbllVTmpabUl5YWtndk56Wk9kVGhoYVRaWWJEWlBUVk12YTNJNWNrZzFlbTlSWkhObWJrWnNPVGQyZFdaTGFqWmlkMU5wVmpadWNXeExjaXREVFc1NU5sTjRia2RRWWpFMWJDczRRWEJsTmpKcGJUbE5XbUZTZHpGT1JVUlFhbFJ5UlZSdk9HZFpZa1YyY3k5QmJWRXpOVEZyUzFOVmFrSTJSekF3YWpCMVdVOUVVREJuYlVoMU9ERkpPRVV6UTNkdWNVbHBjblUyZWpGcldqRnhLMUJ6UVdWM2JtcEllR2R6U0VFemVUWnRZbGQzV2tSeVdGbG1hVmxoVWxGTk9YTkliV3RzUTJsMFJETTRiVFZoWjBrdmNHSnZVRWRwVlZVck5rUlBiMmR5UmxwWlNuTjFRalpxUXpVeE1YQjZjbkF4V210cU5WcFFZVXMwT1d3NFMwVnFPRU00VVUxQlRGaE1NekpvTjAweFlrdDNXVlZJSzBVMFJYcE9hM1JOWnpaVVR6aFZjRzEyVFhKVmNITjVWWEYwUldvMVkzVklTMXBRWm0xbmFFTk9Oa296UTJsdmFqWlBSMkZMTDBkUU5VRm1iRFF2V0hSalpDOXdNbWd2Y25Nek4wVlBaVnBXV0hSTU1HMDNPVmxDTUdWelYwTnlkVTlETjFoR2VGbHdWbkU1VDNNMmNFWk1TMk4zV25CRVNXeFVhWEo0V2xWVVVVRnpObkY2YTIwd05uQTVPR2MzUWtGbEsyUkVjVFprYzI4ME9UbHBXVWcyVkV0WUx6RlpOMFI2YTNabmRHUnBlbXByV0ZCa2MwUjBVVU4yT1ZWM0szZHdPVlUzUkdKSFMyOW5VR1ZOWVROTlpDdHdkbVY2TjFjek5VVnBSWFZoS3l0MFoza3ZRa0pxUmtaR2VUTnNNMWRHY0U4NVMxZG5lamQ2Y0cwM1FXVkxTblE0VkRFeFpHeGxRMlpsV0d0clZVRkxTVUZtTlhGdlNXSmhjSE5hVjNkd1ltdE9SbWhJWVhneWVFbFFSVVJuWm1jeFlYcFdXVGd3V21OR2RXTjBURGRVYkV4dVRWRXZNR3hWVkdKcFUzY3hia2cyT1UxSE5ucFBNR0k1WmpaQ1VXUm5RVzFFTURaNVN6VTJiVVJqV1VKYVZVTkJkMFZCUVdGUFEwRlVaM2RuWjBVd1RVRTBSMEV4VldSRWQwVkNMM2RSUlVGM1NVSm9ha0ZRUW1kT1ZraFNUVUpCWmpoRlFsUkJSRUZSU0M5TlFqQkhRVEZWWkVSblVWZENRbFJyY25semJXTlNiM0pUUTJWR1RERktiVXhQTDNkcFVrNTRVR3BCWmtKblRsWklVMDFGUjBSQlYyZENVbWRsTWxsaFVsRXlXSGx2YkZGTU16QkZlbFJUYnk4dmVqbFRla0puUW1kbmNrSm5SVVpDVVdOQ1FWRlNWVTFHU1hkS1VWbEpTM2RaUWtKUlZVaE5RVWRIUjFkb01HUklRVFpNZVRsMldUTk9kMHh1UW5KaFV6VnVZakk1Ymt3eVpIcGpha1YzUzFGWlNVdDNXVUpDVVZWSVRVRkxSMGhYYURCa1NFRTJUSGs1ZDJFeWEzVmFNamwyV25rNWJtTXpTWGhNTW1SNlkycEZkVmt6U2pCTlJFbEhRVEZWWkVoM1VYSk5RMnQzU2paQmJHOURUMGRKVjJnd1pFaEJOa3g1T1dwamJYZDFZMGQwY0V4dFpIWmlNbU4yV2pOT2VVMVRPVzVqTTBsNFRHMU9lV0pFUVRkQ1owNVdTRk5CUlU1RVFYbE5RV2RIUW0xbFFrUkJSVU5CVkVGSlFtZGFibWRSZDBKQlowbDNSRkZaVEV0M1dVSkNRVWhYWlZGSlJrRjNTWGRFVVZsTVMzZFpRa0pCU0ZkbFVVbEdRWGROZDBSUldVcExiMXBKYUhaalRrRlJSVXhDVVVGRVoyZEZRa0ZFVTJ0SWNrVnZiemxETUdSb1pXMU5XRzlvTm1SR1UxQnphbUprUWxwQ2FVeG5PVTVTTTNRMVVDdFVORlo0Wm5FM2RuRm1UUzlpTlVFelVta3habmxLYlRsaWRtaGtSMkZLVVROaU1uUTJlVTFCV1U0dmIyeFZZWHB6WVV3cmVYbEZiamxYY0hKTFFWTlBjMmhKUVhKQmIzbGFiQ3QwU21GdmVERXhPR1psYzNOdFdHNHhhRWxXZHpReGIyVlJZVEYyTVhabk5FWjJOelI2VUd3MkwwRm9VM0ozT1ZVMWNFTmFSWFEwVjJrMGQxTjBlalprVkZvdlEweEJUbmc0VEZwb01VbzNVVXBXYWpKbWFFMTBabFJLY2psM05Ib3pNRm95TURsbVQxVXdhVTlOZVN0eFpIVkNiWEIyZGxsMVVqZG9Xa3cyUkhWd2MzcG1ibmN3VTJ0bWRHaHpNVGhrUnpsYVMySTFPVlZvZG0xaFUwZGFVbFppVGxGd2MyY3pRbHBzZG1sa01HeEpTMDh5WkRGNGIzcGpiRTk2WjJwWVVGbHZka3BLU1hWc2RIcHJUWFV6TkhGUllqbFRlaTk1YVd4eVlrTm5hamc5SWwxOS5leUp1YjI1alpTSTZJbFJOUkRoU1JtTm1NbTlrWlhkNU4wUm5LekJ2Y0VkT1IzSkRZVnBEZGk5QlZVSmpSRW92U2taUFYyODlJaXdpZEdsdFpYTjBZVzF3VFhNaU9qRTJORFEzTXpnek9UTTNNVEFzSW1Gd2ExQmhZMnRoWjJWT1lXMWxJam9pWTI5dExtZHZiMmRzWlM1aGJtUnliMmxrTG1kdGN5SXNJbUZ3YTBScFoyVnpkRk5vWVRJMU5pSTZJbVpaUlVSV2VVbHFPRFJ4V2xkd1dXazBRMUJ6VlU4MlN6aHVZbU5RWWs0dlkwczJXREl3UTJSM09GVTlJaXdpWTNSelVISnZabWxzWlUxaGRHTm9JanAwY25WbExDSmhjR3REWlhKMGFXWnBZMkYwWlVScFoyVnpkRk5vWVRJMU5pSTZXeUk0VURGelZ6QkZVRXBqYzJ4M04xVjZVbk5wV0V3Mk5IY3JUelV3UldRclVrSkpRM1JoZVRGbk1qUk5QU0pkTENKaVlYTnBZMGx1ZEdWbmNtbDBlU0k2ZEhKMVpTd2laWFpoYkhWaGRHbHZibFI1Y0dVaU9pSkNRVk5KUXl4SVFWSkVWMEZTUlY5Q1FVTkxSVVFpZlEuYzl0Q1dLeUNhdUhMTU82M25pV05pMDQ0THdqRUpHVlBxZEtPTTNNZGFWSmJPbTFDazAxdndKYVBUc25OTkJ1bkRxdzZBbTVxVml6cGZESzRwYUpUQndxbXF5U0JqMWdDanJ3NDBUeWd2aXV0OUN0bDZMUDJDeFBSNmJXaUo4Yk5GMGNlRXhwcEhkN3VFSUtuLWp4ZkNhZk93WmNRaGlRM1JfZnBYdGFQV3dWZURHOEdvd18yQ1BaX0ZyS2x0X3BzQ3dQN3pzVm9CbWNCOXkwV0pUMWthd3FmUTd3SVhJTUZrQi01ejc1cGRYMWFNTzI1VUY0dWhTdDQ5YVU3b3hldjdpVmMtVDNveUt5c2FMYzd4RVdMcEU5MUY2bGdmSUpwU3N2M2pKRTNXbHlKaWU3aTFCTkVOcnd4RUJvU1hLMGhzRkRLZUgtZTRocTVqT0JDemdyVEt3aGF1dGhEYXRhWMVqubvw35oW-R27M7uxMvr50Xx4LEgmxuxw7O5Y2X71KkUAAAAAuT_ZYfLmRi-xIoIAIkfeeABBARyDDvKaBEFvDCuXalasRT97rY-Akdim8kK03QK3EP3gJHq4ddYvvWvgkd_FwoR4zrfstbILRWCpT4Xy9j44c8ylAQIDJiABIVgg5AVnhHv0nmHyuIxAlZRtzI9bZPsk5EsJFxY7pY5uwnQiWCCf0Q1_p4YxWwSEOdjnacuj1ZeyPzq_ZJ1Hn2kIEuZchg",
          "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiQ3hRU21rVXVzQ2w4aWc2cXlBMENwNHFGVTRZOTYwT0FZR1gxYzI0Ry1mbyIsIm9yaWdpbiI6Imh0dHBzOlwvXC93ZWJhdXRobi5maXJzdHllYXIuaWQuYXUiLCJhbmRyb2lkUGFja2FnZU5hbWUiOiJjb20uYW5kcm9pZC5jaHJvbWUifQ"
        },
        "type": "public-key"
        }"#).unwrap();

        debug!("{:?}", rsp_d);

        let result = wan.register_credential_internal(
            &rsp_d,
            UserVerificationPolicy::Discouraged_DO_NOT_USE,
            &chal,
            &[],
            &[COSEAlgorithm::ES256],
            None,
            false,
            &RequestRegistrationExtensions::default(),
            false,
        );
        dbg!("{:?}", &result);
        assert!(result.is_ok());
    }

    #[test]
    fn test_google_pixel_3a_none_attestation() {
        let _ = tracing_subscriber::fmt::try_init();
        let wan = Webauthn::new_unsafe_experts_only(
            "https://webauthn.firstyear.id.au",
            "webauthn.firstyear.id.au",
            &Url::parse("https://webauthn.firstyear.id.au").unwrap(),
            None,
            None,
            None,
        );

        let chal: Base64UrlSafeData =
            serde_json::from_str("\"55Wztjbgks9UkS5jYthawNFik0HSiYuCSB5pzNbT6k0\"").unwrap();
        let chal = Challenge::from(chal);

        let rsp_d: RegisterPublicKeyCredential = serde_json::from_str(r#"{
        "id": "AfzEi3UOVveYjwUwIFO3QuN9V0fomECvAYrD_8S5FAsUJqtGbwpgB9bEfphVOURzFQoEszkuULIj5fMvnTkt6cs",
        "rawId": "AfzEi3UOVveYjwUwIFO3QuN9V0fomECvAYrD_8S5FAsUJqtGbwpgB9bEfphVOURzFQoEszkuULIj5fMvnTkt6cs",
        "response": {
          "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjFarm78N-aFvkduzO7sTL6-dF8eCxIJsbscOzuWNl-9SpFAAAAAAAAAAAAAAAAAAAAAAAAAAAAQQH8xIt1Dlb3mI8FMCBTt0LjfVdH6JhArwGKw__EuRQLFCarRm8KYAfWxH6YVTlEcxUKBLM5LlCyI-XzL505LenLpQECAyYgASFYII2OFisY2sjerzLYjLYvHsQh8V7cnpRcSL4A77wKqcRTIlggm7s0CUKEmkBBFp7Nng-9_pZ5Dm9y39uy6QJmDLgmgho",
          "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiNTVXenRqYmdrczlVa1M1all0aGF3TkZpazBIU2lZdUNTQjVwek5iVDZrMCIsIm9yaWdpbiI6Imh0dHBzOlwvXC93ZWJhdXRobi5maXJzdHllYXIuaWQuYXUiLCJhbmRyb2lkUGFja2FnZU5hbWUiOiJjb20uYW5kcm9pZC5jaHJvbWUifQ"
        },
        "type": "public-key"
        }"#).unwrap();

        debug!("{:?}", rsp_d);

        let result = wan.register_credential_internal(
            &rsp_d,
            UserVerificationPolicy::Discouraged_DO_NOT_USE,
            &chal,
            &[],
            &[COSEAlgorithm::ES256],
            None,
            false,
            &RequestRegistrationExtensions::default(),
            true,
        );
        debug!("{:?}", result);
        assert!(result.is_ok());
    }

    #[test]
    fn test_google_pixel_3a_ignores_requested_algo() {
        let _ = tracing_subscriber::fmt::try_init();
        let wan = Webauthn::new_unsafe_experts_only(
            "https://webauthn.firstyear.id.au",
            "webauthn.firstyear.id.au",
            &Url::parse("https://webauthn.firstyear.id.au").unwrap(),
            None,
            None,
            None,
        );

        let chal: Base64UrlSafeData =
            serde_json::from_str("\"t_We131NpwllyPL0x26bzZgkF5f_XvA7Ocb4b98zlxM\"").unwrap();
        let chal = Challenge::from(chal);

        let rsp_d: RegisterPublicKeyCredential = serde_json::from_str(r#"{
        "id": "AfJfonHsXY_f7_gFmV1dI473Ce--_g0tHhdXUoh7JmMn0gzhYUtU9bFqpCgSljjwJxEXkjzb-11ulePZyI0RiyQ",
        "rawId": "AfJfonHsXY_f7_gFmV1dI473Ce--_g0tHhdXUoh7JmMn0gzhYUtU9bFqpCgSljjwJxEXkjzb-11ulePZyI0RiyQ",
        "response": {
            "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjFarm78N-aFvkduzO7sTL6-dF8eCxIJsbscOzuWNl-9SpFAAAAAAAAAAAAAAAAAAAAAAAAAAAAQQHyX6Jx7F2P3-_4BZldXSOO9wnvvv4NLR4XV1KIeyZjJ9IM4WFLVPWxaqQoEpY48CcRF5I82_tdbpXj2ciNEYskpQECAyYgASFYIE_9awy66uhXZ6hIzPAW2AzIrTMZ7kyC2jtZe0zuH_pOIlggFbNKhOSt8-prIx0snKRqcxULtc2u1rzUUf47g1PxTcU",
            "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoidF9XZTEzMU5wd2xseVBMMHgyNmJ6WmdrRjVmX1h2QTdPY2I0Yjk4emx4TSIsIm9yaWdpbiI6Imh0dHBzOlwvXC93ZWJhdXRobi5maXJzdHllYXIuaWQuYXUiLCJhbmRyb2lkUGFja2FnZU5hbWUiOiJvcmcubW96aWxsYS5maXJlZm94In0"
        },
        "type": "public-key"
        }"#).unwrap();

        debug!("{:?}", rsp_d);

        let result = wan.register_credential_internal(
            &rsp_d,
            UserVerificationPolicy::Discouraged_DO_NOT_USE,
            &chal,
            &[],
            &[
                COSEAlgorithm::RS256,
                COSEAlgorithm::EDDSA,
                COSEAlgorithm::INSECURE_RS1,
            ],
            None,
            false,
            &RequestRegistrationExtensions::default(),
            false,
        );
        debug!("{:?}", result);
        assert!(result.is_err());
    }

    /// See https://github.com/kanidm/webauthn-rs/issues/105
    #[test]
    fn test_firefox_98_hello_incorrectly_truncates_aaguid() {
        let _ = tracing_subscriber::fmt::try_init();
        let wan = Webauthn::new_unsafe_experts_only(
            "https://webauthn.firstyear.id.au",
            "webauthn.firstyear.id.au",
            &Url::parse("https://webauthn.firstyear.id.au").unwrap(),
            None,
            None,
            None,
        );

        let chal: Base64UrlSafeData =
            serde_json::from_str("\"FKVseWmr5DxQ_H9iTyoTgRPIClLspXO0XbOKQfMuaFc\"").unwrap();
        let chal = Challenge::from(chal);

        let rsp_d: RegisterPublicKeyCredential = serde_json::from_str(r#"{
            "id": "6h7wVk2n4Buulhd5fiShGb0BBViIgvDoVO3xhn0A0Mg",
            "rawId": "6h7wVk2n4Buulhd5fiShGb0BBViIgvDoVO3xhn0A0Mg",
            "response": {
            "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVkBWGq5u_Dfmhb5Hbszu7Ey-vnRfHgsSCbG7HDs7ljZfvUqRQAAAAAAACDqHvBWTafgG66WF3l-JKEZvQEFWIiC8OhU7fGGfQDQyKQBAwM5AQAgWQEAt86lR2w_hmnhDr6tvJD5hmIuWt0QkG1sphC8aqeOHuIWnbcBWnxNUrKQibJxEGJilM20s-_w-aUjDoV5MYu4NBgguFHju-qA-qe1sjhqY7UkMkx4Z1KGMeiZNNGgk5Gtmu0xjaq-1RohB3TKADeWTularHWzG6q6sJHgC-qKKa67Rmwr0T4a4S3VjLvjvSPILx88nLJvwqO1rDb5cLOgL5CEjtRijR6SNeN05uBhz2ePn5mMo2lN73pHsMGPo68pGWIWWsb2sC_aBF2eA02Me2jldIgSzMy3y8xsTIg6r_xF105pC8jOPsQVN2TJDxN9zVEuxpY_mUsqGOAFGR-SiyFDAQAB",
            "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJGS1ZzZVdtcjVEeFFfSDlpVHlvVGdSUElDbExzcFhPMFhiT0tRZk11YUZjIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cHM6Ly93ZWJhdXRobi5maXJzdHllYXIuaWQuYXUiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0"
            },
            "type": "public-key"
        }"#).unwrap();

        debug!("{:?}", rsp_d);

        let result = wan.register_credential_internal(
            &rsp_d,
            UserVerificationPolicy::Discouraged_DO_NOT_USE,
            &chal,
            &[],
            &[
                COSEAlgorithm::RS256,
                COSEAlgorithm::EDDSA,
                COSEAlgorithm::INSECURE_RS1,
            ],
            None,
            false,
            &RequestRegistrationExtensions::default(),
            false,
        );
        debug!("{:?}", result);
        assert!(matches!(result, Err(WebauthnError::ParseNOMFailure)));
    }

    #[test]
    fn test_edge_touchid_rk_verified() {
        let _ = tracing_subscriber::fmt::try_init();
        let wan = Webauthn::new_unsafe_experts_only(
            "http://localhost:8080/auth",
            "localhost",
            &Url::parse("http://localhost:8080").unwrap(),
            None,
            None,
            None,
        );

        let chal: Base64UrlSafeData = Base64UrlSafeData(vec![
            108, 33, 62, 167, 162, 234, 36, 63, 176, 231, 161, 58, 41, 233, 117, 157, 210, 244,
            123, 28, 194, 100, 34, 68, 32, 1, 183, 240, 100, 225, 182, 48,
        ]);
        let chal = Challenge::from(chal);

        let rsp_d: RegisterPublicKeyCredential = RegisterPublicKeyCredential {
            id: "AWtT-NSYHNmZjP2R9JAbBmwf3sWMxs_L4_O2XoIvI8HY-rGPjA".to_string(),
            raw_id: Base64UrlSafeData(vec![
                1, 107, 83, 248, 212, 152, 28, 217, 153, 140, 253, 145, 244, 144, 27, 6, 108, 31,
                222, 197, 140, 198, 207, 203, 227, 243, 182, 94, 130, 47, 35, 193, 216, 250, 177,
                143, 140,
            ]),
            response: AuthenticatorAttestationResponseRaw {
                attestation_object: Base64UrlSafeData(vec![
                    163, 99, 102, 109, 116, 102, 112, 97, 99, 107, 101, 100, 103, 97, 116, 116, 83,
                    116, 109, 116, 162, 99, 97, 108, 103, 38, 99, 115, 105, 103, 88, 72, 48, 70, 2,
                    33, 0, 234, 66, 128, 149, 10, 78, 90, 6, 183, 58, 163, 114, 112, 146, 47, 204,
                    176, 27, 86, 218, 77, 135, 121, 88, 40, 94, 115, 7, 221, 248, 13, 37, 2, 33, 0,
                    187, 63, 74, 17, 114, 129, 51, 239, 145, 128, 216, 117, 39, 191, 130, 6, 239,
                    79, 15, 80, 58, 52, 18, 24, 57, 174, 125, 198, 248, 46, 138, 177, 104, 97, 117,
                    116, 104, 68, 97, 116, 97, 88, 169, 73, 150, 13, 229, 136, 14, 140, 104, 116,
                    52, 23, 15, 100, 118, 96, 91, 143, 228, 174, 185, 162, 134, 50, 199, 153, 92,
                    243, 186, 131, 29, 151, 99, 69, 98, 76, 219, 31, 173, 206, 0, 2, 53, 188, 198,
                    10, 100, 139, 11, 37, 241, 240, 85, 3, 0, 37, 1, 107, 83, 248, 212, 152, 28,
                    217, 153, 140, 253, 145, 244, 144, 27, 6, 108, 31, 222, 197, 140, 198, 207,
                    203, 227, 243, 182, 94, 130, 47, 35, 193, 216, 250, 177, 143, 140, 165, 1, 2,
                    3, 38, 32, 1, 33, 88, 32, 143, 255, 51, 238, 28, 38, 130, 245, 24, 48, 164,
                    117, 49, 102, 142, 103, 25, 46, 253, 137, 228, 16, 220, 131, 17, 229, 52, 165,
                    75, 224, 218, 237, 34, 88, 32, 115, 152, 43, 120, 40, 171, 135, 110, 112, 253,
                    28, 142, 154, 9, 9, 149, 94, 254, 147, 235, 38, 4, 215, 26, 217, 51, 245, 151,
                    148, 192, 141, 169,
                ]),
                client_data_json: Base64UrlSafeData(vec![
                    123, 34, 116, 121, 112, 101, 34, 58, 34, 119, 101, 98, 97, 117, 116, 104, 110,
                    46, 99, 114, 101, 97, 116, 101, 34, 44, 34, 99, 104, 97, 108, 108, 101, 110,
                    103, 101, 34, 58, 34, 98, 67, 69, 45, 112, 54, 76, 113, 74, 68, 45, 119, 53,
                    54, 69, 54, 75, 101, 108, 49, 110, 100, 76, 48, 101, 120, 122, 67, 90, 67, 74,
                    69, 73, 65, 71, 51, 56, 71, 84, 104, 116, 106, 65, 34, 44, 34, 111, 114, 105,
                    103, 105, 110, 34, 58, 34, 104, 116, 116, 112, 58, 47, 47, 108, 111, 99, 97,
                    108, 104, 111, 115, 116, 58, 56, 48, 56, 48, 34, 44, 34, 99, 114, 111, 115,
                    115, 79, 114, 105, 103, 105, 110, 34, 58, 102, 97, 108, 115, 101, 125,
                ]),
                transports: None,
            },
            type_: "public-key".to_string(),
            extensions: RegistrationExtensionsClientOutputs::default(),
        };

        debug!("{:?}", rsp_d);

        let result = wan.register_credential_internal(
            &rsp_d,
            UserVerificationPolicy::Required,
            &chal,
            &[],
            &[COSEAlgorithm::ES256],
            None,
            // Some(&AttestationCaList {
            //    cas: vec![AttestationCa::apple_webauthn_root_ca()],
            // }),
            true,
            &RequestRegistrationExtensions::default(),
            true,
        );
        debug!("{:?}", result);
        let cred = result.unwrap();
        assert!(matches!(
            cred.attestation.data,
            ParsedAttestationData::Self_
        ));
    }

    #[test]
    fn test_google_safetynet() {
        #[allow(unused)]
        let _request = r#"{"publicKey": {
            "challenge": "dfo+HlqJp3MLK+J5TLxxmvXJieS3zGwdk9G9H9bPezg=",
            "rp": {
                "name": "webauthn.io",
                "id": "webauthn.io"
            },
            "user": {
                "name": "safetynetter",
                "displayName": "safetynetter",
                "id": "wDkAAAAAAAAAAA=="
            },
            "pubKeyCredParams": [
                {
                "type": "public-key",
                "alg": -7
                }              
            ],
            "authenticatorSelection": {
                "authenticatorAttachment": "platform",
                "userVerification": "preferred"
            },
            "timeout": 60000,
            "attestation": "direct"
            }
        }"#;

        let response = r#"{
            "id":"AUiVU3Mk3uJomfHcJcu6ScwUHRysE2e6IgaTNAzQ34TP0OPifi2LgGD_5hzxRhOfQTB1fW6k63C8tk-MwywpNVI",
            "rawId":"AUiVU3Mk3uJomfHcJcu6ScwUHRysE2e6IgaTNAzQ34TP0OPifi2LgGD_5hzxRhOfQTB1fW6k63C8tk-MwywpNVI",
            "type":"public-key",
            "response":{
                "attestationObject":"o2NmbXRxYW5kcm9pZC1zYWZldHluZXRnYXR0U3RtdKJjdmVyaDE1MTgwMDM3aHJlc3BvbnNlWRS9ZXlKaGJHY2lPaUpTVXpJMU5pSXNJbmcxWXlJNld5Sk5TVWxHYTJwRFEwSkljV2RCZDBsQ1FXZEpVVkpZY205T01GcFBaRkpyUWtGQlFVRkJRVkIxYm5wQlRrSm5hM0ZvYTJsSE9YY3dRa0ZSYzBaQlJFSkRUVkZ6ZDBOUldVUldVVkZIUlhkS1ZsVjZSV1ZOUW5kSFFURlZSVU5vVFZaU01qbDJXako0YkVsR1VubGtXRTR3U1VaT2JHTnVXbkJaTWxaNlRWSk5kMFZSV1VSV1VWRkVSWGR3U0ZaR1RXZFJNRVZuVFZVNGVFMUNORmhFVkVVMFRWUkJlRTFFUVROTlZHc3dUbFp2V0VSVVJUVk5WRUYzVDFSQk0wMVVhekJPVm05M1lrUkZURTFCYTBkQk1WVkZRbWhOUTFaV1RYaEZla0ZTUW1kT1ZrSkJaMVJEYTA1b1lrZHNiV0l6U25WaFYwVjRSbXBCVlVKblRsWkNRV05VUkZVeGRtUlhOVEJaVjJ4MVNVWmFjRnBZWTNoRmVrRlNRbWRPVmtKQmIxUkRhMlIyWWpKa2MxcFRRazFVUlUxNFIzcEJXa0puVGxaQ1FVMVVSVzFHTUdSSFZucGtRelZvWW0xU2VXSXliR3RNYlU1MllsUkRRMEZUU1hkRVVWbEtTMjlhU1doMlkwNUJVVVZDUWxGQlJHZG5SVkJCUkVORFFWRnZRMmRuUlVKQlRtcFlhM293WlVzeFUwVTBiU3N2UnpWM1QyOHJXRWRUUlVOeWNXUnVPRGh6UTNCU04yWnpNVFJtU3pCU2FETmFRMWxhVEVaSWNVSnJOa0Z0V2xaM01rczVSa2N3VHpseVVsQmxVVVJKVmxKNVJUTXdVWFZ1VXpsMVowaEROR1ZuT1c5MmRrOXRLMUZrV2pKd09UTllhSHAxYmxGRmFGVlhXRU40UVVSSlJVZEtTek5UTW1GQlpucGxPVGxRVEZNeU9XaE1ZMUYxV1ZoSVJHRkROMDlhY1U1dWIzTnBUMGRwWm5NNGRqRnFhVFpJTDNob2JIUkRXbVV5YkVvck4wZDFkSHBsZUV0d2VIWndSUzkwV2xObVlsazVNRFZ4VTJ4Q2FEbG1jR293TVRWamFtNVJSbXRWYzBGVmQyMUxWa0ZWZFdWVmVqUjBTMk5HU3pSd1pYWk9UR0Y0UlVGc0swOXJhV3hOZEVsWlJHRmpSRFZ1Wld3MGVFcHBlWE0wTVROb1lXZHhWekJYYUdnMVJsQXpPV2hIYXpsRkwwSjNVVlJxWVhwVGVFZGtkbGd3YlRaNFJsbG9hQzh5VmsxNVdtcFVORXQ2VUVwRlEwRjNSVUZCWVU5RFFXeG5kMmRuU2xWTlFUUkhRVEZWWkVSM1JVSXZkMUZGUVhkSlJtOUVRVlJDWjA1V1NGTlZSVVJFUVV0Q1oyZHlRbWRGUmtKUlkwUkJWRUZOUW1kT1ZraFNUVUpCWmpoRlFXcEJRVTFDTUVkQk1WVmtSR2RSVjBKQ1VYRkNVWGRIVjI5S1FtRXhiMVJMY1hWd2J6UlhObmhVTm1veVJFRm1RbWRPVmtoVFRVVkhSRUZYWjBKVFdUQm1hSFZGVDNaUWJTdDRaMjU0YVZGSE5rUnlabEZ1T1V0NlFtdENaMmR5UW1kRlJrSlJZMEpCVVZKWlRVWlpkMHAzV1VsTGQxbENRbEZWU0UxQlIwZEhNbWd3WkVoQk5reDVPWFpaTTA1M1RHNUNjbUZUTlc1aU1qbHVUREprTUdONlJuWk5WRUZ5UW1kbmNrSm5SVVpDVVdOM1FXOVpabUZJVWpCalJHOTJURE5DY21GVE5XNWlNamx1VERKa2VtTnFTWFpTTVZKVVRWVTRlRXh0VG5sa1JFRmtRbWRPVmtoU1JVVkdha0ZWWjJoS2FHUklVbXhqTTFGMVdWYzFhMk50T1hCYVF6VnFZakl3ZDBsUldVUldVakJuUWtKdmQwZEVRVWxDWjFwdVoxRjNRa0ZuU1hkRVFWbExTM2RaUWtKQlNGZGxVVWxHUVhwQmRrSm5UbFpJVWpoRlMwUkJiVTFEVTJkSmNVRm5hR2cxYjJSSVVuZFBhVGgyV1ROS2MweHVRbkpoVXpWdVlqSTVia3d3WkZWVmVrWlFUVk0xYW1OdGQzZG5aMFZGUW1kdmNrSm5SVVZCWkZvMVFXZFJRMEpKU0RGQ1NVaDVRVkJCUVdSM1EydDFVVzFSZEVKb1dVWkpaVGRGTmt4TldqTkJTMUJFVjFsQ1VHdGlNemRxYW1RNE1FOTVRVE5qUlVGQlFVRlhXbVJFTTFCTVFVRkJSVUYzUWtsTlJWbERTVkZEVTFwRFYyVk1Tblp6YVZaWE5rTm5LMmRxTHpsM1dWUktVbnAxTkVocGNXVTBaVmswWXk5dGVYcHFaMGxvUVV4VFlta3ZWR2g2WTNweGRHbHFNMlJyTTNaaVRHTkpWek5NYkRKQ01HODNOVWRSWkdoTmFXZGlRbWRCU0ZWQlZtaFJSMjFwTDFoM2RYcFVPV1ZIT1ZKTVNTdDRNRm95ZFdKNVdrVldla0UzTlZOWlZtUmhTakJPTUVGQlFVWnRXRkU1ZWpWQlFVRkNRVTFCVW1wQ1JVRnBRbU5EZDBFNWFqZE9WRWRZVURJM09IbzBhSEl2ZFVOSWFVRkdUSGx2UTNFeVN6QXJlVXhTZDBwVlltZEpaMlk0WjBocWRuQjNNbTFDTVVWVGFuRXlUMll6UVRCQlJVRjNRMnR1UTJGRlMwWlZlVm8zWmk5UmRFbDNSRkZaU2t0dldrbG9kbU5PUVZGRlRFSlJRVVJuWjBWQ1FVazVibFJtVWt0SlYyZDBiRmRzTTNkQ1REVTFSVlJXTm10aGVuTndhRmN4ZVVGak5VUjFiVFpZVHpReGExcDZkMG8yTVhkS2JXUlNVbFF2VlhORFNYa3hTMFYwTW1Nd1JXcG5iRzVLUTBZeVpXRjNZMFZYYkV4UldUSllVRXg1Um1wclYxRk9ZbE5vUWpGcE5GY3lUbEpIZWxCb2RETnRNV0kwT1doaWMzUjFXRTAyZEZnMVEzbEZTRzVVYURoQ2IyMDBMMWRzUm1sb2VtaG5iamd4Ukd4a2IyZDZMMHN5VlhkTk5sTTJRMEl2VTBWNGEybFdabllyZW1KS01ISnFkbWM1TkVGc1pHcFZabFYzYTBrNVZrNU5ha1ZRTldVNGVXUkNNMjlNYkRabmJIQkRaVVkxWkdkbVUxZzBWVGw0TXpWdmFpOUpTV1F6VlVVdlpGQndZaTl4WjBkMmMydG1aR1Y2ZEcxVmRHVXZTMU50Y21sM1kyZFZWMWRsV0daVVlra3plbk5wYTNkYVltdHdiVkpaUzIxcVVHMW9kalJ5YkdsNlIwTkhkRGhRYmpod2NUaE5Na3RFWmk5UU0ydFdiM1F6WlRFNFVUMGlMQ0pOU1VsRlUycERRMEY2UzJkQmQwbENRV2RKVGtGbFR6QnRjVWRPYVhGdFFrcFhiRkYxUkVGT1FtZHJjV2hyYVVjNWR6QkNRVkZ6UmtGRVFrMU5VMEYzU0dkWlJGWlJVVXhGZUdSSVlrYzVhVmxYZUZSaFYyUjFTVVpLZG1JelVXZFJNRVZuVEZOQ1UwMXFSVlJOUWtWSFFURlZSVU5vVFV0U01uaDJXVzFHYzFVeWJHNWlha1ZVVFVKRlIwRXhWVVZCZUUxTFVqSjRkbGx0Um5OVk1teHVZbXBCWlVaM01IaE9la0V5VFZSVmQwMUVRWGRPUkVwaFJuY3dlVTFVUlhsTlZGVjNUVVJCZDA1RVNtRk5SVWw0UTNwQlNrSm5UbFpDUVZsVVFXeFdWRTFTTkhkSVFWbEVWbEZSUzBWNFZraGlNamx1WWtkVloxWklTakZqTTFGblZUSldlV1J0YkdwYVdFMTRSWHBCVWtKblRsWkNRVTFVUTJ0a1ZWVjVRa1JSVTBGNFZIcEZkMmRuUldsTlFUQkhRMU54UjFOSllqTkVVVVZDUVZGVlFVRTBTVUpFZDBGM1oyZEZTMEZ2U1VKQlVVUlJSMDA1UmpGSmRrNHdOWHByVVU4NUszUk9NWEJKVW5aS2VucDVUMVJJVnpWRWVrVmFhRVF5WlZCRGJuWlZRVEJSYXpJNFJtZEpRMlpMY1VNNVJXdHpRelJVTW1aWFFsbHJMMnBEWmtNelVqTldXazFrVXk5a1RqUmFTME5GVUZwU2NrRjZSSE5wUzFWRWVsSnliVUpDU2pWM2RXUm5lbTVrU1UxWlkweGxMMUpIUjBac05YbFBSRWxMWjJwRmRpOVRTa2d2VlV3clpFVmhiSFJPTVRGQ2JYTkxLMlZSYlUxR0t5dEJZM2hIVG1oeU5UbHhUUzg1YVd3M01Va3laRTQ0UmtkbVkyUmtkM1ZoWldvMFlsaG9jREJNWTFGQ1ltcDRUV05KTjBwUU1HRk5NMVEwU1N0RWMyRjRiVXRHYzJKcWVtRlVUa001ZFhwd1JteG5UMGxuTjNKU01qVjRiM2x1VlhoMk9IWk9iV3R4TjNwa1VFZElXR3Q0VjFrM2IwYzVhaXRLYTFKNVFrRkNhemRZY2twbWIzVmpRbHBGY1VaS1NsTlFhemRZUVRCTVMxY3dXVE42Tlc5Nk1rUXdZekYwU2t0M1NFRm5UVUpCUVVkcVoyZEZlazFKU1VKTWVrRlBRbWRPVmtoUk9FSkJaamhGUWtGTlEwRlpXWGRJVVZsRVZsSXdiRUpDV1hkR1FWbEpTM2RaUWtKUlZVaEJkMFZIUTBOelIwRlJWVVpDZDAxRFRVSkpSMEV4VldSRmQwVkNMM2RSU1UxQldVSkJaamhEUVZGQmQwaFJXVVJXVWpCUFFrSlpSVVpLYWxJclJ6UlJOamdyWWpkSFEyWkhTa0ZpYjA5ME9VTm1NSEpOUWpoSFFURlZaRWwzVVZsTlFtRkJSa3AyYVVJeFpHNUlRamRCWVdkaVpWZGlVMkZNWkM5alIxbFpkVTFFVlVkRFEzTkhRVkZWUmtKM1JVSkNRMnQzU25wQmJFSm5aM0pDWjBWR1FsRmpkMEZaV1ZwaFNGSXdZMFJ2ZGt3eU9XcGpNMEYxWTBkMGNFeHRaSFppTW1OMldqTk9lVTFxUVhsQ1owNVdTRkk0UlV0NlFYQk5RMlZuU21GQmFtaHBSbTlrU0ZKM1QyazRkbGt6U25OTWJrSnlZVk0xYm1JeU9XNU1NbVI2WTJwSmRsb3pUbmxOYVRWcVkyMTNkMUIzV1VSV1VqQm5Ra1JuZDA1cVFUQkNaMXB1WjFGM1FrRm5TWGRMYWtGdlFtZG5ja0puUlVaQ1VXTkRRVkpaWTJGSVVqQmpTRTAyVEhrNWQyRXlhM1ZhTWpsMlduazVlVnBZUW5aak1td3dZak5LTlV4NlFVNUNaMnR4YUd0cFJ6bDNNRUpCVVhOR1FVRlBRMEZSUlVGSGIwRXJUbTV1TnpoNU5uQlNhbVE1V0d4UlYwNWhOMGhVWjJsYUwzSXpVazVIYTIxVmJWbElVRkZ4TmxOamRHazVVRVZoYW5aM1VsUXlhVmRVU0ZGeU1ESm1aWE54VDNGQ1dUSkZWRlYzWjFwUksyeHNkRzlPUm5ab2MwODVkSFpDUTA5SllYcHdjM2RYUXpsaFNqbDRhblUwZEZkRVVVZzRUbFpWTmxsYVdpOVlkR1ZFVTBkVk9WbDZTbkZRYWxrNGNUTk5SSGh5ZW0xeFpYQkNRMlkxYnpodGR5OTNTalJoTWtjMmVIcFZjalpHWWpaVU9FMWpSRTh5TWxCTVVrdzJkVE5OTkZSNmN6TkJNazB4YWpaaWVXdEtXV2s0ZDFkSlVtUkJka3RNVjFwMUwyRjRRbFppZWxsdGNXMTNhMjAxZWt4VFJGYzFia2xCU21KRlRFTlJRMXAzVFVnMU5uUXlSSFp4YjJaNGN6WkNRbU5EUmtsYVZWTndlSFUyZURaMFpEQldOMU4yU2tORGIzTnBjbE50U1dGMGFpODVaRk5UVmtSUmFXSmxkRGh4THpkVlN6UjJORnBWVGpnd1lYUnVXbm94ZVdjOVBTSmRmUS5leUp1YjI1alpTSTZJazlGTDJkV09FYzRXazFKTW1ORUsyRk1lRzB2VGt4a1dVMHdjemxsVDB0V1NYUlhOblZTVDI5d1prRTlJaXdpZEdsdFpYTjBZVzF3VFhNaU9qRTFOVE13TWpnd05ETTFNamtzSW1Gd2ExQmhZMnRoWjJWT1lXMWxJam9pWTI5dExtZHZiMmRzWlM1aGJtUnliMmxrTG1kdGN5SXNJbUZ3YTBScFoyVnpkRk5vWVRJMU5pSTZJbGRVYkd4aVVuVXhZbFEyYlZoeWRXRmlXVWQ1WmtvMFJGUTVVR1I0YnpGUFMwb3ZWRTQzTVZWU1lXODlJaXdpWTNSelVISnZabWxzWlUxaGRHTm9JanAwY25WbExDSmhjR3REWlhKMGFXWnBZMkYwWlVScFoyVnpkRk5vWVRJMU5pSTZXeUk0VURGelZ6QkZVRXBqYzJ4M04xVjZVbk5wV0V3Mk5IY3JUelV3UldRclVrSkpRM1JoZVRGbk1qUk5QU0pkTENKaVlYTnBZMGx1ZEdWbmNtbDBlU0k2ZEhKMVpYMC56V3ViaWlraGt5alhETUJpV080ajZEdnVBZWdpSUh1WGhaNWQtTEh3Z1VBZFVSMWxNTU0tZ0Y4VklmSEdYcFZNZ1hhN3plR0l5NEROU19uNTdBZ2c0eE5lTVhQMHRpMVJ4QktVVlJKeUc1OXVoejJJbDBtZkl1UVZNckRpSHBiWjdYb2tKcG1jZlUyWU9QbmppcjlWUjlsVlRZUHVHV1phT01ua1kyRnlvbTRGZzhrNFA3dEtWWllzTXNERWR3ZVdOdTM5MS1mcXdKWUxQUWNjQ0ZiNURCRWc0SlMwa05pWG8zLWc3MTFWVGd2Z284WDMyMS03NWw5MnN6UWpDeDQ3aDFzY243ZmE1TkJhTkdfanVPZjV0QnhFbl9uY3N1TjR3RVRnT0JJVHFVN0xZWmxTVEtUX2lYODFncUJOOWtuWGMtQ0NVZUh1LThvLUdmekh1Y1BsSEFoYXV0aERhdGFYxXSm6pITyZwvdLIkkrMgz0AmKpTBqVCgOX8pJQtghB7wRQAAAAC5P9lh8uZGL7EiggAiR954AEEBSJVTcyTe4miZ8dwly7pJzBQdHKwTZ7oiBpM0DNDfhM_Q4-J-LYuAYP_mHPFGE59BMHV9bqTrcLy2T4zDLCk1UqUBAgMmIAEhWCC0eleNTLgwWxaVBqV139T6hONseRz7HgXRIVS9bPxIjSJYIJ1MfwUhvkSEjeiNJ6y5-w8PuuwMAvfgpN7F4Q2EW79v",
                "clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiZGZvLUhscUpwM01MSy1KNVRMeHhtdlhKaWVTM3pHd2RrOUc5SDliUGV6ZyIsIm9yaWdpbiI6Imh0dHBzOlwvXC93ZWJhdXRobi5pbyIsImFuZHJvaWRQYWNrYWdlTmFtZSI6ImNvbS5hbmRyb2lkLmNocm9tZSJ9"}}"#;

        let _ = tracing_subscriber::fmt::try_init();
        let wan = Webauthn::new_unsafe_experts_only(
            "webauthn.io",
            "webauthn.io",
            &Url::parse("https://webauthn.io").unwrap(),
            None,
            None,
            None,
        );

        let chal: Base64UrlSafeData =
            serde_json::from_str("\"dfo+HlqJp3MLK+J5TLxxmvXJieS3zGwdk9G9H9bPezg=\"").unwrap();
        let chal = Challenge::from(chal);

        let rsp_d: RegisterPublicKeyCredential = serde_json::from_str(response).unwrap();

        debug!("{:?}", rsp_d);

        let result = wan.register_credential_internal(
            &rsp_d,
            UserVerificationPolicy::Required,
            &chal,
            &[],
            &[COSEAlgorithm::ES256],
            Some(&AttestationCaList {
                cas: vec![AttestationCa::google_safetynet_ca_old()],
            }),
            true,
            &RequestRegistrationExtensions::default(),
            true,
        );
        dbg!(&result);
        assert!(result.is_ok());

        match result.unwrap().attestation.metadata {
            AttestationMetadata::AndroidSafetyNet {
                apk_package_name: _,
                apk_certificate_digest_sha256: _,
                cts_profile_match,
                basic_integrity,
                evaluation_type: _,
            } => {
                assert!(cts_profile_match);
                assert!(basic_integrity);
            }
            _ => panic!("invalid attestation metadata"),
        };
    }

    #[test]
    fn test_google_safetynet_2() {
        let chal: Base64UrlSafeData =
            serde_json::from_str("\"B3q5igjVbIpBwqnK18k0mgAOLnXTK/Mmv3JTsSMyEKg=\"").unwrap();

        let response = r#"{
            "id":"AfVUnBGvi8ZeETla19A8JtyIuxBsQRyp8FQDfDNC-C_PL0rAKUghHiDB7Aekoh0CYymUVJdd6Z5HA2btQL1aNOg",
            "rawId":"AfVUnBGvi8ZeETla19A8JtyIuxBsQRyp8FQDfDNC-C_PL0rAKUghHiDB7Aekoh0CYymUVJdd6Z5HA2btQL1aNOg",
            "type":"public-key",
            "response":{
                "attestationObject":"o2NmbXRxYW5kcm9pZC1zYWZldHluZXRnYXR0U3RtdKJjdmVyaTIwNTAxNjAzN2hyZXNwb25zZVkgd2V5SmhiR2NpT2lKU1V6STFOaUlzSW5nMVl5STZXeUpOU1VsR1ltcERRMEpHWVdkQmQwbENRV2RKVVVGaE0wOUxUMlJ2VkZrMFVVRkJRVUZCUVROWVdFUkJUa0puYTNGb2EybEhPWGN3UWtGUmMwWkJSRUpIVFZGemQwTlJXVVJXVVZGSFJYZEtWbFY2UldsTlEwRkhRVEZWUlVOb1RWcFNNamwyV2pKNGJFbEdVbmxrV0U0d1NVWk9iR051V25CWk1sWjZTVVY0VFZGNlJWUk5Ra1ZIUVRGVlJVRjRUVXRTTVZKVVNVVk9Ra2xFUmtWT1JFRmxSbmN3ZVUxcVFYcE5ha0Y1VFZSRk1VMXFSbUZHZHpCNVRXcEJNazFVWjNsTlZFVXhUV3BDWVUxQ01IaEhla0ZhUW1kT1ZrSkJUVlJGYlVZd1pFZFdlbVJETldoaWJWSjVZakpzYTB4dFRuWmlWRU5EUVZOSmQwUlJXVXBMYjFwSmFIWmpUa0ZSUlVKQ1VVRkVaMmRGVUVGRVEwTkJVVzlEWjJkRlFrRk1iWEZNUWxoV05FTmFRVFZ6VkRWalZHWjFXR04zTVRGWFJESlpWVmN6WlVGS2RtUnhLMWhKWWtoRVowMU9UVUp5YzNndldFUjROa3h0T1U5dFNrTlZOSFpEY0ZkSlRqUlhRMGd5TUZRNVQyWmxOa2hrZVU1MlJXVnBNM3BvYkhwT01Gb3ZXVlI1YjFSbGNGZHdOVWd2YlhKdVIyOXpVM050Y0VwMU5EVjNPVkpZYm01S2JFbHJSelU1ZEROMFYxSm9ZWE5aWlc1R1kwaGxZMFpvYkcxb2RtNVVRblJIYTAxVmIwVkdSRVpuYW5sdFoydHdVVWRrTW14b2FVOVlXR0p3TXpFMVNYbEdiRWRVVkZwdk5FUkJZVFppTUhwMlZHWlFPWFY2UjFGSlpIaG1hM041VFVsR1ptSkRZVmQ2VGpOUGFuQjFiVkl3TUhnMlNWWmpaRGR5T1V4dk9WQmxWV3c1YTI5NmNqaEZhRFJEV1M5UFFpdEVPVkV2VmpaNFJWcGlWSE5IZVhjMGFVRnhRMHR2TVRSRFJYcERSVkZJTUVaV1dUUTFjRmczYjJJcmJXaG1MMXBLYldOekwwMTRibFpHYmt4NmJEQkRRWGRGUVVGaFQwTkJiamgzWjJkS04wMUJORWRCTVZWa1JIZEZRaTkzVVVWQmQwbEdiMFJCVkVKblRsWklVMVZGUkVSQlMwSm5aM0pDWjBWR1FsRmpSRUZVUVUxQ1owNVdTRkpOUWtGbU9FVkJha0ZCVFVJd1IwRXhWV1JFWjFGWFFrSlVPVkkzWjIxUFpVUXhkbHBSVmtOSVl6QlVkR2gyVDFscE16bEVRV1pDWjA1V1NGTk5SVWRFUVZkblFsRnNOR2huVDNOc1pWSnNRM0pzTVVZeVIydEpVR1ZWTjA4MGEycENOMEpuWjNKQ1owVkdRbEZqUWtGUlVuWk5SekIzVDBGWlNVdDNXVUpDVVZWSVRVRkhSMHhIYURCa1NFRTJUSGs1ZGxrelRuZE1ia0p5WVZNMWJtSXlPVzVNTTAxMldqTlNlazFYVVRCaFZ6VXdURE5vVDB4V09IZGtSRTR6VjFScmQwMUVSVWREUTNOSFFWRlZSa0o2UVVOb2FWWnZaRWhTZDA5cE9IWmpSM1J3VEcxa2RtSXlZM1pqYlZaM1luazVhbHBZU2pCamVUbHVaRWhOZUZwRVVYVmFSMVo1VFVJd1IwRXhWV1JGVVZGWFRVSlRRMFZ0UmpCa1IxWjZaRU0xYUdKdFVubGlNbXhyVEcxT2RtSlVRV2hDWjA1V1NGTkJSVWRxUVZsTlFXZEhRbTFsUWtSQlJVTkJWRUZOUW1kdmNrSm5SVVZCWkZvMVFXZFZSRTFFT0VkQk1WVmtTSGRSTkUxRVdYZE9TMEY1YjBSRFIweHRhREJrU0VFMlRIazVhbU50ZUhwTWJrSnlZVk0xYm1JeU9XNU1NbVF3WTNwR2EwNUhiSFZrUXpsWlRXdHZlVk5JU21aT01VSndWRk0xYW1OdGQzZG5aMFZGUW1kdmNrSm5SVVZCWkZvMVFXZFJRMEpKU0RGQ1NVaDVRVkJCUVdSblFsSnZOMFF4TDFGR05XNUdXblIxUkdRMGFuZDVhMlZ6ZDJKS09IWXpibTlvUTIxbk15c3hTWE5HTlZGQlFVRllLM0JhYTBweVFVRkJSVUYzUWtoTlJWVkRTVkZEYjJSV1JucFBRMVZ1YkhWUlV6QjBNRzlIZFVFemRsWkZSMFp4YjJJNFNWSmlRM0JaZVRkVlptTkJVVWxuUmk5TlpWVlNkRzlFTjFGcmFGaENUakIxY21sRGRFd3ZURU5zTVcxelJFNW9XakZ0TVVoS2VFcFJiMEZrWjBGd1pXSTNkMjVxYXpWSlprSlhZelU1YW5CWVpteDJiR1E1YmtkQlN5dFFiRTVZVTFwalNsWXpTR2hCUVVGQldDdHdXbXRLV1VGQlFVVkJkMEpJVFVWVlEwbFJRMXB2UlcxQmJ6YzBVaXRHVDBwUWVWSkxZa2t5UlNzMlMwTllOa0YxV0cxb1puTlhhMmgwYVVGTFlXZEpaMXAxZG1aSWNVRTJVRTlzTTBKa1YzUmxVMWw0VHpBMlFtTndUM2RVWVRWNk5qVnFTa3cwZEV4RWNrbDNSRkZaU2t0dldrbG9kbU5PUVZGRlRFSlJRVVJuWjBWQ1FVUkpjQzkzYmxGc1puRTNkVlo2ZERVM01IbFJSVEpPUVZBMWFqaDVPR0Z6V1doS1RYY3JVVEJZWjNNMmEzcHFabnBHTDJnM09WcG1SbGhMT1RoM1FWSmhWbkkyYW1WU1FYbzJZM0U0Y1VWSU1VOHlRa1E1ZURWRVEwOVVaekp4Y2xOblNsZGlUVTVWV2tSNVRYVjZSbVZ5UTJFeU56bG9Ra2xRVlhCcU56ZzBZVWRzWVdwNFkyTTNWSFJZU0hwYWNuaG1iR00wZDFCeloySm5RMnR3ZDNWcU5tb3dhbmRETmpkUk5HSnJPVlZZS3pOeGNHdzNNbUZLTW5wV2J6Rm1UMnMzVTBad1NUVTRSak5KTDFjNGJra3ZhMk53YjFCdmNESkNOa294UjNSeFRVUklSbkJ5YzNSblpVcE1iRmt6UVdWbVpXb3llVzlGZDNVeWFqSXJZekV2U2paM1NEVjRZV1JFUzNobk0wNTJhRElyZUdoYVVrWmFiMEZVWWpKbE5sbHplRFJTTUVKMGVXVllORWhhVFdjME9GRmhRazQwTjJ4QmVFRmpaelIxWVZOcVJ5OHZRa2hYVGpNMGNFMUZZV05KZUVkT01EMGlMQ0pOU1VsR2FrUkRRMEV6VTJkQmQwbENRV2RKVGtGblEwOXpaMGw2VG0xWFRGcE5NMkp0ZWtGT1FtZHJjV2hyYVVjNWR6QkNRVkZ6UmtGRVFraE5VWE4zUTFGWlJGWlJVVWRGZDBwV1ZYcEZhVTFEUVVkQk1WVkZRMmhOV2xJeU9YWmFNbmhzU1VaU2VXUllUakJKUms1c1kyNWFjRmt5Vm5wSlJYaE5VWHBGVlUxQ1NVZEJNVlZGUVhoTlRGSXhVbFJKUmtwMllqTlJaMVZxUlhkSWFHTk9UV3BCZDA5RVJYcE5SRUYzVFVSUmVWZG9ZMDVOYW1OM1QxUk5kMDFFUVhkTlJGRjVWMnBDUjAxUmMzZERVVmxFVmxGUlIwVjNTbFpWZWtWcFRVTkJSMEV4VlVWRGFFMWFVakk1ZGxveWVHeEpSbEo1WkZoT01FbEdUbXhqYmxwd1dUSldla2xGZUUxUmVrVlVUVUpGUjBFeFZVVkJlRTFMVWpGU1ZFbEZUa0pKUkVaRlRrUkRRMEZUU1hkRVVWbEtTMjlhU1doMlkwNUJVVVZDUWxGQlJHZG5SVkJCUkVORFFWRnZRMmRuUlVKQlMzWkJjWEZRUTBVeU4yd3dkemw2UXpoa1ZGQkpSVGc1WWtFcmVGUnRSR0ZITjNrM1ZtWlJOR01yYlU5WGFHeFZaV0pWVVhCTE1IbDJNbkkyTnpoU1NrVjRTekJJVjBScVpYRXJia3hKU0U0eFJXMDFhalp5UVZKYWFYaHRlVkpUYW1oSlVqQkxUMUZRUjBKTlZXeGtjMkY2ZEVsSlNqZFBNR2N2T0RKeGFpOTJSMFJzTHk4emREUjBWSEY0YVZKb1RGRnVWRXhZU21SbFFpc3lSR2hyWkZVMlNVbG5lRFozVGpkRk5VNWpWVWd6VW1OelpXcGpjV280Y0RWVGFqRTVka0p0Tm1reFJtaHhURWQ1YldoTlJuSnZWMVpWUjA4emVIUkpTRGt4WkhObmVUUmxSa3RqWmt0V1RGZExNMjh5TVRrd1VUQk1iUzlUYVV0dFRHSlNTalZCZFRSNU1XVjFSa3B0TWtwTk9XVkNPRFJHYTNGaE0ybDJjbGhYVldWV2RIbGxNRU5SWkV0MmMxa3lSbXRoZW5aNGRIaDJkWE5NU25wTVYxbElhelUxZW1OU1FXRmpSRUV5VTJWRmRFSmlVV1pFTVhGelEwRjNSVUZCWVU5RFFWaFpkMmRuUm5sTlFUUkhRVEZWWkVSM1JVSXZkMUZGUVhkSlFtaHFRV1JDWjA1V1NGTlZSVVpxUVZWQ1oyZHlRbWRGUmtKUlkwUkJVVmxKUzNkWlFrSlJWVWhCZDBsM1JXZFpSRlpTTUZSQlVVZ3ZRa0ZuZDBKblJVSXZkMGxDUVVSQlpFSm5UbFpJVVRSRlJtZFJWVXBsU1ZsRWNrcFlhMXBSY1RWa1VtUm9jRU5FTTJ4UGVuVktTWGRJZDFsRVZsSXdha0pDWjNkR2IwRlZOVXM0Y2twdVJXRkxNR2R1YUZNNVUxcHBlblk0U1d0VVkxUTBkMkZCV1VsTGQxbENRbEZWU0VGUlJVVllSRUpoVFVOWlIwTkRjMGRCVVZWR1FucEJRbWhvY0c5a1NGSjNUMms0ZG1JeVRucGpRelYzWVRKcmRWb3lPWFphZVRsdVpFaE9lVTFVUVhkQ1oyZHlRbWRGUmtKUlkzZEJiMWxyWVVoU01HTkViM1pNTTBKeVlWTTFibUl5T1c1TU0wcHNZMGM0ZGxreVZubGtTRTEyV2pOU2VtTnFSWFZhUjFaNVRVUlJSMEV4VldSSWQxRjBUVU56ZDB0aFFXNXZRMWRIU1RKb01HUklRVFpNZVRscVkyMTNkV05IZEhCTWJXUjJZakpqZGxvelVucGpha1YyV2pOU2VtTnFSWFZaTTBwelRVVXdSMEV4VldSSlFWSkhUVVZSZDBOQldVZGFORVZOUVZGSlFrMUVaMGREYVhOSFFWRlJRakZ1YTBOQ1VVMTNTMnBCYjBKblozSkNaMFZHUWxGalEwRlNXV05oU0ZJd1kwaE5Oa3g1T1hkaE1tdDFXakk1ZGxwNU9YbGFXRUoyWXpKc01HSXpTalZNZWtGT1FtZHJjV2hyYVVjNWR6QkNRVkZ6UmtGQlQwTkJaMFZCU1ZaVWIza3lOR3AzV0ZWeU1ISkJVR001TWpSMmRWTldZa3RSZFZsM00yNU1abXhNWmt4b05VRlpWMFZsVm13dlJIVXhPRkZCVjFWTlpHTktObTh2Y1VaYVltaFlhMEpJTUZCT1kzYzVOM1JvWVdZeVFtVnZSRmxaT1VOckwySXJWVWRzZFdoNE1EWjZaRFJGUW1ZM1NEbFFPRFJ1Ym5KM2NGSXJORWRDUkZwTEsxaG9NMGt3ZEhGS2VUSnlaMDl4VGtSbWJISTFTVTFST0ZwVVYwRXplV3gwWVd0NlUwSkxXalpZY0VZd1VIQnhlVU5TZG5BdlRrTkhkakpMV0RKVWRWQkRTblp6WTNBeEwyMHljRlpVZEhsQ2FsbFFVbEVyVVhWRFVVZEJTa3RxZEU0M1VqVkVSbkptVkhGTlYzWlpaMVpzY0VOS1FtdDNiSFUzS3pkTFdUTmpWRWxtZWtVM1kyMUJUSE5yVFV0T1RIVkVlaXRTZWtOamMxbFVjMVpoVlRkV2NETjRURFl3VDFsb2NVWnJkVUZQVDNoRVdqWndTRTlxT1N0UFNtMVpaMUJ0VDFRMFdETXJOMHcxTVdaWVNubFNTRGxMWmt4U1VEWnVWRE14UkRWdWJYTkhRVTluV2pJMkx6aFVPV2h6UWxjeGRXODVhblUxWmxwTVdsaFdWbE0xU0RCSWVVbENUVVZMZVVkTlNWQm9SbGR5YkhRdmFFWlRNamhPTVhwaFMwa3dXa0pIUkRObldXZEVUR0pwUkZRNVprZFljM1J3YXl0R2JXTTBiMnhXYkZkUWVsaGxPREYyWkc5RmJrWmljalZOTWpjeVNHUm5TbGR2SzFkb1ZEbENXVTB3U21rcmQyUldiVzVTWm1aWVoyeHZSVzlzZFZST1kxZDZZelF4WkVad1owcDFPR1pHTTB4SE1HZHNNbWxpVTFscFEyazVZVFpvZGxVd1ZIQndha3A1U1ZkWWFHdEtWR05OU214UWNsZDRNVlo1ZEVWVlIzSllNbXd3U2tSM1VtcFhMelkxTm5Jd1MxWkNNREo0U0ZKTGRtMHlXa3RKTUROVVoyeE1TWEJ0VmtOTE0ydENTMnRMVG5CQ1RtdEdkRGh5YUdGbVkwTkxUMkk1U25ndk9YUndUa1pzVVZSc04wSXpPWEpLYkVwWGExSXhOMUZ1V25GV2NIUkdaVkJHVDFKdldtMUdlazA5SWl3aVRVbEpSbGxxUTBOQ1JYRm5RWGRKUWtGblNWRmtOekJPWWs1ek1pdFNjbkZKVVM5Rk9FWnFWRVJVUVU1Q1oydHhhR3RwUnpsM01FSkJVWE5HUVVSQ1dFMVJjM2REVVZsRVZsRlJSMFYzU2tOU1ZFVmFUVUpqUjBFeFZVVkRhRTFSVWpKNGRsbHRSbk5WTW14dVltbENkV1JwTVhwWlZFVlJUVUUwUjBFeFZVVkRlRTFJVlcwNWRtUkRRa1JSVkVWaVRVSnJSMEV4VlVWQmVFMVRVako0ZGxsdFJuTlZNbXh1WW1sQ1UySXlPVEJKUlU1Q1RVSTBXRVJVU1hkTlJGbDRUMVJCZDAxRVFUQk5iRzlZUkZSSk5FMUVSWGxQUkVGM1RVUkJNRTFzYjNkU2VrVk1UVUZyUjBFeFZVVkNhRTFEVmxaTmVFbHFRV2RDWjA1V1FrRnZWRWRWWkhaaU1tUnpXbE5DVldOdVZucGtRMEpVV2xoS01tRlhUbXhqZVVKTlZFVk5lRVpFUVZOQ1owNVdRa0ZOVkVNd1pGVlZlVUpUWWpJNU1FbEdTWGhOU1VsRFNXcEJUa0puYTNGb2EybEhPWGN3UWtGUlJVWkJRVTlEUVdjNFFVMUpTVU5EWjB0RFFXZEZRWFJvUlVOcGVEZHFiMWhsWWs4NWVTOXNSRFl6YkdGa1FWQkxTRGxuZG13NVRXZGhRMk5tWWpKcVNDODNOazUxT0dGcE5saHNOazlOVXk5cmNqbHlTRFY2YjFGa2MyWnVSbXc1TjNaMVprdHFObUozVTJsV05tNXhiRXR5SzBOTmJuazJVM2h1UjFCaU1UVnNLemhCY0dVMk1tbHRPVTFhWVZKM01VNUZSRkJxVkhKRlZHODRaMWxpUlhaekwwRnRVVE0xTVd0TFUxVnFRalpITURCcU1IVlpUMFJRTUdkdFNIVTRNVWs0UlRORGQyNXhTV2x5ZFRaNk1XdGFNWEVyVUhOQlpYZHVha2g0WjNOSVFUTjVObTFpVjNkYVJISllXV1pwV1dGU1VVMDVjMGh0YTJ4RGFYUkVNemh0TldGblNTOXdZbTlRUjJsVlZTczJSRTl2WjNKR1dsbEtjM1ZDTm1wRE5URXhjSHB5Y0RGYWEybzFXbEJoU3pRNWJEaExSV280UXpoUlRVRk1XRXd6TW1nM1RURmlTM2RaVlVnclJUUkZlazVyZEUxbk5sUlBPRlZ3YlhaTmNsVndjM2xWY1hSRmFqVmpkVWhMV2xCbWJXZG9RMDQyU2pORGFXOXFOazlIWVVzdlIxQTFRV1pzTkM5WWRHTmtMM0F5YUM5eWN6TTNSVTlsV2xaWWRFd3diVGM1V1VJd1pYTlhRM0oxVDBNM1dFWjRXWEJXY1RsUGN6WndSa3hMWTNkYWNFUkpiRlJwY25oYVZWUlJRWE0yY1hwcmJUQTJjRGs0WnpkQ1FXVXJaRVJ4Tm1SemJ6UTVPV2xaU0RaVVMxZ3ZNVmszUkhwcmRtZDBaR2w2YW10WVVHUnpSSFJSUTNZNVZYY3JkM0E1VlRkRVlrZExiMmRRWlUxaE0wMWtLM0IyWlhvM1Z6TTFSV2xGZFdFckszUm5lUzlDUW1wR1JrWjVNMnd6VjBad1R6bExWMmQ2TjNwd2JUZEJaVXRLZERoVU1URmtiR1ZEWm1WWWEydFZRVXRKUVdZMWNXOUpZbUZ3YzFwWGQzQmlhMDVHYUVoaGVESjRTVkJGUkdkbVp6RmhlbFpaT0RCYVkwWjFZM1JNTjFSc1RHNU5VUzh3YkZWVVltbFRkekZ1U0RZNVRVYzJlazh3WWpsbU5rSlJaR2RCYlVRd05ubExOVFp0UkdOWlFscFZRMEYzUlVGQllVOURRVlJuZDJkblJUQk5RVFJIUVRGVlpFUjNSVUl2ZDFGRlFYZEpRbWhxUVZCQ1owNVdTRkpOUWtGbU9FVkNWRUZFUVZGSUwwMUNNRWRCTVZWa1JHZFJWMEpDVkd0eWVYTnRZMUp2Y2xORFpVWk1NVXB0VEU4dmQybFNUbmhRYWtGbVFtZE9Wa2hUVFVWSFJFRlhaMEpTWjJVeVdXRlNVVEpZZVc5c1VVd3pNRVY2VkZOdkx5OTZPVk42UW1kQ1oyZHlRbWRGUmtKUlkwSkJVVkpWVFVaSmQwcFJXVWxMZDFsQ1FsRlZTRTFCUjBkSFYyZ3daRWhCTmt4NU9YWlpNMDUzVEc1Q2NtRlROVzVpTWpsdVRESmtlbU5xUlhkTFVWbEpTM2RaUWtKUlZVaE5RVXRIU0Zkb01HUklRVFpNZVRsM1lUSnJkVm95T1haYWVUbHVZek5KZUV3eVpIcGpha1YxV1ROS01FMUVTVWRCTVZWa1NIZFJjazFEYTNkS05rRnNiME5QUjBsWGFEQmtTRUUyVEhrNWFtTnRkM1ZqUjNSd1RHMWtkbUl5WTNaYU0wNTVUVk01Ym1NelNYaE1iVTU1WWtSQk4wSm5UbFpJVTBGRlRrUkJlVTFCWjBkQ2JXVkNSRUZGUTBGVVFVbENaMXB1WjFGM1FrRm5TWGRFVVZsTVMzZFpRa0pCU0ZkbFVVbEdRWGRKZDBSUldVeExkMWxDUWtGSVYyVlJTVVpCZDAxM1JGRlpTa3R2V2tsb2RtTk9RVkZGVEVKUlFVUm5aMFZDUVVSVGEwaHlSVzl2T1VNd1pHaGxiVTFZYjJnMlpFWlRVSE5xWW1SQ1drSnBUR2M1VGxJemREVlFLMVEwVm5obWNUZDJjV1pOTDJJMVFUTlNhVEZtZVVwdE9XSjJhR1JIWVVwUk0ySXlkRFo1VFVGWlRpOXZiRlZoZW5OaFRDdDVlVVZ1T1Zkd2NrdEJVMDl6YUVsQmNrRnZlVnBzSzNSS1lXOTRNVEU0Wm1WemMyMVliakZvU1ZaM05ERnZaVkZoTVhZeGRtYzBSblkzTkhwUWJEWXZRV2hUY25jNVZUVndRMXBGZERSWGFUUjNVM1I2Tm1SVVdpOURURUZPZURoTVdtZ3hTamRSU2xacU1tWm9UWFJtVkVweU9YYzBlak13V2pJd09XWlBWVEJwVDAxNUszRmtkVUp0Y0haMldYVlNOMmhhVERaRWRYQnplbVp1ZHpCVGEyWjBhSE14T0dSSE9WcExZalU1VldoMmJXRlRSMXBTVm1KT1VYQnpaek5DV214MmFXUXdiRWxMVHpKa01YaHZlbU5zVDNwbmFsaFFXVzkyU2twSmRXeDBlbXROZFRNMGNWRmlPVk42TDNscGJISmlRMmRxT0QwaVhYMC5leUp1YjI1alpTSTZJa3ByYmxwVGIxcDFUbkU0SzA5eWRGQjRNRVJtYzB4VldFWldja296UTBNNVUyMTZSVVJqYkdKSGJtczlJaXdpZEdsdFpYTjBZVzF3VFhNaU9qRTJOVFExTWprek5UWXdNVGNzSW1Gd2ExQmhZMnRoWjJWT1lXMWxJam9pWTI5dExtZHZiMmRzWlM1aGJtUnliMmxrTG1kdGN5SXNJbUZ3YTBScFoyVnpkRk5vWVRJMU5pSTZJbEpaZGt4M1ZtMW5SakpZWVhNeE1VUkVPVEkxU1hWemMwcDFlRXRFTDNkQ04ycGpUMDFxYlUxVVIwRTlJaXdpWTNSelVISnZabWxzWlUxaGRHTm9JanAwY25WbExDSmhjR3REWlhKMGFXWnBZMkYwWlVScFoyVnpkRk5vWVRJMU5pSTZXeUk0VURGelZ6QkZVRXBqYzJ4M04xVjZVbk5wV0V3Mk5IY3JUelV3UldRclVrSkpRM1JoZVRGbk1qUk5QU0pkTENKaVlYTnBZMGx1ZEdWbmNtbDBlU0k2ZEhKMVpTd2laWFpoYkhWaGRHbHZibFI1Y0dVaU9pSkNRVk5KUXlKOS5RR205QjhwdzZ3d3kwWnlseV9sa0xQd181Nnk5dnpGZ2dTN3o2SjB1OW5MZ2xGQmMtVm5EVWdlWkVCellpU3JVNWJYc0tGbjlsRjZNYmp2bXBWZ25ZZ0JGTEVZQWxORkRlLTJDUGYwVWROUjF3Uy1jTWVwMUlLc2RraENRR0w3TFZ6dWNMdlNNUEp0NFF2cUVTY1Fyc2p3OVgtekNLaUt1RXNyRGZyQm9WaHZZRUpqU056TXRJRzhrMWdBdEpKLVFjZGNvTFUxSW1KRXZtVS01VmRZZm9pT3V4eUdVTGFCYmpJUTdvMTkwRkVYdFF1eUhJeFVVa25Wc0FEdkRLOWxvUUEwbHAzOHNsMUVjNGRkYnN5Tk1GQ2N0bk5GZENyb3NwOVBTbVFMTk12MV9iaElnY3RkWVZUa3I5Q1I1OUxKdXI0UFdHbU9HU18zYmpvdDVJQjVRcmdoYXV0aERhdGFYxXSm6pITyZwvdLIkkrMgz0AmKpTBqVCgOX8pJQtghB7wRQAAAAC5P9lh8uZGL7EiggAiR954AEEB9VScEa-Lxl4ROVrX0Dwm3Ii7EGxBHKnwVAN8M0L4L88vSsApSCEeIMHsB6SiHQJjKZRUl13pnkcDZu1AvVo06KUBAgMmIAEhWCAb_i86wuvr28SKU7O5BGr-ZWXDSMkTKnOYqn0etIRCfCJYIOu0ebhB4kJiQuriOSU_2-NEf7tKnsDjhjinH6-IQ6To",
                "clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiQjNxNWlnalZiSXBCd3FuSzE4azBtZ0FPTG5YVEtfTW12M0pUc1NNeUVLZyIsIm9yaWdpbiI6Imh0dHBzOlwvXC93ZWJhdXRobi5pbyIsImFuZHJvaWRQYWNrYWdlTmFtZSI6ImNvbS5hbmRyb2lkLmNocm9tZSJ9"}}"#;

        let _ = tracing_subscriber::fmt::try_init();
        let wan = Webauthn::new_unsafe_experts_only(
            "webauthn.io",
            "webauthn.io",
            &Url::parse("https://webauthn.io").unwrap(),
            None,
            None,
            None,
        );

        let chal = Challenge::from(chal);

        let rsp_d: RegisterPublicKeyCredential = serde_json::from_str(response).unwrap();

        debug!("{:?}", rsp_d);

        let result = wan.register_credential_internal(
            &rsp_d,
            UserVerificationPolicy::Required,
            &chal,
            &[],
            &[COSEAlgorithm::ES256],
            Some(&AttestationCaList {
                cas: vec![AttestationCa::google_safetynet_ca()],
            }),
            true,
            &RequestRegistrationExtensions::default(),
            true,
        );
        dbg!(&result);
        assert!(result.is_ok());

        match result.unwrap().attestation.metadata {
            AttestationMetadata::AndroidSafetyNet {
                apk_package_name: _,
                apk_certificate_digest_sha256: _,
                cts_profile_match,
                basic_integrity,
                evaluation_type: _,
            } => {
                assert!(cts_profile_match);
                assert!(basic_integrity);
            }
            _ => panic!("invalid attestation metadata"),
        };
    }

    #[test]
    fn test_google_android_key() {
        let chal: Base64UrlSafeData =
            serde_json::from_str("\"Tf65bS6D5temh2BwvptqgBPb25iZDRxjwC5ans91IIJDrcrOpnWTK4LVgFjeUV4GDMe44w8SI5NsZssIXTUvDg\"").unwrap();

        let response = r#"{
                "rawId": "AZD7huwZVx7aW1efRa6Uq3JTQNorj3qA9yrLINXEcgvCQYtWiSQa1eOIVrXfCmip6MzP8KaITOvRLjy3TUHO7_c",
                "id": "AZD7huwZVx7aW1efRa6Uq3JTQNorj3qA9yrLINXEcgvCQYtWiSQa1eOIVrXfCmip6MzP8KaITOvRLjy3TUHO7_c",
                "response": {
                    "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiVGY2NWJTNkQ1dGVtaDJCd3ZwdHFnQlBiMjVpWkRSeGp3QzVhbnM5MUlJSkRyY3JPcG5XVEs0TFZnRmplVVY0R0RNZTQ0dzhTSTVOc1pzc0lYVFV2RGciLCJvcmlnaW4iOiJodHRwczpcL1wvd2ViYXV0aG4ub3JnIiwiYW5kcm9pZFBhY2thZ2VOYW1lIjoiY29tLmFuZHJvaWQuY2hyb21lIn0",
                    "attestationObject": "o2NmbXRrYW5kcm9pZC1rZXlnYXR0U3RtdKNjYWxnJmNzaWdYRjBEAiAsp6jPtimcSgc-fgIsVwgqRsZX6eU7KKbkVGWa0CRJlgIgH5yuf_laPyNy4PlS6e8ZHjs57iztxGiTqO7G91sdlWBjeDVjg1kCzjCCAsowggJwoAMCAQICAQEwCgYIKoZIzj0EAwIwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQKDAxHb29nbGUsIEluYy4xEDAOBgNVBAsMB0FuZHJvaWQxOzA5BgNVBAMMMkFuZHJvaWQgS2V5c3RvcmUgU29mdHdhcmUgQXR0ZXN0YXRpb24gSW50ZXJtZWRpYXRlMB4XDTE4MTIwMjA5MTAyNVoXDTI4MTIwMjA5MTAyNVowHzEdMBsGA1UEAwwUQW5kcm9pZCBLZXlzdG9yZSBLZXkwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ4SaIP3ibDSwCIORpYJ3g9_5OICxZUCIqt-vV6JZVJoXQ8S1JFzyaFz5EFQ2fNT6-5SE5wWTZRAR_A3M52IcaPo4IBMTCCAS0wCwYDVR0PBAQDAgeAMIH8BgorBgEEAdZ5AgERBIHtMIHqAgECCgEAAgEBCgEBBCAqQ4LXu9idi1vfF3LP7MoUOSSHuf1XHy63K9-X3gbUtgQAMIGCv4MQCAIGAWduLuFwv4MRCAIGAbDqja1wv4MSCAIGAbDqja1wv4U9CAIGAWduLt_ov4VFTgRMMEoxJDAiBB1jb20uZ29vZ2xlLmF0dGVzdGF0aW9uZXhhbXBsZQIBATEiBCBa0F7CIcj4OiJhJ97FV1AMPldLxgElqdwhywvkoAZglTAzoQUxAwIBAqIDAgEDowQCAgEApQUxAwIBBKoDAgEBv4N4AwIBF7-DeQMCAR6_hT4DAgEAMB8GA1UdIwQYMBaAFD_8rNYasTqegSC41SUcxWW7HpGpMAoGCCqGSM49BAMCA0gAMEUCIGd3OQiTgFX9Y07kE-qvwh2Kx6lEG9-Xr2ORT5s7AK_-AiEAucDIlFjCUo4rJfqIxNY93HXhvID7lNzGIolS0E-BJBhZAnwwggJ4MIICHqADAgECAgIQATAKBggqhkjOPQQDAjCBmDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxFTATBgNVBAoMDEdvb2dsZSwgSW5jLjEQMA4GA1UECwwHQW5kcm9pZDEzMDEGA1UEAwwqQW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBSb290MB4XDTE2MDExMTAwNDYwOVoXDTI2MDEwODAwNDYwOVowgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQKDAxHb29nbGUsIEluYy4xEDAOBgNVBAsMB0FuZHJvaWQxOzA5BgNVBAMMMkFuZHJvaWQgS2V5c3RvcmUgU29mdHdhcmUgQXR0ZXN0YXRpb24gSW50ZXJtZWRpYXRlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6555-EJjWazLKpFMiYbMcK2QZpOCqXMmE_6sy_ghJ0whdJdKKv6luU1_ZtTgZRBmNbxTt6CjpnFYPts-Ea4QFKNmMGQwHQYDVR0OBBYEFD_8rNYasTqegSC41SUcxWW7HpGpMB8GA1UdIwQYMBaAFMit6XdMRcOjzw0WEOR5QzohWjDPMBIGA1UdEwEB_wQIMAYBAf8CAQAwDgYDVR0PAQH_BAQDAgKEMAoGCCqGSM49BAMCA0gAMEUCIEuKm3vugrzAM4euL8CJmLTdw42rJypFn2kMx8OS1A-OAiEA7toBXbb0MunUhDtiTJQE7zp8zL1e-yK75_65dz9ZP_tZAo8wggKLMIICMqADAgECAgkAogWe0Q5DW1cwCgYIKoZIzj0EAwIwgZgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1Nb3VudGFpbiBWaWV3MRUwEwYDVQQKDAxHb29nbGUsIEluYy4xEDAOBgNVBAsMB0FuZHJvaWQxMzAxBgNVBAMMKkFuZHJvaWQgS2V5c3RvcmUgU29mdHdhcmUgQXR0ZXN0YXRpb24gUm9vdDAeFw0xNjAxMTEwMDQzNTBaFw0zNjAxMDYwMDQzNTBaMIGYMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmlldzEVMBMGA1UECgwMR29vZ2xlLCBJbmMuMRAwDgYDVQQLDAdBbmRyb2lkMTMwMQYDVQQDDCpBbmRyb2lkIEtleXN0b3JlIFNvZnR3YXJlIEF0dGVzdGF0aW9uIFJvb3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATuXV7H4cDbbQOmfua2G-xNal1qaC4P_39JDn13H0Qibb2xr_oWy8etxXfSVpyqt7AtVAFdPkMrKo7XTuxIdUGko2MwYTAdBgNVHQ4EFgQUyK3pd0xFw6PPDRYQ5HlDOiFaMM8wHwYDVR0jBBgwFoAUyK3pd0xFw6PPDRYQ5HlDOiFaMM8wDwYDVR0TAQH_BAUwAwEB_zAOBgNVHQ8BAf8EBAMCAoQwCgYIKoZIzj0EAwIDRwAwRAIgNSGj74s0Rh6c1WDzHViJIGrco2VB9g2ezooZjGZIYHsCIE0L81HZMHx9W9o1NB2oRxtjpYVlPK1PJKfnTa9BffG_aGF1dGhEYXRhWMWVaQiPHs7jIylUA129ENfK45EwWidRtVm7j9fLsim91EUAAAAAKPN9K5K4QcSwKoYM73zANABBAVUvAmX241vMKYd7ZBdmkNWaYcNYhoSZCJjFRGmROb6I4ygQUVmH6k9IMwcbZGeAQ4v4WMNphORudwje5h7ty9ClAQIDJiABIVggOEmiD94mw0sAiDkaWCd4Pf-TiAsWVAiKrfr1eiWVSaEiWCB0PEtSRc8mhc-RBUNnzU-vuUhOcFk2UQEfwNzOdiHGjw"
                },
                "type": "public-key"}"#;

        let _ = tracing_subscriber::fmt::try_init();
        let wan = Webauthn::new_unsafe_experts_only(
            "webauthn.org",
            "webauthn.org",
            &Url::parse("https://webauthn.org").unwrap(),
            None,
            None,
            None,
        );

        let chal = Challenge::from(chal);

        let rsp_d: RegisterPublicKeyCredential = serde_json::from_str(response).unwrap();

        debug!("{:?}", rsp_d);

        let result = wan.register_credential_internal(
            &rsp_d,
            UserVerificationPolicy::Required,
            &chal,
            &[],
            &[COSEAlgorithm::ES256],
            Some(&AttestationCaList {
                cas: vec![AttestationCa::android_software_ca()],
            }),
            true,
            &RequestRegistrationExtensions::default(),
            true,
        );
        dbg!(&result);
        assert!(result.is_ok());

        match result.unwrap().attestation.metadata {
            AttestationMetadata::AndroidKey {
                is_km_tee,
                is_attest_tee,
            } => {
                assert!(is_km_tee);
                assert!(!is_attest_tee);
            }
            _ => panic!("invalid metadata"),
        }
    }

    #[test]
    fn test_validate_origin_localhost_port() {
        let collected = url::Url::parse("http://localhost:3000").unwrap();
        let config = url::Url::parse("http://localhost:8000").unwrap();

        let result = super::WebauthnCore::validate_origin(false, true, &collected, &config);
        dbg!(&result);
        assert!(result.is_ok());

        let result = super::WebauthnCore::validate_origin(true, false, &collected, &config);
        assert!(result.is_err());
    }
}

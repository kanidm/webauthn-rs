#[cfg(doc)]
use crate::stubs::*;

use crate::authenticator_hashed::AuthenticatorBackendHashedClientData;
use crate::crypto::{compute_sha256, get_group};
use crate::error::WebauthnCError;
use openssl::{bn, ec, hash, pkey, rand, sign};
use serde_cbor_2::value::Value;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::iter;

use base64urlsafedata::Base64UrlSafeData;

use webauthn_rs_proto::{
    AllowCredentials, AuthenticationExtensionsClientOutputs, AuthenticatorAssertionResponseRaw,
    AuthenticatorAttachment, AuthenticatorAttestationResponseRaw, PublicKeyCredential,
    PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions,
    RegisterPublicKeyCredential, RegistrationExtensionsClientOutputs, UserVerificationPolicy,
};

pub struct SoftPasskey {
    tokens: HashMap<Vec<u8>, Vec<u8>>,
    counter: u32,
    falsify_uv: bool,
}

impl SoftPasskey {
    pub fn new(falsify_uv: bool) -> Self {
        SoftPasskey {
            tokens: HashMap::new(),
            counter: 0,
            falsify_uv,
        }
    }
}

impl Default for SoftPasskey {
    fn default() -> Self {
        Self::new(false)
    }
}

#[derive(Debug)]
pub struct U2FSignData {
    key_handle: Vec<u8>,
    counter: u32,
    signature: Vec<u8>,
    flags: u8,
}

impl AuthenticatorBackendHashedClientData for SoftPasskey {
    fn perform_register(
        &mut self,
        client_data_json_hash: Vec<u8>,
        options: PublicKeyCredentialCreationOptions,
        _timeout_ms: u32,
    ) -> Result<RegisterPublicKeyCredential, WebauthnCError> {
        // Let credTypesAndPubKeyAlgs be a new list whose items are pairs of PublicKeyCredentialType and a COSEAlgorithmIdentifier.
        // Done in rust types.

        // For each current of options.pubKeyCredParams:
        //     If current.type does not contain a PublicKeyCredentialType supported by this implementation, then continue.
        //     Let alg be current.alg.
        //     Append the pair of current.type and alg to credTypesAndPubKeyAlgs.
        let cred_types_and_pub_key_algs: Vec<_> = options
            .pub_key_cred_params
            .iter()
            .filter_map(|param| {
                if param.type_ != "public-key" {
                    None
                } else {
                    Some((param.type_.clone(), param.alg))
                }
            })
            .collect();

        trace!("Found -> {:x?}", cred_types_and_pub_key_algs);

        // If credTypesAndPubKeyAlgs is empty and options.pubKeyCredParams is not empty, return a DOMException whose name is "NotSupportedError", and terminate this algorithm.
        if cred_types_and_pub_key_algs.is_empty() {
            return Err(WebauthnCError::NotSupported);
        }

        // Webauthn-rs doesn't support this yet.
        /*
            // Let clientExtensions be a new map and let authenticatorExtensions be a new map.

            // If the extensions member of options is present, then for each extensionId → clientExtensionInput of options.extensions:
            //     If extensionId is not supported by this client platform or is not a registration extension, then continue.
            //     Set clientExtensions[extensionId] to clientExtensionInput.
            //     If extensionId is not an authenticator extension, then continue.
            //     Let authenticatorExtensionInput be the (CBOR) result of running extensionId’s client extension processing algorithm on clientExtensionInput. If the algorithm returned an error, continue.
            //     Set authenticatorExtensions[extensionId] to the base64url encoding of authenticatorExtensionInput.
        */

        // Not required.
        // If the options.signal is present and its aborted flag is set to true, return a DOMException whose name is "AbortError" and terminate this algorithm.

        // Let issuedRequests be a new ordered set.

        // Let authenticators represent a value which at any given instant is a set of client platform-specific handles, where each item identifies an authenticator presently available on this client platform at that instant.

        // Start lifetimeTimer.

        // While lifetimeTimer has not expired, perform the following actions depending upon lifetimeTimer, and the state and response for each authenticator in authenticators:

        //    If lifetimeTimer expires,
        //        For each authenticator in issuedRequests invoke the authenticatorCancel operation on authenticator and remove authenticator from issuedRequests.

        //    If the user exercises a user agent user-interface option to cancel the process,
        //        For each authenticator in issuedRequests invoke the authenticatorCancel operation on authenticator and remove authenticator from issuedRequests. Return a DOMException whose name is "NotAllowedError".

        //    If the options.signal is present and its aborted flag is set to true,
        //        For each authenticator in issuedRequests invoke the authenticatorCancel operation on authenticator and remove authenticator from issuedRequests. Then return a DOMException whose name is "AbortError" and terminate this algorithm.

        //    If an authenticator becomes available on this client device,
        //         If options.authenticatorSelection is present:
        //             If options.authenticatorSelection.authenticatorAttachment is present and its value is not equal to authenticator’s authenticator attachment modality, continue.
        //             If options.authenticatorSelection.requireResidentKey is set to true and the authenticator is not capable of storing a client-side-resident public key credential source, continue.
        //             If options.authenticatorSelection.userVerification is set to required and the authenticator is not capable of performing user verification, continue.
        //          Let userVerification be the effective user verification requirement for credential creation, a Boolean value, as follows. If options.authenticatorSelection.userVerification
        //              is set to required -> Let userVerification be true.
        //              is set to preferred
        //                  If the authenticator
        //                      is capable of user verification -> Let userVerification be true.
        //                      is not capable of user verification -> Let userVerification be false.
        //              is set to discouraged -> Let userVerification be false.
        //          Let userPresence be a Boolean value set to the inverse of userVerification.
        //          Let excludeCredentialDescriptorList be a new list.
        //          For each credential descriptor C in options.excludeCredentials:
        //              If C.transports is not empty, and authenticator is connected over a transport not mentioned in C.transports, the client MAY continue.
        //              Otherwise, Append C to excludeCredentialDescriptorList.
        //          Invoke the authenticatorMakeCredential operation on authenticator with clientDataHash, options.rp, options.user, options.authenticatorSelection.requireResidentKey, userPresence, userVerification, credTypesAndPubKeyAlgs, excludeCredentialDescriptorList, and authenticatorExtensions as parameters.

        //          Append authenticator to issuedRequests.

        //    If an authenticator ceases to be available on this client device,
        //         Remove authenticator from issuedRequests.

        //    If any authenticator returns a status indicating that the user cancelled the operation,
        //         Remove authenticator from issuedRequests.
        //         For each remaining authenticator in issuedRequests invoke the authenticatorCancel operation on authenticator and remove it from issuedRequests.

        //    If any authenticator returns an error status equivalent to "InvalidStateError",
        //         Remove authenticator from issuedRequests.
        //         For each remaining authenticator in issuedRequests invoke the authenticatorCancel operation on authenticator and remove it from issuedRequests.
        //         Return a DOMException whose name is "InvalidStateError" and terminate this algorithm.

        //    If any authenticator returns an error status not equivalent to "InvalidStateError",
        //         Remove authenticator from issuedRequests.

        //    If any authenticator indicates success,
        //         Remove authenticator from issuedRequests.
        //         Let credentialCreationData be a struct whose items are:
        //         Let constructCredentialAlg be an algorithm that takes a global object global, and whose steps are:

        //         Let attestationObject be a new ArrayBuffer, created using global’s %ArrayBuffer%, containing the bytes of credentialCreationData.attestationObjectResult’s value.

        //         Let id be attestationObject.authData.attestedCredentialData.credentialId.
        //         Let pubKeyCred be a new PublicKeyCredential object associated with global whose fields are:
        //         For each remaining authenticator in issuedRequests invoke the authenticatorCancel operation on authenticator and remove it from issuedRequests.
        //         Return constructCredentialAlg and terminate this algorithm.

        // For our needs, we let the u2f auth library handle the above, but currently it can't accept
        // verified devices for u2f with ctap1/2. We may need to change u2f/authenticator library in the future.
        // As a result this really limits our usage to certain device classes. This is why we implement
        // this section in a seperate function call.

        let (platform_attached, resident_key, user_verification) =
            match &options.authenticator_selection {
                Some(auth_sel) => {
                    let pa = auth_sel
                        .authenticator_attachment
                        .as_ref()
                        .map(|v| v == &AuthenticatorAttachment::Platform)
                        .unwrap_or(false);
                    let uv = auth_sel.user_verification == UserVerificationPolicy::Required;
                    (pa, auth_sel.require_resident_key, uv)
                }
                None => (false, false, false),
            };

        let rp_id_hash = compute_sha256(options.rp.id.as_bytes()).to_vec();

        // =====

        if user_verification && !self.falsify_uv {
            error!("User Verification not supported by softtoken");
            return Err(WebauthnCError::NotSupported);
        }

        if platform_attached {
            error!("Platform Attachement not supported by softtoken");
            return Err(WebauthnCError::NotSupported);
        }

        if resident_key {
            error!("Resident Keys not supported by softtoken");
            return Err(WebauthnCError::NotSupported);
        }

        // Generate a random credential id
        let mut key_handle: Vec<u8> = Vec::with_capacity(32);
        key_handle.resize_with(32, Default::default);
        rand::rand_bytes(key_handle.as_mut_slice())?;

        // Create a new key.
        let ecgroup = get_group()?;

        let eckey = ec::EcKey::generate(&ecgroup)?;

        // Extract the public x and y coords.
        let ecpub_points = eckey.public_key();

        let mut bnctx = bn::BigNumContext::new()?;

        let mut xbn = bn::BigNum::new()?;

        let mut ybn = bn::BigNum::new()?;

        ecpub_points.affine_coordinates_gfp(&ecgroup, &mut xbn, &mut ybn, &mut bnctx)?;

        let mut public_key_x = Vec::with_capacity(32);
        let mut public_key_y = Vec::with_capacity(32);

        public_key_x.resize(32, 0);
        public_key_y.resize(32, 0);

        let xbnv = xbn.to_vec();
        let ybnv = ybn.to_vec();

        let (_pad, x_fill) = public_key_x.split_at_mut(32 - xbnv.len());
        x_fill.copy_from_slice(&xbnv);

        let (_pad, y_fill) = public_key_y.split_at_mut(32 - ybnv.len());
        y_fill.copy_from_slice(&ybnv);

        // Extract the DER cert for later
        let ecpriv_der = eckey.private_key_to_der()?;

        // Now setup to sign.
        let pkey = pkey::PKey::from_ec_key(eckey)?;

        let mut signer = sign::Signer::new(hash::MessageDigest::sha256(), &pkey)?;

        // =====

        // From the u2f response, we now need to assemble the attestation object now.

        // cbor encode the public key. We already decomposed this, so just create
        // the correct bytes.
        let mut map = BTreeMap::new();
        // KeyType -> EC2
        map.insert(Value::Integer(1), Value::Integer(2));
        // Alg -> ES256
        map.insert(Value::Integer(3), Value::Integer(-7));

        // Curve -> P-256
        map.insert(Value::Integer(-1), Value::Integer(1));
        // EC X coord
        map.insert(Value::Integer(-2), Value::Bytes(public_key_x));
        // EC Y coord
        map.insert(Value::Integer(-3), Value::Bytes(public_key_y));

        let pk_cbor = Value::Map(map);
        let pk_cbor_bytes = serde_cbor_2::to_vec(&pk_cbor).map_err(|e| {
            error!("PK CBOR -> {:x?}", e);
            WebauthnCError::Cbor
        })?;

        let key_handle_len: u16 = u16::try_from(key_handle.len()).map_err(|e| {
            error!("CBOR kh len is not u16 -> {:x?}", e);
            WebauthnCError::Cbor
        })?;

        // combine aaGuid, KeyHandle, CborPubKey into a AttestedCredentialData. (acd)
        let aaguid: [u8; 16] = [0; 16];

        // make a 00 aaguid
        let khlen_be_bytes = key_handle_len.to_be_bytes();
        let acd_iter = aaguid
            .iter()
            .chain(khlen_be_bytes.iter())
            .copied()
            .chain(key_handle.iter().copied())
            .chain(pk_cbor_bytes.iter().copied());

        // set counter to 0 during create
        // Combine rp_id_hash, flags, counter, acd, into authenticator data.
        // The flags are always user_present, att present
        let flags = if user_verification {
            0b01000101
        } else {
            0b01000001
        };

        let authdata: Vec<u8> = rp_id_hash
            .iter()
            .copied()
            .chain(iter::once(flags))
            .chain(
                // A 0 u32 counter
                iter::repeat(0).take(4),
            )
            .chain(acd_iter)
            .collect();

        // 4.b. Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using the credential public key with alg.

        let verification_data: Vec<u8> = authdata
            .iter()
            .chain(client_data_json_hash.iter())
            .copied()
            .collect();

        // Do the signature
        let signature = signer
            .update(verification_data.as_slice())
            .and_then(|_| signer.sign_to_vec())?;

        let mut attest_map = BTreeMap::new();

        /*
        match options.attestation {
            None | Some(AttestationConveyancePreference::None) => {
            }
            Some(AttestationConveyancePreference::Indirect)
            | Some(AttestationConveyancePreference::Direct) => {
                todo!();
            }
        }
        */

        attest_map.insert(
            Value::Text("fmt".to_string()),
            Value::Text("packed".to_string()),
        );
        let mut att_stmt_map = BTreeMap::new();
        att_stmt_map.insert(Value::Text("alg".to_string()), Value::Integer(-7));
        att_stmt_map.insert(Value::Text("sig".to_string()), Value::Bytes(signature));

        attest_map.insert(Value::Text("attStmt".to_string()), Value::Map(att_stmt_map));
        attest_map.insert(Value::Text("authData".to_string()), Value::Bytes(authdata));

        let ao = Value::Map(attest_map);

        let ao_bytes = serde_cbor_2::to_vec(&ao).map_err(|e| {
            error!("AO CBOR -> {:x?}", e);
            WebauthnCError::Cbor
        })?;

        // Return a DOMException whose name is "NotAllowedError". In order to prevent information leak that could identify the user without consent, this step MUST NOT be executed before lifetimeTimer has expired. See §14.5 Registration Ceremony Privacy for details.

        // Okay, now persist the token. We shouldn't fail from here.
        self.tokens.insert(key_handle.clone(), ecpriv_der);

        let id: String = Base64UrlSafeData(key_handle.clone()).to_string();

        let rego = RegisterPublicKeyCredential {
            id,
            raw_id: Base64UrlSafeData(key_handle),
            response: AuthenticatorAttestationResponseRaw {
                attestation_object: Base64UrlSafeData(ao_bytes),
                client_data_json: Base64UrlSafeData(vec![]),
                transports: None,
            },
            type_: "public-key".to_string(),
            extensions: RegistrationExtensionsClientOutputs::default(),
        };

        trace!("rego  -> {:x?}", rego);
        Ok(rego)
    }

    fn perform_auth(
        &mut self,
        client_data_json_hash: Vec<u8>,
        options: PublicKeyCredentialRequestOptions,
        timeout_ms: u32,
    ) -> Result<PublicKeyCredential, WebauthnCError> {
        // Let clientExtensions be a new map and let authenticatorExtensions be a new map.

        // If the extensions member of options is present, then for each extensionId → clientExtensionInput of options.extensions:
        // ...

        // This is where we deviate from the spec, since we aren't a browser.

        let user_verification = options.user_verification == UserVerificationPolicy::Required;

        let rp_id_hash = compute_sha256(options.rp_id.as_bytes()).to_vec();

        let u2sd = self.perform_u2f_sign(
            rp_id_hash.clone(),
            client_data_json_hash,
            timeout_ms.into(),
            options.allow_credentials.as_slice(),
            user_verification,
        )?;

        trace!("u2sd -> {:x?}", u2sd);
        // Transform the result to webauthn

        // The flags are set from the device.

        let authdata: Vec<u8> = rp_id_hash
            .iter()
            .copied()
            .chain(iter::once(u2sd.flags))
            .chain(
                // A 0 u32 counter
                u2sd.counter.to_be_bytes().iter().copied(),
            )
            .collect();

        let id: String = Base64UrlSafeData(u2sd.key_handle.clone()).to_string();

        Ok(PublicKeyCredential {
            id,
            raw_id: Base64UrlSafeData(u2sd.key_handle.clone()),
            response: AuthenticatorAssertionResponseRaw {
                authenticator_data: Base64UrlSafeData(authdata),
                client_data_json: Base64UrlSafeData(vec![]),
                signature: Base64UrlSafeData(u2sd.signature),
                user_handle: None,
            },
            type_: "public-key".to_string(),
            extensions: AuthenticationExtensionsClientOutputs::default(),
        })
    }
}

pub trait U2FToken {
    fn perform_u2f_sign(
        &mut self,
        // This is rp.id_hash
        app_bytes: Vec<u8>,
        // This is client_data_json_hash
        chal_bytes: Vec<u8>,
        // timeout from options
        timeout_ms: u64,
        // list of creds
        allowed_credentials: &[AllowCredentials],
        user_verification: bool,
    ) -> Result<U2FSignData, WebauthnCError>;
}

impl U2FToken for SoftPasskey {
    fn perform_u2f_sign(
        &mut self,
        // This is rp.id_hash
        app_bytes: Vec<u8>,
        // This is client_data_json_hash
        chal_bytes: Vec<u8>,
        // timeout from options
        _timeout_ms: u64,
        // list of creds
        allowed_credentials: &[AllowCredentials],
        user_verification: bool,
    ) -> Result<U2FSignData, WebauthnCError> {
        if user_verification && !self.falsify_uv {
            error!("User Verification not supported by softtoken");
            return Err(WebauthnCError::NotSupported);
        }

        let cred = allowed_credentials
            .iter()
            .filter_map(|ac| {
                self.tokens
                    .get(&ac.id.0)
                    .map(|v| (ac.id.0.clone(), v.clone()))
            })
            .take(1)
            .next();

        let (key_handle, pkder) = if let Some((key_handle, pkder)) = cred {
            (key_handle, pkder)
        } else {
            error!("Credential ID not found");
            return Err(WebauthnCError::Internal);
        };

        debug!("Using -> {:?}", key_handle);

        let eckey = ec::EcKey::private_key_from_der(pkder.as_slice())?;

        let pkey = pkey::PKey::from_ec_key(eckey)?;

        let mut signer = sign::Signer::new(hash::MessageDigest::sha256(), &pkey)?;

        // Increment the counter.
        self.counter += 1;
        let counter = self.counter;

        let flags = if user_verification {
            0b00000101
        } else {
            0b00000001
        };

        let verification_data: Vec<u8> = app_bytes
            .iter()
            .chain(iter::once(&flags))
            .chain(counter.to_be_bytes().iter())
            .chain(chal_bytes.iter())
            .copied()
            .collect();

        let signature = signer
            .update(verification_data.as_slice())
            .and_then(|_| signer.sign_to_vec())?;

        Ok(U2FSignData {
            key_handle,
            counter,
            signature,
            flags,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::SoftPasskey;
    use crate::prelude::{Url, WebauthnAuthenticator};
    use webauthn_rs_core::WebauthnCore as Webauthn;
    use webauthn_rs_proto::{
        AttestationConveyancePreference, COSEAlgorithm, UserVerificationPolicy,
    };

    #[test]
    fn webauthn_authenticator_wan_softpasskey_self_attest() {
        let _ = tracing_subscriber::fmt::try_init();
        let wan = Webauthn::new_unsafe_experts_only(
            "https://localhost:8080/auth",
            "localhost",
            vec![url::Url::parse("https://localhost:8080").unwrap()],
            None,
            None,
            None,
        );

        let unique_id = [
            158, 170, 228, 89, 68, 28, 73, 194, 134, 19, 227, 153, 107, 220, 150, 238,
        ];
        let name = "william";

        let (chal, reg_state) = wan
            .generate_challenge_register_options(
                &unique_id,
                name,
                name,
                AttestationConveyancePreference::Direct,
                Some(UserVerificationPolicy::Preferred),
                None,
                None,
                COSEAlgorithm::secure_algs(),
                false,
                None,
                false,
            )
            .unwrap();

        info!("🍿 challenge -> {:x?}", chal);

        let mut wa = WebauthnAuthenticator::new(SoftPasskey::new(true));
        let r = wa
            .do_registration(Url::parse("https://localhost:8080").unwrap(), chal)
            .map_err(|e| {
                error!("Error -> {:x?}", e);
                e
            })
            .expect("Failed to register");

        let cred = wan.register_credential(&r, &reg_state, None).unwrap();

        let (chal, auth_state) = wan
            .generate_challenge_authenticate(vec![cred], None)
            .unwrap();

        let r = wa
            .do_authentication(Url::parse("https://localhost:8080").unwrap(), chal)
            .map_err(|e| {
                error!("Error -> {:x?}", e);
                e
            })
            .expect("Failed to auth");

        let auth_res = wan
            .authenticate_credential(&r, &auth_state)
            .expect("webauth authentication denied");
        info!("auth_res -> {:x?}", auth_res);
    }
}

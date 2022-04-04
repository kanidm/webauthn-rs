extern crate nom;
#[macro_use]
extern crate tracing;

use crate::error::WebauthnCError;
use base64urlsafedata::Base64UrlSafeData;

use serde_cbor::value::Value;
use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::iter;
use url::Url;

use openssl::sha;

pub use webauthn_rs_proto::{
    AllowCredentials,
    // AttestationConveyancePreference,
    AuthenticatorAssertionResponseRaw,
    AuthenticatorAttachment,
    AuthenticatorAttestationResponseRaw,
    // AttestationObject
    // AuthenticatorData,
    CollectedClientData,
    CreationChallengeResponse,
    PublicKeyCredential,
    RegisterPublicKeyCredential,
    RequestChallengeResponse,
    UserVerificationPolicy,
};

#[derive(Debug)]
pub struct U2FRegistrationData {
    public_key_x: Vec<u8>,
    public_key_y: Vec<u8>,
    key_handle: Vec<u8>,
    att_cert: Vec<u8>,
    signature: Vec<u8>,
}

#[derive(Debug)]
pub struct U2FSignData {
    appid: Vec<u8>,
    key_handle: Vec<u8>,
    counter: u32,
    signature: Vec<u8>,
    user_present: u8,
}

pub mod error;
pub mod softtok;

#[cfg(feature = "nfc")]
pub mod nfc;
#[cfg(feature = "u2fhid")]
pub mod u2fhid;

fn compute_sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = sha::Sha256::new();
    hasher.update(data);
    hasher.finish()
}

pub struct WebauthnAuthenticator<T>
where
    T: U2FToken,
{
    token: T,
}

pub trait U2FToken {
    fn perform_u2f_register(
        &mut self,
        // This is rp.id_hash
        app_bytes: Vec<u8>,
        // This is client_data_json_hash
        chal_bytes: Vec<u8>,
        // timeout from options
        timeout_ms: u64,
        platform_attached: bool,
        resident_key: bool,
        user_verification: bool,
    ) -> Result<U2FRegistrationData, WebauthnCError>;

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

impl<T> WebauthnAuthenticator<T>
where
    T: U2FToken,
{
    pub fn new(token: T) -> Self {
        WebauthnAuthenticator { token }
    }
}

impl<T> WebauthnAuthenticator<T>
where
    T: U2FToken,
{
    /// 5.1.3. Create a New Credential - PublicKeyCredential’s [[Create]](origin, options, sameOriginWithAncestors) Method
    /// https://www.w3.org/TR/webauthn/#createCredential
    ///
    /// 6.3.2. The authenticatorMakeCredential Operation
    /// https://www.w3.org/TR/webauthn/#op-make-cred
    pub fn do_registration(
        &mut self,
        origin: &str,
        options: CreationChallengeResponse,
        // _same_origin_with_ancestors: bool,
    ) -> Result<RegisterPublicKeyCredential, WebauthnCError> {
        // Assert: options.publicKey is present.
        // This is asserted through rust types.

        // If sameOriginWithAncestors is false, return a "NotAllowedError" DOMException.
        // We just don't take this value.

        // Let options be the value of options.publicKey.
        let options = &options.public_key;

        // If the timeout member of options is present, check if its value lies within a reasonable range as defined by the client and if not, correct it to the closest value lying within that range. Set a timer lifetimeTimer to this adjusted value. If the timeout member of options is not present, then set lifetimeTimer to a client-specific default.
        let timeout = options
            .timeout
            .map(|t| if t > 60000 { 60000 } else { t })
            .unwrap_or(60000);

        // Let callerOrigin be origin. If callerOrigin is an opaque origin, return a DOMException whose name is "NotAllowedError", and terminate this algorithm.
        // This is a bit unclear - see https://github.com/w3c/wpub/issues/321.
        // It may be a browser specific quirk.
        // https://html.spec.whatwg.org/multipage/origin.html
        // As a result we don't need to check for our needs.

        // Let effectiveDomain be the callerOrigin’s effective domain. If effective domain is not a valid domain, then return a DOMException whose name is "Security" and terminate this algorithm.
        let caller_origin = Url::parse(origin).map_err(|pe| {
            error!("url parse failure -> {:x?}", pe);
            WebauthnCError::Security
        })?;

        let effective_domain = caller_origin
            .domain()
            // Checking by IP today muddies things. We'd need a check for rp.id about suffixes
            // to be different for this.
            // .or_else(|| caller_origin.host_str())
            .ok_or(WebauthnCError::Security)
            .map_err(|e| {
                error!("origin has no domain or host_str");
                e
            })?;

        trace!("effective domain -> {:x?}", effective_domain);
        trace!("relying party id -> {:x?}", options.rp.id);

        // If options.rp.id
        //      Is present
        //          If options.rp.id is not a registrable domain suffix of and is not equal to effectiveDomain, return a DOMException whose name is "Security", and terminate this algorithm.
        //      Is not present
        //          Set options.rp.id to effectiveDomain.

        if !effective_domain.ends_with(&options.rp.id) {
            error!("relying party id domain is not suffix of effective domain.");
            return Err(WebauthnCError::Security);
        }

        // Check origin is https:// if effectiveDomain != localhost.
        if !(effective_domain == "localhost" || caller_origin.scheme() == "https") {
            error!("An insecure domain or scheme in origin. Must be localhost or https://");
            return Err(WebauthnCError::Security);
        }

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

        // Let collectedClientData be a new CollectedClientData instance whose fields are:
        //    type
        //        The string "webauthn.create".
        //    challenge
        //        The base64url encoding of options.challenge.
        //    origin
        //        The serialization of callerOrigin.

        //    Not Supported Yet.
        //    tokenBinding
        //        The status of Token Binding between the client and the callerOrigin, as well as the Token Binding ID associated with callerOrigin, if one is available.
        let collected_client_data = CollectedClientData {
            type_: "webauthn.create".to_string(),
            challenge: options.challenge.clone(),
            origin: caller_origin,
            token_binding: None,
            cross_origin: None,
            unknown_keys: BTreeMap::new(),
        };

        //  Let clientDataJSON be the JSON-serialized client data constructed from collectedClientData.
        let client_data_json =
            serde_json::to_string(&collected_client_data).map_err(|_| WebauthnCError::Json)?;

        // Let clientDataHash be the hash of the serialized client data represented by clientDataJSON.
        let client_data_json_hash = compute_sha256(client_data_json.as_bytes()).to_vec();

        trace!("client_data_json -> {:x?}", client_data_json);
        trace!("client_data_json_hash -> {:x?}", client_data_json_hash);

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

        let u2rd = self.token.perform_u2f_register(
            rp_id_hash.clone(),
            client_data_json_hash,
            timeout.into(),
            platform_attached,
            resident_key,
            user_verification,
        )?;

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
        map.insert(Value::Integer(-2), Value::Bytes(u2rd.public_key_x));
        // EC Y coord
        map.insert(Value::Integer(-3), Value::Bytes(u2rd.public_key_y));

        let pk_cbor = Value::Map(map);
        let pk_cbor_bytes = serde_cbor::to_vec(&pk_cbor).map_err(|e| {
            error!("PK CBOR -> {:x?}", e);
            WebauthnCError::Cbor
        })?;

        let key_handle_len: u16 = u16::try_from(u2rd.key_handle.len()).map_err(|e| {
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
            .chain(u2rd.key_handle.iter().copied())
            .chain(pk_cbor_bytes.iter().copied());

        // set counter to 0 during create
        // Combine rp_id_hash, flags, counter, acd, into authenticator data.
        // The flags are always user_present, att present
        let flags = 0b01000001;

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

        let mut attest_map = BTreeMap::new();

        match options.attestation {
            // None | Some(AttestationConveyancePreference::None) => {
            _ => {
                attest_map.insert(
                    Value::Text("fmt".to_string()),
                    Value::Text("none".to_string()),
                );
                attest_map.insert(Value::Text("attStmt".to_string()), Value::Null);
                attest_map.insert(Value::Text("authData".to_string()), Value::Bytes(authdata));
            } /*
              _ => {
              //    create a u2f attestation from authData, attest cert, a signature,)
                  unimplemented!();
              }
              */
        }

        let ao = Value::Map(attest_map);

        let ao_bytes = serde_cbor::to_vec(&ao).map_err(|e| {
            error!("AO CBOR -> {:x?}", e);
            WebauthnCError::Cbor
        })?;

        // Return a DOMException whose name is "NotAllowedError". In order to prevent information leak that could identify the user without consent, this step MUST NOT be executed before lifetimeTimer has expired. See §14.5 Registration Ceremony Privacy for details.

        let id: String = Base64UrlSafeData(u2rd.key_handle.clone()).to_string();

        let rego = RegisterPublicKeyCredential {
            id,
            raw_id: Base64UrlSafeData(u2rd.key_handle),
            response: AuthenticatorAttestationResponseRaw {
                attestation_object: Base64UrlSafeData(ao_bytes),
                client_data_json: Base64UrlSafeData(client_data_json.as_bytes().to_vec()),
            },
            type_: "public-key".to_string(),
        };

        trace!("rego  -> {:x?}", rego);
        Ok(rego)
    }

    /// https://www.w3.org/TR/webauthn/#getAssertion
    pub fn do_authentication(
        &mut self,
        origin: &str,
        options: RequestChallengeResponse,
    ) -> Result<PublicKeyCredential, WebauthnCError> {
        // Assert: options.publicKey is present.
        // This is asserted through rust types.

        // If sameOriginWithAncestors is false, return a "NotAllowedError" DOMException.
        // We just don't take this value.

        // Let options be the value of options.publicKey.
        let options = &options.public_key;

        // If the timeout member of options is present, check if its value lies within a reasonable range as defined by the client and if not, correct it to the closest value lying within that range. Set a timer lifetimeTimer to this adjusted value. If the timeout member of options is not present, then set lifetimeTimer to a client-specific default.
        let timeout = options
            .timeout
            .map(|t| if t > 60000 { 60000 } else { t })
            .unwrap_or(60000);

        // Let callerOrigin be origin. If callerOrigin is an opaque origin, return a DOMException whose name is "NotAllowedError", and terminate this algorithm.
        // This is a bit unclear - see https://github.com/w3c/wpub/issues/321.
        // It may be a browser specific quirk.
        // https://html.spec.whatwg.org/multipage/origin.html
        // As a result we don't need to check for our needs.

        // Let effectiveDomain be the callerOrigin’s effective domain. If effective domain is not a valid domain, then return a DOMException whose name is "Security" and terminate this algorithm.
        let caller_origin = Url::parse(origin).map_err(|pe| {
            error!("url parse failure -> {:x?}", pe);
            WebauthnCError::Security
        })?;

        let effective_domain = caller_origin
            .domain()
            // Checking by IP today muddies things. We'd need a check for rp.id about suffixes
            // to be different for this.
            // .or_else(|| caller_origin.host_str())
            .ok_or(WebauthnCError::Security)
            .map_err(|e| {
                error!("origin has no domain or host_str");
                e
            })?;

        trace!("effective domain -> {:x?}", effective_domain);
        trace!("relying party id -> {:x?}", options.rp_id);

        // If options.rp.id
        //      Is present
        //          If options.rp.id is not a registrable domain suffix of and is not equal to effectiveDomain, return a DOMException whose name is "Security", and terminate this algorithm.
        //      Is not present
        //          Set options.rp.id to effectiveDomain.

        if !effective_domain.ends_with(&options.rp_id) {
            error!("relying party id domain is not suffix of effective domain.");
            return Err(WebauthnCError::Security);
        }

        // Check origin is https:// if effectiveDomain != localhost.
        if !(effective_domain == "localhost" || caller_origin.scheme() == "https") {
            error!("An insecure domain or scheme in origin. Must be localhost or https://");
            return Err(WebauthnCError::Security);
        }

        // Let clientExtensions be a new map and let authenticatorExtensions be a new map.

        // If the extensions member of options is present, then for each extensionId → clientExtensionInput of options.extensions:
        // ...

        // Let collectedClientData be a new CollectedClientData instance whose fields are:
        let collected_client_data = CollectedClientData {
            type_: "webauthn.get".to_string(),
            challenge: options.challenge.clone(),
            origin: caller_origin,
            token_binding: None,
            cross_origin: None,
            unknown_keys: BTreeMap::new(),
        };

        // Let clientDataJSON be the JSON-serialized client data constructed from collectedClientData.
        let client_data_json =
            serde_json::to_string(&collected_client_data).map_err(|_| WebauthnCError::Json)?;

        // Let clientDataHash be the hash of the serialized client data represented by clientDataJSON.
        let client_data_json_hash = compute_sha256(client_data_json.as_bytes()).to_vec();

        trace!("client_data_json -> {:x?}", client_data_json);
        trace!("client_data_json_hash -> {:x?}", client_data_json_hash);

        // This is where we deviate from the spec, since we aren't a browser.

        let user_verification = options.user_verification == UserVerificationPolicy::Required;

        let rp_id_hash = compute_sha256(options.rp_id.as_bytes()).to_vec();

        let u2sd = self.token.perform_u2f_sign(
            rp_id_hash.clone(),
            client_data_json_hash,
            timeout.into(),
            options.allow_credentials.as_slice(),
            user_verification,
        )?;

        trace!("u2sd -> {:x?}", u2sd);
        // Transform the result to webauthn

        // The flags are set from the device.

        let authdata: Vec<u8> = rp_id_hash
            .iter()
            .copied()
            .chain(iter::once(u2sd.user_present))
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
                client_data_json: Base64UrlSafeData(client_data_json.as_bytes().to_vec()),
                signature: Base64UrlSafeData(u2sd.signature),
                user_handle: None,
            },
            extensions: None,
            type_: "public-key".to_string(),
        })
    }
}

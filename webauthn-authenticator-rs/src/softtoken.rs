#[cfg(doc)]
use crate::stubs::*;

use crate::{
    authenticator_hashed::AuthenticatorBackendHashedClientData,
    crypto::{compute_sha256, get_group},
    ctap2::commands::{value_to_vec_u8, GetInfoResponse},
    error::WebauthnCError,
    BASE64_ENGINE,
};
use base64::Engine;
use openssl::x509::{
    extension::{AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectKeyIdentifier},
    X509NameBuilder, X509Ref, X509ReqBuilder, X509,
};
use openssl::{asn1, bn, ec, hash, pkey, rand, sign};
use serde::{Deserialize, Serialize};
use serde_cbor_2::value::Value;
use std::collections::HashMap;
use std::iter;
use std::{collections::BTreeMap, fs::File, io::Read};
use std::{
    collections::BTreeSet,
    io::{Seek, Write},
};
use uuid::Uuid;

use base64urlsafedata::Base64UrlSafeData;

use webauthn_rs_proto::{
    AllowCredentials, AuthenticationExtensionsClientOutputs, AuthenticatorAssertionResponseRaw,
    AuthenticatorAttachment, AuthenticatorAttestationResponseRaw, AuthenticatorTransport,
    PublicKeyCredential, PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions,
    RegisterPublicKeyCredential, RegistrationExtensionsClientOutputs, UserVerificationPolicy,
};

pub const AAGUID: Uuid = uuid::uuid!("0fb9bcbc-a0d4-4042-bbb0-559bc1631e28");

#[derive(Serialize, Deserialize)]
pub struct SoftToken {
    #[serde(with = "PKeyPrivateDef")]
    _ca_key: pkey::PKey<pkey::Private>,
    #[serde(with = "X509Def")]
    ca_cert: X509,
    #[serde(with = "PKeyPrivateDef")]
    intermediate_key: pkey::PKey<pkey::Private>,
    #[serde(with = "X509Def")]
    intermediate_cert: X509,
    tokens: HashMap<Vec<u8>, Vec<u8>>,
    counter: u32,
    falsify_uv: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "pkey::PKey<pkey::Private>")]
struct PKeyPrivateDef {
    #[serde(getter = "private_key_to_der")]
    der: Value,
}

fn private_key_to_der(k: &pkey::PKeyRef<pkey::Private>) -> Value {
    Value::Bytes(
        k.private_key_to_der()
            .expect("Cannot convert private key to DER"),
    )
}

impl From<PKeyPrivateDef> for pkey::PKey<pkey::Private> {
    fn from(def: PKeyPrivateDef) -> Self {
        let b = value_to_vec_u8(def.der, "der").expect("Cannot deserialise private key");
        Self::private_key_from_der(&b).expect("Cannot read private key as DER")
    }
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "X509")]
struct X509Def {
    #[serde(getter = "x509_to_der")]
    der: Value,
}

fn x509_to_der(k: &X509Ref) -> Value {
    Value::Bytes(k.to_der().expect("Cannot convert certificate to DER"))
}

impl From<X509Def> for X509 {
    fn from(def: X509Def) -> Self {
        let b = value_to_vec_u8(def.der, "der").expect("Cannot deserialise certificate");
        Self::from_der(&b).expect("Cannot read certificate as DER")
    }
}

fn build_ca(unique_id: Uuid) -> Result<(pkey::PKey<pkey::Private>, X509), WebauthnCError> {
    let ecgroup = get_group()?;
    let eckey = ec::EcKey::generate(&ecgroup)?;
    let ca_key = pkey::PKey::from_ec_key(eckey)?;
    let mut x509_name = X509NameBuilder::new()?;

    x509_name.append_entry_by_text("C", "AU")?;
    x509_name.append_entry_by_text("ST", "QLD")?;
    x509_name.append_entry_by_text("O", "Webauthn Authenticator RS")?;
    // we have to insert a unique ID here so that the subject name is unique to allow verification
    // with a ca-store to work correctly.
    x509_name.append_entry_by_text("CN", format!("Dynamic Softtoken CA {}", unique_id).as_str())?;
    let x509_name = x509_name.build();

    let mut cert_builder = X509::builder()?;
    // Yes, 2 actually means 3 here ...
    cert_builder.set_version(2)?;

    let serial_number = bn::BigNum::from_u32(1).and_then(|serial| serial.to_asn1_integer())?;

    cert_builder.set_serial_number(&serial_number)?;
    cert_builder.set_subject_name(&x509_name)?;
    cert_builder.set_issuer_name(&x509_name)?;

    let not_before = asn1::Asn1Time::days_from_now(0)?;
    cert_builder.set_not_before(&not_before)?;
    let not_after = asn1::Asn1Time::days_from_now(1)?;
    cert_builder.set_not_after(&not_after)?;

    cert_builder.append_extension(BasicConstraints::new().critical().ca().build()?)?;
    cert_builder.append_extension(
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()?,
    )?;

    let subject_key_identifier =
        SubjectKeyIdentifier::new().build(&cert_builder.x509v3_context(None, None))?;
    cert_builder.append_extension(subject_key_identifier)?;

    cert_builder.set_pubkey(&ca_key)?;

    cert_builder.sign(&ca_key, hash::MessageDigest::sha256())?;
    let ca_cert = cert_builder.build();

    Ok((ca_key, ca_cert))
}

fn build_intermediate(
    ca_key: &pkey::PKeyRef<pkey::Private>,
    ca_cert: &X509Ref,
) -> Result<(pkey::PKey<pkey::Private>, X509), WebauthnCError> {
    let ecgroup = get_group()?;
    let eckey = ec::EcKey::generate(&ecgroup)?;
    let int_key = pkey::PKey::from_ec_key(eckey)?;

    //
    let mut req_builder = X509ReqBuilder::new()?;
    req_builder.set_pubkey(&int_key)?;

    let mut x509_name = X509NameBuilder::new()?;
    x509_name.append_entry_by_text("C", "AU")?;
    x509_name.append_entry_by_text("ST", "QLD")?;
    x509_name.append_entry_by_text("O", "Webauthn Authenticator RS")?;
    x509_name.append_entry_by_text("CN", "Dynamic Softtoken Leaf Certificate")?;
    // Requirement of packed attestation.
    x509_name.append_entry_by_text("OU", "Authenticator Attestation")?;
    let x509_name = x509_name.build();

    req_builder.set_subject_name(&x509_name)?;
    req_builder.sign(&int_key, hash::MessageDigest::sha256())?;
    let req = req_builder.build();
    // ==

    let mut cert_builder = X509::builder()?;
    // Yes, 2 actually means 3 here ...
    cert_builder.set_version(2)?;
    let serial_number = bn::BigNum::from_u32(2).and_then(|serial| serial.to_asn1_integer())?;

    cert_builder.set_pubkey(&int_key)?;

    cert_builder.set_serial_number(&serial_number)?;
    cert_builder.set_subject_name(req.subject_name())?;
    cert_builder.set_issuer_name(ca_cert.subject_name())?;

    let not_before = asn1::Asn1Time::days_from_now(0)?;
    cert_builder.set_not_before(&not_before)?;
    let not_after = asn1::Asn1Time::days_from_now(1)?;
    cert_builder.set_not_after(&not_after)?;

    cert_builder.append_extension(BasicConstraints::new().build()?)?;

    cert_builder.append_extension(
        KeyUsage::new()
            .critical()
            .non_repudiation()
            .digital_signature()
            .key_encipherment()
            .build()?,
    )?;

    let subject_key_identifier =
        SubjectKeyIdentifier::new().build(&cert_builder.x509v3_context(Some(ca_cert), None))?;
    cert_builder.append_extension(subject_key_identifier)?;

    let auth_key_identifier = AuthorityKeyIdentifier::new()
        .keyid(false)
        .issuer(false)
        .build(&cert_builder.x509v3_context(Some(ca_cert), None))?;
    cert_builder.append_extension(auth_key_identifier)?;

    /*
    let subject_alt_name = SubjectAlternativeName::new()
        .dns("*.example.com")
        .dns("hello.com")
        .build(&cert_builder.x509v3_context(Some(ca_cert), None))?;
    cert_builder.append_extension(subject_alt_name)?;
    */

    cert_builder.sign(ca_key, hash::MessageDigest::sha256())?;
    let int_cert = cert_builder.build();

    Ok((int_key, int_cert))
}

impl SoftToken {
    pub fn new(falsify_uv: bool) -> Result<(Self, X509), WebauthnCError> {
        let ca_uuid = Uuid::new_v4();

        let (ca_key, ca_cert) = build_ca(ca_uuid)?;

        let ca = ca_cert.clone();
        /*
        // Disabled as older openssl versions can't provide this.
        trace!(
            "{}",
            String::from_utf8_lossy(&ca.to_text().map_err(|e| {
                error!("OpenSSL Error -> {:?}", e);
                WebauthnCError::OpenSSL
            })?)
        );
        */

        let (intermediate_key, intermediate_cert) = build_intermediate(&ca_key, &ca_cert)?;

        /*
        // Disabled as older openssl versions can't provide this.
        trace!(
            "{}",
            String::from_utf8_lossy(&intermediate_cert.to_text().map_err(|e| {
                error!("OpenSSL Error -> {:?}", e);
                WebauthnCError::OpenSSL
            })?)
        );
        */

        Ok((
            SoftToken {
                // We could consider throwing these away?
                _ca_key: ca_key,
                ca_cert,
                intermediate_key,
                intermediate_cert,
                tokens: HashMap::new(),
                counter: 0,
                falsify_uv,
            },
            ca,
        ))
    }

    pub fn get_info(&self) -> GetInfoResponse {
        GetInfoResponse {
            versions: BTreeSet::from(["FIDO_2_0".to_string()]),
            aaguid: Some(AAGUID),
            transports: Some(vec!["internal".to_string()]),
            ..Default::default()
        }
    }

    pub fn to_cbor(&self) -> Result<Vec<u8>, WebauthnCError> {
        serde_cbor_2::ser::to_vec(self).map_err(|e| {
            error!("SoftToken.to_cbor: {:?}", e);
            WebauthnCError::Cbor
        })
    }

    pub fn from_cbor(v: &[u8]) -> Result<Self, WebauthnCError> {
        serde_cbor_2::from_slice(v).map_err(|e| {
            error!("SoftToken::from_cbor: {:?}", e);
            WebauthnCError::Cbor
        })
    }
}

#[derive(Debug)]
pub struct U2FSignData {
    key_handle: Vec<u8>,
    counter: u32,
    signature: Vec<u8>,
    flags: u8,
}

impl AuthenticatorBackendHashedClientData for SoftToken {
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
            // These will be supported in future :)
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
        let khlen_be_bytes = key_handle_len.to_be_bytes();
        let acd_iter = AAGUID
            .as_bytes()
            .iter()
            .chain(khlen_be_bytes.iter())
            .copied()
            .chain(key_handle.iter().copied())
            .chain(pk_cbor_bytes.iter().copied());

        // set counter to 0 during create
        // Combine rp_id_hash, flags, counter, acd, into authenticator data.
        // The flags are always att present, user verified, user present
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

        // Now setup to sign.
        // NOTE: for the token version we use the intermediate!
        let mut signer = sign::Signer::new(hash::MessageDigest::sha256(), &self.intermediate_key)?;

        // Do the signature
        let signature = signer
            .update(verification_data.as_slice())
            .and_then(|_| signer.sign_to_vec())?;

        let mut attest_map = BTreeMap::new();

        attest_map.insert(
            Value::Text("fmt".to_string()),
            Value::Text("packed".to_string()),
        );
        let mut att_stmt_map = BTreeMap::new();
        att_stmt_map.insert(Value::Text("alg".to_string()), Value::Integer(-7));

        let x509_bytes = Value::Bytes(self.intermediate_cert.to_der()?);

        att_stmt_map.insert(
            Value::Text("x5c".to_string()),
            Value::Array(vec![x509_bytes]),
        );
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

        let rego = RegisterPublicKeyCredential {
            id: BASE64_ENGINE.encode(&key_handle),
            raw_id: key_handle.into(),
            response: AuthenticatorAttestationResponseRaw {
                attestation_object: ao_bytes.into(),
                client_data_json: Base64UrlSafeData::new(),
                transports: Some(vec![AuthenticatorTransport::Internal]),
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
            user_verification && self.falsify_uv,
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

        Ok(PublicKeyCredential {
            id: BASE64_ENGINE.encode(&u2sd.key_handle),
            raw_id: u2sd.key_handle.into(),
            response: AuthenticatorAssertionResponseRaw {
                authenticator_data: authdata.into(),
                client_data_json: Base64UrlSafeData::new(),
                signature: u2sd.signature.into(),
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

impl U2FToken for SoftToken {
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
                    .get(ac.id.as_ref())
                    .map(|v| (ac.id.clone().into(), v.clone()))
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

        trace!("Signing: {:?}", verification_data.as_slice());
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

/// [SoftToken] which is read form, and automatically saved to a [File] when
/// dropped.
///
/// ## Warning
///
/// **[SoftTokenFile] is intended for testing purposes only, and is not intended
/// for production or long-term usage.**
///
/// [SoftTokenFile] stores private key material insecurely with no protection
/// of any kind. Its serialisation format is subject to change in the future
/// *without warning*, which may prevent loading or saving [SoftTokenFile]s
/// created with other versions of this code.
pub struct SoftTokenFile {
    token: SoftToken,
    file: File,
}

impl SoftTokenFile {
    /// Creates a new [SoftTokenFile] which will be saved when dropped.
    pub fn new(token: SoftToken, file: File) -> Self {
        Self { token, file }
    }

    /// Reads a [SoftToken] from a [File].
    pub fn open(mut file: File) -> Result<Self, WebauthnCError> {
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;

        let token: SoftToken = serde_cbor_2::from_slice(&buf).map_err(|e| {
            error!("Error reading SoftToken: {:?}", e);
            WebauthnCError::Cbor
        })?;

        Ok(Self { token, file })
    }

    /// Saves the [SoftToken] to a [File].
    fn save(&mut self) -> Result<(), WebauthnCError> {
        trace!("Saving SoftToken to {:?}", self.file);
        let d = self.token.to_cbor()?;
        self.file.set_len(0)?;
        self.file.rewind()?;
        self.file.write_all(&d)?;
        self.file.flush()?;
        Ok(())
    }
}

/// Extracts the [File] handle from this [SoftTokenFile], dropping (and saving)
/// the [SoftTokenFile] in the process.
impl TryFrom<SoftTokenFile> for File {
    type Error = WebauthnCError;
    fn try_from(value: SoftTokenFile) -> Result<Self, Self::Error> {
        Ok(value.file.try_clone()?)
    }
}

impl AsRef<SoftToken> for SoftTokenFile {
    fn as_ref(&self) -> &SoftToken {
        &self.token
    }
}

/// Drops the [SoftTokenFile], automatically saving it to disk.
impl Drop for SoftTokenFile {
    fn drop(&mut self) {
        self.save().unwrap_or_else(|e| {
            error!("Error saving SoftToken: {:?}", e);
        });
    }
}

impl AuthenticatorBackendHashedClientData for SoftTokenFile {
    fn perform_register(
        &mut self,
        client_data_hash: Vec<u8>,
        options: PublicKeyCredentialCreationOptions,
        timeout_ms: u32,
    ) -> Result<RegisterPublicKeyCredential, WebauthnCError> {
        self.token
            .perform_register(client_data_hash, options, timeout_ms)
    }

    fn perform_auth(
        &mut self,
        client_data_hash: Vec<u8>,
        options: PublicKeyCredentialRequestOptions,
        timeout_ms: u32,
    ) -> Result<PublicKeyCredential, WebauthnCError> {
        self.token
            .perform_auth(client_data_hash, options, timeout_ms)
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use openssl::{hash::MessageDigest, rand::rand_bytes, sign::Verifier, x509::X509};
    use std::time::Duration;
    use tempfile::tempfile;
    use webauthn_rs_core::{
        proto::{AttestationCaList, AttestationCaListBuilder, COSEKey},
        WebauthnCore as Webauthn,
    };
    use webauthn_rs_proto::{
        AllowCredentials, AttestationConveyancePreference, COSEAlgorithm, PubKeyCredParams,
        RelyingParty, User, UserVerificationPolicy,
    };

    use crate::{
        ctap2::{
            commands::{
                value_to_vec_u8, GetAssertionRequest, GetAssertionResponse, MakeCredentialRequest,
                MakeCredentialResponse,
            },
            CBORResponse,
        },
        perform_auth_with_request, perform_register_with_request,
        prelude::{Url, WebauthnAuthenticator},
        softtoken::SoftToken,
    };

    const AUTHENTICATOR_TIMEOUT: Duration = Duration::from_secs(60);

    #[test]
    fn webauthn_authenticator_wan_softtoken_direct_attest() {
        let _ = tracing_subscriber::fmt::try_init();
        let wan = Webauthn::new_unsafe_experts_only(
            "https://localhost:8080/auth",
            "localhost",
            vec![url::Url::parse("https://localhost:8080").unwrap()],
            AUTHENTICATOR_TIMEOUT,
            None,
            None,
        );

        let (soft_token, ca_root) = SoftToken::new(true).unwrap();

        let mut wa = WebauthnAuthenticator::new(soft_token);

        let unique_id = [
            158, 170, 228, 89, 68, 28, 73, 194, 134, 19, 227, 153, 107, 220, 150, 238,
        ];
        let name = "william";

        let builder = wan
            .new_challenge_register_builder(&unique_id, name, name)
            .unwrap()
            .attestation(AttestationConveyancePreference::Direct)
            .user_verification_policy(UserVerificationPolicy::Preferred);

        let (chal, reg_state) = wan.generate_challenge_register(builder).unwrap();

        info!("🍿 challenge -> {:x?}", chal);

        let r = wa
            .do_registration(Url::parse("https://localhost:8080").unwrap(), chal)
            .map_err(|e| {
                error!("Error -> {:x?}", e);
                e
            })
            .expect("Failed to register");

        let mut att_ca_builder = AttestationCaListBuilder::new();
        att_ca_builder
            .insert_device_x509(ca_root, AAGUID, "softtoken".to_string(), Default::default())
            .expect("Failed to build att ca list");
        let att_ca_list: AttestationCaList = att_ca_builder.build();

        let cred = wan
            .register_credential(&r, &reg_state, Some(&att_ca_list))
            .unwrap();

        info!("Credential -> {:?}", cred);

        let (chal, auth_state) = wan
            .new_challenge_authenticate_builder(vec![cred], None)
            .and_then(|b| wan.generate_challenge_authenticate(b))
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

    #[test]
    fn softtoken_persistence() {
        let _ = tracing_subscriber::fmt::try_init();
        let wan = Webauthn::new_unsafe_experts_only(
            "https://localhost:8080/auth",
            "localhost",
            vec![url::Url::parse("https://localhost:8080").unwrap()],
            AUTHENTICATOR_TIMEOUT,
            None,
            None,
        );

        let (soft_token, ca_root) = SoftToken::new(true).unwrap();
        let file = tempfile().unwrap();
        let soft_token = SoftTokenFile::new(soft_token, file);
        assert_eq!(soft_token.token.tokens.len(), 0);

        let mut wa = WebauthnAuthenticator::new(soft_token);

        let unique_id = [
            158, 170, 228, 89, 68, 28, 73, 194, 134, 19, 227, 153, 107, 220, 150, 238,
        ];
        let name = "william";

        let builder = wan
            .new_challenge_register_builder(&unique_id, name, name)
            .unwrap()
            .attestation(AttestationConveyancePreference::Direct)
            .user_verification_policy(UserVerificationPolicy::Preferred);

        let (chal, reg_state) = wan.generate_challenge_register(builder).unwrap();

        info!("🍿 challenge -> {:x?}", chal);

        let r = wa
            .do_registration(Url::parse("https://localhost:8080").unwrap(), chal)
            .map_err(|e| {
                error!("Error -> {:x?}", e);
                e
            })
            .expect("Failed to register");

        let mut att_ca_builder = AttestationCaListBuilder::new();
        att_ca_builder
            .insert_device_x509(ca_root, AAGUID, "softtoken".to_string(), Default::default())
            .expect("Failed to build att ca list");
        let att_ca_list: AttestationCaList = att_ca_builder.build();

        let cred = wan
            .register_credential(&r, &reg_state, Some(&att_ca_list))
            .unwrap();

        info!("Credential -> {:?}", cred);

        assert_eq!(wa.backend.token.tokens.len(), 1);

        // Save the credential to disk
        let mut file: File = wa.backend.try_into().unwrap();
        assert!(file.stream_position().unwrap() > 0);

        // Rewind and reload
        file.rewind().unwrap();

        let soft_token = SoftTokenFile::open(file).unwrap();
        assert_eq!(soft_token.token.tokens.len(), 1);

        let mut wa = WebauthnAuthenticator::new(soft_token);

        let (chal, auth_state) = wan
            .new_challenge_authenticate_builder(vec![cred], None)
            .and_then(|b| wan.generate_challenge_authenticate(b))
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

    #[test]
    fn perform_register_auth_with_command() {
        let _ = tracing_subscriber::fmt::try_init();
        let (mut soft_token, _) = SoftToken::new(true).unwrap();
        let mut client_data_hash = vec![0; 32];
        let mut user_id = vec![0; 16];
        rand_bytes(&mut client_data_hash).unwrap();
        rand_bytes(&mut user_id).unwrap();

        let request = MakeCredentialRequest {
            client_data_hash: client_data_hash.clone(),
            rp: RelyingParty {
                name: "example.com".to_string(),
                id: "example.com".to_string(),
            },
            user: User {
                id: Base64UrlSafeData::from(user_id),
                name: "sampleuser".to_string(),
                display_name: "Sample User".to_string(),
            },
            pub_key_cred_params: vec![
                PubKeyCredParams {
                    type_: "public-key".to_string(),
                    alg: -7,
                },
                PubKeyCredParams {
                    type_: "public-key".to_string(),
                    alg: -257,
                },
            ],
            exclude_list: vec![],
            options: None,
            pin_uv_auth_param: None,
            pin_uv_auth_proto: None,
            enterprise_attest: None,
        };

        let response = perform_register_with_request(&mut soft_token, request, 10000).unwrap();

        // All keys should be ints
        let m: Value = serde_cbor_2::from_slice(response.as_slice()).unwrap();
        let m = if let Value::Map(m) = m {
            m
        } else {
            panic!("unexpected type")
        };
        assert!(m.keys().all(|k| matches!(k, Value::Integer(_))));

        // Try to deserialise the MakeCredentialResponse again
        let response =
            <MakeCredentialResponse as CBORResponse>::try_from(response.as_slice()).unwrap();
        trace!(?response);

        // Run packed attestation verification
        // https://www.w3.org/TR/webauthn-2/#sctn-packed-attestation
        let mut att_stmt = if let Value::Map(m) = response.att_stmt.unwrap() {
            m
        } else {
            panic!("unexpected type");
        };
        trace!(?att_stmt);
        let signature = value_to_vec_u8(
            att_stmt.remove(&Value::Text("sig".to_string())).unwrap(),
            "att_stmt.sig",
        )
        .unwrap();

        // Extract attestation certificate
        let x5c = if let Value::Array(v) = att_stmt.remove(&Value::Text("x5c".to_string())).unwrap()
        {
            v
        } else {
            panic!("Unexpected type");
        };
        let x5c = value_to_vec_u8(x5c[0].to_owned(), "x5c[0]").unwrap();
        let verification_cert = X509::from_der(&x5c).unwrap();
        let pubkey = verification_cert.public_key().unwrap();

        // Reconstruct verification data (auth_data + client_data_hash)
        let mut verification_data =
            value_to_vec_u8(response.auth_data.unwrap(), "verification_data").unwrap();
        let auth_data_len = verification_data.len();
        verification_data.reserve(client_data_hash.len());
        verification_data.extend_from_slice(&client_data_hash);

        let mut verifier = Verifier::new(MessageDigest::sha256(), &pubkey).unwrap();
        assert!(verifier
            .verify_oneshot(&signature, &verification_data)
            .unwrap());

        // https://www.w3.org/TR/webauthn-2/#attestation-object
        let cred_id_off = /* rp_id_hash */ 32 + /* flags */ 1 + /* counter */ 4 + /* aaguid */ 16;
        let cred_id_len = u16::from_be_bytes(
            (&verification_data[cred_id_off..cred_id_off + 2])
                .try_into()
                .unwrap(),
        ) as usize;
        let cred_id = Base64UrlSafeData::from(
            (verification_data[cred_id_off + 2..cred_id_off + 2 + cred_id_len]).to_vec(),
        );

        // Future assertions are signed with this COSEKey
        let cose_key: Value = serde_cbor_2::from_slice(
            &verification_data[cred_id_off + 2 + cred_id_len..auth_data_len],
        )
        .unwrap();
        let cose_key = COSEKey::try_from(&cose_key).unwrap();

        rand_bytes(&mut client_data_hash).unwrap();
        let request = GetAssertionRequest {
            client_data_hash: client_data_hash.clone(),
            rp_id: "example.com".to_string(),
            allow_list: vec![AllowCredentials {
                type_: "public-key".to_string(),
                id: cred_id.to_owned(),
                transports: None,
            }],
            options: None,
            pin_uv_auth_param: None,
            pin_uv_auth_proto: None,
        };
        trace!(?request);

        let response = perform_auth_with_request(&mut soft_token, request, 10000).unwrap();
        let response =
            <GetAssertionResponse as CBORResponse>::try_from(response.as_slice()).unwrap();
        trace!(?response);

        // Check correct matching credential
        assert_eq!(response.credential.unwrap().id, cred_id);

        // Check the signature
        let signature = response.signature.unwrap();
        let mut verification_data = response.auth_data.unwrap();
        verification_data.reserve(client_data_hash.len());
        verification_data.extend_from_slice(&client_data_hash);

        assert!(cose_key
            .verify_signature(&signature, &verification_data)
            .unwrap());
    }
}

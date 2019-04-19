extern crate base64;
#[macro_use]
extern crate serde_derive;
extern crate byteorder;
extern crate openssl;

mod attestation;
pub mod constants;
mod crypto;
pub mod error;
pub mod proto;

use std::collections::BTreeMap;
use std::convert::TryFrom;

use attestation::*;
use constants::*;
use crypto::{compute_sha256, COSEContentType};
use error::*;
use proto::*;
use rand::prelude::*;

type UserId = String;

#[derive(Clone)]
pub struct Challenge(Vec<u8>);

impl std::fmt::Debug for Challenge {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}",
            base64::encode_mode(&self.0, base64::Base64Mode::Standard)
        )
    }
}

impl std::fmt::Display for Challenge {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}",
            base64::encode_mode(&self.0, base64::Base64Mode::Standard)
        )
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Credential {
    // What do we actually need to store here?
    // I think we need the credId, the COSEKey
    pub cred_id: CredentialID,
    pub cred: crypto::COSEKey,
}

impl Credential {
    fn new(acd: &AttestedCredentialData, ck: crypto::COSEKey) -> Self {
        Credential {
            cred_id: acd.credential_id.clone(),
            cred: ck,
        }
    }
}

impl PartialEq<Credential> for Credential {
    fn eq(&self, c: &Credential) -> bool {
        self.cred_id == c.cred_id
    }
}

// We have to remember the challenges we issued, so keep a reference ...
#[derive(Debug)]
pub struct Webauthn<T> {
    rng: StdRng,
    config: T,
    pkcp: Vec<PubKeyCredParams>,
    rp_id_hash: Vec<u8>,
}

impl<T> Webauthn<T> {
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
        // println!("rp_id: {:?}", config.get_relying_party_id());
        let rp_id_hash = compute_sha256(config.get_relying_party_id().as_bytes());
        Webauthn {
            // rng: config.get_rng(),
            // We use stdrng because unlike thread_rng, it's a csprng, which given
            // this is a cryptographic operation, we kind of want!
            rng: StdRng::from_entropy(),
            config: config,
            pkcp: pkcp,
            rp_id_hash: rp_id_hash,
        }
    }

    fn generate_challenge(&mut self) -> Challenge {
        Challenge((0..CHALLENGE_SIZE_BYTES).map(|_| self.rng.gen()).collect())
    }

    fn generate_challenge_response(
        &mut self,
        username: &UserId,
        chal: &Challenge,
    ) -> CreationChallengeResponse
    where
        T: WebauthnConfig,
    {
        // println!("Challenge for {} -> {:?}", username, chal);
        CreationChallengeResponse::new(
            self.config.get_relying_party_name(),
            username.clone(),
            username.clone(),
            username.clone(),
            chal.to_string(),
            self.pkcp.clone(),
            self.config.get_authenticator_timeout(),
        )
        // Now, do we persist the challenge here for tests so we can
        // byyass the RNG parts?
        // Or do we do it in the challenge_register, and have the test
        // just pass in the challenge to the verify so that tests
        // don't need a config at all?
    }

    pub fn generate_challenge_register(&mut self, username: UserId) -> CreationChallengeResponse
    where
        T: WebauthnConfig,
    {
        let chal = self.generate_challenge();
        let c = self.generate_challenge_response(&username, &chal);

        self.config.persist_challenge(username, chal);
        c
    }

    // From the rfc https://w3c.github.io/webauthn/#registering-a-new-credential
    pub fn register_credential(
        &mut self,
        reg: RegisterResponse,
        username: UserId,
    ) -> Result<(), WebauthnError>
    where
        T: WebauthnConfig,
    {
        // get the challenge (it's username associated)
        let chal = self
            .config
            .retrieve_challenge(&username)
            .ok_or(WebauthnError::ChallengeNotFound)?;
        // send to register_credential_internal
        let credential = self.register_credential_internal(reg, chal)?;

        // Check that the credentialId is not yet registered to any other user. If registration is requested for a credential that is already registered to a different user, the Relying Party SHOULD fail this registration ceremony, or it MAY decide to accept the registration, e.g. while deleting the older registration.

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
        reg: RegisterResponse,
        chal: Challenge,
    ) -> Result<Credential, WebauthnError>
    where
        T: WebauthnConfig,
    {
        // println!("reg: {:?}", reg);

        // Let JSONtext be the result of running UTF-8 decode on the value of response.clientDataJSON.
        //  ^-- this is done in the actix extractors.

        // Let C, the client data claimed as collected during the credential creation, be the result of running an implementation-specific JSON parser on JSONtext.
        //
        // Now, we actually do a much larger conversion in one shot
        // here, where we get the AuthenticatorAttestationResponse

        let data = AuthenticatorAttestationResponse::try_from(&reg.response)?;

        // println!("data: {:?}", data);

        // Verify that the value of C.type is webauthn.create.
        if data.client_data_json.type_ != "webauthn.create" {
            return Err(WebauthnError::InvalidClientDataType);
        }

        // Verify that the value of C.challenge matches the challenge that was sent to the authenticator in the create() call.
        // First, we have to decode the challenge to vec?
        /*
        let decoded_challenge =
            base64::decode_mode(&client_data.challenge, base64::Base64Mode::Standard)
                .or(base64::decode_mode(
                    &client_data.challenge,
                    base64::Base64Mode::UrlSafe,
                ))
                .map_err(|e| WebauthnError::ParseBase64Failure(e))?;
        */

        // println!("decoded_challenge {:?}", decoded_challenge);

        if data.client_data_json.challenge != chal.0 {
            return Err(WebauthnError::MismatchedChallenge);
        }

        // Verify that the value of C.origin matches the Relying Party's origin.
        if &data.client_data_json.origin != self.config.get_origin() {
            return Err(WebauthnError::InvalidRPOrigin);
        }

        // Verify that the value of C.tokenBinding.status matches the state of Token Binding for the TLS connection over which the assertion was obtained. If Token Binding was used on that TLS connection, also verify that C.tokenBinding.id matches the base64url encoding of the Token Binding ID for the connection.
        //
        //  This could be reasonably complex to do, given that we could be behind a load balancer
        // or we may not directly know the status of TLS inside this api. I'm open to creative
        // suggestions on this topic!
        //

        // 7. Compute the hash of response.clientDataJSON using SHA-256.
        //    This will be used in step 14.
        // First you have to decode this from base64!!! The spec is UNCLEAR about this fact
        /*
        let client_data_raw =
            base64::decode_mode(&reg.response.clientDataJSON, base64::Base64Mode::Standard)
                .or(base64::decode_mode(
                    &reg.response.clientDataJSON,
                    base64::Base64Mode::UrlSafe,
                ))
                .map_err(|e| WebauthnError::ParseBase64Failure(e))?;
        */
        let client_data_json_hash = compute_sha256(data.client_data_json_bytes.as_slice());

        // println!("client_data_json_hash: {:?}", base64::encode(client_data_json_hash.as_slice()));

        // Perform CBOR decoding on the attestationObject field of the AuthenticatorAttestationResponse structure to obtain the attestation statement format fmt, the authenticator data authData, and the attestation statement attStmt.
        // let attest_data = AttestationObject::try_from(&reg.response.attestationObject)?;
        println!("{:?}", data.attestation_object);

        // Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party.
        //
        //  NOW: Remember that RP ID https://w3c.github.io/webauthn/#rp-id is NOT THE SAME as the RP name
        // it's actually derived from the RP origin.
        if data.attestation_object.authData.rp_id_hash != self.rp_id_hash {
            println!("rp_id_hash from authenitcatorData does not match our rp_id_hash");
            let a: String = base64::encode(&data.attestation_object.authData.rp_id_hash);
            let b: String = base64::encode(&self.rp_id_hash);
            println!("{:?} != {:?}", a, b);
            return Err(WebauthnError::InvalidRPIDHash);
        }

        // Verify that the User Present bit of the flags in authData is set.
        if !data.attestation_object.authData.user_present {
            return Err(WebauthnError::UserNotPresent);
        }

        // Check that signCount has not gone backwards (NOT AN RFC REQUIREMENT, THIS IS AN ADDITIONAL STEP FOR THIS IMPLEMENTATION)
        //
        //  We probably need a config.get_user_token_counter((user, tokenid)) -> counter funciton hook.

        // If user verification is required for this registration, verify that the User Verified bit of the flags in authData is set.
        if self.config.get_user_verification_required()
            && !data.attestation_object.authData.user_verified
        {
            return Err(WebauthnError::UserNotVerified);
        }

        // Verify that the values of the client extension outputs in clientExtensionResults and the authenticator extension outputs in the extensions in authData are as expected, considering the client extension input values that were given as the extensions option in the create() call. In particular, any extension identifier values in the clientExtensionResults and the extensions in authData MUST be also be present as extension identifier values in the extensions member of options, i.e., no extensions are present that were not requested. In the general case, the meaning of "are as expected" is specific to the Relying Party and which extensions are in use.

        // TODO: Today we send NO EXTENSIONS, so we'll never have a case where the extensions
        // are present! But because extensions are possible from the config we WILL need to manage
        // this situation eventually!!!
        match &data.attestation_object.authData.extensions {
            Some(ex) => {
                // We don't know how to handle client extensions yet!!!
                return Err(WebauthnError::InvalidExtensions);
            }
            None => {}
        }

        // Determine the attestation statement format by performing a USASCII case-sensitive match on fmt against the set of supported WebAuthn Attestation Statement Format Identifier values. An up-to-date list of registered WebAuthn Attestation Statement Format Identifier values is maintained in the IANA registry of the same name [WebAuthn-Registries]. ( https://tools.ietf.org/html/draft-hodges-webauthn-registries-02 )
        //
        //  https://w3c.github.io/webauthn/#packed-attestation
        //  https://w3c.github.io/webauthn/#tpm-attestation
        //  https://w3c.github.io/webauthn/#android-key-attestation
        //  https://w3c.github.io/webauthn/#android-safetynet-attestation
        //  https://w3c.github.io/webauthn/#fido-u2f-attestation
        //  https://w3c.github.io/webauthn/#none-attestation
        let attest_format = AttestationFormat::try_from(data.attestation_object.fmt.as_str())?;

        // 14. Verify that attStmt is a correct attestation statement, conveying a valid attestation signature, by using the attestation statement format fmt’s verification procedure given attStmt, authData and the hash of the serialized client data computed in step 7.

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
            ),
            _ => {
                // No other types are currently implemented
                Err(WebauthnError::AttestationNotSupported)
            }
        }?;

        // Now based on result ...

        // 15. If validation is successful, obtain a list of acceptable trust anchors (attestation root certificates or ECDAA-Issuer public keys) for that attestation type and attestation statement format fmt, from a trusted source or from policy. For example, the FIDO Metadata Service [FIDOMetadataService] provides one way to obtain such information, using the aaguid in the attestedCredentialData in authData.

        // 16: Assess the attestation trustworthiness using the outputs of the verification procedure in step 14, as follows: (SEE RFC)
        // If the attestation statement attStmt successfully verified but is not trustworthy per step 16 above, the Relying Party SHOULD fail the registration ceremony.

        let credential = match attest_result {
            // We probably should have policy to deal with this ...
            AttestationType::Uncertain(credential) => Ok(credential),
            _ => {
                // We don't know how to assert trust in this yet.
                Err(WebauthnError::AttestationTrustFailure)
            }
        }?;

        //  If the attestation statement attStmt verified successfully and is found to be trustworthy, then register the new credential with the account that was denoted in the options.user passed to create(), by associating it with the credentialId and credentialPublicKey in the attestedCredentialData in authData, as appropriate for the Relying Party's system.

        // Already returned above if trust failed.

        // So we return the credential here, and the caller persists it.
        // We turn this into  a"helper" and serialisable credential structure that
        // people can use a bit nicer.
        Ok(credential)
    }

    // https://w3c.github.io/webauthn/#verifying-assertion
    pub fn verify_credential_internal(
        &self,
        rsp: PublicKeyCredential,
        chal: Challenge,
        creds: &Vec<Credential>,
    ) -> Result<(), WebauthnError>
    where
        T: WebauthnConfig,
    {
        // If the allowCredentials option was given when this authentication ceremony was initiated, verify that credential.id identifies one of the public key credentials that were listed in allowCredentials.
        //
        // We always supply allowCredentials in this library, so we expect creds as a vec of credentials
        // that would be equivalent to what was allowed.
        println!("rsp: {:?}", rsp);

        let rawId = base64::decode_mode(&rsp.rawId, base64::Base64Mode::Standard)
            .or(base64::decode_mode(&rsp.rawId, base64::Base64Mode::UrlSafe))
            .map_err(|e| WebauthnError::ParseBase64Failure(e))?;

        // Identify the user being authenticated and verify that this user is the owner of the public
        // key credential source credentialSource identified by credential.id:
        //
        // This this requirement is ... fun. It means we have to parse *everything* above first,
        // so that we can actually get at cred.id.
        //  If the user was identified before the authentication ceremony was initiated, e.g., via a
        //  username or cookie,
        //      verify that the identified user is the owner of credentialSource. If
        //      credential.response.userHandle is present, let userHandle be its value. Verify that
        //      userHandle also maps to the same user.
        //  If the user was not identified before the authentication ceremony was initiated,
        //      verify that credential.response.userHandle is present, and that the user identified
        //      by this value is the owner of credentialSource.
        //
        // TODO: Not implemented correctly yet!

        // Using credential’s id attribute (or the corresponding rawId, if base64url encoding is
        // inappropriate for your use case), look up the corresponding credential public key.

        let cred_opt = creds.iter().fold(None, |acc, c| {
            if acc.is_none() && c.cred_id == rawId {
                Some(c.clone())
            } else {
                acc
            }
        });

        let cred = cred_opt.ok_or(WebauthnError::CredentialNotFound)?;

        // Let cData, authData and sig denote the value of credential’s response's clientDataJSON, authenticatorData, and signature respectively.
        // Let JSONtext be the result of running UTF-8 decode on the value of cData.
        let data = AuthenticatorAssertionResponse::try_from(&rsp.response)?;
        println!("data: {:?}", data);

        let c = &data.clientDataJSON;

        // Let C, the client data claimed as used for the signature, be the result of running an implementation-specific JSON parser on JSONtext.
        //     Note: C may be any implementation-specific data structure representation, as long as C’s components are referenceable, as required by this algorithm.

        // Verify that the value of C.type is the string webauthn.get.
        if c.type_ != "webauthn.get" {
            return Err(WebauthnError::InvalidClientDataType);
        }

        // Verify that the value of C.challenge matches the challenge that was sent to the authenticator in the PublicKeyCredentialRequestOptions passed to the get() call.
        if c.challenge != chal.0 {
            return Err(WebauthnError::MismatchedChallenge);
        }

        // Verify that the value of C.origin matches the Relying Party's origin.
        if &c.origin != self.config.get_origin() {
            return Err(WebauthnError::InvalidRPOrigin);
        }

        // Verify that the value of C.tokenBinding.status matches the state of Token Binding for the TLS connection over which the attestation was obtained. If Token Binding was used on that TLS connection, also verify that C.tokenBinding.id matches the base64url encoding of the Token Binding ID for the connection.

        // Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party.
        if data.authenticatorData.rp_id_hash != self.rp_id_hash {
            println!("rp_id_hash from authenitcatorData does not match our rp_id_hash");
            let a: String = base64::encode(&data.authenticatorData.rp_id_hash);
            let b: String = base64::encode(&self.rp_id_hash);
            println!("{:?} != {:?}", a, b);
            return Err(WebauthnError::InvalidRPIDHash);
        }

        // Verify that the User Present bit of the flags in authData is set.
        if !data.authenticatorData.user_present {
            return Err(WebauthnError::UserNotPresent);
        }

        // If user verification is required for this assertion, verify that the User Verified bit of the flags in authData is set.
        if self.config.get_user_verification_required() && !data.authenticatorData.user_verified {
            return Err(WebauthnError::UserNotVerified);
        }

        // Verify that the values of the client extension outputs in clientExtensionResults and the authenticator extension outputs in the extensions in authData are as expected, considering the client extension input values that were given as the extensions option in the get() call. In particular, any extension identifier values in the clientExtensionResults and the extensions in authData MUST be also be present as extension identifier values in the extensions member of options, i.e., no extensions are present that were not requested. In the general case, the meaning of "are as expected" is specific to the Relying Party and which extensions are in use.

        // Note: Since all extensions are OPTIONAL for both the client and the authenticator, the Relying Party MUST be prepared to handle cases where none or not all of the requested extensions were acted upon.
        match &data.authenticatorData.extensions {
            Some(ex) => {
                // pass
            }
            None => {}
        }

        // Let hash be the result of computing a hash over the cData using SHA-256.
        let client_data_json_hash = compute_sha256(data.clientDataJSONBytes.as_slice());

        // Using the credential public key looked up in step 3, verify that sig is a valid signature over the binary concatenation of authData and hash.
        // Note: This verification step is compatible with signatures generated by FIDO U2F authenticators. See §6.1.2 FIDO U2F Signature Format Compatibility.

        let verification_data: Vec<u8> = data
            .authenticatorDataBytes
            .iter()
            .chain(client_data_json_hash.iter())
            .map(|b| *b)
            .collect();

        let verified = cred
            .cred
            .verify_signature(&data.signature, &verification_data)?;

        println!("verified: {:?}", verified);

        // If the signature counter value authData.signCount is nonzero or the value stored in conjunction with credential’s id attribute is nonzero, then run the following sub-step:

        // If the signature counter value authData.signCount is

        // greater than the signature counter value stored in conjunction with credential’s id attribute.
        //Update the stored signature counter value, associated with credential’s id attribute, to be the value of authData.signCount.
        // less than or equal to the signature counter value stored in conjunction with credential’s id attribute.
        // This is a signal that the authenticator may be cloned, i.e. at least two copies of the credential private key may exist and are being used in parallel. Relying Parties should incorporate this information into their risk scoring. Whether the Relying Party updates the stored signature counter value in this case, or not, or fails the authentication ceremony or not, is Relying Party-specific.

        // If all the above steps are successful, continue with the authentication ceremony as appropriate. Otherwise, fail the authentication ceremony.
        unimplemented!();
    }

    pub fn verify_credential(
        &self,
        lgn: PublicKeyCredential,
        username: String,
    ) -> Result<(), WebauthnError>
    where
        T: WebauthnConfig,
    {
        // https://w3c.github.io/webauthn/#verifying-assertion
        println!("{:?}", lgn);

        // self.verify_credential_internal(cred)

        unimplemented!();
    }

    pub fn generate_challenge_login(&mut self, username: UserId) -> RequestChallengeResponse
    where
        T: WebauthnConfig,
    {
        let chal = self.generate_challenge();

        // Get the user's existing creds if any.

        let uc = self.config.retrieve_credentials(&username);

        println!("login_challenge: {:?}", uc);

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

        // Store the chal associated to the user.
        // Now put that into the correct challenge format
        let r = RequestChallengeResponse::new(
            chal.to_string(),
            self.config.get_authenticator_timeout(),
            self.config.get_relying_party_id(),
            ac,
            None,
        );
        self.config.persist_challenge(username, chal);
        r
    }
}

pub trait WebauthnConfig {
    fn get_relying_party_name(&self) -> String;

    // TODO: This should be a generic impl that produceds the following from origin
    //    https://name:port/path
    //            name  <<-- this is the rp_id
    // It should check it is https also.
    // For now, we expect people to over-ride it though ...
    fn get_relying_party_id(&self) -> String;

    fn persist_challenge(&mut self, userid: UserId, challenge: Challenge) -> Result<(), ()>;

    fn retrieve_challenge(&mut self, userid: &UserId) -> Option<Challenge>;

    fn does_exist_credential(&self, userid: &UserId, cred: &Credential) -> Result<bool, ()>;

    fn persist_credential(&mut self, userid: UserId, credential: Credential) -> Result<(), ()>;

    fn retrieve_credentials(&self, userid: &UserId) -> Option<&Vec<Credential>>;

    fn get_credential_algorithms(&self) -> Vec<COSEContentType> {
        vec![COSEContentType::ECDSA_SHA256]
    }

    fn get_authenticator_timeout(&self) -> u32 {
        AUTHENTICATOR_TIMEOUT
    }

    // Currently false, because I can't work out what is needed to get the UV bit to set ...
    fn get_user_verification_required(&self) -> bool {
        false
    }

    // This probably shouldn't be the default impl, so move it?
    fn get_origin(&self) -> &String;

    // By default do we need any?
    // TODO: Is this the right type? The standard is a bit confusing
    // in this section:
    // https://w3c.github.io/webauthn/#extensions
    fn get_extensions(&self) -> Option<JSONExtensions> {
        None
    }

    /*
    fn get_rng(&self) -> dyn rand::Rng {
        StdRng::from_entropy()
    }
    */
}

#[derive(Debug)]
pub struct WebauthnEphemeralConfig {
    chals: BTreeMap<UserId, Challenge>,
    creds: BTreeMap<UserId, Vec<Credential>>,
    rp_name: String,
    rp_id: String,
    rp_origin: String,
}

impl WebauthnConfig for WebauthnEphemeralConfig {
    fn get_relying_party_name(&self) -> String {
        self.rp_name.clone()
    }

    fn get_relying_party_id(&self) -> String {
        self.rp_id.clone()
    }

    fn persist_challenge(&mut self, userid: UserId, challenge: Challenge) -> Result<(), ()> {
        self.chals.insert(userid, challenge);
        Ok(())
    }

    fn retrieve_challenge(&mut self, userid: &UserId) -> Option<Challenge> {
        self.chals.remove(userid)
    }

    fn does_exist_credential(&self, userid: &UserId, cred: &Credential) -> Result<bool, ()> {
        match self.creds.get(userid) {
            Some(creds) => Ok(creds.contains(cred)),
            None => Ok(false),
        }
    }

    fn persist_credential(&mut self, userid: UserId, credential: Credential) -> Result<(), ()> {
        match self.creds.get_mut(&userid) {
            Some(v) => {
                v.push(credential);
            }
            None => {
                self.creds.insert(userid, vec![credential]);
            }
        };
        println!("persist_credential: {:?}", self.creds);

        Ok(())
    }

    fn retrieve_credentials(&self, userid: &UserId) -> Option<&Vec<Credential>> {
        println!("{:?}", self.creds);
        self.creds.get(userid)
    }

    fn get_origin(&self) -> &String {
        &self.rp_origin
    }
}

impl WebauthnEphemeralConfig {
    pub fn new(rp_name: &str, rp_origin: &str, rp_id: &str) -> Self {
        WebauthnEphemeralConfig {
            chals: BTreeMap::new(),
            creds: BTreeMap::new(),
            rp_name: rp_name.to_string(),
            rp_id: rp_id.to_string(),
            rp_origin: rp_origin.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::{COSEContentType, COSEEC2Key, COSEKey, COSEKeyType, ECDSACurve};
    use crate::*;

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
        let rsp_d: RegisterResponse = serde_json::from_str(rsp).unwrap();

        // Now register, providing our fake challenge.
        let result = wan.register_credential_internal(rsp_d, zero_chal);
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
        let rsp_d: RegisterResponse = serde_json::from_str(rsp).unwrap();
        let result = wan.register_credential_internal(rsp_d, chal);
        println!("{:?}", result);
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

        let mut wan = Webauthn::new(wan_c);

        // Captured authentication attempt

        let rsp = r#"
        {"id":"at-FfKGsOI21EhtCu7Vx-7t7FKkpUOyKXIkEBBD_vC-eym_AdW6Y9V8WyKxHmii11EBQEe7uFQ0bkYwb0GWmUQ","rawId":"at+FfKGsOI21EhtCu7Vx+7t7FKkpUOyKXIkEBBD/vC+eym/AdW6Y9V8WyKxHmii11EBQEe7uFQ0bkYwb0GWmUQ==","response":{"authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2MBAAAAFA==","clientDataJSON":"eyJjaGFsbGVuZ2UiOiJXZ1h6X2tUdjNXVVUxa3c4aG0tT0dvR1M0WkNIWF8zYkVxSEgyUHZWcDhNIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9","signature":"MEYCIQDmLVOqv85cdRup4Fr8Pf9zC4AWO+XKBJqa8xPwYFCCMAIhAOiExLoyes0xipmUmq0BVlqJaCKLn/MFKG9GIDsCGq/+","userHandle":null},"type":"public-key"}
        "#;
        let rsp_d: PublicKeyCredential = serde_json::from_str(rsp).unwrap();

        // Now verify it!
        let r = wan.verify_credential_internal(rsp_d, zero_chal, &vec![cred]);
        println!("RESULT: {:?}", r);
        assert!(r.is_ok());
    }
}

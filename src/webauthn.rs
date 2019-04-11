use super::proto::*;
use rand::prelude::*;
use std::collections::BTreeMap;

// Can this ever change?
const CHALLENGE_SIZE_BYTES: usize = 32;
const AUTHENTICATOR_TIMEOUT: u32 = 6000;

pub enum Algorithm {
    ALG_ECDSA_SHA256,
    ALG_RSASSA_PKCS15_SHA256,
    ALG_RSASSA_PSS_SHA256,
}

impl From<&Algorithm> for i16 {
    fn from(a: &Algorithm) -> i16 {
        match a {
            ALG_ECDSA_SHA256 => -7,
            ALG_RSASSA_PKCS15_SHA256 => -257,
            ALG_RSASSA_PSS_SHA256 => -37,
        }
    }
}

type UserId = String;

#[derive(Clone)]
struct Challenge(Vec<u8>);

impl std::fmt::Debug for Challenge {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", base64::encode(&self.0))
    }
}

impl std::fmt::Display for Challenge {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", base64::encode(&self.0))
    }
}

// We have to remember the challenges we issued, so keep a reference ...

pub struct Webauthn {
    rng: StdRng,
    chals: BTreeMap<UserId, Challenge>,
    creds: BTreeMap<UserId, Vec<CredentialID>>,
    rp: String,
    pkcp: Vec<PubKeyCredParams>,
}

impl Webauthn {
    pub fn new(rp: String, alg: Vec<Algorithm>) -> Self {
        Webauthn {
            rng: StdRng::from_entropy(),
            chals: BTreeMap::new(),
            creds: BTreeMap::new(),
            rp: rp,
            pkcp: alg
                .iter()
                .map(|a| PubKeyCredParams {
                    type_: "public-key".to_string(),
                    alg: a.into(),
                })
                .collect(),
        }
    }

    fn generate_challenge(&mut self) -> Challenge {
        Challenge(
            (0..CHALLENGE_SIZE_BYTES)
                .map(|_| self.rng.gen())
                .collect::<Vec<u8>>(),
        )
    }

    pub fn generate_challenge_register(&mut self, username: UserId) -> CreationChallengeResponse {
        let chal = self.generate_challenge();

        println!("Challenge for {} -> {:?}", username, chal);
        let c = CreationChallengeResponse::new(
            self.rp.clone(),
            username.clone(),
            username.clone(),
            username.clone(),
            chal.to_string(),
            self.pkcp.clone(),
            AUTHENTICATOR_TIMEOUT,
        );

        // Do we need any other data?
        // Ensure single challenge at a time? Other?
        self.chals.insert(username, chal);
        c
    }

    pub fn generate_challenge_login(&mut self, username: UserId) -> RequestChallengeResponse {
        let chal = self.generate_challenge();

        // Get the user's existing creds if any.

        let uc = self.creds.get(username.as_str());
        let ac = match uc {
            Some(creds) => creds
                .iter()
                .map(|cred_id| AllowCredentials {
                    type_: "public-key".to_string(),
                    id: cred_id.clone(),
                })
                .collect(),
            None => Vec::new(),
        };
        println!("Creds for {} -> {:?}", username, ac);

        unimplemented!();
    }

    // From the rfc https://w3c.github.io/webauthn/#registering-a-new-credential
    pub fn register_credential(&mut self, reg: RegisterResponse) -> Option<()> {
        println!("{:?}", reg);

        // Let JSONtext be the result of running UTF-8 decode on the value of response.clientDataJSON.
        //  ^-- this is done in the actix extractors.

        // Let C, the client data claimed as collected during the credential creation, be the result of running an implementation-specific JSON parser on JSONtext.
        let client_data = CollectedClientData::from(&reg.response.clientDataJSON);
        println!("{:?}", client_data);

        // Verify that the value of C.type is webauthn.create.

        if client_data.type_ != "webauthn.create" {
            println!("Invalid client_data type");
            return None;
        }

        // Verify that the value of C.challenge matches the challenge that was sent to the authenticator in the create() call.

        // Verify that the value of C.origin matches the Relying Party's origin.

        // Verify that the value of C.tokenBinding.status matches the state of Token Binding for the TLS connection over which the assertion was obtained. If Token Binding was used on that TLS connection, also verify that C.tokenBinding.id matches the base64url encoding of the Token Binding ID for the connection.

        // Compute the hash of response.clientDataJSON using SHA-256.

        // Perform CBOR decoding on the attestationObject field of the AuthenticatorAttestationResponse structure to obtain the attestation statement format fmt, the authenticator data authData, and the attestation statement attStmt.

        let attest_data = AttestationObject::from(&reg.response.attestationObject);
        println!("{:?}", attest_data);

        // Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party.

        // Verify that the User Present bit of the flags in authData is set.

        // Check that signCount has not gone backwards (NOT AN RFC REQUIREMENT)

        // If user verification is required for this registration, verify that the User Verified bit of the flags in authData is set.

        // Verify that the values of the client extension outputs in clientExtensionResults and the authenticator extension outputs in the extensions in authData are as expected, considering the client extension input values that were given as the extensions option in the create() call. In particular, any extension identifier values in the clientExtensionResults and the extensions in authData MUST be also be present as extension identifier values in the extensions member of options, i.e., no extensions are present that were not requested. In the general case, the meaning of "are as expected" is specific to the Relying Party and which extensions are in use.

        // Determine the attestation statement format by performing a USASCII case-sensitive match on fmt against the set of supported WebAuthn Attestation Statement Format Identifier values. An up-to-date list of registered WebAuthn Attestation Statement Format Identifier values is maintained in the IANA registry of the same name [WebAuthn-Registries].

        // Verify that attStmt is a correct attestation statement, conveying a valid attestation signature, by using the attestation statement format fmt’s verification procedure given attStmt, authData and the hash of the serialized client data computed in step 7.

        // If validation is successful, obtain a list of acceptable trust anchors (attestation root certificates or ECDAA-Issuer public keys) for that attestation type and attestation statement format fmt, from a trusted source or from policy. For example, the FIDO Metadata Service [FIDOMetadataService] provides one way to obtain such information, using the aaguid in the attestedCredentialData in authData.


        // 16: Assess the attestation trustworthiness using the outputs of the verification procedure in step 14, as follows: (SEE RFC)
        // If the attestation statement attStmt successfully verified but is not trustworthy per step 16 above, the Relying Party SHOULD fail the registration ceremony.

        // Check that the credentialId is not yet registered to any other user. If registration is requested for a credential that is already registered to a different user, the Relying Party SHOULD fail this registration ceremony, or it MAY decide to accept the registration, e.g. while deleting the older registration.

        //  If the attestation statement attStmt verified successfully and is found to be trustworthy, then register the new credential with the account that was denoted in the options.user passed to create(), by associating it with the credentialId and credentialPublicKey in the attestedCredentialData in authData, as appropriate for the Relying Party's system.

        None
    }

    pub fn verify_credential(&self, lgn: LoginRequest) -> Option<()> {
        // https://w3c.github.io/webauthn/#verifying-assertion
        println!("{:?}", lgn);

        None
    }
}

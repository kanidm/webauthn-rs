use crate::{
    cbor::*,
    error::WebauthnCError,
    transport::Token,
    util::{compute_sha256, creation_to_clientdata, get_to_clientdata},
    AuthenticatorBackend,
};

use openssl::{
    bn,
    ec::{self, EcKey},
    md::Md,
    nid,
    pkey::{PKey, Private},
    pkey_ctx::PkeyCtx,
    rand::rand_bytes,
};
use url::Url;
use webauthn_rs_core::proto::{COSEEC2Key, COSEKey, COSEKeyType, ECDSACurve};
use webauthn_rs_proto::COSEAlgorithm;

pub struct Ctap21PreAuthenticator<T: Token> {
    info: GetInfoResponse,
    token: T,
}

impl<T: Token> Ctap21PreAuthenticator<T> {
    pub fn new(info: GetInfoResponse, token: T) -> Self {
        Self { info, token }
    }
}

impl<T: Token> AuthenticatorBackend for Ctap21PreAuthenticator<T> {
    fn perform_register(
        &mut self,
        origin: Url,
        options: webauthn_rs_proto::PublicKeyCredentialCreationOptions,
        timeout_ms: u32,
    ) -> Result<webauthn_rs_proto::RegisterPublicKeyCredential, crate::prelude::WebauthnCError>
    {
        let client_data = creation_to_clientdata(origin, options.challenge.clone());
        let client_data: Vec<u8> = serde_json::to_string(&client_data)
            .map_err(|_| WebauthnCError::Json)?
            .into();
        let client_data_hash = compute_sha256(&client_data).to_vec();

        // Get pin retries
        trace!("supported pin protocols = {:?}", self.info.pin_protocols);
        if let Some(protocols) = &self.info.pin_protocols {
            for protocol in protocols {
                let p = ClientPinRequest {
                    pin_uv_protocol: Some(*protocol),
                    sub_command: ClientPinSubCommand::GetPinRetries,
                    ..Default::default()
                };

                let ret = self.token.transmit(p)?;
                trace!(?ret);
            }
        }

        // 6.5.5.4: Obtaining the shared secret
        // TODO: select protocol wisely
        let p = ClientPinRequest {
            pin_uv_protocol: Some(2),
            sub_command: ClientPinSubCommand::GetKeyAgreement,
            ..Default::default()
        };
        let ret = self.token.transmit(p)?;
        let key_agreement = ret.key_agreement.ok_or_else(|| WebauthnCError::Internal)?;
        trace!(?key_agreement);

        // The platform calls encapsulate with the public key that the authenticator
        // returned in order to generate the platform key-agreement key and the shared secret.
        let mut iface = PinUvPlatformInterfaceProtocolTwo::default();
        iface.initialize();
        let (platform_key_agreement_key, shared_secret) = iface.encapsulate(key_agreement)?;

        // Get a pin token

        // TODO: implement PINs
        // let mc = MakeCredentialRequest {
        //     client_data_hash,
        //     rp: options.rp,
        //     user: options.user,
        //     pub_key_cred_params: options.pub_key_cred_params,

        //     options: None,
        //     pin_uv_auth_param: None,
        //     pin_uv_auth_proto: None,
        //     enterprise_attest: None,
        // };

        // let ret = self.token.transmit(mc);
        // trace!(?ret);

        todo!();
    }
    fn perform_auth(
        &mut self,
        origin: Url,
        options: webauthn_rs_proto::PublicKeyCredentialRequestOptions,
        timeout_ms: u32,
    ) -> Result<webauthn_rs_proto::PublicKeyCredential, crate::prelude::WebauthnCError> {
        let clientdata = get_to_clientdata(origin, options.challenge.clone());

        todo!();
    }
}

trait PinUvPlatformInterface: Default {
    fn encrypt(&self, key: Vec<u8>, dem_plaintext: Vec<u8>) -> Vec<u8>;
    fn decrypt(
        &self,
        key: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Result</* plaintext */ Vec<u8>, WebauthnCError>;
    fn authenticate(&self, key: Vec<u8>, message: Vec<u8>) -> Vec<u8>;

    fn ecdh(&self, peer_cose_key: COSEKey) -> Result<Vec<u8>, WebauthnCError> {
        // 1. Parse peerCoseKey as specified for getPublicKey, below, and produce a P-256 point, Y.
        //    If unsuccessful, or if the resulting point is not on the curve, return error.

        // 2. Calculate xY, the shared point. (I.e. the scalar-multiplication of the peer’s point, Y,
        //    with the local private key agreement key.)
        let private_key = self.get_private_key().to_owned();
        let mut z: [u8; 32] = [0; 32];
        if let COSEKeyType::EC_EC2(ec) = peer_cose_key.key {
            ecdh(private_key, &ec, &mut z).map_err(|_| WebauthnCError::OpenSSL)?;
        } else {
            error!("Unexpected peer key type: {:?}", peer_cose_key);
            return Err(WebauthnCError::OpenSSL);
        }
        // 3. Let Z be the 32-byte, big-endian encoding of the x-coordinate of the shared point.
        // ???

        // 4. Return kdf(Z).
        Ok(self.kdf(&z))
    }

    fn encapsulate(
        &self,
        peer_cose_key: COSEKey,
    ) -> Result<(&COSEKey, /* shared_secret */ Vec<u8>), WebauthnCError> {
        // Let sharedSecret be the result of calling ecdh(peerCoseKey). Return any resulting error.
        // Return (getPublicKey(), sharedSecret)
        let shared_secret = self.ecdh(peer_cose_key)?;

        Ok((self.get_public_key(), shared_secret))
    }

    fn get_public_key(&self) -> &COSEKey;
    fn get_private_key(&self) -> &EcKey<Private>;
    fn kdf(&self, z: &[u8]) -> Vec<u8>;

    fn set_key(&mut self, public_key: COSEKey, private_key: EcKey<Private>);
    fn reset_pin_uv_auth_token(&mut self);

    fn initialize(&mut self) {
        let (public, private) = regenerate().expect("generating key");
        self.set_key(public, private);
        self.reset_pin_uv_auth_token();
    }
}

#[derive(Default)]
struct PinUvPlatformInterfaceProtocolOne {}

impl PinUvPlatformInterface for PinUvPlatformInterfaceProtocolOne {
    fn kdf(&self, z: &[u8]) -> Vec<u8> {
        // Return SHA-256(Z)
        compute_sha256(z).to_vec()
    }

    fn encrypt(&self, key: Vec<u8>, dem_plaintext: Vec<u8>) -> Vec<u8> {
        // Return the AES-256-CBC encryption of demPlaintext using an all-zero IV.
        // (No padding is performed as the size of demPlaintext is required to be a multiple of the AES block length.)
        todo!()
    }

    fn decrypt(
        &self,
        key: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Result</* plaintext */ Vec<u8>, WebauthnCError> {
        // If the size of demCiphertext is not a multiple of the AES block length, return error.
        // Otherwise return the AES-256-CBC decryption of demCiphertext using an all-zero IV.
        todo!()
    }

    fn authenticate(&self, key: Vec<u8>, message: Vec<u8>) -> Vec<u8> {
        // Return the first 16 bytes of the result of computing HMAC-SHA-256 with the given key and message.
        todo!()
    }

    fn get_public_key(&self) -> &COSEKey {
        todo!()
    }

    fn reset_pin_uv_auth_token(&mut self) {
        todo!()
    }

    fn set_key(&mut self, public_key: COSEKey, private_key: EcKey<Private>) {
        todo!()
    }

    fn get_private_key(&self) -> &EcKey<Private> {
        todo!()
    }
}

#[derive(Default)]
struct PinUvPlatformInterfaceProtocolTwo {
    pin_uv_auth_token: [u8; 32],
    public_key: Option<COSEKey>,
    private_key: Option<EcKey<Private>>,
}

impl PinUvPlatformInterface for PinUvPlatformInterfaceProtocolTwo {
    fn encrypt(&self, key: Vec<u8>, dem_plaintext: Vec<u8>) -> Vec<u8> {
        // 1. Discard the first 32 bytes of key. (This selects the AES-key portion of the shared secret.)
        let key = &key[32..];

        // 2. Let iv be a 16-byte, random bytestring.
        let mut iv: [u8; 16] = [0; 16];
        rand_bytes(&mut iv).expect("encrypt::iv");

        // 3. Let ct be the AES-256-CBC encryption of demPlaintext using key and iv. (No padding is performed as the size of demPlaintext is required to be a multiple of the AES block length.)
        let cipher = openssl::symm::Cipher::aes_256_cbc();
        let ct = openssl::symm::encrypt(cipher, key, Some(&iv), dem_plaintext.as_slice())
            .expect("oopsencrypt");

        // 4. Return iv || ct.
        let mut o = iv.to_vec();
        o.extend_from_slice(ct.as_slice());

        o
    }

    fn decrypt(
        &self,
        key: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Result</* plaintext */ Vec<u8>, WebauthnCError> {
        // 1. Discard the first 32 bytes of key. (This selects the AES-key portion of the shared secret.)
        let key = &key[..32];

        // 2. If demPlaintext is less than 16 bytes in length, return an error
        // THIS IS AN ERROR, should be demCiphertext
        if ciphertext.len() < 16 {
            error!("ciphertext too short");
            return Err(WebauthnCError::MessageTooShort);
        }
        // 3. Split demPlaintext after the 16th byte to produce two subspans, iv and ct.
        // ALSO AN ERROR, as above
        let (iv, ct) = ciphertext.split_at(16);

        // 4. Return the AES-256-CBC decryption of ct using key and iv.
        let cipher = openssl::symm::Cipher::aes_256_cbc();
        let pt = openssl::symm::decrypt(cipher, key, Some(iv), ct).expect("openssl decrypt");

        Ok(pt)
    }

    fn authenticate(&self, key: Vec<u8>, message: Vec<u8>) -> Vec<u8> {
        // 1. If key is longer than 32 bytes, discard the excess.
        //    (This selects the HMAC-key portion of the shared secret. When key is the
        //    pinUvAuthToken, it is exactly 32 bytes long and thus this step has no effect.)
        // 2. Return the result of computing HMAC-SHA-256 on key and message.

        todo!()
    }

    fn get_public_key(&self) -> &COSEKey {
        self.public_key
            .as_ref()
            .expect("public key not initialised")
    }

    fn get_private_key(&self) -> &EcKey<Private> {
        self.private_key
            .as_ref()
            .expect("private key not initialised")
    }

    fn kdf(&self, z: &[u8]) -> Vec<u8> {
        // Return
        // HKDF-SHA-256(salt = 32 zero bytes, IKM = Z, L = 32, info = "CTAP2 HMAC key") ||
        // HKDF-SHA-256(salt = 32 zero bytes, IKM = Z, L = 32, info = "CTAP2 AES key")
        // (see [RFC5869] for the definition of HKDF).
        let mut o: Vec<u8> = vec![0; 64];
        let zero: [u8; 32] = [0; 32];
        hkdf_sha_256(&zero, z, "CTAP2 HMAC key".as_bytes(), &mut o[0..32]).expect("hkdf_sha_256");
        hkdf_sha_256(&zero, z, "CTAP2 AES key".as_bytes(), &mut o[32..64]).expect("hkdf_sha_256");

        o
    }

    fn reset_pin_uv_auth_token(&mut self) {
        rand_bytes(&mut self.pin_uv_auth_token).expect("rand_bytes");
    }

    fn set_key(&mut self, public_key: COSEKey, private_key: EcKey<Private>) {
        self.public_key = Some(public_key);
        self.private_key = Some(private_key);
    }
}

fn hkdf_sha_256(
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    output: &mut [u8],
) -> Result<(), openssl::error::ErrorStack> {
    let mut ctx = PkeyCtx::new_id(openssl::pkey::Id::HKDF)?;
    ctx.derive_init()?;
    ctx.set_hkdf_md(Md::sha256())?;
    ctx.set_hkdf_salt(salt)?;
    ctx.set_hkdf_key(ikm)?;
    ctx.add_hkdf_info(info)?;
    ctx.derive(Some(output))?;
    Ok(())
}

fn ecdh(
    private_key: EcKey<Private>,
    peer_key: &COSEEC2Key,
    output: &mut [u8],
) -> Result<(), openssl::error::ErrorStack> {
    let peer_key = PKey::from_ec_key(peer_key.into())?;
    let mut pkey = PKey::from_ec_key(private_key)?;
    let mut ctx = PkeyCtx::new(&pkey)?;
    ctx.derive_init()?;
    ctx.derive_set_peer(&peer_key)?;
    ctx.derive(Some(output))?;

    Ok(())
}

fn regenerate() -> Result<(COSEKey, EcKey<Private>), openssl::error::ErrorStack> {
    // Create a new key.
    let ecgroup = ec::EcGroup::from_curve_name(nid::Nid::X9_62_PRIME256V1)?;
    let eckey = ec::EcKey::generate(&ecgroup)?;

    // Extract the public x and y coords.
    let ecpub_points = eckey.public_key();

    let mut bnctx = bn::BigNumContext::new()?;
    let mut xbn = bn::BigNum::new()?;
    let mut ybn = bn::BigNum::new()?;

    ecpub_points.affine_coordinates_gfp(&ecgroup, &mut xbn, &mut ybn, &mut bnctx)?;

    Ok((
        COSEKey {
            type_: COSEAlgorithm::PinUvProtocol,
            key: COSEKeyType::EC_EC2(COSEEC2Key {
                curve: ECDSACurve::SECP256R1,
                x: xbn.to_vec().into(),
                y: ybn.to_vec().into(),
            }),
        },
        eckey,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf() {
        let salt: Vec<u8> = (0..0x0d).collect();
        let ikm: [u8; 22] = [0x0b; 22];
        let info: Vec<u8> = (0xf0..0xfa).collect();
        let expected: [u8; 42] = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
            0x2f, 0x2a, 0x2d, 0x2d, 0xa, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
            0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x0, 0x72, 0x8, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
        ];

        let mut output: [u8; 42] = [0; 42];

        hkdf_sha_256(salt.as_slice(), &ikm, info.as_slice(), &mut output)
            .expect("hkdf_sha_256 fail");
        assert_eq!(expected, output);
    }
}

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
    sign,
    symm, hash,
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

                // let p = ClientPinRequest {
                //     pin_uv_protocol: Some(*protocol),
                //     sub_command: ClientPinSubCommand::GetUvRetries,
                //     ..Default::default()
                // };

                // let ret = self.token.transmit(p)?;
                // trace!(?ret);
            }
        }

        // TODO: get the pin
        let pin = "1234";

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
        let mut iface = PinUvPlatformInterfaceProtocolOne::default();
        iface.initialize();
        let shared_secret = iface.encapsulate(key_agreement)?;
        trace!(?shared_secret);

        todo!();

        // broken
        // 6.5.5.7.1. Getting pinUvAuthToken using getPinToken (superseded)
        let p = ClientPinRequest {
            pin_uv_protocol: Some(2),
            sub_command: ClientPinSubCommand::GetPinToken,
            key_agreement: Some(iface.get_public_key()),
            pin_hash_enc: Some(iface.encrypt(
                shared_secret.as_slice(),
                &(compute_sha256(pin.as_bytes()))[..16],
            )),
            ..Default::default()
        };

        // 6.5.5.7.2. Getting pinUvAuthToken using getPinUvAuthTokenUsingPinWithPermissions (ClientPIN)
        /*
        let p = ClientPinRequest {
            pin_uv_protocol: Some(2),
            sub_command: ClientPinSubCommand::GetPinUvAuthTokenUsingPinWithPermissions,
            key_agreement: Some(iface.get_public_key()),
            pin_hash_enc: Some(iface.encrypt(shared_secret.as_slice(), &(compute_sha256(pin.as_bytes()))[..16])),
            permissions: Permissions::MAKE_CREDENTIAL,
            // need rpId?
            ..Default::default()
        };
        */

        let ret = self.token.transmit(p)?;
        trace!(?ret);

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
    fn encrypt(&self, key: &[u8], dem_plaintext: &[u8]) -> Vec<u8>;
    fn decrypt(
        &self,
        key: &[u8],
        ciphertext: &[u8],
    ) -> Result</* plaintext */ Vec<u8>, WebauthnCError>;
    fn authenticate(&self, key: &[u8], message: &[u8]) -> Vec<u8>;

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
        trace!(?z);

        // 4. Return kdf(Z).
        Ok(self.kdf(&z))
    }

    fn encapsulate(&self, peer_cose_key: COSEKey) -> Result<Vec<u8>, WebauthnCError> {
        // Let sharedSecret be the result of calling ecdh(peerCoseKey). Return any resulting error.
        // Return (getPublicKey(), sharedSecret)
        let shared_secret = self.ecdh(peer_cose_key)?;

        Ok(shared_secret)
    }

    fn get_public_key(&self) -> COSEKey {
        let ecgroup = ec::EcGroup::from_curve_name(nid::Nid::X9_62_PRIME256V1).unwrap();
        let eckey = self.get_private_key();
        // Extract the public x and y coords.
        let ecpub_points = eckey.public_key();

        let mut bnctx = bn::BigNumContext::new().unwrap();
        let mut xbn = bn::BigNum::new().unwrap();
        let mut ybn = bn::BigNum::new().unwrap();

        ecpub_points
            .affine_coordinates_gfp(&ecgroup, &mut xbn, &mut ybn, &mut bnctx)
            .unwrap();

        COSEKey {
            type_: COSEAlgorithm::PinUvProtocol,
            key: COSEKeyType::EC_EC2(COSEEC2Key {
                curve: ECDSACurve::SECP256R1,
                x: xbn.to_vec().into(),
                y: ybn.to_vec().into(),
            }),
        }
    }

    fn get_private_key(&self) -> &EcKey<Private>;
    fn kdf(&self, z: &[u8]) -> Vec<u8>;

    fn set_private_key(&mut self, private_key: EcKey<Private>);
    fn reset_pin_uv_auth_token(&mut self);

    fn initialize(&mut self) {
        let private = regenerate().expect("generating key");
        self.set_private_key(private);
        self.reset_pin_uv_auth_token();
    }
}

#[derive(Default)]
struct PinUvPlatformInterfaceProtocolOne {
    pin_uv_auth_token: [u8; 32],
    private_key: Option<EcKey<Private>>,
}

/// Encrypts some data using AES-256-CBC, with no padding.
///
/// `plaintext.len()` must be a multiple of the cipher's blocksize.
fn encrypt(key: &[u8], iv: Option<&[u8]>, plaintext: &[u8]) -> Vec<u8> {
    let cipher = symm::Cipher::aes_256_cbc();
    let mut ct = vec![0; plaintext.len() + cipher.block_size()];
    let mut c = symm::Crypter::new(cipher, symm::Mode::Encrypt, &key, None).unwrap();
    c.pad(false);
    let l = c.update(&plaintext, &mut ct).unwrap();
    let l = l + c.finalize(&mut ct[l..]).unwrap();
    ct.truncate(l);
    ct
}

impl PinUvPlatformInterface for PinUvPlatformInterfaceProtocolOne {
    fn kdf(&self, z: &[u8]) -> Vec<u8> {
        // Return SHA-256(Z)
        compute_sha256(z).to_vec()
    }

    fn encrypt(&self, key: &[u8], dem_plaintext: &[u8]) -> Vec<u8> {
        // Return the AES-256-CBC encryption of demPlaintext using an all-zero IV.
        // (No padding is performed as the size of demPlaintext is required to be a multiple of the AES block length.)
        encrypt(key, None, dem_plaintext)
    }

    fn decrypt(
        &self,
        key: &[u8],
        ciphertext: &[u8],
    ) -> Result</* plaintext */ Vec<u8>, WebauthnCError> {
        // If the size of demCiphertext is not a multiple of the AES block length, return error.
        // Otherwise return the AES-256-CBC decryption of demCiphertext using an all-zero IV.
        todo!()
    }

    fn authenticate(&self, key: &[u8], message: &[u8]) -> Vec<u8> {
        // Return the first 16 bytes of the result of computing HMAC-SHA-256
        // with the given key and message.
        let key = PKey::hmac(&key).unwrap();
        let mut signer = sign::Signer::new(hash::MessageDigest::sha256(), &key).unwrap();
        signer.update(&message).unwrap();
        signer.sign_to_vec().unwrap()
    }

    fn reset_pin_uv_auth_token(&mut self) {}

    fn set_private_key(&mut self, private_key: EcKey<Private>) {
        self.private_key = Some(private_key)
    }

    fn get_private_key(&self) -> &EcKey<Private> {
        self.private_key
            .as_ref()
            .expect("private key not initialised")
    }
}

#[derive(Default)]
struct PinUvPlatformInterfaceProtocolTwo {
    pin_uv_auth_token: [u8; 32],
    private_key: Option<EcKey<Private>>,
}

impl PinUvPlatformInterface for PinUvPlatformInterfaceProtocolTwo {
    fn encrypt(&self, key: &[u8], dem_plaintext: &[u8]) -> Vec<u8> {
        // 1. Discard the first 32 bytes of key. (This selects the AES-key
        //    portion of the shared secret.)
        let key = &key[32..];

        // 2. Let iv be a 16-byte, random bytestring.
        let mut iv: [u8; 16] = [0; 16];
        rand_bytes(&mut iv).expect("encrypt::iv");

        // 3. Let ct be the AES-256-CBC encryption of demPlaintext using key and
        //    iv. (No padding is performed as the size of demPlaintext is
        //    required to be a multiple of the AES block length.)
        let ct = encrypt(key, Some(iv.as_slice()), dem_plaintext);

        // 4. Return iv || ct.
        let mut o = iv.to_vec();
        o.extend_from_slice(ct.as_slice());

        o
    }

    fn decrypt(
        &self,
        key: &[u8],
        ciphertext: &[u8],
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

    fn authenticate(&self, key: &[u8], message: &[u8]) -> Vec<u8> {
        // 1. If key is longer than 32 bytes, discard the excess.
        //    (This selects the HMAC-key portion of the shared secret. When key is the
        //    pinUvAuthToken, it is exactly 32 bytes long and thus this step has no effect.)
        // 2. Return the result of computing HMAC-SHA-256 on key and message.

        todo!()
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
        hkdf_sha_256(&zero, z, b"CTAP2 HMAC key", &mut o[0..32]).expect("hkdf_sha_256");
        hkdf_sha_256(&zero, z, b"CTAP2 AES key", &mut o[32..64]).expect("hkdf_sha_256");

        o
    }

    fn reset_pin_uv_auth_token(&mut self) {
        rand_bytes(&mut self.pin_uv_auth_token).expect("rand_bytes");
    }

    fn set_private_key(&mut self, private_key: EcKey<Private>) {
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
    // let mut ctx = BigNumContext::new()?;

    // let mut x = BigNum::new()?;
    // let mut y = BigNum::new()?;
    // let peer_key: EcKey<Public> = peer_key.into();
    // let peer_key_pub = peer_key.public_key();

    // let pk = private_key.private_key();
    // let group = private_key.group();

    // let mut pt = EcPoint::new(group)?;
    // pt.mul(group, peer_key_pub, pk, &ctx)?;
    // pt.affine_coordinates_gfp(group, &mut x, &mut y, &mut ctx)?;

    // let buflen = (group.degree() + 7) / 8;
    // trace!(?buflen);
    // let x = x.to_vec();
    // trace!(?x);
    //output.copy_from_slice(x.as_slice());

    // Both the low level and high level return same outputs.
    let peer_key = PKey::from_ec_key(peer_key.into())?;
    let pkey = PKey::from_ec_key(private_key)?;
    let mut ctx = PkeyCtx::new(&pkey)?;
    ctx.derive_init()?;
    ctx.derive_set_peer(&peer_key)?;
    ctx.derive(Some(output))?;
    // trace!(?output);

    Ok(())
}

fn regenerate() -> Result<EcKey<Private>, openssl::error::ErrorStack> {
    // Create a new key.
    let ecgroup = ec::EcGroup::from_curve_name(nid::Nid::X9_62_PRIME256V1)?;
    let eckey = ec::EcKey::generate(&ecgroup)?;

    Ok(eckey)
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

    #[test]
    fn test_pin_encryption_and_hashing() {
        // https://github.com/mozilla/authenticator-rs/blob/f2d255c48d3e3762a27873b270520072bf501d0e/src/crypto/mod.rs#L833
        let pin = "1234";

        let shared_secret = vec![
            0x82, 0xE3, 0xD8, 0x41, 0xE2, 0x5C, 0x5C, 0x13, 0x46, 0x2C, 0x12, 0x3C, 0xC3, 0xD3,
            0x98, 0x78, 0x65, 0xBA, 0x3D, 0x20, 0x46, 0x74, 0xFB, 0xED, 0xD4, 0x7E, 0xF5, 0xAB,
            0xAB, 0x8D, 0x13, 0x72,
        ];
        let expected_new_pin_enc = vec![
            0x70, 0x66, 0x4B, 0xB5, 0x81, 0xE2, 0x57, 0x45, 0x1A, 0x3A, 0xB9, 0x1B, 0xF1, 0xAA,
            0xD8, 0xE4, 0x5F, 0x6C, 0xE9, 0xB5, 0xC3, 0xB0, 0xF3, 0x2B, 0x5E, 0xCD, 0x62, 0xD0,
            0xBA, 0x3B, 0x60, 0x5F, 0xD9, 0x18, 0x31, 0x66, 0xF6, 0xC5, 0xFA, 0xF3, 0xE4, 0xDA,
            0x24, 0x81, 0x50, 0x2C, 0xD0, 0xCE, 0xE0, 0x15, 0x8B, 0x35, 0x1F, 0xC3, 0x92, 0x08,
            0xA7, 0x7C, 0xB2, 0x74, 0x4B, 0xD4, 0x3C, 0xF9,
        ];
        let expected_pin_auth = vec![
            0x8E, 0x7F, 0x01, 0x69, 0x97, 0xF3, 0xB0, 0xA2, 0x7B, 0xA4, 0x34, 0x7A, 0x0E, 0x49,
            0xFD, 0xF5,
        ];

        // Padding to 64 bytes
        let input: Vec<u8> = pin
            .as_bytes()
            .iter()
            .chain(std::iter::repeat(&0x00))
            .take(64)
            .cloned()
            .collect();

        let mut t = PinUvPlatformInterfaceProtocolOne::default();
        t.initialize();

        let new_pin_enc = t.encrypt(&shared_secret, &input);
        assert_eq!(new_pin_enc, expected_new_pin_enc);

        let pin_auth = t.authenticate(&shared_secret, &new_pin_enc);
        assert_eq!(pin_auth[0..16], expected_pin_auth);
    }
}

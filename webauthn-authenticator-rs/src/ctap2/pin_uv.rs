#[cfg(doc)]
use crate::stubs::*;

use crate::{
    crypto::{compute_sha256, decrypt, ecdh, encrypt, get_group, hkdf_sha_256, regenerate},
    error::WebauthnCError,
};
use openssl::{
    bn,
    ec::{EcKey, EcKeyRef},
    hash,
    pkey::{PKey, Private},
    rand::rand_bytes,
    sign,
};
use std::{fmt::Debug, ops::Deref};
use webauthn_rs_core::proto::{COSEEC2Key, COSEKey, COSEKeyType, ECDSACurve};
use webauthn_rs_proto::COSEAlgorithm;

use super::commands::{ClientPinRequest, ClientPinSubCommand, Permissions};

pub struct PinUvPlatformInterface {
    protocol: Box<dyn PinUvPlatformInterfaceProtocol>,
    /// A cached [COSEKey] representation of `private_key`.
    public_key: COSEKey,
    /// The platform private key used for this session.
    private_key: EcKey<Private>,
}

impl Debug for PinUvPlatformInterface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PinUvPlatformInterface")
            .field(
                "protocol.pin_uv_protocol",
                &self.protocol.get_pin_uv_protocol(),
            )
            .finish()
    }
}

/// Makes [PinUvPlatformInterface] act like [PinUvPlatformInterfaceProtocol] for easier access to trait methods.
impl Deref for PinUvPlatformInterface {
    type Target = dyn PinUvPlatformInterfaceProtocol;

    fn deref(&self) -> &Self::Target {
        self.protocol.deref()
    }
}

impl PinUvPlatformInterface {
    /// Creates a [PinUvPlatformInterface] for a specific protocol, and generates a new private key.
    pub(super) fn new<T: PinUvPlatformInterfaceProtocol + Default + 'static>(
    ) -> Result<Self, WebauthnCError> {
        let private_key = regenerate()?;
        Self::__new_with_private_key::<T>(private_key)
    }

    /// Creates a [PinUvPlatformInterface] for a specific protocol, with a given private key.
    ///
    /// This interface is only exposed for tests.
    pub(super) fn __new_with_private_key<T: PinUvPlatformInterfaceProtocol + Default + 'static>(
        private_key: EcKey<Private>,
    ) -> Result<Self, WebauthnCError> {
        let public_key = get_public_key(&private_key)?;
        Ok(Self {
            protocol: Box::<T>::default(),
            public_key,
            private_key,
        })
    }

    /// Creates a [PinUvPlatformInterface] given a list of supported protocols. The first supported
    /// protocol will be used.
    ///
    /// Returns [`WebauthnCError::NotSupported`] if no protocols are supported.
    pub(super) fn select_protocol(protocols: Option<&Vec<u32>>) -> Result<Self, WebauthnCError> {
        if let Some(protocols) = protocols {
            for p in protocols.iter() {
                match p {
                    1 => return Self::new::<PinUvPlatformInterfaceProtocolOne>(),
                    2 => return Self::new::<PinUvPlatformInterfaceProtocolTwo>(),
                    // Ignore unsupported protocols
                    _ => (),
                }
            }
        }
        Err(WebauthnCError::NotSupported)
    }

    fn ecdh(&self, peer_cose_key: COSEKey) -> Result<Vec<u8>, WebauthnCError> {
        // Defined in protocol one, but also used in protocol two.

        // 1. Parse peerCoseKey as specified for getPublicKey, below, and produce a P-256 point, Y.
        //    If unsuccessful, or if the resulting point is not on the curve, return error.

        // 2. Calculate xY, the shared point. (I.e. the scalar-multiplication of the peer’s point, Y,
        //    with the local private key agreement key.)
        // 3. Let Z be the 32-byte, big-endian encoding of the x-coordinate of the shared point.
        let mut z: [u8; 32] = [0; 32];
        if let COSEKeyType::EC_EC2(ec) = peer_cose_key.key {
            ecdh(self.private_key.to_owned(), (&ec).try_into()?, &mut z)?;
        } else {
            error!("Unexpected peer key type: {:?}", peer_cose_key);
            return Err(WebauthnCError::Internal);
        }

        // 4. Return kdf(Z).
        self.kdf(&z)
    }

    /// Generates an encapsulation for the authenticator's public key and returns the shared secret.
    pub fn encapsulate(&self, peer_cose_key: COSEKey) -> Result<Vec<u8>, WebauthnCError> {
        // Let sharedSecret be the result of calling ecdh(peerCoseKey). Return any resulting error.
        let shared_secret = self.ecdh(peer_cose_key)?;

        // Return (getPublicKey(), sharedSecret)
        Ok(shared_secret)
    }

    /// Generates a `getKeyAgreement` command.
    pub fn get_key_agreement_cmd(&self) -> ClientPinRequest {
        ClientPinRequest {
            pin_uv_protocol: Some(self.get_pin_uv_protocol()),
            sub_command: ClientPinSubCommand::GetKeyAgreement,
            ..Default::default()
        }
    }

    /// Generates a `getPinToken` command.
    pub fn get_pin_token_cmd(
        &self,
        pin: &str,
        shared_secret: &[u8],
    ) -> Result<ClientPinRequest, WebauthnCError> {
        Ok(ClientPinRequest {
            pin_uv_protocol: Some(self.get_pin_uv_protocol()),
            sub_command: ClientPinSubCommand::GetPinToken,
            key_agreement: Some(self.public_key.clone()),
            pin_hash_enc: Some(
                self.encrypt(shared_secret, &(compute_sha256(pin.as_bytes()))[..16])?,
            ),
            ..Default::default()
        })
    }

    /// Generates a `getPinUvAuthTokenUsingUvWithPermission` command.
    ///
    /// See also: `get_pin_uv_auth_token_using_pin_with_permissions_cmd`
    pub fn get_pin_uv_auth_token_using_uv_with_permissions_cmd(
        &self,
        permissions: Permissions,
        rp_id: Option<String>,
    ) -> ClientPinRequest {
        ClientPinRequest {
            pin_uv_protocol: Some(self.get_pin_uv_protocol()),
            sub_command: ClientPinSubCommand::GetPinUvAuthTokenUsingUvWithPermissions,
            key_agreement: Some(self.public_key.clone()),
            permissions,
            rp_id,
            ..Default::default()
        }
    }

    /// Generates a `getPinUvAuthTokenUsingPinWithPermissions` command.
    ///
    /// See also: `get_pin_uv_auth_token_using_uv_with_permissions_cmd`
    pub fn get_pin_uv_auth_token_using_pin_with_permissions_cmd(
        &self,
        pin: &str,
        shared_secret: &[u8],
        permissions: Permissions,
        rp_id: Option<String>,
    ) -> Result<ClientPinRequest, WebauthnCError> {
        // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#getPinUvAuthTokenUsingPinWithPermissions
        Ok(ClientPinRequest {
            pin_uv_protocol: Some(self.get_pin_uv_protocol()),
            sub_command: ClientPinSubCommand::GetPinUvAuthTokenUsingPinWithPermissions,
            key_agreement: Some(self.public_key.clone()),
            pin_hash_enc: Some(
                self.encrypt(shared_secret, &(compute_sha256(pin.as_bytes()))[..16])?,
            ),
            permissions,
            rp_id,
            ..Default::default()
        })
    }

    #[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
    /// Generates a `setPin` command.
    pub fn set_pin_cmd(
        &self,
        padded_pin: [u8; 64],
        shared_secret: &[u8],
    ) -> Result<ClientPinRequest, WebauthnCError> {
        let new_pin_enc = self.encrypt(shared_secret, &padded_pin)?;
        let pin_uv_auth_param = Some(self.authenticate(shared_secret, new_pin_enc.as_slice())?);
        Ok(ClientPinRequest {
            pin_uv_protocol: Some(self.get_pin_uv_protocol()),
            sub_command: ClientPinSubCommand::SetPin,
            key_agreement: Some(self.public_key.clone()),
            new_pin_enc: Some(new_pin_enc),
            pin_uv_auth_param,
            ..Default::default()
        })
    }

    #[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
    /// Generates a `changePin` command.
    pub fn change_pin_cmd(
        &self,
        old_pin: &str,
        new_padded_pin: [u8; 64],
        shared_secret: &[u8],
    ) -> Result<ClientPinRequest, WebauthnCError> {
        // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#changingExistingPin
        let pin_hash_enc =
            self.encrypt(shared_secret, &(compute_sha256(old_pin.as_bytes()))[..16])?;
        let new_pin_enc = self.encrypt(shared_secret, &new_padded_pin)?;

        let mut pin_uv_auth_param = Vec::with_capacity(pin_hash_enc.len() + new_pin_enc.len());
        pin_uv_auth_param.extend_from_slice(new_pin_enc.as_slice());
        pin_uv_auth_param.extend_from_slice(pin_hash_enc.as_slice());
        let pin_uv_auth_param =
            Some(self.authenticate(shared_secret, pin_uv_auth_param.as_slice())?);

        Ok(ClientPinRequest {
            pin_uv_protocol: Some(self.get_pin_uv_protocol()),
            sub_command: ClientPinSubCommand::ChangePin,
            key_agreement: Some(self.public_key.clone()),
            pin_hash_enc: Some(pin_hash_enc),
            new_pin_enc: Some(new_pin_enc),
            pin_uv_auth_param,
            ..Default::default()
        })
    }
}

pub trait PinUvPlatformInterfaceProtocol: Sync + Send {
    fn kdf(&self, z: &[u8]) -> Result<Vec<u8>, WebauthnCError>;

    /// Encrypts a `plaintext` to produce a ciphertext, which may be longer than
    /// the `plaintext`. The `plaintext` is restricted to being a multiple of
    /// the AES block size (16 bytes) in length.
    fn encrypt(&self, key: &[u8], dem_plaintext: &[u8]) -> Result<Vec<u8>, WebauthnCError>;

    /// Decrypts a `ciphertext` and returns the plaintext.
    fn decrypt(
        &self,
        key: &[u8],
        ciphertext: &[u8],
    ) -> Result</* plaintext */ Vec<u8>, WebauthnCError>;

    /// Computes a MAC of the given `message`.
    fn authenticate(&self, key: &[u8], message: &[u8]) -> Result<Vec<u8>, WebauthnCError>;

    /// Gets the numeric identifier for this [PinUvPlatformInterfaceProtocol].
    fn get_pin_uv_protocol(&self) -> u32;
}

#[derive(Default)]
pub struct PinUvPlatformInterfaceProtocolOne {}

impl PinUvPlatformInterfaceProtocol for PinUvPlatformInterfaceProtocolOne {
    fn kdf(&self, z: &[u8]) -> Result<Vec<u8>, WebauthnCError> {
        // Return SHA-256(Z)
        Ok(compute_sha256(z).to_vec())
    }

    fn encrypt(&self, key: &[u8], dem_plaintext: &[u8]) -> Result<Vec<u8>, WebauthnCError> {
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
        decrypt(key, None, ciphertext)
    }

    fn authenticate(&self, key: &[u8], message: &[u8]) -> Result<Vec<u8>, WebauthnCError> {
        // Return the first 16 bytes of the result of computing HMAC-SHA-256
        // with the given key and message.
        let key = PKey::hmac(key)?;
        let mut signer = sign::Signer::new(hash::MessageDigest::sha256(), &key)?;
        signer.update(message)?;
        let mut o = signer.sign_to_vec()?;
        o.truncate(16);
        Ok(o)
    }

    fn get_pin_uv_protocol(&self) -> u32 {
        1
    }
}

#[derive(Default)]
pub struct PinUvPlatformInterfaceProtocolTwo {}

impl PinUvPlatformInterfaceProtocol for PinUvPlatformInterfaceProtocolTwo {
    fn encrypt(&self, key: &[u8], dem_plaintext: &[u8]) -> Result<Vec<u8>, WebauthnCError> {
        // 1. Discard the first 32 bytes of key. (This selects the AES-key
        //    portion of the shared secret.)
        let key = &key[32..];

        // 2. Let iv be a 16-byte, random bytestring.
        let mut iv: [u8; 16] = [0; 16];
        rand_bytes(&mut iv)?;

        // 3. Let ct be the AES-256-CBC encryption of demPlaintext using key and
        //    iv. (No padding is performed as the size of demPlaintext is
        //    required to be a multiple of the AES block length.)
        let ct = encrypt(key, Some(iv.as_slice()), dem_plaintext)?;

        // 4. Return iv || ct.
        let mut o = iv.to_vec();
        o.extend_from_slice(ct.as_slice());

        Ok(o)
    }

    fn decrypt(
        &self,
        key: &[u8],
        ciphertext: &[u8],
    ) -> Result</* plaintext */ Vec<u8>, WebauthnCError> {
        // 1. Discard the first 32 bytes of key. (This selects the AES-key portion of the shared secret.)
        let key = &key[32..];

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
        decrypt(key, Some(iv), ct)
    }

    fn authenticate(&self, key: &[u8], message: &[u8]) -> Result<Vec<u8>, WebauthnCError> {
        // 1. If key is longer than 32 bytes, discard the excess.
        //    (This selects the HMAC-key portion of the shared secret. When key is the
        //    pinUvAuthToken, it is exactly 32 bytes long and thus this step has no effect.)
        let key = PKey::hmac(&key[..32])?;

        // 2. Return the result of computing HMAC-SHA-256 on key and message.
        let mut signer = sign::Signer::new(hash::MessageDigest::sha256(), &key)?;
        signer.update(message)?;
        Ok(signer.sign_to_vec()?)
    }

    fn kdf(&self, z: &[u8]) -> Result<Vec<u8>, WebauthnCError> {
        // Return
        // HKDF-SHA-256(salt = 32 zero bytes, IKM = Z, L = 32, info = "CTAP2 HMAC key") ||
        // HKDF-SHA-256(salt = 32 zero bytes, IKM = Z, L = 32, info = "CTAP2 AES key")
        // (see [RFC5869] for the definition of HKDF).
        let mut o: Vec<u8> = vec![0; 64];
        let zero: [u8; 32] = [0; 32];
        hkdf_sha_256(&zero, z, Some(b"CTAP2 HMAC key"), &mut o[0..32])?;
        hkdf_sha_256(&zero, z, Some(b"CTAP2 AES key"), &mut o[32..64])?;

        Ok(o)
    }

    fn get_pin_uv_protocol(&self) -> u32 {
        2
    }
}

/// Gets the public key for a private key as [COSEKey] for PinUvProtocol.
fn get_public_key(private_key: &EcKeyRef<Private>) -> Result<COSEKey, WebauthnCError> {
    let ecgroup = get_group()?;
    // Extract the public x and y coords.
    let ecpub_points = private_key.public_key();

    let mut bnctx = bn::BigNumContext::new()?;
    let mut xbn = bn::BigNum::new()?;
    let mut ybn = bn::BigNum::new()?;

    ecpub_points.affine_coordinates_gfp(&ecgroup, &mut xbn, &mut ybn, &mut bnctx)?;

    Ok(COSEKey {
        type_: COSEAlgorithm::PinUvProtocol,
        key: COSEKeyType::EC_EC2(COSEEC2Key {
            curve: ECDSACurve::SECP256R1,
            x: xbn.to_vec().into(),
            y: ybn.to_vec().into(),
        }),
    })
}

#[cfg(test)]
mod tests {
    use openssl::ec;

    use super::*;

    #[test]
    fn pin_encryption_and_hashing() {
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
        let mut padded_pin: [u8; 64] = [0; 64];
        padded_pin[..pin.len()].copy_from_slice(pin.as_bytes());

        let t = PinUvPlatformInterface::new::<PinUvPlatformInterfaceProtocolOne>().unwrap();

        let new_pin_enc = t.encrypt(&shared_secret, &padded_pin).unwrap();
        assert_eq!(new_pin_enc, expected_new_pin_enc);

        let pin_auth = t.authenticate(&shared_secret, &new_pin_enc).unwrap();
        assert_eq!(pin_auth[0..16], expected_pin_auth);

        let decrypted_pin = t
            .decrypt(&shared_secret, expected_new_pin_enc.as_slice())
            .expect("decrypt error");
        assert_eq!(decrypted_pin, padded_pin.to_vec());
    }

    // https://github.com/Yubico/python-fido2/blob/8c00d0494501028135fd13adbe8c56a8d8b7e437/tests/test_ctap2.py#L274
    #[test]
    fn shared_secret() {
        let expected_secret = vec![
            0xc4, 0x2a, 0x3, 0x9d, 0x54, 0x81, 0x0, 0xdf, 0xba, 0x52, 0x1e, 0x48, 0x7d, 0xeb, 0xcb,
            0xbb, 0x8b, 0x66, 0xbb, 0x74, 0x96, 0xf8, 0xb1, 0x86, 0x2a, 0x7a, 0x39, 0x5e, 0xd8,
            0x3e, 0x1a, 0x1c,
        ];
        let dev_public_key = COSEKey {
            type_: COSEAlgorithm::PinUvProtocol,
            key: COSEKeyType::EC_EC2(COSEEC2Key {
                curve: ECDSACurve::SECP256R1,
                x: vec![
                    0x5, 0x1, 0xd5, 0xbc, 0x78, 0xda, 0x92, 0x52, 0x56, 0xa, 0x26, 0xcb, 0x8, 0xfc,
                    0xc6, 0xc, 0xbe, 0xb, 0x6d, 0x3b, 0x8e, 0x1d, 0x1f, 0xce, 0xe5, 0x14, 0xfa,
                    0xc0, 0xaf, 0x67, 0x51, 0x68,
                ]
                .into(),
                y: vec![
                    0xd5, 0x51, 0xb3, 0xed, 0x46, 0xf6, 0x65, 0x73, 0x1f, 0x95, 0xb4, 0x53, 0x29,
                    0x39, 0xc2, 0x5d, 0x91, 0xdb, 0x7e, 0xb8, 0x44, 0xbd, 0x96, 0xd4, 0xab, 0xd4,
                    0x8, 0x37, 0x85, 0xf8, 0xdf, 0x47,
                ]
                .into(),
            }),
        };

        let mut ctx = bn::BigNumContext::new().unwrap();
        let group = get_group().unwrap();
        let x = bn::BigNum::from_hex_str(
            "44D78D7989B97E62EA993496C9EF6E8FD58B8B00715F9A89153DDD9C4657E47F",
        )
        .unwrap();
        let y = bn::BigNum::from_hex_str(
            "EC802EE7D22BD4E100F12E48537EB4E7E96ED3A47A0A3BD5F5EEAB65001664F9",
        )
        .unwrap();
        // let ec_pub = ec::EcKey::from_public_key_affine_coordinates(&group, &x, &y).unwrap();
        let mut ec_pub = ec::EcPoint::new(&group).unwrap();
        ec_pub
            .set_affine_coordinates_gfp(&group, &x, &y, &mut ctx)
            .unwrap();
        let ec_priv = bn::BigNum::from_hex_str(
            "7452E599FEE739D8A653F6A507343D12D382249108A651402520B72F24FE7684",
        )
        .unwrap();
        let ec_priv = ec::EcKey::from_private_components(&group, &ec_priv, &ec_pub).unwrap();

        let t =
            PinUvPlatformInterface::__new_with_private_key::<PinUvPlatformInterfaceProtocolOne>(
                ec_priv,
            )
            .unwrap();

        let shared_secret = t.encapsulate(dev_public_key).unwrap();
        assert_eq!(expected_secret, shared_secret);

        // Get PIN token
        // https://github.com/Yubico/python-fido2/blob/8c00d0494501028135fd13adbe8c56a8d8b7e437/tests/test_ctap2.py#L293
        let expected = ClientPinRequest {
            sub_command: ClientPinSubCommand::GetPinToken,
            key_agreement: Some(t.public_key.clone()),
            pin_uv_protocol: Some(1),
            pin_hash_enc: Some(vec![
                0xaf, 0xe8, 0x32, 0x7c, 0xe4, 0x16, 0xda, 0x8e, 0xe3, 0xd0, 0x57, 0x58, 0x9c, 0x2c,
                0xe1, 0xa9,
            ]),
            ..Default::default()
        };

        assert_eq!(
            expected,
            t.get_pin_token_cmd("1234", &shared_secret).unwrap()
        );

        #[cfg(feature = "ctap2-management")]
        {
            // Set PIN
            // https://github.com/Yubico/python-fido2/blob/8c00d0494501028135fd13adbe8c56a8d8b7e437/tests/test_ctap2.py#L307
            let mut padded_pin: [u8; 64] = [0; 64];
            padded_pin[..4].copy_from_slice("1234".as_bytes());
            let expected = ClientPinRequest {
                sub_command: ClientPinSubCommand::SetPin,
                key_agreement: Some(t.public_key.clone()),
                pin_uv_protocol: Some(1),
                pin_uv_auth_param: Some(vec![
                    0x7b, 0x40, 0xc0, 0x84, 0xcc, 0xc5, 0x79, 0x41, 0x94, 0x18, 0x9a, 0xb5, 0x78,
                    0x36, 0x47, 0x5f,
                ]),
                new_pin_enc: Some(vec![
                    0x02, 0x22, 0xfc, 0x42, 0xc6, 0xdd, 0x76, 0xa2, 0x74, 0xa7, 0x05, 0x78, 0x58,
                    0xb9, 0xb2, 0x9d, 0x98, 0xe8, 0xa7, 0x22, 0xec, 0x2d, 0xc6, 0x66, 0x84, 0x76,
                    0x16, 0x8c, 0x53, 0x20, 0x47, 0x3c, 0xec, 0x99, 0x07, 0xb4, 0xcd, 0x76, 0xce,
                    0x79, 0x43, 0xc9, 0x6b, 0xa5, 0x68, 0x39, 0x43, 0x21, 0x1d, 0x84, 0x47, 0x1e,
                    0x64, 0xd9, 0xc5, 0x1e, 0x54, 0x76, 0x34, 0x88, 0xcd, 0x66, 0x52, 0x6a,
                ]),
                ..Default::default()
            };

            assert_eq!(expected, t.set_pin_cmd(padded_pin, &shared_secret).unwrap());

            // Change PIN
            // https://github.com/Yubico/python-fido2/blob/8c00d0494501028135fd13adbe8c56a8d8b7e437/tests/test_ctap2.py#L325
            let mut new_padded_pin: [u8; 64] = [0; 64];
            new_padded_pin[..4].copy_from_slice("4321".as_bytes());
            let expected = ClientPinRequest {
                sub_command: ClientPinSubCommand::ChangePin,
                key_agreement: Some(t.public_key.clone()),
                pin_uv_protocol: Some(1),
                pin_uv_auth_param: Some(vec![
                    0xfb, 0x97, 0xe9, 0x2f, 0x37, 0x24, 0xd7, 0xc8, 0x5e, 0x0, 0x1d, 0x7f, 0x93,
                    0xe6, 0x49, 0xa,
                ]),
                new_pin_enc: Some(vec![
                    0x42, 0x80, 0xe1, 0x4a, 0xac, 0x4f, 0xcb, 0xf0, 0x2d, 0xd0, 0x79, 0x98, 0x5f,
                    0x0c, 0x0f, 0xfc, 0x9e, 0xa7, 0xd5, 0xf9, 0xc1, 0x73, 0xfd, 0x1a, 0x4c, 0x84,
                    0x38, 0x26, 0xf7, 0x59, 0x0c, 0xb3, 0xc2, 0xd0, 0x80, 0xc6, 0x92, 0x3e, 0x2f,
                    0xe6, 0xd7, 0xa5, 0x2c, 0x31, 0xea, 0x13, 0x09, 0xd3, 0xfc, 0xca, 0x3d, 0xed,
                    0xae, 0x8a, 0x2e, 0xf1, 0x4b, 0x63, 0x30, 0xca, 0xfc, 0x79, 0x33, 0x9e,
                ]),
                pin_hash_enc: Some(vec![
                    0xaf, 0xe8, 0x32, 0x7c, 0xe4, 0x16, 0xda, 0x8e, 0xe3, 0xd0, 0x57, 0x58, 0x9c,
                    0x2c, 0xe1, 0xa9,
                ]),
                ..Default::default()
            };

            assert_eq!(
                expected,
                t.change_pin_cmd("1234", new_padded_pin, &shared_secret)
                    .unwrap()
            );

            let message = [0xff; 64];
            let signed_message = t.authenticate(&shared_secret, &message).unwrap();
            let expected_signature = vec![
                0xb3, 0x01, 0x68, 0x96, 0x07, 0x4e, 0x5a, 0x89, 0x54, 0xe8, 0xe3, 0x05, 0x69, 0xd2,
                0x34, 0x21,
            ];
            assert_eq!(16, expected_signature.len());
            assert_eq!(expected_signature, signed_message);
        }
    }

    #[test]
    fn shared_secret_pin_protocol_two() {
        let expected_secret = vec![
            0x65, 0xef, 0x95, 0x5d, 0xd8, 0xcf, 0xca, 0xca, 0xb4, 0x89, 0xad, 0x58, 0x2d, 0x64,
            0xb8, 0x72, 0x29, 0x9c, 0xec, 0x19, 0x70, 0xae, 0xff, 0xb1, 0x0c, 0x90, 0xb9, 0xd9,
            0xf4, 0xb4, 0xf1, 0xa7, 0x46, 0xcc, 0x03, 0x96, 0x48, 0x25, 0xcc, 0xba, 0xf1, 0x59,
            0xfd, 0xe1, 0x95, 0x8b, 0x20, 0x63, 0x87, 0x1b, 0xd5, 0xb6, 0x6e, 0xcf, 0x28, 0x97,
            0x2e, 0xaa, 0xc5, 0x83, 0x21, 0x4a, 0x22, 0xd8,
        ];
        let dev_public_key = COSEKey {
            type_: COSEAlgorithm::PinUvProtocol,
            key: COSEKeyType::EC_EC2(COSEEC2Key {
                curve: ECDSACurve::SECP256R1,
                x: vec![
                    0x5, 0x1, 0xd5, 0xbc, 0x78, 0xda, 0x92, 0x52, 0x56, 0xa, 0x26, 0xcb, 0x8, 0xfc,
                    0xc6, 0xc, 0xbe, 0xb, 0x6d, 0x3b, 0x8e, 0x1d, 0x1f, 0xce, 0xe5, 0x14, 0xfa,
                    0xc0, 0xaf, 0x67, 0x51, 0x68,
                ]
                .into(),
                y: vec![
                    0xd5, 0x51, 0xb3, 0xed, 0x46, 0xf6, 0x65, 0x73, 0x1f, 0x95, 0xb4, 0x53, 0x29,
                    0x39, 0xc2, 0x5d, 0x91, 0xdb, 0x7e, 0xb8, 0x44, 0xbd, 0x96, 0xd4, 0xab, 0xd4,
                    0x8, 0x37, 0x85, 0xf8, 0xdf, 0x47,
                ]
                .into(),
            }),
        };

        let mut ctx = bn::BigNumContext::new().unwrap();
        let group = get_group().unwrap();
        let x = bn::BigNum::from_hex_str(
            "44D78D7989B97E62EA993496C9EF6E8FD58B8B00715F9A89153DDD9C4657E47F",
        )
        .unwrap();
        let y = bn::BigNum::from_hex_str(
            "EC802EE7D22BD4E100F12E48537EB4E7E96ED3A47A0A3BD5F5EEAB65001664F9",
        )
        .unwrap();
        let mut ec_pub = ec::EcPoint::new(&group).unwrap();
        ec_pub
            .set_affine_coordinates_gfp(&group, &x, &y, &mut ctx)
            .unwrap();
        let ec_priv = bn::BigNum::from_hex_str(
            "7452E599FEE739D8A653F6A507343D12D382249108A651402520B72F24FE7684",
        )
        .unwrap();
        let ec_priv = ec::EcKey::from_private_components(&group, &ec_priv, &ec_pub).unwrap();

        let t =
            PinUvPlatformInterface::__new_with_private_key::<PinUvPlatformInterfaceProtocolTwo>(
                ec_priv,
            )
            .unwrap();

        let shared_secret = t.encapsulate(dev_public_key).unwrap();
        assert_eq!(expected_secret, shared_secret);

        // PIN Protocol 2's encrypt() has a dynamic IV, so we can't test PIN functions with it with known values.

        let message = [0xff; 64];
        let signed_message = t.authenticate(&shared_secret, &message).unwrap();
        let expected_signature = vec![
            0x5f, 0xa8, 0x1a, 0xf3, 0x3e, 0x37, 0x2c, 0x49, 0xa0, 0x54, 0xa0, 0x6b, 0xdb, 0x18,
            0xe9, 0x25, 0xc9, 0xef, 0x08, 0x41, 0x27, 0x17, 0x67, 0xb3, 0x48, 0x44, 0xd1, 0x27,
            0x0b, 0x40, 0xb3, 0x9c,
        ];
        // Signature is SHA256, so we should get an appropriate length value back
        assert_eq!(256 / 8, expected_signature.len());
        assert_eq!(expected_signature, signed_message);
    }

    #[test]
    fn select() {
        let t = PinUvPlatformInterface::select_protocol(None);
        assert_eq!(Some(WebauthnCError::NotSupported), t.err());

        // Single supported protocol
        let t = PinUvPlatformInterface::select_protocol(Some(&vec![1])).unwrap();
        assert_eq!(1, t.get_pin_uv_protocol());

        let t = PinUvPlatformInterface::select_protocol(Some(&vec![2])).unwrap();
        assert_eq!(2, t.get_pin_uv_protocol());

        // Always choose the first supported protocol (even if it is lower)
        let t = PinUvPlatformInterface::select_protocol(Some(&vec![2, 1])).unwrap();
        assert_eq!(2, t.get_pin_uv_protocol());

        let t = PinUvPlatformInterface::select_protocol(Some(&vec![1, 2])).unwrap();
        assert_eq!(1, t.get_pin_uv_protocol());

        // Newer, unknown protocol should fall back to first one we support
        let t = PinUvPlatformInterface::select_protocol(Some(&vec![9999, 2, 1])).unwrap();
        assert_eq!(2, t.get_pin_uv_protocol());

        // Unknown protocol
        let t = PinUvPlatformInterface::select_protocol(Some(&vec![9999]));
        assert_eq!(Some(WebauthnCError::NotSupported), t.err());
    }
}

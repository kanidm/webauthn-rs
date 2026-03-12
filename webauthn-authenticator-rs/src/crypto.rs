//! Common cryptographic routines for FIDO2.
#[cfg(doc)]
use crate::stubs::*;

#[cfg(any(doc, feature = "cable"))]
use crypto_glue::ecdh_p256::EcdhP256PublicKey;
use crypto_glue::{
    aes256::Aes256Key,
    aes256cbc::{
        Aes256CbcDec, Aes256CbcEnc, Aes256CbcIv, BlockDecryptMut, BlockEncryptMut, KeyIvInit,
    },
    block_padding::NoPadding,
    hkdf_s256::HkdfSha256,
    s256::{Sha256, Sha256Output},
    traits::Digest,
};

use crate::error::WebauthnCError;

pub fn compute_sha256(data: &[u8]) -> Sha256Output {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize()
}

#[cfg(feature = "cable")]
/// Computes the SHA256 of `a || b`.
pub fn compute_sha256_2(a: &[u8], b: &[u8]) -> Sha256Output {
    let mut hasher = Sha256::new();
    hasher.update(a);
    hasher.update(b);
    hasher.finalize()
}

/// Encrypts some data using AES-256-CBC, with no padding.
///
/// `plaintext.len()` must be a multiple of the cipher's blocksize.
pub fn encrypt(
    key: &Aes256Key,
    iv: &Aes256CbcIv,
    plaintext: &[u8],
) -> Result<Vec<u8>, WebauthnCError> {
    let enc = Aes256CbcEnc::new(key, iv);

    let ciphertext = enc.encrypt_padded_vec_mut::<NoPadding>(plaintext);

    Ok(ciphertext)
}

/// Decrypts some data using AES-256-CBC, with no padding.
pub fn decrypt(
    key: &Aes256Key,
    iv: &Aes256CbcIv,
    ciphertext: &[u8],
) -> Result<Vec<u8>, WebauthnCError> {
    let enc = Aes256CbcDec::new(key, iv);

    enc.decrypt_padded_vec_mut::<NoPadding>(ciphertext)
        .map_err(|_| WebauthnCError::CryptographyAes256CbcDecrypt)
}

pub fn hkdf_sha_256(
    salt: &[u8],
    ikm: &[u8],
    info: Option<&[u8]>,
    output: &mut [u8],
) -> Result<(), WebauthnCError> {
    let hk = HkdfSha256::new(Some(salt), ikm);

    let empty: &[u8] = &[];

    let info = info.unwrap_or(empty);

    hk.expand(info, output)
        .map_err(|_| WebauthnCError::CryptographyHkdfExpand)?;
    Ok(())
}

#[cfg(any(doc, feature = "cable"))]
/// Reads `buf` as a compressed or uncompressed P-256 key.
pub fn public_key_from_bytes(buf: &[u8]) -> Result<EcdhP256PublicKey, WebauthnCError> {
    EcdhP256PublicKey::from_sec1_bytes(buf).map_err(|_| WebauthnCError::CryptographyPublicKey)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod test {
    use super::*;
    use crypto_glue::ecdh_p256;

    #[test]
    fn hkdf() {
        let _ = tracing_subscriber::fmt::try_init();
        let salt: Vec<u8> = (0..0x0d).collect();
        let ikm: [u8; 22] = [0x0b; 22];
        let info: Vec<u8> = (0xf0..0xfa).collect();
        let expected: [u8; 42] = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
            0x2f, 0x2a, 0x2d, 0x2d, 0xa, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
            0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x0, 0x72, 0x8, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
        ];

        let mut output: [u8; 42] = [0; 42];

        hkdf_sha_256(salt.as_slice(), &ikm, Some(info.as_slice()), &mut output)
            .expect("hkdf_sha_256 fail");
        assert_eq!(expected, output);
    }

    #[test]
    fn hkdf_chromium() {
        // Compare hkdf using values debug-logged from Chromium
        let _ = tracing_subscriber::fmt::try_init();
        let ck = [
            0x30, 0x7a, 0x70, 0x6e, 0x63, 0x38, 0x2e, 0x8e, 0x9d, 0x46, 0xcc, 0xdb, 0xc, 0xeb,
            0xed, 0x5c, 0x2b, 0x19, 0x28, 0xc5, 0xae, 0x2d, 0xee, 0x63, 0x52, 0xe1, 0x30, 0xac,
            0xe1, 0xf7, 0x4f, 0x44,
        ];
        let expected = [
            0x1f, 0xba, 0x3c, 0xce, 0x17, 0x62, 0x2c, 0x68, 0x26, 0x8d, 0x9f, 0x75, 0xb5, 0xa8,
            0xa3, 0x35, 0x1b, 0x51, 0x7f, 0x9, 0x6f, 0xb5, 0xe2, 0x94, 0x94, 0x1a, 0xf7, 0xe3,
            0xa6, 0xa8, 0xd6, 0xe1, 0xe3, 0x4f, 0x1a, 0xa3, 0x74, 0x72, 0x38, 0xc0, 0x4d, 0x3b,
            0xd2, 0x5e, 0x7, 0xef, 0x1b, 0x35, 0xfe, 0xf3, 0x59, 0x0, 0xd, 0x75, 0x56, 0x15, 0xcd,
            0x85, 0xbe, 0x27, 0xcf, 0xc8, 0x7, 0xd1,
        ];
        let mut actual = [0; 64];

        hkdf_sha_256(&ck, &[], None, &mut actual).unwrap();
        assert_eq!(expected, actual);
    }

    /// Test using ECDH with ourselves and fully-random keys.
    #[test]
    fn ecdh_p256_basic() {
        let _ = tracing_subscriber::fmt::try_init();

        let alice_secret = ecdh_p256::new_secret();
        let alice_pub = alice_secret.public_key();

        let bob_secret = ecdh_p256::new_secret();
        let bob_pub = bob_secret.public_key();
        assert_ne!(alice_pub, bob_pub);

        let alice_out = alice_secret.diffie_hellman(&bob_pub);
        let bob_out = bob_secret.diffie_hellman(&alice_pub);
        assert_eq!(alice_out.raw_secret_bytes(), bob_out.raw_secret_bytes());
    }

    /// Test using ECDH with static keys.
    #[test]
    fn ecdh_expected() {
        use crypto_glue::{
            ecdh_p256::EcdhP256EphemeralSecret, ecdsa_p256::EcdsaP256NonZeroScalar,
            traits::ToEncodedPoint,
        };

        let alice_secret = EcdsaP256NonZeroScalar::from_repr((*b"\x13\xeaL\xe1\xd1\xff\xb3\xc2\x88\\\x8eb 0[\xe8a\x92\x1d\xee\xdd\x17\xca:\x171\xae\xbf\x8c\xf0\xdc\xb8").into()).unwrap();
        let bob_secret = EcdsaP256NonZeroScalar::from_repr((*b"\x84\x0ed:\x90\xee\xb9}\xc8\xb4\xb5\x12\x03\x8b\xc5~\xe1\x13\x04\xceZ\x9d,\xfd\xd6F\x13\xea\xb0\x96?q").into()).unwrap();

        // We need our secrets to be constant for testing. EphemeralSecret is a wrapper for
        // NonZeroScalar, so we can transmute it directly.
        let alice_secret: EcdhP256EphemeralSecret = unsafe { std::mem::transmute(alice_secret) };
        let bob_secret: EcdhP256EphemeralSecret = unsafe { std::mem::transmute(bob_secret) };

        // Check that we can get the same pubkey from either side:
        let alice_pub = alice_secret.public_key();
        let alice_pub_point = alice_pub.to_encoded_point(false);
        assert_eq!(alice_pub_point.as_bytes(), b"\x04\xa5\x99\xe0\xdd{\x1a\xa3m0\x98\x80R\x1a\xc2\x8b\xbe\xc3A\x81\x91W$\x055\x16\xe5\xb0\tF\x86\xe8`\xaf\xe6.\x98\xf5:\x99\xf1\xb4\x1cai\x96\xb0e\x83\x8c&\x12*\xfd,~\x14\xb8\xf8q9-\xd1\x18\xed");

        let bob_pub = bob_secret.public_key();
        let bob_pub_point = bob_pub.to_encoded_point(false);
        assert_eq!(bob_pub_point.as_bytes(), b"\x04\xe3F/\xe9\xd6\x8e\xb5L\xc9!\x14w\x0cs8z)\xcc)\r\x87]\x829fC \xf7>\xe5\x07b\x8b\xe8\xfd\xdd\0\xd66\x9d\x11\xfe\xec\xe4Z\x0c\xf4\xc3e#\x19\xc5\xa0\x81\x19\xe7\xd8}}\xd3a\xea\x9a\x12");

        // Now lets do ECDH (like caBLE), and check that Alice came up with our expected secret:
        let alice_out = alice_secret.diffie_hellman(&bob_pub);
        assert_eq!(alice_out.raw_secret_bytes().as_slice(), b"\xeeom\xee\xac\x9a\xbc9\xaf\x97g\x83\x11\x87!\x19\x86\xc0D\xc8\x93\xde\xb8wG\x19\xfe\xecy\xe5\x19z");

        // And repeat the process for Bob:
        let bob_out = alice_secret.diffie_hellman(&bob_pub);
        assert_eq!(alice_out.raw_secret_bytes(), bob_out.raw_secret_bytes());
    }

    /*
    #[test]
    fn ecdh_p256_openssl() {
        use openssl::{
            bn::{BigNum, BigNumContext},
            ec::{EcGroup, EcKey, EcKeyRef, EcPoint, EcPointRef, PointConversionForm},
            nid::Nid,
            pkey::{PKey, Private, Public},
            pkey_ctx::PkeyCtx,
        };

        fn get_group() -> Result<EcGroup, WebauthnCError> {
            Ok(EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?)
        }

        fn regenerate() -> Result<EcKey<Private>, WebauthnCError> {
            let ecgroup = get_group()?;
            let eckey = EcKey::generate(&ecgroup)?;
            Ok(eckey)
        }

        fn ecdh_openssl(
            private_key: EcKey<Private>,
            peer_key: EcKey<Public>,
            output: &mut [u8],
        ) -> Result<(), WebauthnCError> {
            let peer_key = PKey::from_ec_key(peer_key)?;
            let pkey = PKey::from_ec_key(private_key)?;
            let mut ctx = PkeyCtx::new(&pkey)?;
            ctx.derive_init()?;
            ctx.derive_set_peer(&peer_key)?;
            ctx.derive(Some(output))?;
            Ok(())
        }

        fn public_key_from_private(
            key: &EcKeyRef<Private>,
        ) -> Result<EcKey<Public>, WebauthnCError> {
            Ok(EcKey::from_public_key(key.group(), key.public_key())?)
        }

        fn public_key_from_bytes(buf: &[u8]) -> Result<EcKey<Public>, WebauthnCError> {
            let group = get_group()?;
            let mut ctx = BigNumContext::new()?;
            let point = EcPoint::from_bytes(&group, buf, &mut ctx)?;
            Ok(EcKey::from_public_key(&group, &point)?)
        }

        fn point_to_bytes(point: &EcPointRef, compressed: bool) -> Result<Vec<u8>, WebauthnCError> {
            let group = get_group()?;
            let mut ctx = BigNumContext::new()?;
            Ok(point.to_bytes(
                &group,
                if compressed {
                    PointConversionForm::COMPRESSED
                } else {
                    PointConversionForm::UNCOMPRESSED
                },
                &mut ctx,
            )?)
        }

        let _ = tracing_subscriber::fmt::try_init();

        let alice_secret = ecdh_p256::new_secret();
        let bob_secret = regenerate().unwrap();

        let alice_pub = alice_secret.public_key();
        let alice_point = alice_pub.to_encoded_point(false);
        let alice_bytes = alice_point.as_bytes();
        let alice_ossl = public_key_from_bytes(alice_bytes).unwrap();

        let bob_pub = public_key_from_private(&bob_secret).unwrap();
        let bob_points = bob_pub.public_key();
        let bob_bytes = point_to_bytes(bob_pub.public_key(), false).unwrap();
        let bob_rc = super::public_key_from_bytes(&bob_bytes).unwrap();

        assert_eq!(alice_bytes.len(), bob_bytes.len());

        // Dump openssl coords
        let group = get_group().unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let mut bob_openssl_x = BigNum::new().unwrap();
        let mut bob_openssl_y = BigNum::new().unwrap();
        bob_points
            .affine_coordinates(&group, &mut bob_openssl_x, &mut bob_openssl_y, &mut ctx)
            .unwrap();
        warn!(
            "bob_openssl: x = {:?}, y = {:?}",
            bob_openssl_x.to_hex_str(),
            bob_openssl_y.to_hex_str()
        );

        // Now do RustCrypto
        let bob_rc_point = bob_rc.as_affine().to_encoded_point(false);
        let bob_coords = bob_rc_point.coordinates();
        warn!("bob_rustcrypto: {:02x?}", bob_coords);

        let mut alice_out = [0; 32];
        ecdh(&alice_secret, &bob_rc, &mut alice_out).unwrap();

        let mut bob_out = [0; 32];
        ecdh_openssl(bob_secret, alice_ossl, &mut bob_out).unwrap();

        assert_eq!(
            alice_out,
            bob_out,
            "{:?} != {:?}",
            hex::encode(alice_out),
            hex::encode(bob_out)
        );
    }
    */
}

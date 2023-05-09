//! Common cryptographic routines for FIDO2.
#[cfg(doc)]
use crate::stubs::*;

#[cfg(any(doc, feature = "cable"))]
use openssl::{
    bn::BigNumContext,
    ec::{EcKeyRef, EcPoint, EcPointRef, PointConversionForm},
};
use openssl::{
    ec::{EcGroup, EcKey},
    md::Md,
    nid::Nid,
    pkey::{Id, PKey, Private, Public},
    pkey_ctx::PkeyCtx,
    sha::Sha256,
    symm::{Cipher, Crypter, Mode},
};

use crate::error::WebauthnCError;

pub type SHA256Hash = [u8; 32];

pub fn compute_sha256(data: &[u8]) -> SHA256Hash {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finish()
}

#[cfg(feature = "cable")]
/// Computes the SHA256 of `a || b`.
pub fn compute_sha256_2(a: &[u8], b: &[u8]) -> SHA256Hash {
    let mut hasher = Sha256::new();
    hasher.update(a);
    hasher.update(b);
    hasher.finish()
}

/// Gets an [EcGroup] for P-256
pub fn get_group() -> Result<EcGroup, WebauthnCError> {
    Ok(EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?)
}

/// Encrypts some data using AES-256-CBC, with no padding.
///
/// `plaintext.len()` must be a multiple of the cipher's blocksize.
pub fn encrypt(key: &[u8], iv: Option<&[u8]>, plaintext: &[u8]) -> Result<Vec<u8>, WebauthnCError> {
    let cipher = Cipher::aes_256_cbc();
    let mut ct = vec![0; plaintext.len() + cipher.block_size()];
    let mut c = Crypter::new(cipher, Mode::Encrypt, key, iv)?;
    c.pad(false);
    let l = c.update(plaintext, &mut ct)?;
    let l = l + c.finalize(&mut ct[l..])?;
    ct.truncate(l);
    Ok(ct)
}

/// Decrypts some data using AES-256-CBC, with no padding.
pub fn decrypt(
    key: &[u8],
    iv: Option<&[u8]>,
    ciphertext: &[u8],
) -> Result<Vec<u8>, WebauthnCError> {
    let cipher = Cipher::aes_256_cbc();
    if ciphertext.len() % cipher.block_size() != 0 {
        error!(
            "ciphertext length {} is not a multiple of {} bytes",
            ciphertext.len(),
            cipher.block_size()
        );
        return Err(WebauthnCError::Internal);
    }

    let mut pt = vec![0; ciphertext.len() + cipher.block_size()];
    let mut c = Crypter::new(cipher, Mode::Decrypt, key, iv)?;
    c.pad(false);
    let l = c.update(ciphertext, &mut pt)?;
    let l = l + c.finalize(&mut pt[l..])?;
    pt.truncate(l);
    Ok(pt)
}

pub fn hkdf_sha_256(
    salt: &[u8],
    ikm: &[u8],
    info: Option<&[u8]>,
    output: &mut [u8],
) -> Result<(), WebauthnCError> {
    let mut ctx = PkeyCtx::new_id(Id::HKDF)?;
    ctx.derive_init()?;
    ctx.set_hkdf_md(Md::sha256())?;
    ctx.set_hkdf_salt(salt)?;
    ctx.set_hkdf_key(ikm)?;
    if let Some(info) = info {
        ctx.add_hkdf_info(info)?;
    }
    ctx.derive(Some(output))?;
    Ok(())
}

/// Generate a fresh, random P-256 private key
pub fn regenerate() -> Result<EcKey<Private>, WebauthnCError> {
    let ecgroup = get_group()?;
    let eckey = EcKey::generate(&ecgroup)?;
    Ok(eckey)
}

pub fn ecdh(
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

#[cfg(any(doc, feature = "cable"))]
/// Reads `buf` as a compressed or uncompressed P-256 key.
pub fn public_key_from_bytes(buf: &[u8]) -> Result<EcKey<Public>, WebauthnCError> {
    let group = get_group()?;
    let mut ctx = BigNumContext::new()?;
    let point = EcPoint::from_bytes(&group, buf, &mut ctx)?;
    Ok(EcKey::from_public_key(&group, &point)?)
}

#[cfg(any(doc, feature = "cable"))]
/// Converts a P-256 `point` into compressed or uncompressed bytes.
pub fn point_to_bytes(point: &EcPointRef, compressed: bool) -> Result<Vec<u8>, WebauthnCError> {
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

#[cfg(any(doc, feature = "cable"))]
/// Gets the public key for a private `key`.
pub fn public_key_from_private(key: &EcKeyRef<Private>) -> Result<EcKey<Public>, WebauthnCError> {
    Ok(EcKey::from_public_key(key.group(), key.public_key())?)
}

#[cfg(test)]
mod test {
    use super::*;

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
}

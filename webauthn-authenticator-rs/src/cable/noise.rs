//! caBLE version of [Noise protocol][].
//!
//! caBLE uses a variant of [Noise protocol][] to establish a secure channel
//! between the initiator and authenticator in a way that the tunnel server
//! can't decrypt.
//!
//! [Noise protocol]: http://noiseprotocol.org/noise.html
#[cfg(doc)]
use crate::stubs::*;

use std::mem::size_of;

use openssl::{
    ec::{EcKey, EcKeyRef, EcPointRef},
    pkey::{Private, Public},
    symm::{decrypt_aead, encrypt_aead, Cipher},
};

use crate::{cable::Psk, prelude::WebauthnCError};

#[cfg(feature = "cable")]
use crate::crypto::{
    compute_sha256_2, ecdh, hkdf_sha_256, point_to_bytes, public_key_from_bytes, regenerate,
};

const NOISE_KN_PROTOCOL: &[u8; 32] = b"Noise_KNpsk0_P256_AESGCM_SHA256\0";
const NOISE_NK_PROTOCOL: &[u8; 32] = b"Noise_NKpsk0_P256_AESGCM_SHA256\0";
const PADDING_MUL: usize = 32;
pub type EncryptionKey = [u8; 32];
pub type Nonce = [u8; 12];
const OLD_ADDITIONAL_BYTES: [u8; 1] = [/* version */ 2];
const NEW_ADDITIONAL_BYTES: [u8; 0] = [];

#[derive(Clone, Copy)]
pub enum HandshakeType {
    KNpsk0,
    NKpsk0,
}

/// Variations of the Noise protocol used by caBLE.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum NonceType {
    /// Old [Crypter] mode.
    ///
    /// This uses a little-endian nonce and extra additional bytes.
    #[default]
    Old,

    /// New [Crypter] mode.
    ///
    /// This follows the Noise standard with a big-endian nonce and no
    /// additional bytes.
    New,

    /// Handshake ([CableNoise]) mode.
    ///
    /// This uses a big-endian nonce at the wrong byte offset.
    Handshake,
}

/// Implements the Noise [CipherState][0] object, with variations for caBLE's
/// non-standard behaviour.
///
/// Unlike regular Noise, this uses a 32-bit nonce value.
///
/// [0]: https://noiseprotocol.org/noise.html#the-cipherstate-object
pub struct CipherState {
    n: u32,
    nonce_type: NonceType,
    padding: bool,
    k: Option<EncryptionKey>,
}

impl CipherState {
    fn new(nonce_type: NonceType, padding: bool) -> Self {
        Self {
            k: None,
            n: 0,
            nonce_type,
            padding,
        }
    }

    fn init_key(&mut self, key: EncryptionKey) {
        self.k = Some(key);
        self.n = 0;
    }

    pub fn encrypt(&mut self, pt: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>, WebauthnCError> {
        if let Some(k) = self.k.as_ref() {
            if self.n == u32::MAX {
                return Err(WebauthnCError::NonceOverflow);
            }

            let aad = aad.unwrap_or_else(|| {
                if self.nonce_type == NonceType::Old {
                    &OLD_ADDITIONAL_BYTES
                } else {
                    &NEW_ADDITIONAL_BYTES
                }
            });

            let padded = self.padding.then(|| pad(pt));

            let nonce = self.construct_nonce();
            self.n += 1;

            let cipher = Cipher::aes_256_gcm();
            let mut tag = [0; 16];

            let mut encrypted = encrypt_aead(
                cipher,
                k,
                Some(&nonce),
                aad,
                padded.as_deref().unwrap_or(pt),
                &mut tag,
            )?;
            encrypted.reserve(16);
            encrypted.extend_from_slice(&tag);

            Ok(encrypted)
        } else {
            Ok(pt.to_vec())
        }
    }

    pub fn decrypt(&mut self, ct: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>, WebauthnCError> {
        if let Some(k) = self.k.as_ref() {
            if self.n == u32::MAX {
                return Err(WebauthnCError::NonceOverflow);
            }

            let aad = aad.unwrap_or_else(|| {
                if self.nonce_type == NonceType::Old {
                    &OLD_ADDITIONAL_BYTES
                } else {
                    &NEW_ADDITIONAL_BYTES
                }
            });

            let msg_len = ct.len() - 16;
            let nonce = self.construct_nonce();

            let cipher = Cipher::aes_256_gcm();

            let decrypted =
                decrypt_aead(cipher, k, Some(&nonce), aad, &ct[..msg_len], &ct[msg_len..]);

            let mut decrypted = match decrypted {
                Err(e) => {
                    if self.nonce_type == NonceType::Old && self.n == 0 {
                        // Switch to new construction mode
                        trace!("trying new construction");
                        self.nonce_type = NonceType::New;
                        return self.decrypt(ct, None);
                    } else {
                        // throw original error
                        return Err(e.into());
                    }
                }
                Ok(d) => d,
            };

            self.n += 1;

            if self.padding {
                unpad(&mut decrypted)?;
            }

            Ok(decrypted)
        } else {
            Ok(ct.to_vec())
        }
    }

    fn construct_nonce(&self) -> Nonce {
        let mut nonce = [0; size_of::<Nonce>()];

        use NonceType::*;
        match self.nonce_type {
            // First 4 bytes are little-endian nonce
            Old => nonce[..size_of::<u32>()].copy_from_slice(&self.n.to_le_bytes()),
            // Last 4 bytes are big-endian nonce
            New => nonce[size_of::<Nonce>() - size_of::<u32>()..]
                .copy_from_slice(&self.n.to_be_bytes()),
            // First 4 bytes are big-endian nonce
            Handshake => nonce[..size_of::<u32>()].copy_from_slice(&self.n.to_be_bytes()),
        }

        nonce
    }
}

/// Implements the [SymmetricState][] object in Noise, using caBLE's variant of
/// the Noise protocol.
///
/// [SymmetricState]: https://noiseprotocol.org/noise.html#the-symmetricstate-object
pub struct CableNoise {
    ck: [u8; 32],
    h: [u8; 32],

    cipher_state: CipherState,

    ephemeral_key: EcKey<Private>,
    local_identity: Option<EcKey<Private>>,
}

impl CableNoise {
    /// InitializeSymmetric
    fn new(handshake_type: HandshakeType) -> Result<Self, WebauthnCError> {
        // Protocol name is always HASHLEN bytes
        let protocol_name = match handshake_type {
            HandshakeType::KNpsk0 => *NOISE_KN_PROTOCOL,
            HandshakeType::NKpsk0 => *NOISE_NK_PROTOCOL,
        };

        let ephemeral_key = regenerate()?;

        Ok(Self {
            ck: protocol_name,
            h: protocol_name,
            cipher_state: CipherState::new(NonceType::Handshake, false),
            ephemeral_key,
            local_identity: None,
        })
    }

    /// `SymmetricState.MixHash(data)`
    ///
    /// Sets `h = HASH(h || data}`
    fn mix_hash(&mut self, data: &[u8]) {
        self.h = compute_sha256_2(&self.h, data);
    }

    fn mix_hash_point(&mut self, point: &EcPointRef) -> Result<(), WebauthnCError> {
        let point = point_to_bytes(point, false)?;
        self.mix_hash(&point);
        Ok(())
    }

    /// `SymmetricState.MixKey(input_key_material)`
    fn mix_key(&mut self, ikm: &[u8]) -> Result<(), WebauthnCError> {
        let mut o = [0; 64];
        hkdf_sha_256(&self.ck, ikm, None, &mut o)?;
        let (ck, temp_k) = o.split_at(32);
        self.ck.copy_from_slice(ck);
        self.cipher_state
            .init_key(temp_k.try_into().expect("incorrect temp_k length"));
        Ok(())
    }

    /// `SymmetricState.MixKeyAndHash(input_key_material)`
    fn mix_key_and_hash(&mut self, ikm: &[u8]) -> Result<(), WebauthnCError> {
        // https://source.chromium.org/chromium/chromium/src/+/main:device/fido/cable/noise.cc;l=90;drc=38321ee39cd73ac2d9d4400c56b90613dee5fe29
        let mut o = [0; 32 * 3];
        hkdf_sha_256(&self.ck, ikm, None, &mut o)?;
        let (ck, temp) = o.split_at(32);
        let (temp_h, temp_k) = temp.split_at(32);

        self.ck.copy_from_slice(ck);
        self.mix_hash(temp_h);
        self.cipher_state
            .init_key(temp_k.try_into().expect("incorrect temp_k length"));
        Ok(())
    }

    /// `SymmetricState.EncryptAndHash(plaintext)`
    fn encrypt_and_hash(&mut self, pt: &[u8]) -> Result<Vec<u8>, WebauthnCError> {
        let ct = self.cipher_state.encrypt(pt, Some(&self.h))?;
        self.mix_hash(&ct);
        Ok(ct)
    }

    /// `SymmetricState.DecryptAndHash(ciphertext)`
    fn decrypt_and_hash(&mut self, ct: &[u8]) -> Result<Vec<u8>, WebauthnCError> {
        let pt = self.cipher_state.decrypt(ct, Some(&self.h))?;
        self.mix_hash(ct);
        Ok(pt)
    }

    /// `SymmetricState.Split()`
    ///
    /// Returns `write_key, read_key` to create a [Crypter] for encrypting
    /// further transport messages. `write_key` is for messages sent by the
    /// initiator, `read_key` is for messages sent by the authenticator.
    fn traffic_keys(&self) -> Result<(EncryptionKey, EncryptionKey), WebauthnCError> {
        let mut o = [0; size_of::<EncryptionKey>() * 2];
        hkdf_sha_256(&self.ck, &[], None, &mut o)?;

        let mut a = [0; size_of::<EncryptionKey>()];
        let mut b = [0; size_of::<EncryptionKey>()];
        a.copy_from_slice(&o[..size_of::<EncryptionKey>()]);
        b.copy_from_slice(&o[size_of::<EncryptionKey>()..]);
        Ok((a, b))
    }

    fn get_ephemeral_key_public_bytes(&self) -> Result<[u8; 65], WebauthnCError> {
        let mut o = [0; 65];
        let v = point_to_bytes(self.ephemeral_key.public_key(), false)?;
        if v.len() != o.len() {
            error!("unexpected public key length {} != {}", v.len(), o.len());
            return Err(WebauthnCError::Internal);
        }
        o.copy_from_slice(&v);
        Ok(o)
    }

    /// Starts a Noise handshake with a peer as the initiating party (platform).
    ///
    /// Returns `(CableNoise, initial_message)`. `initial_message` is sent to
    /// the responding party ([CableNoise::build_responder]).
    pub fn build_initiator(
        local_identity: Option<&EcKeyRef<Private>>,
        psk: Psk,
        peer_identity: Option<[u8; 65]>,
    ) -> Result<(Self, Vec<u8>), WebauthnCError> {
        // BuildInitialMessage
        // https://source.chromium.org/chromium/chromium/src/+/main:device/fido/cable/v2_handshake.cc;l=880;drc=38321ee39cd73ac2d9d4400c56b90613dee5fe29

        let mut noise = if let Some(peer_identity) = peer_identity {
            // TODO: test
            let mut noise = Self::new(HandshakeType::NKpsk0)?;
            let prologue = [0];
            noise.mix_hash(&prologue);
            noise.mix_hash(&peer_identity);
            noise
        } else if let Some(local_identity) = local_identity {
            let mut noise = Self::new(HandshakeType::KNpsk0)?;
            let prologue = [1];
            noise.mix_hash(&prologue);
            noise.mix_hash_point(local_identity.public_key())?;
            noise.local_identity = Some(local_identity.to_owned());
            noise
        } else {
            error!("build_initiator requires local_identity or peer_identity");
            return Err(WebauthnCError::Internal);
        };

        noise.mix_key_and_hash(&psk)?;

        let ephemeral_key_public_bytes = noise.get_ephemeral_key_public_bytes()?;

        noise.mix_hash(&ephemeral_key_public_bytes);
        noise.mix_key(&ephemeral_key_public_bytes)?;

        if let Some(peer_identity) = peer_identity {
            // TODO: test
            let peer_identity_point = public_key_from_bytes(&peer_identity)?;
            let mut es_key = [0; 32];
            ecdh(
                noise.ephemeral_key.to_owned(),
                peer_identity_point,
                &mut es_key,
            )?;
            noise.mix_key(&es_key)?;
        }

        let ct = noise.encrypt_and_hash(&[])?;

        let mut handshake_message = Vec::with_capacity(ephemeral_key_public_bytes.len() + ct.len());
        handshake_message.extend_from_slice(&ephemeral_key_public_bytes);
        handshake_message.extend_from_slice(&ct);

        Ok((noise, handshake_message))
    }

    /// Processes the response from the responding party (authenticator) and
    /// creates a [Crypter] for further message passing.
    ///
    /// * `response` is the message from the responding party ([CableNoise::build_responder])
    ///
    /// ## Warning
    ///
    /// This function mutates the state of `self`, *even on errors*. This
    /// renders the internal state invalid for "retrying" or future
    /// transactions.
    pub fn process_response(mut self, response: &[u8]) -> Result<Crypter, WebauthnCError> {
        if response.len() < 65 {
            error!("Handshake response too short ({} bytes)", response.len());
            return Err(WebauthnCError::MessageTooShort);
        }

        // ProcessResponse
        let (peer_point_bytes, ct) = response.split_at(65);

        let peer_key = public_key_from_bytes(peer_point_bytes)?;
        let mut shared_key_ee = [0; 32];
        ecdh(
            self.ephemeral_key.to_owned(),
            peer_key.to_owned(),
            &mut shared_key_ee,
        )?;
        self.mix_hash(peer_point_bytes);
        self.mix_key(peer_point_bytes)?;
        self.mix_key(&shared_key_ee)?;

        if let Some(local_identity) = &self.local_identity {
            let mut shared_key_se = [0; 32];
            ecdh(local_identity.to_owned(), peer_key, &mut shared_key_se)?;
            self.mix_key(&shared_key_se)?;
        }

        let pt = self.decrypt_and_hash(ct)?;
        if !pt.is_empty() {
            error!(
                "expected handshake to be empty, got {} bytes: {:02x?}",
                pt.len(),
                &pt
            );
            return Err(WebauthnCError::MessageTooLarge);
        }

        // https://source.chromium.org/chromium/chromium/src/+/main:device/fido/cable/v2_handshake.cc;l=982;drc=38321ee39cd73ac2d9d4400c56b90613dee5fe29
        let (write_key, read_key) = self.traffic_keys()?;

        trace!(?write_key);
        trace!(?read_key);
        Ok(Crypter::new(read_key, write_key))
    }

    /// Starts a Noise handshake with a peer as the responding party (authenticator):
    ///
    /// * `message` is the value from the initiating party ([CableNoise::build_initiator])
    ///
    /// Returns `(crypter, response)`. `response` is sent to the initiating party ([CableNoise::process_response]).
    pub fn build_responder(
        local_identity: Option<&EcKeyRef<Private>>,
        psk: Psk,
        peer_identity: Option<&EcKeyRef<Public>>,
        message: &[u8],
    ) -> Result<(Crypter, Vec<u8>), WebauthnCError> {
        if message.len() < 65 {
            error!("Initiator message too short ({} bytes)", message.len());
            return Err(WebauthnCError::MessageTooShort);
        }

        // RespondToHandshake
        // https://source.chromium.org/chromium/chromium/src/+/main:device/fido/cable/v2_handshake.cc;l=987;drc=38321ee39cd73ac2d9d4400c56b90613dee5fe29
        let (peer_point_bytes, ct) = message.split_at(65);

        let mut noise = if let Some(local_identity) = local_identity {
            let mut noise = Self::new(HandshakeType::NKpsk0)?;
            let prologue = [0];
            noise.mix_hash(&prologue);
            noise.mix_hash_point(local_identity.public_key())?;
            noise.local_identity = Some(local_identity.to_owned());

            noise
        } else if let Some(peer_identity) = peer_identity {
            let mut noise = Self::new(HandshakeType::KNpsk0)?;
            let prologue = [1];
            noise.mix_hash(&prologue);
            noise.mix_hash_point(peer_identity.public_key())?;
            noise
        } else {
            error!("build_initiator requires local_identity or peer_identity");
            return Err(WebauthnCError::Internal);
        };

        noise.mix_key_and_hash(&psk)?;
        noise.mix_hash(peer_point_bytes);
        noise.mix_key(peer_point_bytes)?;

        let peer_point = public_key_from_bytes(peer_point_bytes)?;

        if let Some(local_identity) = local_identity {
            let mut es_key = [0; 32];
            ecdh(
                local_identity.to_owned(),
                peer_point.to_owned(),
                &mut es_key,
            )?;
            noise.mix_key(&es_key)?;
        }

        let pt = noise.decrypt_and_hash(ct)?;
        if !pt.is_empty() {
            error!(
                "expected handshake to be empty, got {} bytes: {:02x?}",
                pt.len(),
                &pt
            );
            return Err(WebauthnCError::MessageTooLarge);
        }

        let ephemeral_key_public_bytes = noise.get_ephemeral_key_public_bytes()?;
        noise.mix_hash(&ephemeral_key_public_bytes);
        noise.mix_key(&ephemeral_key_public_bytes)?;

        let mut shared_key_ee = [0; 32];
        ecdh(
            noise.ephemeral_key.to_owned(),
            peer_point,
            &mut shared_key_ee,
        )?;
        noise.mix_key(&shared_key_ee)?;

        if let Some(peer_identity) = peer_identity {
            let mut shared_key_se = [0; 32];
            ecdh(
                noise.ephemeral_key.to_owned(),
                peer_identity.to_owned(),
                &mut shared_key_se,
            )?;
            noise.mix_key(&shared_key_se)?;
        }

        let ct = noise.encrypt_and_hash(&[])?;
        let mut response_message = Vec::with_capacity(ephemeral_key_public_bytes.len() + ct.len());
        response_message.extend_from_slice(&ephemeral_key_public_bytes);
        response_message.extend_from_slice(&ct);

        let (read_key, write_key) = noise.traffic_keys()?;
        trace!(?read_key);
        trace!(?write_key);
        Ok((Crypter::new(read_key, write_key), response_message))
    }
}

/// Encrypted message passing channel for caBLE.
///
/// This is a pair of [CipherState] objects, one used by the initiator, one used
/// by the authenticator. Messages are encrypted with AES-GCM.
///
/// This has two different construction modes: "old" and "new". This object
/// defaults to "old" mode, and will switch to "new" mode automatically if the
/// first message decrypted was sent in "new" mode.
///
/// "new" mode acts as a pair of regular Noise [CipherState][] objects, with
/// padding.
///
/// "old" mode differences:
///
/// * it always sets an additional byte of `0x02`.
/// * it encodes the nonce as little-endian, rather than big-endian.
///
/// [CipherState]: https://noiseprotocol.org/noise.html#the-cipherstate-object
pub struct Crypter {
    reader: CipherState,
    writer: CipherState,
}

impl Crypter {
    fn new(read_key: EncryptionKey, write_key: EncryptionKey) -> Self {
        let mut reader = CipherState::new(NonceType::Old, true);
        reader.init_key(read_key);

        let mut writer = CipherState::new(NonceType::Old, true);
        writer.init_key(write_key);

        Self { reader, writer }
    }

    /// Switches to "new construction", for caBLE v2.1+.
    pub fn use_new_construction(&mut self) {
        self.reader.nonce_type = NonceType::New;
        self.writer.nonce_type = NonceType::New;
    }

    pub fn encrypt(&mut self, pt: &[u8]) -> Result<Vec<u8>, WebauthnCError> {
        self.writer.encrypt(pt, None)
    }

    pub fn decrypt(&mut self, ct: &[u8]) -> Result<Vec<u8>, WebauthnCError> {
        let pt = self.reader.decrypt(ct, None)?;
        self.writer.nonce_type = self.reader.nonce_type;
        Ok(pt)
    }

    #[cfg(test)]
    /// Returns `true` if the `other` [Crypter] uses "remote side" (swapped)
    /// read and write keys.
    ///
    /// This function is only useful for testing.
    pub(super) fn is_counterparty(&self, other: &Self) -> bool {
        self.reader.k == other.writer.k && self.writer.k == other.reader.k
    }
}

/// Pads a message to a multiple of [PADDING_MUL] bytes.
///
/// See also: [unpad]
fn pad(msg: &[u8]) -> Vec<u8> {
    let padded_len = (msg.len() + PADDING_MUL) & !(PADDING_MUL - 1);
    assert!(padded_len > msg.len());
    let zeros = padded_len - msg.len() - 1;
    assert!(zeros < 256);

    let mut padded = vec![0; padded_len];
    padded[..msg.len()].copy_from_slice(msg);
    padded[padded_len - 1] = zeros as u8;
    padded
}

/// Unpads a message padded with [pad].
fn unpad(msg: &mut Vec<u8>) -> Result<(), WebauthnCError> {
    let padding_len = (msg.last().copied().unwrap_or_default() as usize) + 1;
    if padding_len > msg.len() {
        error!(
            "Invalid caBLE message (padding length {} > message length {})",
            padding_len,
            msg.len()
        );
        return Err(WebauthnCError::Internal);
    }

    msg.truncate(msg.len() - padding_len);
    Ok(())
}

#[cfg(test)]
mod test {
    use std::collections::BTreeMap;

    use base64urlsafedata::Base64UrlSafeData;
    use webauthn_rs_proto::{PubKeyCredParams, PublicKeyCredentialDescriptor, RelyingParty, User};

    use crate::{
        cable::framing::{CableFrame, CableFrameType},
        crypto::public_key_from_private,
        ctap2::{commands::MakeCredentialRequest, CBORCommand},
    };

    use super::*;

    #[test]
    fn noise() {
        let _ = tracing_subscriber::fmt::try_init();
        let identity_key = regenerate().unwrap();
        let identity_pub = public_key_from_private(&identity_key).unwrap();
        let psk = [0; size_of::<Psk>()];

        let (initiator_noise, initiator_msg) =
            CableNoise::build_initiator(Some(&identity_key), psk.to_owned(), None).unwrap();

        let (mut responder_crypt, responder_msg) =
            CableNoise::build_responder(None, psk, Some(&identity_pub), &initiator_msg).unwrap();

        let mut initiator_crypt = initiator_noise.process_response(&responder_msg).unwrap();

        assert!(initiator_crypt.is_counterparty(&responder_crypt));
        responder_crypt.use_new_construction();

        let ct = responder_crypt.encrypt(b"Hello, world!").unwrap();
        let pt = initiator_crypt.decrypt(&ct).unwrap();
        assert_eq!(b"Hello, world!", pt.as_slice());
        // Decrypting the same ciphertext twice should fail, because of the nonce change
        assert!(initiator_crypt.decrypt(&ct).is_err());

        let ct2 = initiator_crypt
            .encrypt(b"The quick brown fox jumps over the lazy dog")
            .unwrap();

        // Decrypting responder's initial ciphertext should fail because of different keys from Noise
        assert!(responder_crypt.decrypt(&ct).is_err());

        // A failure in Crypter shouldn't impact our ability to receive correct ciphertexts, if they're in order
        let pt2 = responder_crypt.decrypt(&ct2).unwrap();
        assert_eq!(
            b"The quick brown fox jumps over the lazy dog",
            pt2.as_slice()
        );
        assert!(responder_crypt.decrypt(&ct).is_err());
    }

    #[test]
    fn encrypt_decrypt() {
        let _ = tracing_subscriber::fmt::try_init();

        let key0 = [123; 32];
        let key1 = [231; 32];

        let mut alice = Crypter::new(key0, key1);
        let mut bob = Crypter::new(key1, key0);
        let mut corrupted = Crypter::new(key1, key0);

        for l in 0..530 {
            let msg = vec![0xff; l];
            let mut crypted = alice.encrypt(&msg).unwrap();
            let decrypted = bob.decrypt(&crypted).unwrap();

            assert_eq!(msg, decrypted);
            assert_eq!(bob.reader.nonce_type, NonceType::Old);
            if l > 0 {
                crypted[(l * 3) % l] ^= 0x01;
            }
            corrupted.reader.n = bob.reader.n;
            assert!(corrupted.decrypt(&crypted).is_err());
        }
    }

    #[test]
    fn encrypt_decrypt_new() {
        let _ = tracing_subscriber::fmt::try_init();

        let key0 = [123; 32];
        let key1 = [231; 32];

        let mut alice = Crypter::new(key0, key1);
        alice.use_new_construction();
        let mut bob = Crypter::new(key1, key0);
        let mut corrupted = Crypter::new(key1, key0);

        for l in 1..5 {
            let msg = vec![0xff; l];
            let mut crypted = alice.encrypt(&msg).unwrap();
            let decrypted = bob.decrypt(&crypted).unwrap();

            assert!(bob.writer.nonce_type == NonceType::New);
            assert_eq!(msg, decrypted);
            if l > 0 {
                crypted[(l * 3) % l] ^= 0x01;
            }
            corrupted.reader.nonce_type = bob.reader.nonce_type;
            corrupted.reader.n = bob.reader.n;
            assert!(corrupted.decrypt(&crypted).is_err());
        }
    }

    #[test]
    fn unencrypted() {
        let mut c = CipherState::new(NonceType::New, true);
        let pt = b"Hello, world!";

        // When CipherState has no key, it should pass through as plaintext and
        // not affect the nonce value.
        let r = c.encrypt(pt, None).unwrap();
        assert_eq!(pt, r.as_slice());
        assert_eq!(0, c.n);

        let r = c.decrypt(pt, None).unwrap();
        assert_eq!(pt, r.as_slice());
        assert_eq!(0, c.n);
    }

    #[test]
    fn construction() {
        let _ = tracing_subscriber::fmt::try_init();
        // Patched chromium to leak its key data
        let write_key = [
            0x1f, 0xba, 0x3c, 0xce, 0x17, 0x62, 0x2c, 0x68, 0x26, 0x8d, 0x9f, 0x75, 0xb5, 0xa8,
            0xa3, 0x35, 0x1b, 0x51, 0x7f, 0x9, 0x6f, 0xb5, 0xe2, 0x94, 0x94, 0x1a, 0xf7, 0xe3,
            0xa6, 0xa8, 0xd6, 0xe1,
        ];
        let read_key = [
            0xe3, 0x4f, 0x1a, 0xa3, 0x74, 0x72, 0x38, 0xc0, 0x4d, 0x3b, 0xd2, 0x5e, 0x7, 0xef,
            0x1b, 0x35, 0xfe, 0xf3, 0x59, 0x0, 0xd, 0x75, 0x56, 0x15, 0xcd, 0x85, 0xbe, 0x27, 0xcf,
            0xc8, 0x7, 0xd1,
        ];
        let req = MakeCredentialRequest {
            client_data_hash: vec![
                0x38, 0x89, 0x28, 0x5c, 0x8c, 0x63, 0x23, 0x95, 0xc, 0xed, 0x7, 0x49, 0x84, 0xf9,
                0xf9, 0x46, 0x3b, 0xc1, 0x73, 0x9b, 0xb6, 0x21, 0xa9, 0xe5, 0xf1, 0xee, 0x8d, 0xd9,
                0x39, 0x3b, 0xa2, 0x80,
            ],
            rp: RelyingParty {
                name: String::from("webauthn.firstyear.id.au"),
                id: String::from("webauthn.firstyear.id.au"),
            },
            user: User {
                id: Base64UrlSafeData::from(vec![
                    0xd6, 0xd7, 0xaa, 0x29, 0x8f, 0xe8, 0x4a, 0x6, 0xaa, 0xde, 0xd7, 0xe4, 0x9d,
                    0x90, 0xa, 0x62,
                ]),
                name: String::from("a"),
                display_name: String::from("a"),
            },
            pub_key_cred_params: vec![
                PubKeyCredParams {
                    type_: String::from("public-key"),
                    alg: -7,
                },
                PubKeyCredParams {
                    type_: String::from("public-key"),
                    alg: -257,
                },
            ],
            exclude_list: vec![PublicKeyCredentialDescriptor {
                type_: String::from("public-key"),
                id: Base64UrlSafeData::from(vec![0, 1, 2, 3]),
                transports: None,
            }],
            options: Some(BTreeMap::from([(String::from("uv"), true)])),
            pin_uv_auth_param: None,
            pin_uv_auth_proto: None,
            enterprise_attest: None,
        };

        let req = CableFrame {
            protocol_version: 1,
            message_type: CableFrameType::Ctap,
            data: req.cbor().unwrap(),
        };

        let expected_req_encoding = [
            0x1, 0x1, 0xa6, 0x1, 0x58, 0x20, 0x38, 0x89, 0x28, 0x5c, 0x8c, 0x63, 0x23, 0x95, 0xc,
            0xed, 0x7, 0x49, 0x84, 0xf9, 0xf9, 0x46, 0x3b, 0xc1, 0x73, 0x9b, 0xb6, 0x21, 0xa9,
            0xe5, 0xf1, 0xee, 0x8d, 0xd9, 0x39, 0x3b, 0xa2, 0x80, 0x2, 0xa2, 0x62, 0x69, 0x64,
            0x78, 0x18, 0x77, 0x65, 0x62, 0x61, 0x75, 0x74, 0x68, 0x6e, 0x2e, 0x66, 0x69, 0x72,
            0x73, 0x74, 0x79, 0x65, 0x61, 0x72, 0x2e, 0x69, 0x64, 0x2e, 0x61, 0x75, 0x64, 0x6e,
            0x61, 0x6d, 0x65, 0x78, 0x18, 0x77, 0x65, 0x62, 0x61, 0x75, 0x74, 0x68, 0x6e, 0x2e,
            0x66, 0x69, 0x72, 0x73, 0x74, 0x79, 0x65, 0x61, 0x72, 0x2e, 0x69, 0x64, 0x2e, 0x61,
            0x75, 0x3, 0xa3, 0x62, 0x69, 0x64, 0x50, 0xd6, 0xd7, 0xaa, 0x29, 0x8f, 0xe8, 0x4a, 0x6,
            0xaa, 0xde, 0xd7, 0xe4, 0x9d, 0x90, 0xa, 0x62, 0x64, 0x6e, 0x61, 0x6d, 0x65, 0x61,
            0x61, 0x6b, 0x64, 0x69, 0x73, 0x70, 0x6c, 0x61, 0x79, 0x4e, 0x61, 0x6d, 0x65, 0x61,
            0x61, 0x4, 0x82, 0xa2, 0x63, 0x61, 0x6c, 0x67, 0x26, 0x64, 0x74, 0x79, 0x70, 0x65,
            0x6a, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x2d, 0x6b, 0x65, 0x79, 0xa2, 0x63, 0x61,
            0x6c, 0x67, 0x39, 0x1, 0x0, 0x64, 0x74, 0x79, 0x70, 0x65, 0x6a, 0x70, 0x75, 0x62, 0x6c,
            0x69, 0x63, 0x2d, 0x6b, 0x65, 0x79, 0x5, 0x81, 0xa2, 0x62, 0x69, 0x64, 0x44, 0x0, 0x1,
            0x2, 0x3, 0x64, 0x74, 0x79, 0x70, 0x65, 0x6a, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x2d,
            0x6b, 0x65, 0x79, 0x7, 0xa1, 0x62, 0x75, 0x76, 0xf5,
        ];

        let r = req.to_bytes().unwrap();

        assert_eq!(r, expected_req_encoding);

        let expected_req_padded = [
            0x1, 0x1, 0xa6, 0x1, 0x58, 0x20, 0x38, 0x89, 0x28, 0x5c, 0x8c, 0x63, 0x23, 0x95, 0xc,
            0xed, 0x7, 0x49, 0x84, 0xf9, 0xf9, 0x46, 0x3b, 0xc1, 0x73, 0x9b, 0xb6, 0x21, 0xa9,
            0xe5, 0xf1, 0xee, 0x8d, 0xd9, 0x39, 0x3b, 0xa2, 0x80, 0x2, 0xa2, 0x62, 0x69, 0x64,
            0x78, 0x18, 0x77, 0x65, 0x62, 0x61, 0x75, 0x74, 0x68, 0x6e, 0x2e, 0x66, 0x69, 0x72,
            0x73, 0x74, 0x79, 0x65, 0x61, 0x72, 0x2e, 0x69, 0x64, 0x2e, 0x61, 0x75, 0x64, 0x6e,
            0x61, 0x6d, 0x65, 0x78, 0x18, 0x77, 0x65, 0x62, 0x61, 0x75, 0x74, 0x68, 0x6e, 0x2e,
            0x66, 0x69, 0x72, 0x73, 0x74, 0x79, 0x65, 0x61, 0x72, 0x2e, 0x69, 0x64, 0x2e, 0x61,
            0x75, 0x3, 0xa3, 0x62, 0x69, 0x64, 0x50, 0xd6, 0xd7, 0xaa, 0x29, 0x8f, 0xe8, 0x4a, 0x6,
            0xaa, 0xde, 0xd7, 0xe4, 0x9d, 0x90, 0xa, 0x62, 0x64, 0x6e, 0x61, 0x6d, 0x65, 0x61,
            0x61, 0x6b, 0x64, 0x69, 0x73, 0x70, 0x6c, 0x61, 0x79, 0x4e, 0x61, 0x6d, 0x65, 0x61,
            0x61, 0x4, 0x82, 0xa2, 0x63, 0x61, 0x6c, 0x67, 0x26, 0x64, 0x74, 0x79, 0x70, 0x65,
            0x6a, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x2d, 0x6b, 0x65, 0x79, 0xa2, 0x63, 0x61,
            0x6c, 0x67, 0x39, 0x1, 0x0, 0x64, 0x74, 0x79, 0x70, 0x65, 0x6a, 0x70, 0x75, 0x62, 0x6c,
            0x69, 0x63, 0x2d, 0x6b, 0x65, 0x79, 0x5, 0x81, 0xa2, 0x62, 0x69, 0x64, 0x44, 0x0, 0x1,
            0x2, 0x3, 0x64, 0x74, 0x79, 0x70, 0x65, 0x6a, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x2d,
            0x6b, 0x65, 0x79, 0x7, 0xa1, 0x62, 0x75, 0x76, 0xf5, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1f,
        ];
        let p = pad(&r);
        assert_eq!(p, expected_req_padded);

        let expected_req_crypted = [
            0x50, 0x62, 0xcf, 0x34, 0x57, 0x1e, 0x8, 0x27, 0xa7, 0xc0, 0x20, 0x7f, 0x7c, 0x0, 0x18,
            0x45, 0x67, 0xd6, 0x13, 0xea, 0xb0, 0xda, 0x8, 0xa, 0xd0, 0x42, 0xd8, 0x6, 0x64, 0xc5,
            0x9d, 0xf7, 0xb0, 0x1a, 0x13, 0xdb, 0x17, 0xfd, 0x27, 0x75, 0x75, 0xcc, 0xff, 0x53,
            0xb6, 0xa3, 0x4f, 0xdb, 0x4f, 0xbc, 0xf8, 0x32, 0xf3, 0xd3, 0x60, 0xf8, 0xe5, 0xa7,
            0xda, 0xee, 0x7f, 0x26, 0x5a, 0x92, 0x53, 0xa9, 0x4, 0xd6, 0xeb, 0xff, 0x2f, 0x93,
            0x70, 0xd3, 0x55, 0x36, 0xd8, 0xbf, 0x5, 0x48, 0x30, 0xaa, 0xad, 0xff, 0xb9, 0x96,
            0xb4, 0x20, 0xb2, 0xb3, 0x17, 0xa, 0xc8, 0xa, 0x83, 0x79, 0x68, 0x23, 0xed, 0x3c, 0x28,
            0x4b, 0x17, 0x7c, 0x23, 0x40, 0xc, 0xa0, 0x12, 0x4d, 0x6a, 0x68, 0x26, 0x3d, 0x39,
            0x78, 0x3c, 0xfe, 0xf0, 0x27, 0x3f, 0xdf, 0x3b, 0xfc, 0xfa, 0xa, 0x6c, 0x33, 0xdf,
            0x31, 0x9b, 0x12, 0x6f, 0x6e, 0x82, 0x90, 0xd2, 0x2c, 0x4c, 0xd3, 0x2a, 0x7a, 0x97,
            0x88, 0x56, 0xba, 0x22, 0x73, 0xd1, 0xbe, 0x1c, 0xa, 0x29, 0x1e, 0x5e, 0xe1, 0x97,
            0x41, 0x6a, 0xa0, 0xf7, 0xa1, 0x4, 0xe4, 0xd0, 0xac, 0x58, 0x2b, 0x70, 0x84, 0x82,
            0x32, 0x6d, 0x5f, 0xf0, 0xf1, 0x76, 0x8c, 0x14, 0x16, 0xd0, 0x16, 0xb1, 0xf8, 0x92,
            0x42, 0xe7, 0xe, 0x80, 0x31, 0x2f, 0xe6, 0xb6, 0xd4, 0x2, 0x9a, 0x40, 0xad, 0xa3, 0x74,
            0xb3, 0x1e, 0x7d, 0x66, 0xfa, 0xc3, 0xba, 0x72, 0x83, 0x94, 0x4b, 0x9b, 0x60, 0xda,
            0x4b, 0x98, 0xf6, 0x78, 0x4, 0x9, 0x5f, 0xd3, 0x9c, 0xd1, 0xd4, 0x5d, 0x75, 0xc9, 0x3d,
            0x2d, 0x86, 0xcb, 0xfc, 0x21, 0x61, 0x6f, 0x9f, 0x1a, 0x57, 0x6c, 0xcf, 0x8c, 0x86,
            0x2e, 0xe1, 0x85, 0x12, 0x5f, 0xc1, 0xed, 0x7e, 0xd2, 0x48, 0x6e, 0x2c, 0x5f, 0xbf,
            0xc3, 0x9c, 0x91, 0x95, 0x97, 0xdd, 0x86, 0xc3, 0x38, 0xe7, 0xdf, 0x55, 0x3d, 0x51,
            0xe8,
        ];
        let mut crypter = Crypter::new(read_key, write_key);
        crypter.use_new_construction();

        let ct = crypter.encrypt(&r).unwrap();

        assert_eq!(ct.len(), expected_req_crypted.len());
        assert_eq!(&ct, &expected_req_crypted);

        let mut peer_crypter = Crypter::new(write_key, read_key);
        let pt = peer_crypter.decrypt(&ct).unwrap();
        assert_eq!(pt, r);
        let msg = CableFrame::from_bytes(1, &pt);
        assert_eq!(msg.message_type, CableFrameType::Ctap);
    }
}

//! Structures for device discovery over BTLE.
#[cfg(doc)]
use crate::stubs::*;

use crypto_glue::{
    block_padding::generic_array::{
        sequence::Split,
        typenum::{U32, U64},
        GenericArray,
    },
    ecdh_p256::{self, EcdhP256EphemeralSecret},
    hmac_s256::{self, HmacSha256Key},
    rand::{rngs::ThreadRng, RngCore},
    traits::Zeroizing,
};
use num_traits::ToPrimitive;
use std::mem::size_of;
use tokio_tungstenite::tungstenite::http::{uri::Builder, Uri};

use crate::{
    cable::{btle::*, handshake::*, tunnel::get_domain, CableRequestType, Psk},
    crypto::{decrypt, encrypt, hkdf_sha_256},
    error::WebauthnCError,
};

type BleAdvert = [u8; size_of::<CableEid>() + 4];
type RoutingId = [u8; 3];
type BleNonce = [u8; 10];
type QrSecret = [u8; 16];

/// Two concatenated [`Aes256Key`s][crypto_glue::aes256::Aes256Key], the encryption key and signing
/// key.
type EidKey = Zeroizing<GenericArray<u8, U64>>;

/// Alias for a non-[`Zeroizing`][] form of [`Aes256Key`][crypto_glue::aes256::Aes256Key], used to
/// reassure Rust's type checker.
type NonZeroingAes256Key = GenericArray<u8, U32>;

type CableEid = [u8; 16];
type TunnelId = [u8; 16];

/// An all-zero AES256 CBC IV.
const ZERO_IV: [u8; 16] = [0; 16];

// const BASE64URL: base64::Config = base64::Config::new(base64::CharacterSet::UrlSafe, false);

#[derive(FromPrimitive, ToPrimitive, Debug, PartialEq, Eq)]
#[repr(u32)]
enum DerivedValueType {
    EIDKey = 1,
    TunnelID = 2,
    Psk = 3,
    PairedSecret = 4,
    IdentityKeySeed = 5,
    PerContactIDSecret = 6,
}

impl DerivedValueType {
    pub fn derive(&self, ikm: &[u8], salt: &[u8], output: &mut [u8]) -> Result<(), WebauthnCError> {
        let typ = self.to_u32().ok_or(WebauthnCError::Internal)?.to_le_bytes();
        hkdf_sha_256(salt, ikm, Some(&typ), output)
    }
}

pub struct Discovery {
    request_type: CableRequestType,
    pub(super) local_identity: EcdhP256EphemeralSecret,
    qr_secret: QrSecret,
    eid_key: EidKey,
}

impl Discovery {
    /// Creates a [Discovery] for a given `request_type`.
    ///
    /// This method generates a random `qr_secret` and `local_identity`, and is
    /// suitable for use by an initiator.
    pub fn new(request_type: CableRequestType) -> Result<Self, WebauthnCError> {
        // chrome_authenticator_request_delegate.cc  ChromeAuthenticatorRequestDelegate::ConfigureCable
        let mut qr_secret: QrSecret = [0; size_of::<QrSecret>()];
        let mut rng = ThreadRng::default();
        rng.try_fill_bytes(&mut qr_secret)?;
        Self::new_with_qr_secret(request_type, qr_secret)
    }

    /// Creates a [Discovery] for a given `request_type` and `qr_secret`.
    ///
    /// This method generates a random `local_identity`, and is suitable for use
    /// by an authenticator.  See [HandshakeV2::to_discovery] for a public API.
    pub(super) fn new_with_qr_secret(
        request_type: CableRequestType,
        qr_secret: QrSecret,
    ) -> Result<Self, WebauthnCError> {
        let local_identity = ecdh_p256::new_secret();
        let mut eid_key: EidKey = EidKey::default();
        DerivedValueType::EIDKey.derive(&qr_secret, &[], &mut eid_key)?;

        Ok(Self {
            request_type,
            local_identity,
            qr_secret,
            eid_key,
        })
    }

    /// Decrypts a Bluetooth service data advertisement with this [Discovery]'s
    /// `eid_key`.
    ///
    /// Returns `Ok(None)` when the advertisement was encrypted using a
    /// different key, or if the advertisement length was incorrct.
    pub fn decrypt_advert<'a>(
        &self,
        advert: impl TryInto<&'a BleAdvert>,
    ) -> Result<Option<Eid>, WebauthnCError> {
        Eid::decrypt_advert(advert, &self.eid_key)
    }

    /// Encrypts an [Eid] with this [Discovery]'s `eid_key`.
    ///
    /// Returns a byte array to be transmitted in as the payload of a Bluetooth
    /// service data advertisement.
    pub fn encrypt_advert(&self, eid: &Eid) -> Result<BleAdvert, WebauthnCError> {
        eid.encrypt_advert(&self.eid_key)
    }

    /// Makes a [HandshakeV2] for this [Discovery].
    ///
    /// This payload includes the `request_type`, public key for the
    /// `local_identity`, and `qr_secret`.
    pub fn make_handshake(&self) -> Result<HandshakeV2, WebauthnCError> {
        let public_key = self.local_identity.public_key();
        HandshakeV2::new(self.request_type, public_key, self.qr_secret)
    }

    /// Waits on a [Scanner] to return a BTLE advertisement which can be
    /// decrypted by data this [Discovery]
    pub async fn wait_for_matching_response(
        &self,
        scanner: &Scanner,
    ) -> Result<Option<Eid>, WebauthnCError> {
        let mut rx = scanner.scan().await?;
        while let Some(a) = rx.recv().await {
            trace!("advert: {:?}", a);
            if let Some(eid) = self.decrypt_advert(a.as_slice())? {
                rx.close();
                return Ok(Some(eid));
            }
        }

        Ok(None)
    }

    /// Derives the tunnel ID associated with this [Discovery]
    pub fn derive_tunnel_id(&self) -> Result<TunnelId, WebauthnCError> {
        let mut tunnel_id: TunnelId = [0; size_of::<TunnelId>()];
        DerivedValueType::TunnelID.derive(&self.qr_secret, &[], &mut tunnel_id)?;
        Ok(tunnel_id)
    }

    /// Derives the pre-shared key for an [Eid] targetting this [Discovery]
    pub fn derive_psk(&self, eid: &Eid) -> Result<Psk, WebauthnCError> {
        let mut psk: Psk = [0; size_of::<Psk>()];
        DerivedValueType::Psk.derive(&self.qr_secret, &eid.as_bytes(), &mut psk)?;
        Ok(psk)
    }

    /// Gets the WebSocket connection URI which the authenticator will use to
    /// connect to the initiator.
    pub fn get_new_tunnel_uri(&self, domain_id: u16) -> Result<Uri, WebauthnCError> {
        if let Some(domain) = get_domain(domain_id) {
            Ok(self.build_new_tunnel_uri(Builder::new().scheme("wss").authority(domain))?)
        } else {
            error!("unknown WebSocket tunnel URI for {:?}", domain_id);
            Err(WebauthnCError::NotSupported)
        }
    }

    /// Builds a WebSocket connection URI which the authenticator will use
    /// to connect to the initiator, using a [Builder] to provide the protocol
    /// and scheme.
    ///
    /// This method is an internal implementation detail. Use
    /// [`get_new_tunnel_uri()`][Self::get_new_tunnel_uri] instead.
    pub(super) fn build_new_tunnel_uri(&self, builder: Builder) -> Result<Uri, WebauthnCError> {
        // https://source.chromium.org/chromium/chromium/src/+/main:device/fido/cable/v2_handshake.cc;l=170;drc=de9f16dcca1d5057ba55973fa85a5b27423d414f
        let tunnel_id = hex::encode_upper(self.derive_tunnel_id()?);
        builder
            .path_and_query(format!("/cable/new/{}", tunnel_id))
            .build()
            .map_err(|e| {
                error!("cannot build WebSocket tunnel URI: {e}");
                WebauthnCError::Internal
            })
    }
}

/// Authenticator-provided payload, sent to the initiator as an encrypted BTLE
/// service data advertisement, which allows it to connect to the authenticator
/// via the tunnel server.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Eid {
    /// The [well-known tunnel server][get_domain] to connect to, chosen by the
    /// authenticator.
    pub tunnel_server_id: u16,

    /// A tunnel server-provided routing ID which allows the initiator to
    /// connect to the authenticator's session.
    pub routing_id: RoutingId,

    /// An authenticator-provided nonce which is used to derive further secrets
    /// during the [CableNoise][super::noise::CableNoise] handshake.
    pub nonce: BleNonce,
}

impl Eid {
    /// Creates a new [Eid] using a random nonce.
    pub fn new(tunnel_server_id: u16, routing_id: RoutingId) -> Result<Self, WebauthnCError> {
        let mut rng = ThreadRng::default();
        let mut nonce: BleNonce = [0; size_of::<BleNonce>()];
        rng.try_fill_bytes(&mut nonce)?;

        Ok(Self {
            tunnel_server_id,
            routing_id,
            nonce,
        })
    }

    /// Converts this [Eid] into unencrypted bytes.
    fn as_bytes(&self) -> CableEid {
        let mut o: CableEid = [0; size_of::<CableEid>()];
        let mut p = 1;
        let mut q = p + size_of::<BleNonce>();
        o[p..q].copy_from_slice(&self.nonce);

        p = q;
        q += size_of::<RoutingId>();
        o[p..q].copy_from_slice(&self.routing_id);

        p = q;
        q += size_of::<u16>();
        o[p..q].copy_from_slice(&self.tunnel_server_id.to_le_bytes());

        o
    }

    /// Parses an [Eid] from unencrypted bytes.
    ///
    /// `eid` must be 16 bytes long.
    ///
    /// Returns `None` on other errors. This generally means the [CableEid] was
    /// encrypted with a different key, because it was intended for a different
    /// initiator.
    fn from_bytes<'a>(eid: impl TryInto<&'a CableEid>) -> Option<Self> {
        let eid: &'a CableEid = eid.try_into().ok()?;
        let mut p = 0;
        if eid[p] != 0 {
            warn!(
                "reserved bits not 0 in decrypted caBLE advertisement, got 0x{:02x}",
                eid[p]
            );
            return None;
        }

        p += 1;
        let mut nonce: BleNonce = [0; size_of::<BleNonce>()];
        let mut q = p + size_of::<BleNonce>();
        nonce.copy_from_slice(&eid[p..q]);

        p = q;
        q += size_of::<RoutingId>();
        let mut routing_id: RoutingId = [0; size_of::<RoutingId>()];
        routing_id.copy_from_slice(&eid[p..q]);

        p = q;
        q += size_of::<u16>();
        let tunnel_server_id = u16::from_le_bytes(eid[p..q].try_into().ok()?);

        let eid = Self {
            nonce,
            routing_id,
            tunnel_server_id,
        };

        // Invalid tunnel server ID is a parse failure
        eid.get_domain_builder().is_some().then_some(eid)
    }

    /// Decrypts and parses a BTLE advertisement with a given key.
    ///
    /// Returns `Ok(None)` if `advert` was the wrong length, `advert` was not
    /// decryptable (or signed) with `key`, the resulting payload was invalid.
    ///
    /// See [Discovery::decrypt_advert] for a public API.
    fn decrypt_advert<'a>(
        advert: impl TryInto<&'a BleAdvert>,
        key: &EidKey,
    ) -> Result<Option<Eid>, WebauthnCError> {
        let advert: &BleAdvert = match advert.try_into() {
            Ok(a) => a,
            Err(_) => {
                // We want to return `None" rather than error here, because BTLE
                // adverts may be any length. This lets us ignore junk
                // advertisements sent with caBLE UUIDs.
                warn!("Incorrect caBLE advertisement length");
                return Ok(None);
            }
        };

        // trace!("Decrypting {:?} with key {:?}", hex::encode(advert), hex::encode(key));
        let (encryption_key, signing_key): (NonZeroingAes256Key, NonZeroingAes256Key) = key.split();
        let mut extended_signing_key = HmacSha256Key::default();
        extended_signing_key[..32].copy_from_slice(&signing_key);
        let calculated_hmac = hmac_s256::oneshot(&extended_signing_key, &advert[..16]).into_bytes();

        if calculated_hmac[..4] != advert[16..20] {
            // We probably saw another nearby caBLE session
            warn!("incorrect HMAC when decrypting caBLE advertisement");
            return Ok(None);
        }

        // HMAC checks out, try to decrypt
        let plaintext = decrypt(&encryption_key.into(), &ZERO_IV.into(), &advert[..16])?;
        Ok(Eid::from_bytes(plaintext.as_slice()))
    }

    /// Converts this [Eid] into an encrypted payload for BLE advertisements.
    ///
    /// See [Discovery::encrypt_advert] for a public API.
    fn encrypt_advert(&self, key: &EidKey) -> Result<BleAdvert, WebauthnCError> {
        let eid = self.as_bytes();
        let (k0, k1): (NonZeroingAes256Key, NonZeroingAes256Key) = key.split();
        let c = encrypt(&k0.into(), &ZERO_IV.into(), &eid)?;

        let mut crypted: BleAdvert = [0; size_of::<BleAdvert>()];
        crypted[..size_of::<CableEid>()].copy_from_slice(&c);

        // Sign the advertisement with HMAC-SHA-256
        let signing_key: HmacSha256Key =
            hmac_s256::key_from_slice(&k1).ok_or(WebauthnCError::Internal)?;
        let calculated_hmac = hmac_s256::oneshot(&signing_key, &crypted[..16]).into_bytes();

        // Take the first 4 bytes of the signature
        crypted[size_of::<CableEid>()..].copy_from_slice(&calculated_hmac[..4]);

        Ok(crypted)
    }

    /// Gets the tunnel server domain for this [Eid].
    fn get_domain_builder(&self) -> Option<Builder> {
        Some(
            Builder::new()
                .scheme("wss")
                .authority(get_domain(self.tunnel_server_id)?),
        )
    }

    /// Gets the Websocket connection URI which the initiator will use to
    /// connect to the authenticator.
    ///
    /// `tunnel_id` is provided by [Discovery::derive_tunnel_id].
    pub fn get_connect_uri(&self, tunnel_id: TunnelId) -> Option<Uri> {
        // https://source.chromium.org/chromium/chromium/src/+/main:device/fido/cable/v2_handshake.cc;l=179;drc=de9f16dcca1d5057ba55973fa85a5b27423d414f
        self.get_domain_builder()
            .and_then(|builder| self.build_connect_uri(builder, tunnel_id))
    }

    /// Builds a WebSocket connection URI which the initiator will use to
    /// connect to the authenticator.
    ///
    /// This method is an internal implementation detail. Use
    /// [`get_connect_uri()`][Self::get_connect_uri] instead.
    pub(super) fn build_connect_uri(&self, builder: Builder, tunnel_id: TunnelId) -> Option<Uri> {
        // https://source.chromium.org/chromium/chromium/src/+/main:device/fido/cable/v2_handshake.cc;l=179;drc=de9f16dcca1d5057ba55973fa85a5b27423d414f
        let routing_id = hex::encode_upper(self.routing_id);
        let tunnel_id = hex::encode_upper(tunnel_id);

        builder
            .path_and_query(format!("/cable/connect/{}/{}", routing_id, tunnel_id))
            .build()
            .ok()
    }

    // TODO: needed for pairing
    // fn get_contact_uri(&self) -> Option<Uri> {
    //     self.get_domain().and_then(|domain| {
    //         let routing_id = base64::encode_config(&self.routing_id, BASE64URL);
    //         Uri::builder()
    //             .scheme("wss")
    //             .authority(domain)
    //             .path_and_query(format!("/cable/contact/{}", routing_id))
    //             .build()
    //             .ok()
    //     })
    // }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn eid_from_bytes() {
        let eid = [
            // Reserved byte
            0, //
            // Nonce
            9, 139, 115, 107, 54, 169, 140, 185, 164, 47, //
            // Routing ID
            9, 10, 11, //
            // Tunnel server ID
            255, 1,
        ];
        let expected = Eid {
            tunnel_server_id: 0x01FF,
            routing_id: [9, 10, 11],
            nonce: [9, 139, 115, 107, 54, 169, 140, 185, 164, 47],
        };
        assert_eq!(Some(expected), Eid::from_bytes(&eid));

        // Reading wrong lengths should fail
        for x in 0..15 {
            assert!(Eid::from_bytes(&eid[..x]).is_none());
        }
        assert!(Eid::from_bytes(&[0; 17][..]).is_none());

        // Setting tunnel server ID to invalid value should fail
        let mut bad = eid;
        bad[15] = 0;
        assert!(Eid::from_bytes(&bad).is_none());

        // Setting reserved byte should fail
        let mut bad = eid;
        bad[0] = 1;
        assert!(Eid::from_bytes(&bad).is_none());
    }

    #[test]
    fn encrypt_decrypt() {
        let _ = tracing_subscriber::fmt::try_init();

        let d = Discovery::new_with_qr_secret(CableRequestType::MakeCredential, [0; 16]).unwrap();
        let c = Eid {
            tunnel_server_id: 0xf980,
            routing_id: [9, 10, 11],
            nonce: [9, 139, 115, 107, 54, 169, 140, 185, 164, 47],
        };

        let advert = d.encrypt_advert(&c).unwrap();

        // Decrypt the encrypted advertisement => same value
        let c2 = d.decrypt_advert(&advert).unwrap().unwrap();
        assert_eq!(c, c2);

        // Make sure URLs stay consistent
        assert_eq!(
            "wss://cable.my4kstlhndi4c.net/cable/new/3EEF97097986413B059EAA2A30D653D4",
            d.get_new_tunnel_uri(c.tunnel_server_id)
                .unwrap()
                .to_string()
        );

        let builder = Builder::new().scheme("ws").authority("localhost:8080");
        assert_eq!(
            "ws://localhost:8080/cable/new/3EEF97097986413B059EAA2A30D653D4",
            d.build_new_tunnel_uri(builder).unwrap().to_string()
        );

        let tunnel_id = d.derive_tunnel_id().unwrap();
        assert_eq!(
            "wss://cable.my4kstlhndi4c.net/cable/connect/090A0B/3EEF97097986413B059EAA2A30D653D4",
            c.get_connect_uri(tunnel_id.to_owned()).unwrap().to_string()
        );

        // Changing the tunnel server ID should work too
        let mut google_eid = c;
        google_eid.tunnel_server_id = 0;
        assert_eq!(
            "wss://cable.ua5v.com/cable/connect/090A0B/3EEF97097986413B059EAA2A30D653D4",
            google_eid
                .get_connect_uri(tunnel_id.to_owned())
                .unwrap()
                .to_string()
        );

        let mut apple_eid = c;
        apple_eid.tunnel_server_id = 1;
        assert_eq!(
            "wss://cable.auth.com/cable/connect/090A0B/3EEF97097986413B059EAA2A30D653D4",
            apple_eid
                .get_connect_uri(tunnel_id.to_owned())
                .unwrap()
                .to_string()
        );

        // Providing a custom builder
        let builder = Builder::new().scheme("ws").authority("localhost:8080");
        assert_eq!(
            "ws://localhost:8080/cable/connect/090A0B/3EEF97097986413B059EAA2A30D653D4",
            c.build_connect_uri(builder, tunnel_id.to_owned())
                .unwrap()
                .to_string()
        );

        // Changing bits fails
        let mut bad = advert;
        bad[0] ^= 1;
        assert!(d.decrypt_advert(&bad).unwrap().is_none());

        // Changing HMAC fails
        let mut bad = advert;
        bad[size_of::<CableEid>()] ^= 1;
        assert!(d.decrypt_advert(&bad).unwrap().is_none());

        // Decrypting an advert with the wrong length returns None, not error
        for x in 0..(advert.len() - 1) {
            assert!(d.decrypt_advert(&advert[..x]).unwrap().is_none());
        }
    }

    #[test]
    fn decrypt_known() {
        let _ = tracing_subscriber::fmt::try_init();
        let qr_secret = [
            1, 254, 166, 247, 196, 128, 116, 147, 220, 37, 111, 158, 172, 247, 86, 201,
        ];

        let discovery =
            Discovery::new_with_qr_secret(CableRequestType::DiscoverableMakeCredential, qr_secret)
                .unwrap();

        assert_eq!(
            "wss://cable.ua5v.com/cable/new/367CBBF5F5085DF4098476AFE4B9B1D2",
            discovery.get_new_tunnel_uri(0).unwrap().to_string(),
        );

        let advert = [
            2, 125, 132, 237, 96, 118, 181, 94, 36, 124, 131, 15, 130, 149, 94, 77, 18, 110, 127,
            67,
        ];

        let r = discovery.decrypt_advert(&advert).unwrap().unwrap();
        trace!("eid: {:?}", r);

        let expected = Eid {
            tunnel_server_id: 0,
            routing_id: [2, 101, 85],
            nonce: [139, 181, 197, 201, 164, 77, 145, 58, 94, 178],
        };
        assert_eq!(expected, r);
        assert_eq!(
            "wss://cable.ua5v.com/cable/connect/026555/367CBBF5F5085DF4098476AFE4B9B1D2",
            r.get_connect_uri(discovery.derive_tunnel_id().unwrap())
                .unwrap()
                .to_string()
        );
    }
}

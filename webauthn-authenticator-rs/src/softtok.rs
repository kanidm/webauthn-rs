use crate::error::WebauthnCError;
use crate::U2FToken;
use crate::{U2FRegistrationData, U2FSignData};
use openssl::{bn, ec, hash, nid, pkey, rand, sign};
use std::collections::HashMap;
use std::iter;
use webauthn_rs_proto::AllowCredentials;

pub struct U2FSoft {
    tokens: HashMap<Vec<u8>, Vec<u8>>,
    counter: u32,
}

impl U2FSoft {
    pub fn new() -> Self {
        U2FSoft {
            tokens: HashMap::new(),
            counter: 0,
        }
    }
}

impl Default for U2FSoft {
    fn default() -> Self {
        Self::new()
    }
}

impl U2FToken for U2FSoft {
    fn perform_u2f_register(
        &mut self,
        // This is rp.id_hash
        app_bytes: Vec<u8>,
        // This is client_data_json_hash
        chal_bytes: Vec<u8>,
        // timeout from options
        _timeout_ms: u64,
        //
        platform_attached: bool,
        resident_key: bool,
        user_verification: bool,
    ) -> Result<U2FRegistrationData, WebauthnCError> {
        if user_verification {
            error!("User Verification not supported by softtoken");
            return Err(WebauthnCError::NotSupported);
        }

        if platform_attached {
            error!("Platform Attachement not supported by softtoken");
            return Err(WebauthnCError::NotSupported);
        }

        if resident_key {
            error!("Resident Keys not supported by softtoken");
            return Err(WebauthnCError::NotSupported);
        }

        // Generate a random credential id
        let mut key_handle: Vec<u8> = Vec::with_capacity(32);
        key_handle.resize_with(32, Default::default);
        rand::rand_bytes(key_handle.as_mut_slice()).map_err(|e| {
            error!("OpenSSL Error -> {:?}", e);
            WebauthnCError::OpenSSL
        })?;

        // Create a new key.
        let ecgroup = ec::EcGroup::from_curve_name(nid::Nid::X9_62_PRIME256V1).map_err(|e| {
            error!("OpenSSL Error -> {:?}", e);
            WebauthnCError::OpenSSL
        })?;

        let eckey = ec::EcKey::generate(&ecgroup).map_err(|e| {
            error!("OpenSSL Error -> {:?}", e);
            WebauthnCError::OpenSSL
        })?;

        // Extract the public x and y coords.
        let ecpub_points = eckey.public_key();

        let mut bnctx = bn::BigNumContext::new().map_err(|e| {
            error!("OpenSSL Error -> {:?}", e);
            WebauthnCError::OpenSSL
        })?;

        let mut xbn = bn::BigNum::new().map_err(|e| {
            error!("OpenSSL Error -> {:?}", e);
            WebauthnCError::OpenSSL
        })?;

        let mut ybn = bn::BigNum::new().map_err(|e| {
            error!("OpenSSL Error -> {:?}", e);
            WebauthnCError::OpenSSL
        })?;

        ecpub_points
            .affine_coordinates_gfp(&ecgroup, &mut xbn, &mut ybn, &mut bnctx)
            .map_err(|e| {
                error!("OpenSSL Error -> {:?}", e);
                WebauthnCError::OpenSSL
            })?;

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
        let ecpriv_der = eckey.private_key_to_der().map_err(|e| {
            error!("OpenSSL Error -> {:?}", e);
            WebauthnCError::OpenSSL
        })?;

        // Now setup to sign.
        let pkey = pkey::PKey::from_ec_key(eckey).map_err(|e| {
            error!("OpenSSL Error -> {:?}", e);
            WebauthnCError::OpenSSL
        })?;

        let mut signer = sign::Signer::new(hash::MessageDigest::sha256(), &pkey).map_err(|e| {
            error!("OpenSSL Error -> {:?}", e);
            WebauthnCError::OpenSSL
        })?;

        // User Presence is asserted by the token refusing to register
        // if not present.
        // Let verificationData be the concatenation of (0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F) (see Section 4.3 of [FIDO-U2F-Message-Formats])
        // Let publicKeyU2F be the concatenation 0x04 || x || y.
        // 0x04 signifies ecc uncompressed.

        let r: [u8; 1] = [0x00];
        let s: [u8; 1] = [0x04];
        let verification_data: Vec<u8> = (&r)
            .iter()
            .chain(app_bytes.iter())
            .chain(chal_bytes.iter())
            .chain(key_handle.iter())
            // This is the public key
            .chain(s.iter())
            .chain(public_key_x.iter())
            .chain(public_key_y.iter())
            .copied()
            .collect();

        // Do the signature
        let signature = signer
            .update(verification_data.as_slice())
            .and_then(|_| signer.sign_to_vec())
            .map_err(|e| {
                error!("OpenSSL Error -> {:?}", e);
                WebauthnCError::OpenSSL
            })?;

        // WARNING: This is lollll
        let att_cert = Vec::new();

        // Okay, now persist the token. We can't fail from here.
        self.tokens.insert(key_handle.clone(), ecpriv_der);

        Ok(U2FRegistrationData {
            public_key_x,
            public_key_y,
            key_handle,
            att_cert,
            signature,
        })
    }

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
        if user_verification {
            error!("User Verification not supported by softtoken");
            return Err(WebauthnCError::NotSupported);
        }

        let cred = allowed_credentials
            .iter()
            .filter_map(|ac| {
                self.tokens
                    .get(&ac.id.0)
                    .map(|v| (ac.id.0.clone(), v.clone()))
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

        let eckey = ec::EcKey::private_key_from_der(pkder.as_slice()).map_err(|e| {
            error!("OpenSSL Error -> {:?}", e);
            WebauthnCError::OpenSSL
        })?;

        let pkey = pkey::PKey::from_ec_key(eckey).map_err(|e| {
            error!("OpenSSL Error -> {:?}", e);
            WebauthnCError::OpenSSL
        })?;

        let mut signer = sign::Signer::new(hash::MessageDigest::sha256(), &pkey).map_err(|e| {
            error!("OpenSSL Error -> {:?}", e);
            WebauthnCError::OpenSSL
        })?;

        // Increment the counter.
        self.counter += 1;
        let counter = self.counter;
        let user_present = 1;

        let verification_data: Vec<u8> = app_bytes
            .iter()
            .chain(iter::once(&user_present))
            .chain(counter.to_be_bytes().iter())
            .chain(chal_bytes.iter())
            .copied()
            .collect();

        let signature = signer
            .update(verification_data.as_slice())
            .and_then(|_| signer.sign_to_vec())
            .map_err(|e| {
                error!("OpenSSL Error -> {:?}", e);
                WebauthnCError::OpenSSL
            })?;

        let appid = Vec::new();

        Ok(U2FSignData {
            appid,
            key_handle,
            counter,
            signature,
            user_present,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::softtok::U2FSoft;
    use crate::WebauthnAuthenticator;
    use webauthn_rs_core::WebauthnCore as Webauthn;

    #[test]
    fn webauthn_authenticator_wan_softtoken() {
        let _ = tracing_subscriber::fmt::try_init();
        let wan = Webauthn::new_unsafe_experts_only(
            "https://localhost:8080/auth",
            "localhost",
            &url::Url::parse("https://localhost:8080").unwrap(),
            None,
            None,
            None,
        );

        let unique_id = [
            158, 170, 228, 89, 68, 28, 73, 194, 134, 19, 227, 153, 107, 220, 150, 238,
        ];
        let display_name = "william";

        let (chal, reg_state) = wan
            .generate_challenge_register(&unique_id, display_name, false)
            .unwrap();

        println!("🍿 challenge -> {:x?}", chal);

        let mut wa = WebauthnAuthenticator::new(U2FSoft::new());
        let r = wa
            .do_registration("https://localhost:8080", chal)
            .map_err(|e| {
                error!("Error -> {:x?}", e);
                e
            })
            .expect("Failed to register");

        let cred = wan.register_credential(&r, &reg_state, None).unwrap();

        let (chal, auth_state) = wan.generate_challenge_authenticate(vec![cred]).unwrap();

        let r = wa
            .do_authentication("https://localhost:8080", chal)
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
}

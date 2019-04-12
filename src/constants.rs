
// Can this ever change?
pub const CHALLENGE_SIZE_BYTES: usize = 32;
pub const AUTHENTICATOR_TIMEOUT: u32 = 6000;

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

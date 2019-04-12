// Can this ever change?
pub const CHALLENGE_SIZE_BYTES: usize = 32;
pub const AUTHENTICATOR_TIMEOUT: u32 = 6000;

#[derive(Debug)]
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

impl Algorithm {
    pub fn new(i: i64) -> Option<Algorithm> {
        match i {
            -7 => Some(Algorithm::ALG_ECDSA_SHA256),
            _ => None,
        }
    }
}

// Needs to take a struct
pub enum AttStmtType {
    X5C,
}

// Can this ever change?
pub const CHALLENGE_SIZE_BYTES: usize = 32;

// WebAuthn L3 §6.5.1 (Attested Credential Data): credentialIdLength "Value MUST be <= 1023"
// However, for compatibility with future PQC key-wrapped-keys, we will use a softer limit
// of 4096 bytes to fit up to ML-DSA-65
pub const CREDENTIAL_ID_MAX_LENGTH: u16 = 4096;

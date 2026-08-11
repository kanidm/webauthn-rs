// Can this ever change?
pub const CHALLENGE_SIZE_BYTES: usize = 32;

// WebAuthn L3 §6.5.1 (Attested Credential Data): credentialIdLength "Value MUST be <= 1023"
pub const CREDENTIAL_ID_MAX_LENGTH: u16 = 1023;

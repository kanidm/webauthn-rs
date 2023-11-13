use std::time::Duration;

// Can this ever change?
pub const CHALLENGE_SIZE_BYTES: usize = 32;
pub const DEFAULT_AUTHENTICATOR_TIMEOUT: Duration = Duration::from_millis(60000);

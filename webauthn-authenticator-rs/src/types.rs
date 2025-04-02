//! Types used in a public API.
//!
//! These types need to be present regardless of which features were selected
//! at build time, because they are part of some other API which doesn't change.

/// caBLE request type.
#[derive(Debug, PartialEq, Eq, Clone, Default, Copy)]
pub enum CableRequestType {
    /// Logging in with an existing credential.
    #[default]
    GetAssertion,

    /// Creating a new, non-discoverable credential.
    MakeCredential,

    /// Creating a new, discoverable credential.
    DiscoverableMakeCredential,
}

/// States that a caBLE connection can be in for
/// [crate::ui::UiCallback::cable_status_update].
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum CableState {
    /// The initiator or authenticator is connecting to the tunnel server.
    ConnectingToTunnelServer,

    /// The authenticator is waiting for the initiator to connect to the tunnel
    /// server, and send a challenge.
    WaitingForInitiatorConnection,

    /// The initiator or authenticator is establishing an encrypted channel.
    Handshaking,

    /// The authenticator is waiting for the initiator to respond.
    WaitingForInitiatorResponse,

    /// The authenticator is waiting for a command from the initiator.
    WaitingForInitiatorCommand,

    /// The initiator or authenticator is processing what it received from the
    /// other side.
    Processing,

    /// The initiator has sent a message to the authenticator, and waiting for
    /// a response. This may be that the device is waiting for some sort of
    /// user verification action (like entering PIN or biometrics) to complete
    /// the operation.
    WaitingForAuthenticatorResponse,
}

// lastEnrollSampleStatus
#[derive(Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EnrollSampleStatus {
    Good = 0x00,
    TooHigh = 0x01,
    TooLow = 0x02,
    TooLeft = 0x03,
    TooRight = 0x04,
    TooFast = 0x05,
    TooSlow = 0x06,
    PoorQuality = 0x07,
    TooSkewed = 0x08,
    TooShort = 0x09,
    MergeFailure = 0x0a,
    AlreadyExists = 0x0b,
    // 0x0c unused
    NoUserActivity = 0x0d,
    NoUserPresenceTransition = 0x0e,
}

impl TryFrom<u32> for EnrollSampleStatus {
    type Error = u32;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(EnrollSampleStatus::Good),
            0x01 => Ok(EnrollSampleStatus::TooHigh),
            0x02 => Ok(EnrollSampleStatus::TooLow),
            0x03 => Ok(EnrollSampleStatus::TooLeft),
            0x04 => Ok(EnrollSampleStatus::TooRight),
            0x05 => Ok(EnrollSampleStatus::TooFast),
            0x06 => Ok(EnrollSampleStatus::TooSlow),
            0x07 => Ok(EnrollSampleStatus::PoorQuality),
            0x08 => Ok(EnrollSampleStatus::TooSkewed),
            0x09 => Ok(EnrollSampleStatus::TooShort),
            0x0a => Ok(EnrollSampleStatus::MergeFailure),
            0x0b => Ok(EnrollSampleStatus::AlreadyExists),
            // 0x0c unused
            0x0d => Ok(EnrollSampleStatus::NoUserActivity),
            0x0e => Ok(EnrollSampleStatus::NoUserPresenceTransition),
            _ => Err(value),
        }
    }
}

use serde::Serialize;

use self::CBORCommand;
use super::*;

/// `authenticatorReset` request type.
/// 
/// This has no parameters or response type. This may not be available over all
/// transports, and generally only works within the first 10 seconds of the
/// authenticator powering up.
/// 
/// Reference: <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorReset>
#[derive(Serialize, Debug, Clone)]
pub struct ResetRequest {}

impl CBORCommand for ResetRequest {
    const CMD: u8 = 0x07;
    const HAS_PAYLOAD: bool = false;
    type Response = NoResponse;
}

use std::str::FromStr;

use serde::{Deserialize, Serialize};
use serde_cbor::Value;
use webauthn_rs_proto::AuthenticatorTransport;

use self::CBORCommand;
use super::*;

// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorReset
#[derive(Serialize, Debug, Clone)]
pub struct ResetRequest {}

impl CBORCommand for ResetRequest {
    const CMD: u8 = 0x07;
    const HAS_PAYLOAD: bool = false;
    type Response = NoResponse;
}

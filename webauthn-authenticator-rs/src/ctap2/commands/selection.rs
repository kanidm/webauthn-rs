use serde::Serialize;

use self::CBORCommand;
use super::*;

/// `authenticatorSelection` request type.
///
/// This feature **requires** FIDO v2.1. v2.1-PRE isn't good enough.
///
/// This has no parameters or response type.
///
/// <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorSelection>
#[derive(Serialize, Debug, Clone)]
pub struct SelectionRequest {}

impl CBORCommand for SelectionRequest {
    const CMD: u8 = 0x0b;
    const HAS_PAYLOAD: bool = false;
    type Response = NoResponse;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::iso7816::ISO7816LengthForm;

    #[test]
    fn selection_request() {
        let req = SelectionRequest {};
        let short = vec![0x80, 0x10, 0, 0, 1, 0xb, 0];
        let ext = vec![0x80, 0x10, 0, 0, 0, 0, 1, 0xb, 0, 0];

        let a = to_short_apdus(&req.cbor().unwrap());
        assert_eq!(1, a.len());
        assert_eq!(short, a[0].to_bytes(&ISO7816LengthForm::ShortOnly).unwrap());
        assert_eq!(short, a[0].to_bytes(&ISO7816LengthForm::Extended).unwrap());

        assert_eq!(
            ext,
            to_extended_apdu(req.cbor().unwrap())
                .to_bytes(&ISO7816LengthForm::Extended)
                .unwrap()
        );
        assert_eq!(
            ext,
            to_extended_apdu(req.cbor().unwrap())
                .to_bytes(&ISO7816LengthForm::ExtendedOnly)
                .unwrap()
        );
        assert!(to_extended_apdu(req.cbor().unwrap())
            .to_bytes(&ISO7816LengthForm::ShortOnly)
            .is_err());
    }
}

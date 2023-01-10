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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::iso7816::ISO7816LengthForm;

    #[test]
    fn reset_request() {
        let req = ResetRequest {};
        let short = vec![0x80, 0x10, 0, 0, 1, 0x7, 0];
        let ext = vec![0x80, 0x10, 0, 0, 0, 0, 1, 0x7, 0, 0];

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

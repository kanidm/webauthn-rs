// https://en.wikipedia.org/wiki/Smart_card_application_protocol_data_unit

pub const APPLET_U2F_V2: [u8; 6] = [0x55, 0x32, 0x46, 0x5f, 0x56, 0x32];
pub const APPLET_FIDO_2_0: [u8; 8] = [0x46, 0x49, 0x44, 0x4f, 0x5f, 0x32, 0x5f, 0x30];
pub const APPLET_DF: [u8; 8] = [
    /* RID */ 0xA0, 0x00, 0x00, 0x06, 0x47, /* PIX */ 0x2F, 0x00, 0x01,
];

pub const FRAG_MAX: usize = 0xF0;

#[cfg(test)]
mod tests {
    //use super::*;
    use crate::cbor::CBORCommand;
    use crate::cbor::*;
    use crate::nfc::*;

    #[cfg(feature = "nfc")]
    #[test]
    fn get_authenticator_info() {
        let req = GetInfoRequest {};
        let short = vec![0x80, 0x10, 0, 0, 1, 0x4, 0];
        let ext = vec![0x80, 0x10, 0, 0, 0, 0, 1, 0x4, 0, 0xff, 0xff];

        let a = req.to_short_apdus().unwrap();
        assert_eq!(1, a.len());
        assert_eq!(short, a[0].to_bytes(ISO7816LengthForm::ShortOnly).unwrap());
        assert_eq!(short, a[0].to_bytes(ISO7816LengthForm::Extended).unwrap());

        assert_eq!(
            ext,
            req.to_extended_apdu()
                .unwrap()
                .to_bytes(ISO7816LengthForm::Extended)
                .unwrap()
        );
        assert_eq!(
            ext,
            req.to_extended_apdu()
                .unwrap()
                .to_bytes(ISO7816LengthForm::ExtendedOnly)
                .unwrap()
        );
        assert!(req
            .to_extended_apdu()
            .unwrap()
            .to_bytes(ISO7816LengthForm::ShortOnly)
            .is_err());
    }
}

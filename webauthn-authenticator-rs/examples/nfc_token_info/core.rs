use pcsc::*;
use std::ffi::CStr;

use webauthn_authenticator_rs::nfc::apdu::*;
use webauthn_authenticator_rs::nfc::*;

fn access_card(card: NFCCard<'_>) {
    info!("Card detected ...");

    match card.select_u2f_v2_applet() {
        Ok(Selected::FIDO_2_1_PRE(mut token)) => {
            info!("Using token {:?}", token);

            token.hack_make_cred();
        }
        _ => {
            unimplemented!();
        }
    }
}

pub(crate) fn event_loop() {
    let mut reader = NFCReader::default();
    info!("Using reader: {:?}", reader);

    while let Ok(card) = reader.wait_for_card() {
        access_card(card);
    }
}

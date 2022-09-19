// use webauthn_authenticator_rs::nfc::*;
use webauthn_authenticator_rs::transport::*;

fn access_card<T: Token>(card: T) {
    info!("Card detected ...");

    match card.select_any() {
        Ok(Selected::FIDO_2_1_PRE(mut token)) => {
            info!("Using token {:?}", token);

            token.hack_make_cred().unwrap();
            token.deselect_applet().unwrap();
        }
        _ => {
            unimplemented!();
        }
    }
}

pub(crate) fn event_loop() {
    let mut reader = AnyTransport::default();
    // let mut reader = NFCReader::default();
    info!("Using reader: {:?}", reader);

    match reader.tokens() {
        Ok(mut tokens) => {
            while let Some(mut card) = tokens.pop() {
                card.init().expect("couldn't init card");
                access_card(card);
            }
        }
        Err(e) => panic!("Error: {:?}", e),
    }
}

use futures::executor::block_on;
// use webauthn_authenticator_rs::nfc::*;
use webauthn_authenticator_rs::{transport::*, ui::Cli, ctap2::CtapAuthenticator};

fn access_card<T: Token>(card: T) {
    info!("Card detected ...");

    let auth = block_on(CtapAuthenticator::new(card, &Cli{}));

    match auth {
        Some(x) => {
            info!("Using token: {:?}", x);
        }
        None => unimplemented!(),
    }
}

pub(crate) fn event_loop() {
    let mut reader = AnyTransport::default();
    // let mut reader = NFCReader::default();
    info!("Using reader: {:?}", reader);

    match reader.tokens() {
        Ok(mut tokens) => {
            while let Some(card) = tokens.pop() {
                access_card(card);
            }
        }
        Err(e) => panic!("Error: {:?}", e),
    }
}

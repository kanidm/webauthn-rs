use futures::executor::block_on;
use webauthn_authenticator_rs::{ctap2::CtapAuthenticator, transport::*, ui::Cli};

fn access_card<T: Token>(card: T) {
    info!("Card detected ...");

    let auth = block_on(CtapAuthenticator::new(card, &Cli {}));

    match auth {
        Some(x) => {
            info!("Using token: {:?}", x);
        }
        None => unimplemented!(),
    }
}

pub(crate) fn event_loop() {
    let mut reader = block_on(AnyTransport::new()).unwrap();
    info!("Using reader: {:?}", reader);

    match reader.tokens() {
        Ok(mut tokens) => {
            while let Some(card) = tokens.pop() {
                access_card(card);
            }
        }
        Err(e) => panic!("Error: {e:?}"),
    }
}

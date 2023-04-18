use webauthn_authenticator_rs::{ctap2::CtapAuthenticator, transport::*, ui::Cli};

async fn access_card<T: Token>(card: T) {
    info!("Card detected ...");

    let auth = CtapAuthenticator::new(card, &Cli {}).await;

    match auth {
        Some(x) => {
            info!("Using token: {:?}", x);
        }
        None => unimplemented!(),
    }
}

pub(crate) async fn event_loop() {
    let mut reader = AnyTransport::new().await.unwrap();
    info!("Using reader: {:?}", reader);

    match reader.tokens() {
        Ok(mut tokens) => {
            while let Some(card) = tokens.pop() {
                access_card(card).await;
            }
        }
        Err(e) => panic!("Error: {e:?}"),
    }
}

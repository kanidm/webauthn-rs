#[macro_use]
extern crate tracing;

use std::io::{stdin, stdout, Write};
use std::ops::Deref;

use futures::executor::block_on;
use webauthn_authenticator_rs::ctap2::CtapAuthenticator;
use webauthn_authenticator_rs::prelude::Url;
use webauthn_authenticator_rs::softtoken::SoftToken;
use webauthn_authenticator_rs::transport::*;
use webauthn_authenticator_rs::ui::{Cli, UiCallback};
use webauthn_authenticator_rs::AuthenticatorBackend;
use webauthn_rs_core::proto::RequestAuthenticationExtensions;
use webauthn_rs_core::WebauthnCore as Webauthn;

fn select_transport<'a, U: UiCallback>(ui: &'a U) -> impl AuthenticatorBackend + 'a {
    let mut reader = AnyTransport::default();
    info!("Using reader: {:?}", reader);

    match reader.tokens() {
        Ok(mut tokens) => {
            while let Some(card) = tokens.pop() {
                let auth = block_on(CtapAuthenticator::new(card, ui));

                match auth {
                    Some(auth) => return auth,
                    None => (),
                }
            }
        }
        Err(e) => panic!("Error: {:?}", e),
    }

    panic!("no card");
}

fn select_provider<'a>(ui: &'a Cli) -> Box<dyn AuthenticatorBackend + 'a> {
    let mut providers: Vec<(&str, fn(&'a Cli) -> Box<dyn AuthenticatorBackend>)> = Vec::new();

    providers.push(("SoftToken", |_| Box::new(SoftToken::new().unwrap().0)));
    providers.push(("CTAP", |ui| Box::new(select_transport(ui))));

    #[cfg(feature = "u2fhid")]
    providers.push(("Mozilla", |_| {
        Box::new(webauthn_authenticator_rs::u2fhid::U2FHid::default())
    }));

    #[cfg(feature = "win10")]
    providers.push(("Windows 10", |_| {
        Box::new(webauthn_authenticator_rs::win10::Win10::default())
    }));

    if providers.is_empty() {
        panic!("oops, no providers available in this build!");
    }

    loop {
        println!("Select a provider:");
        for (i, (name, _)) in providers.iter().enumerate() {
            println!("({}): {}", i + 1, name);
        }

        let mut buf = String::new();
        print!("? ");
        stdout().flush().ok();
        stdin().read_line(&mut buf).expect("Cannot read stdin");
        let selected: Result<u64, _> = buf.trim().parse();
        match selected {
            Ok(v) => {
                if v < 1 || (v as usize) > providers.len() {
                    println!("Input out of range: {}", v);
                } else {
                    let p = providers.remove((v as usize) - 1);
                    println!("Using {}...", p.0);
                    return p.1(&ui);
                }
            }
            Err(_) => println!("Input was not a number"),
        }
        println!();
    }
}

fn main() {
    tracing_subscriber::fmt::init();
    // TODO
    let ui = Cli {};

    let mut u = select_provider(&ui);

    // WARNING: don't use this as an example of how to use the library!
    let wan = Webauthn::new_unsafe_experts_only(
        "https://localhost:8080/auth",
        "localhost",
        vec![url::Url::parse("https://localhost:8080").unwrap()],
        Some(1),
        None,
        None,
    );

    let unique_id = [
        158, 170, 228, 89, 68, 28, 73, 194, 134, 19, 227, 153, 107, 220, 150, 238,
    ];
    let name = "william";

    let (chal, reg_state) = wan
        .generate_challenge_register(&unique_id, name, name, false)
        .unwrap();

    info!("🍿 challenge -> {:x?}", chal);

    let r = u
        .perform_register(
            Url::parse("https://localhost:8080").unwrap(),
            chal.public_key,
            60_000,
        )
        .unwrap();

    let cred = wan.register_credential(&r, &reg_state, None).unwrap();

    trace!(?cred);
    loop {
        let (chal, auth_state) = wan
            .generate_challenge_authenticate(
                vec![cred],
                Some(RequestAuthenticationExtensions {
                    appid: Some("example.app.id".to_string()),
                    uvm: None,
                    hmac_get_secret: None,
                }),
            )
            .unwrap();

        let r = u
            .perform_auth(
                Url::parse("https://localhost:8080").unwrap(),
                chal.public_key,
                60_000,
            )
            .map_err(|e| {
                error!("Error -> {:x?}", e);
                e
            })
            .expect("Failed to auth");
        trace!(?r);

        let auth_res = wan
            .authenticate_credential(&r, &auth_state)
            .expect("webauth authentication denied");

        info!("auth_res -> {:x?}", auth_res);
        let mut buf = String::new();
        println!("Press ENTER to try again, or Ctrl-C to abort");
        stdout().flush().ok();
        stdin().read_line(&mut buf).expect("Cannot read stdin");
    }
}

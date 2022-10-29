#[macro_use]
extern crate tracing;

use std::io::{stdin, stdout, Write};

use webauthn_authenticator_rs::prelude::Url;
use webauthn_authenticator_rs::softtoken::SoftToken;
use webauthn_authenticator_rs::AuthenticatorBackend;
use webauthn_rs_core::proto::RequestAuthenticationExtensions;
use webauthn_rs_core::WebauthnCore as Webauthn;

fn select_provider() -> Box<dyn AuthenticatorBackend> {
    let mut providers: Vec<(&str, fn() -> Box<dyn AuthenticatorBackend>)> = Vec::new();

    providers.push(("SoftToken", || Box::new(SoftToken::new().unwrap().0)));

    #[cfg(feature = "u2fhid")]
    providers.push(("Mozilla", || {
        Box::new(webauthn_authenticator_rs::u2fhid::U2FHid::default())
    }));

    #[cfg(feature = "win10")]
    providers.push(("Windows 10", || {
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
                    return p.1();
                }
            }
            Err(_) => println!("Input was not a number"),
        }
        println!();
    }
}

fn main() {
    tracing_subscriber::fmt::init();

    let mut u = select_provider();

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
}

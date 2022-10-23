#[macro_use]
extern crate tracing;

use clap::{Args, Parser, Subcommand};

use webauthn_authenticator_rs::transport::ctap21pre::Ctap21PreAuthenticator;
use webauthn_authenticator_rs::transport::*;
use webauthn_authenticator_rs::ui::{Cli, UiCallback};

#[derive(Debug, Args)]
pub struct SetPinOpt {
    #[clap(short, long)]
    pub new_pin: String,
}

#[derive(Debug, Args)]
pub struct ChangePinOpt {
    #[clap(short, long)]
    pub old_pin: String,

    #[clap(short, long)]
    pub new_pin: String,
}

#[derive(Debug, Subcommand)]
#[clap(about = "authenticator key manager")]
pub enum Opt {
    /// Show information about the connected FIDO token.
    Info,
    /// Sets a PIN on a FIDO token which does not already have one.
    SetPin(SetPinOpt),
    /// Changes a PIN on a FIDO token which already has a PIN set.
    ChangePin(ChangePinOpt),
}

#[derive(Debug, clap::Parser)]
#[clap(about = "Fido Metadata Service parsing tool")]
pub struct CliParser {
    #[clap(subcommand)]
    pub commands: Opt,
}

fn access_card<T: Token, U: UiCallback>(card: T, ui: U) -> Ctap21PreAuthenticator<T, U> {
    info!("Card detected ...");

    card.auth(ui).expect("couldn't open card")
}

fn select_transport() -> Ctap21PreAuthenticator<AnyToken, Cli> {
    // TODO
    let ui = Cli {};

    let mut reader = AnyTransport::default();
    info!("Using reader: {:?}", reader);

    match reader.tokens() {
        Ok(mut tokens) => {
            while let Some(mut card) = tokens.pop() {
                card.init().expect("couldn't init card");
                return access_card(card, ui);
            }
        }
        Err(e) => panic!("Error: {:?}", e),
    }

    panic!("no card");
}

fn main() {
    println!("DANGER: make sure you only have one key connected");
    let opt = CliParser::parse();
    tracing_subscriber::fmt::init();

    let authenticator = select_transport();

    match opt.commands {
        Opt::Info => {
            let info = authenticator.get_info();
            println!("{:?}", info);
        }

        Opt::SetPin(o) => {
            authenticator
                .set_new_pin(&o.new_pin)
                .expect("Error setting PIN");
        }

        Opt::ChangePin(o) => {
            authenticator
                .change_pin(&o.old_pin, &o.new_pin)
                .expect("Error changing PIN");
        }
    }
}

#[macro_use]
extern crate tracing;

use std::io::{stdin, stdout, Write};

use clap::{ArgAction, Args, Parser, Subcommand};

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

#[derive(Debug, Args)]
pub struct SetMinPinLengthOpt {
    #[clap(short, long)]
    pub length: Option<u32>,
    #[clap(short, long)]
    pub rpids: Option<Vec<String>>,
    #[clap(long, action = ArgAction::SetTrue)]
    pub force_change: bool,
}

#[derive(Debug, Subcommand)]
#[clap(about = "authenticator key manager")]
pub enum Opt {
    /// Show information about the connected FIDO token.
    Info,
    /// Resets the connected FIDO token to factory settings, deleting all keys.
    ///
    /// This command will only work for the first 10 seconds since the token was
    /// plugged in, _may_ only work on _one_ transport (for multi-interface
    /// tokens), and is only _guaranteed_ to work over USB HID.
    FactoryReset,
    /// Toggles the "Always Require User Verification" feature.
    ToggleAlwaysUv,
    SetMinPinLength(SetMinPinLengthOpt),
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

        Opt::FactoryReset => {
            println!("Resetting token to factory settings. Type 'yes' to continue.");
            let mut buf = String::new();
            stdout().flush().ok();
            stdin().read_line(&mut buf).expect("Cannot read stdin");

            if buf == "yes\n" {
                authenticator
                    .factory_reset()
                    .expect("Error resetting token");
            } else {
                panic!("Unexpected response {:?}, exiting!", buf);
            }
        }

        Opt::ToggleAlwaysUv => {
            authenticator.toggle_always_uv().expect("Error toggling UV");
        }

        Opt::SetMinPinLength(o) => {
            if !o.force_change && o.rpids == None && o.length == None {
                panic!("Expected at least one option");
            }
            authenticator
                .set_min_pin_length(
                    o.length,
                    o.rpids.unwrap_or_default(),
                    if o.force_change { Some(true) } else { None },
                )
                .expect("error setting policy");
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

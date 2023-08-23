extern crate tracing;

use std::fs::OpenOptions;

use clap::{Args, Parser, Subcommand};
use webauthn_authenticator_rs::softtoken::{SoftToken, SoftTokenFile};

#[derive(Debug, clap::Parser)]
#[clap(about = "SoftToken management tool")]
pub struct CliParser {
    #[clap(subcommand)]
    pub commands: Opt,
}

#[derive(Debug, Subcommand)]
pub enum Opt {
    Create(CreateArgs),
}

#[derive(Debug, Args)]
pub struct CreateArgs {
    #[clap()]
    pub filename: String,
}

fn main() {
    use Opt::*;

    let opt = CliParser::parse();
    tracing_subscriber::fmt::init();
    match opt.commands {
        Create(args) => {
            let (token, _) = SoftToken::new(false).unwrap();
            let f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(args.filename)
                .unwrap();
            let authenticator = SoftTokenFile::new(token, f);
            drop(authenticator);
        }
    }
}

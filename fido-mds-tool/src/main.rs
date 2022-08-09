// #![deny(warnings)]
#![warn(unused_extern_crates)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]

use clap::Parser;
use clap::{Args, Subcommand};
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use fido_mds::FidoMds;

#[derive(Debug, Args)]
pub struct CommonOpt {
    #[clap(short, long)]
    pub debug: bool,
    /// Path to the MDS file
    #[clap(parse(from_os_str), short = 'p', long = "path")]
    pub path: PathBuf,
}

#[derive(Debug, Subcommand)]
#[clap(about = "Fido Metadata Service parsing tool")]
pub enum Opt {
    /// Parse and display the content of the MDS file
    Parse(CommonOpt),
}

impl Opt {
    fn debug(&self) -> bool {
        match self {
            Opt::Parse(CommonOpt { debug, .. }) => *debug,
        }
    }
}

#[derive(Debug, clap::Parser)]
#[clap(about = "Fido Metadata Service parsing tool")]
pub struct CliParser {
    #[clap(subcommand)]
    pub commands: Opt,
}

fn main() {
    let opt = CliParser::parse();

    let fmt_layer = fmt::layer().with_writer(std::io::stderr);

    let filter_layer = if opt.commands.debug() {
        match EnvFilter::try_new("fido-mds=debug,fido-mds-tool=debug") {
            Ok(f) => f,
            Err(e) => {
                eprintln!("ERROR! Unable to start tracing {:?}", e);
                return;
            }
        }
    } else {
        match EnvFilter::try_from_default_env() {
            Ok(f) => f,
            Err(_) => EnvFilter::new("fido-mds=warn,fido-mds-tool=warn"),
        }
    };

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .init();

    match opt.commands {
        Opt::Parse(CommonOpt { debug: _, path }) => {
            tracing::trace!("{:?}", path);

            let s = match fs::read_to_string(path) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(?e);
                    return;
                }
            };

            match FidoMds::from_str(&s) {
                Ok(mds) => {
                    tracing::info!(%mds, "hooray");
                }
                Err(e) => {
                    tracing::error!(?e);
                }
            }
        }
    }
}

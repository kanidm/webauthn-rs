#![deny(warnings)]
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
use tracing::{debug, trace, warn};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use fido_mds::FidoMds;
use uuid::Uuid;

#[derive(Debug, Args)]
pub struct CommonOpt {
    #[clap(short, long)]
    pub debug: bool,
    /// Path to the MDS file
    #[clap(parse(from_os_str), short = 'p', long = "path")]
    pub path: PathBuf,
}

#[derive(Debug, Args)]
pub struct QueryOpt {
    pub aaguid: Uuid,
    #[clap(flatten)]
    pub common: CommonOpt,
}

#[derive(Debug, Subcommand)]
#[clap(about = "Fido Metadata Service parsing tool")]
pub enum Opt {
    /// Parse and display the list of U2F devices from an MDS file.
    ListU2f(CommonOpt),
    /// Parse and display the list of Fido2 devices from an MDS file.
    ListFido2 {
        #[clap(flatten)]
        common: CommonOpt,
        /// Show extra details about devices.
        #[clap(short = 'x', long = "extra")]
        extra_details: bool,
    },
    /// Query and display metadata for a specific FIDO2 device by its AAGUID
    QueryAaguid(QueryOpt),
}

impl Opt {
    fn debug(&self) -> bool {
        match self {
            Opt::ListU2f(CommonOpt { debug, .. }) | 
            Opt::ListFido2{
                common: CommonOpt { debug, .. },
                ..
            } => {
                *debug
            }
            Opt::QueryAaguid(QueryOpt {
                common: CommonOpt { debug, .. },
                ..
            }) => *debug,
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
        Opt::ListU2f(CommonOpt { debug: _, path }) => {
            trace!("{:?}", path);

            let s = match fs::read_to_string(path) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(?e);
                    return;
                }
            };

            match FidoMds::from_str(&s) {
                Ok(mds) => {
                    debug!("{} fido metadata avaliable", mds.u2f.len());
                    for fd in mds.u2f.values() {
                        eprintln!("{}", fd);
                    }
                }
                Err(e) => {
                    tracing::error!(?e);
                }
            }
        }
        Opt::ListFido2 { 
            common: CommonOpt { debug: _, path },
            extra_details,
        } => {
            trace!("{:?}", path);

            let s = match fs::read_to_string(path) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(?e);
                    return;
                }
            };

            match FidoMds::from_str(&s) {
                Ok(mds) => {
                    debug!("{} fido metadata avaliable", mds.fido2.len());
                    for fd in mds.fido2_description.values() {
                        eprintln!("{}", fd);
                        if extra_details {
                            println!("  authentication_algorithms:");
                            for alg in fd.authentication_algorithms.iter() {
                                println!("    * {}", alg);
                            }

                            println!("  user_verification_details:");
                            for uvm_or in fd.user_verification_details.iter() {
                                let mut first = true;
                                print!("    *");
                                for uvm_and in uvm_or.iter() {
                                    if !first {
                                        print!(" AND");
                                    }
                                    first = false;
                                    print!(" {}", uvm_and);
                                }
                                println!("");
                            }

                        }

                    }
                }
                Err(e) => {
                    tracing::error!(?e);
                }
            }
        }
        Opt::QueryAaguid(QueryOpt {
            aaguid,
            common: CommonOpt { debug: _, path },
        }) => {
            trace!("{:?}", path);

            let s = match fs::read_to_string(path) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(?e);
                    return;
                }
            };

            match FidoMds::from_str(&s) {
                Ok(mds) => {
                    debug!("{} fido metadata avaliable", mds.fido2.len());
                    match mds.fido2.get(&aaguid) {
                        Some(fd) => {
                            println!("aaguid: {}", fd.aaguid);
                            println!("last update: {}", fd.time_of_last_status_change);
                            println!("description: {}", fd.description);
                            println!("authenticator_version: {}", fd.authenticator_version);
                            println!("authentication_algorithms:");
                            for alg in fd.authentication_algorithms.iter() {
                                println!("  {:?}", alg);
                            }
                            println!("public_key_alg_and_encodings: ");
                            for alg in fd.public_key_alg_and_encodings.iter() {
                                println!("  {:?}", alg);
                            }

                            println!("user_verification_details:");
                            for uvm_or in fd.user_verification_details.iter() {
                                println!("-- OR");
                                for uvm_and in uvm_or.iter() {
                                    println!("  AND");
                                    println!("  {}", uvm_and);
                                }
                            }
                            println!("key_protection:");
                            for kp in fd.key_protection.iter() {
                                println!("  {:?}", kp);
                            }
                            println!("is_key_restricted: {}", fd.is_key_restricted);
                            println!(
                                "is_fresh_user_verification_required: {}",
                                fd.is_fresh_user_verification_required
                            );

                            // attestation root certificates

                            println!("supported_extensions:");
                            for se in fd.supported_extensions.iter() {
                                println!(
                                    "  {} - {} - {}",
                                    se.id,
                                    se.fail_if_unknown,
                                    se.data.as_deref().unwrap_or("")
                                );
                            }

                            if let Some(authenticator_info) = &fd.authenticator_get_info {
                                println!("authenticator_get_info: {:?}", authenticator_info);
                            } else {
                                println!("authenticator_get_info: not present")
                            }

                            println!("status_reports:");
                            for sr in fd.status_reports.iter() {
                                println!("  {:?}", sr);
                            }
                        }
                        None => warn!("No metadata associated with {}", aaguid),
                    }
                }
                Err(e) => {
                    tracing::error!(?e);
                }
            }
        }
    }
}

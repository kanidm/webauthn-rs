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
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::rc::Rc;
use std::str::FromStr;
use tracing::{debug, error, info, trace, warn};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use url::Url;

use fido_mds::mds::AuthenticatorStatus;
use fido_mds::query::{AttrValueAssertion, Query};
use fido_mds::FidoMds;
use fido_mds::FIDO2;

const MDS_URL: &str = "https://mds.fidoalliance.org/";

#[derive(Debug, Args)]
pub struct CommonOpt {
    #[clap(short, long)]
    pub debug: bool,
    /// Path to the MDS file
    #[clap(short, long, default_value = "/tmp/mds.blob.jwt")]
    pub path: PathBuf,
}

#[derive(Debug, Args)]
pub struct QueryOpt {
    /// A query over the MDS. This query is "scim" like and supports logical conditions. Examples are
    ///
    /// * "desc cn yubikey"
    /// * "aaguid eq X or aaguid ne Y"
    /// * "status gte l1 and not (aaguid eq Z)"
    ///
    /// Supported query types and operators are:
    ///
    /// * aaguid eq \<uuid\>
    /// * desc eq \<string\>
    /// * desc cnt \<string\>
    /// * status gte [valid|l1|l1+|l2|l2+|l3|l3+]
    /// * states eq [valid|l1|l1+|l2|l2+|l3|l3+]
    /// * transport eq [usb|nfc|lightning|ble|internal]
    /// * uvm cnt [presence|pin_internal|pin_external|fingerprint_internal|handprint_internal|eyeprint_internal|voiceprint_internal|faceprint_internal|faceprint_internal|pattern_internal]
    ///
    pub query: String,
    #[clap(short, long)]
    pub output_cert_roots: bool,
    #[clap(long, hide(true))]
    pub show_insecure_devices: bool,
    #[clap(flatten)]
    pub common: CommonOpt,
}

#[derive(Debug, Subcommand)]
#[clap(about = "Fido Metadata Service parsing tool")]
pub enum Opt {
    /// Fetch the latest copy of the MDS and store it into the provided path.
    Fetch(CommonOpt),

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
    /// Query and display metadata for FIDO2 devices based on a query expression.
    Query(QueryOpt),
}

impl Opt {
    fn debug(&self) -> bool {
        match self {
            Opt::Fetch(CommonOpt { debug, .. })
            | Opt::ListU2f(CommonOpt { debug, .. })
            | Opt::ListFido2 {
                common: CommonOpt { debug, .. },
                ..
            } => *debug,
            Opt::Query(QueryOpt {
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

    let filter_result = EnvFilter::try_from_default_env().or_else(|_| {
        if opt.commands.debug() {
            EnvFilter::try_new("fido_mds=debug,fido_mds_tool=debug")
        } else {
            EnvFilter::try_new("fido_mds=info,fido_mds_tool=info")
        }
    });

    let filter_layer = match filter_result {
        Ok(fr) => fr,
        Err(e) => {
            eprintln!("Failed to setup tracing filter layer {:?}", e);
            return;
        }
    };

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .init();

    match opt.commands {
        Opt::Fetch(CommonOpt { debug: _, path }) => {
            let mds_url = match Url::parse(MDS_URL) {
                Ok(mdsurl) => mdsurl,
                Err(e) => {
                    error!(err = ?e, "Error - invalid MDS URL");
                    return;
                }
            };

            info!("Fetching from {} to {:?}", mds_url, path);

            let mut f = match File::create(path) {
                Ok(f) => f,
                Err(e) => {
                    error!("Failed to open file for MDS - {:?}", e);
                    return;
                }
            };

            let data = match reqwest::blocking::get(mds_url).and_then(|req| req.text()) {
                Ok(data) => data,
                Err(e) => {
                    error!("Failed to fetch MDS - {:?}", e);
                    return;
                }
            };

            if let Err(e) = f.write_all(data.as_bytes()) {
                error!("Failed to write file for MDS - {:?}", e);
            } else {
                info!("Ok!");
            }
        }
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
                    for fd in mds.u2f.iter() {
                        eprintln!("{fd}");
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
                    for fd in mds.fido2.iter() {
                        eprintln!("{fd}");
                        if extra_details {
                            println!("  authentication_algorithms:");
                            for alg in fd.authentication_algorithms.iter() {
                                println!("    * {alg}");
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
                                    print!(" {uvm_and}");
                                }
                                println!();
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::error!(?e);
                }
            }
        }
        Opt::Query(QueryOpt {
            query,
            output_cert_roots,
            show_insecure_devices,
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

            let query = match Query::from_str(&query) {
                Ok(q) => q,
                Err(e) => {
                    tracing::error!(?e, "Failed to parse query");
                    return;
                }
            };

            // For safety, we wrap this in a "gte" for valid authenticators ONLY.
            let query = if show_insecure_devices {
                query
            } else {
                Query::And(
                    Box::new(Query::Not(Box::new(Query::Op(
                        AttrValueAssertion::StatusLt(AuthenticatorStatus::FidoCertified),
                    )))),
                    Box::new(query),
                )
            };

            match FidoMds::from_str(&s) {
                Ok(mds) => {
                    debug!("{} fido metadata avaliable", mds.fido2.len());
                    match mds.fido2_query(&query) {
                        Some(fds) => {
                            if output_cert_roots {
                                display_cert_roots(&fds)
                            } else {
                                display_query_results(&fds)
                            }
                        }
                        None => warn!("No metadata matched query"),
                    }
                }
                Err(e) => {
                    tracing::error!(?e);
                }
            }
        }
    }
}

fn display_cert_roots(fds: &[Rc<FIDO2>]) {
    match FidoMds::fido2_to_attestation_ca_list(fds) {
        Some(att_ca_list) => match serde_json::to_string(&att_ca_list) {
            Ok(list) => println!("{}", list),
            Err(e) => {
                eprintln!("Failed to serialise CA list - {:?}", e);
            }
        },
        None => {
            eprintln!("Invalid MDS data - check errors for more details.")
        }
    }
}

fn display_query_results(fds: &[Rc<FIDO2>]) {
    for fd in fds {
        println!("aaguid: {}", fd.aaguid);
        println!("last update: {}", fd.time_of_last_status_change);
        println!("description: {}", fd.description);
        println!("authenticator_version: {}", fd.authenticator_version);
        println!("authentication_algorithms:");
        for alg in fd.authentication_algorithms.iter() {
            println!("  {alg:?}");
        }
        println!("public_key_alg_and_encodings: ");
        for alg in fd.public_key_alg_and_encodings.iter() {
            println!("  {alg:?}");
        }

        println!("user_verification_details:");
        for uvm_or in fd.user_verification_details.iter() {
            println!("-- OR");
            for uvm_and in uvm_or.iter() {
                println!("  AND");
                println!("  {uvm_and}");
            }
        }
        println!("key_protection:");
        for kp in fd.key_protection.iter() {
            println!("  {kp:?}");
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
            println!("authenticator_get_info: {authenticator_info:#?}");
        } else {
            println!("authenticator_get_info: not present")
        }

        println!("status_reports:");
        for sr in fd.status_reports.iter() {
            println!("  {sr:#?}");
        }

        println!();
    }
    // End fds
}

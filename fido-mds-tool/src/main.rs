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

use fido_mds::query::Query;
use fido_mds::FidoMds;
use fido_mds::{FIDO2, FIDO_MDS_URL};

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
    /// * "desc cnt yubikey"
    ///
    /// * "aaguid eq X or aaguid ne Y"
    ///
    /// * "status gte l1 and not (aaguid eq Z)"
    ///
    /// Supported query types and operators are:
    ///
    /// * aaguid eq \<uuid\>
    ///
    /// * desc eq \<string\>
    ///
    /// * desc cnt \<string\>
    ///
    /// * status gte [valid|l1|l1+|l2|l2+|l3|l3+]
    ///
    /// * states eq [valid|l1|l1+|l2|l2+|l3|l3+]
    ///
    /// * transport eq [usb|nfc|lightning|ble|internal]
    ///
    /// * uvm cnt [presence|pin_internal|pin_external|fingerprint_internal|handprint_internal|eyeprint_internal|voiceprint_internal|faceprint_internal|faceprint_internal|pattern_internal]
    ///
    pub query: String,
    #[clap(short, long)]
    pub output_cert_roots: bool,
    #[clap(short = 'x', long = "extra")]
    extra_details: bool,
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
            eprintln!("Failed to setup tracing filter layer {e:?}");
            return;
        }
    };

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .init();

    match opt.commands {
        Opt::Fetch(CommonOpt { debug: _, path }) => {
            let mds_url = match Url::parse(FIDO_MDS_URL) {
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
                Err(err) => {
                    tracing::error!(?err, "read_to_string");
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
                Err(err) => {
                    tracing::error!(?err, "mds from str");
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
                Err(err) => {
                    tracing::error!(?err, "read_to_string");
                    return;
                }
            };

            let mds = match FidoMds::from_str(&s) {
                Ok(mds) => {
                    debug!("{} fido metadata avaliable", mds.fido2.len());
                    mds
                }
                Err(err) => {
                    tracing::error!(?err, "mds from str");
                    return;
                }
            };

            let query = Query::exclude_compromised_devices();

            match mds.fido2_query(&query) {
                Some(fds) => display_query_results(&fds, extra_details),
                None => {
                    error!("An internal error has occured, please report a bug!");
                }
            }
        }
        Opt::Query(QueryOpt {
            query,
            output_cert_roots,
            show_insecure_devices,
            extra_details,
            common: CommonOpt { debug: _, path },
        }) => {
            trace!("{:?}", path);

            let s = match fs::read_to_string(path) {
                Ok(s) => s,
                Err(err) => {
                    tracing::error!(?err, "read_to_string");
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
                    Box::new(Query::exclude_compromised_devices()),
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
                                display_query_results(&fds, extra_details)
                            }
                        }
                        None => warn!("No metadata matched query"),
                    }
                }
                Err(err) => {
                    tracing::error!(?err, "mds from str");
                }
            }
        }
    }
}

fn display_cert_roots(fds: &[Rc<FIDO2>]) {
    match FidoMds::fido2_to_attestation_ca_list(fds) {
        Some(att_ca_list) => match serde_json::to_string(&att_ca_list) {
            Ok(list) => println!("{list}"),
            Err(e) => {
                eprintln!("Failed to serialise CA list - {e:?}");
            }
        },
        None => {
            eprintln!("Invalid MDS data - check errors for more details.")
        }
    }
}

fn display_query_results(fds: &[Rc<FIDO2>], extra_details: bool) {
    for fd in fds {
        if extra_details {
            println!("description: {}", fd.description);

            println!("  aaguid: {}", fd.aaguid);
            println!("  last update: {}", fd.time_of_last_status_change);
            println!("  authenticator_version: {}", fd.authenticator_version);
            println!("  authentication_algorithms:");
            for alg in fd.authentication_algorithms.iter() {
                println!("    - {alg}");
            }

            /*
            println!("  public_key_alg_and_encodings: ");
            for alg in fd.public_key_alg_and_encodings.iter() {
                println!("    * {alg:?}");
            }
            */

            println!("  user_verification_details:");
            for uvm_or in fd.user_verification_details.iter() {
                let mut first = true;
                print!("    -");
                for uvm_and in uvm_or.iter() {
                    if !first {
                        print!(" AND");
                    }
                    first = false;
                    print!(" {uvm_and}");
                }
                println!();
            }

            println!("  key_protection:");
            for kp in fd.key_protection.iter() {
                println!("    - {kp:?}");
            }
            println!("  is_key_restricted: {}", fd.is_key_restricted);
            println!(
                "  is_fresh_user_verification_required: {}",
                fd.is_fresh_user_verification_required
            );

            if let Some(authenticator_info) = &fd.authenticator_get_info {
                println!("  authenticator_get_info:");
                println!("    versions:");
                for ver in &authenticator_info.versions {
                    println!("      - {ver}");
                }
                println!("    extensions:");
                for extn in &authenticator_info.extensions {
                    println!("      - {extn}");
                }

                // options?

                println!("    transports:");
                for tran in &authenticator_info.transports {
                    println!("      - {tran}");
                }

                if let Some(mpl) = authenticator_info.min_pin_length {
                    println!("    minimum pin length: {mpl}");
                }

                if !authenticator_info.certifications.is_empty() {
                    println!("    certifications:");
                    for (cert, cert_ver) in &authenticator_info.certifications {
                        println!("      - {cert} - {cert_ver}");
                    }
                }

                if let Some(mrk) = authenticator_info.remaining_discoverable_credentials {
                    println!("    resident key slots: {mrk}");
                }
            } else {
                println!("  authenticator_get_info: not present")
            }

            println!("  status_reports:");
            for sr in fd.status_reports.iter() {
                if let Some(e_date) = sr.effective_date() {
                    println!("    - {} - {}", e_date, sr.as_str());
                } else {
                    println!("    - current - {}", sr.as_str());
                }
            }

            println!();
        } else {
            println!("{fd}");
            /*
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
            println!("");
            */
        }
    }
    // End fds
}

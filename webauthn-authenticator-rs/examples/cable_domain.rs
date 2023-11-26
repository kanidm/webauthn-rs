//! Derives caBLE tunnel server hostnames.
//!
//! ```sh
//! cargo run --example cable_domain --features cable -- --help
//! ```
use clap::{error::ErrorKind, ArgGroup, CommandFactory, Parser, ValueHint};
use std::{fmt::Write, net::ToSocketAddrs};
use webauthn_authenticator_rs::cable::get_domain;

#[derive(Debug, clap::Parser)]
#[clap(
    about = "Derives caBLE tunnel server hostnames",
    after_help = "\
When deriving exactly one tunnel server hostname, only the hostname will be \
printed, and an unknown ID will result in an error.

When deriving multiple (or all) tunnel server hostnames, or when using `--csv` \
or `--resolve`, the output will switch to CSV format.

When outputting CSV, entries for unknown tunnel IDs will be an empty string, \
rather than an error."
)]
#[clap(group(
    ArgGroup::new("ids")
        .required(true)
        .args(&["tunnel_server_ids", "all"])
))]
pub struct CliParser {
    /// One or more tunnel server IDs.
    #[clap(value_name = "ID", value_hint = ValueHint::Other)]
    pub tunnel_server_ids: Vec<u16>,

    /// Derives all 65,536 possible tunnel server hostnames.
    #[clap(short, long)]
    pub all: bool,

    /// Enable CSV output mode.
    ///
    /// This is automatically enabled when requesting multiple (or all) tunnel
    /// server IDs, or when using `--resolve`.
    #[clap(short, long)]
    pub csv: bool,

    /// Resolve tunnel server hostnames to IP addresses.
    ///
    /// This generally results in network traffic, so will be slow.
    #[clap(short, long)]
    pub resolve: bool,
}

/// Resolves a hostname to (an) IP address(es) using the system resolver,
/// and return it as a comma-separated list.
///
/// Returns [None] on resolution failure or no results.
fn resolver(hostname: &str) -> Option<String> {
    (hostname, 443).to_socket_addrs().ok().and_then(|addrs| {
        let mut o: String = addrs.fold(String::new(), |mut out, addr| {
            let _ = write!(out, "{},", addr.ip());
            out
        });
        o.pop();

        if o.is_empty() {
            return None;
        }

        Some(o)
    })
}

/// Prints caBLE tunnel server hostnames in CSV format.
fn print_hostnames(i: impl Iterator<Item = u16>, resolve: bool) {
    for domain_id in i {
        let domain = get_domain(domain_id);
        let addrs = if resolve {
            domain.as_deref().and_then(resolver)
        } else {
            None
        }
        .unwrap_or_default();
        let domain = domain.unwrap_or_default();

        if resolve {
            println!("{domain_id},{domain:?},{addrs:?}",);
        } else {
            println!("{domain_id},{domain:?}",);
        }
    }
}

fn main() {
    let opt = CliParser::parse();
    tracing_subscriber::fmt::init();

    if opt.tunnel_server_ids.len() == 1 && !(opt.resolve || opt.csv) {
        let domain_id = opt.tunnel_server_ids[0];
        match get_domain(domain_id) {
            Some(d) => println!("{d}"),
            None => CliParser::command()
                .error(
                    ErrorKind::ValueValidation,
                    format!("unknown tunnel server ID: {domain_id}"),
                )
                .exit(),
        }
    } else {
        if opt.resolve {
            println!("tunnel_server_id,hostname,addrs");
        } else {
            println!("tunnel_server_id,hostname");
        }

        if opt.all {
            print_hostnames(u16::MIN..=u16::MAX, opt.resolve);
        } else {
            print_hostnames(opt.tunnel_server_ids.into_iter(), opt.resolve);
        }
    }
}

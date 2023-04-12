use clap::{ArgGroup, CommandFactory, Parser};
use webauthn_authenticator_rs::cable::get_domain;

#[derive(Debug, clap::Parser)]
#[clap(
    about = "caBLE tunnel server domain list",
    after_help = "\
When exactly one tunnel server ID is requested, only the hostname will be \
printed, and an unknown ID will result in an error.

When multiple (or all) IDs are requested, the output will be in CSV format, \
and any unknown tunnel IDs will result in an empty string.",
)]
#[clap(group(
    ArgGroup::new("ids")
        .required(true)
        .args(&["tunnel-server-ids", "all"])
))]
pub struct CliParser {
    /// Derive one or more caBLE tunnel server hostnames by tunnel server ID.
    #[clap()]
    pub tunnel_server_ids: Vec<u16>,

    /// Lists all possible caBLE tunnel server domain names.
    #[clap(short, long)]
    pub all: bool,
}

fn print_domains(i: impl Iterator<Item = u16>) {
    for domain_id in i {
        println!(
            "{domain_id},{:?}",
            get_domain(domain_id).unwrap_or_default()
        );
    }
}

fn main() {
    let opt = CliParser::parse();
    tracing_subscriber::fmt::init();

    if opt.tunnel_server_ids.len() == 1 {
        let domain_id = opt.tunnel_server_ids[0];
        match get_domain(domain_id) {
            Some(d) => println!("{d}"),
            None => CliParser::command()
                .error(
                    clap::ErrorKind::InvalidValue,
                    format!("unknown domain ID: {domain_id}"),
                )
                .exit(),
        }
    } else {
        println!("tunnel_server_id,hostname");
        if opt.all {
            print_domains(u16::MIN..=u16::MAX);
        } else {
            print_domains(opt.tunnel_server_ids.into_iter());
        }
    }
}

//! A simple command-line wrapper around webauthn-rs

//! There are four subcommands, each representing a server-side step
//! in the basic webauthn protocol:
//!
//! - register-start
//! - register-finish
//! - authenticate-start
//! - authenticate-finish
//!
//! The subcommand specifies which step from the list above is being
//! invoked.  It reads the corresponding JSON Request struct below
//! from stdin, carries out the Webauthn step, and writes the JSON
//! Response struct to stdout if no errors occur.  If an error occurs,
//! it writes a JSON object with a single field, "error", which
//! contains a string describing the error.
//!
//! The Response structs contain fields labeled "client" and "server".
//! The value in the client field should be sent to the browser.  The
//! value in the server field should be used on the server, AND SHOULD
//! NOT BE SENT TO THE CLIENT LEST SECURITY BE COMPROMISED.
//!
//! The --pretty-print option adds indentation and line breaks to the
//! JSON output, making it easier to read.
//!
//! The purpose of this program is twofold: to facilitate testing, and
//! to make it easy to implement Webauthn in other programming
//! languages by doing simple JSON I/O with this program.

use anyhow::Result;
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::io::{self, Read, Write};
use std::process;
use uuid::Uuid;
use webauthn_rs::prelude::*;

#[derive(Deserialize)]
struct RegisterStartRequest {
    exclude_credentials: Vec<CredentialID>,
    rp_id: String,
    rp_origin: String,
    user_display_name: String,
    user_name: String,
    uuid: Uuid,
}

#[derive(Serialize)]
struct RegisterStartResponse {
    client: CreationChallengeResponse,
    server: PasskeyRegistration,
}

#[derive(Deserialize)]
struct RegisterFinishRequest {
    register_public_key_credential: RegisterPublicKeyCredential,
    passkey_registration: PasskeyRegistration,
    rp_id: String,
    rp_origin: String,
}

#[derive(Serialize)]
struct RegisterFinishResponse {
    server: Passkey,
}

#[derive(Deserialize)]
struct AuthenticateStartRequest {
    passkeys: Vec<Passkey>,
    rp_id: String,
    rp_origin: String,
}

#[derive(Serialize)]
struct AuthenticateStartResponse {
    client: RequestChallengeResponse,
    server: PasskeyAuthentication,
}

#[derive(Deserialize)]
struct AuthenticateFinishRequest {
    passkey_authentication: PasskeyAuthentication,
    public_key_credential: PublicKeyCredential,
    rp_id: String,
    rp_origin: String,
}

#[derive(Serialize)]
struct AuthenticateFinishResponse {
    server: AuthenticationResult,
}

#[derive(Debug, Subcommand)]
pub enum Step {
    AuthenticateStart,
    AuthenticateFinish,
    RegisterStart,
    RegisterFinish,
}

#[derive(Debug, Parser)]
#[clap(
    about = "a simple command-line wrapper around webauthn-rs",
    name = "webauthnrs-proxy",
    version = "0.1.0"
)]
pub struct Args {
    #[clap(subcommand)]
    pub step: Step,
    #[clap(long)]
    pub pretty_print: bool,
}

fn main() {
    let args = Args::parse();
    let mut buffer = String::new();

    io::stdin()
        .read_to_string(&mut buffer)
        .expect("Failed to read from stdin.");

    let pp = args.pretty_print;
    let json = match args.step {
        Step::AuthenticateFinish => to_json_result(pp, authenticate_finish(&buffer)),
        Step::AuthenticateStart => to_json_result(pp, authenticate_start(&buffer)),
        Step::RegisterFinish => to_json_result(pp, register_finish(&buffer)),
        Step::RegisterStart => to_json_result(pp, register_start(&buffer)),
    };

    // Output only JSON.  Set exit code.
    println!("{}", json.clone().unwrap_or_else(|s| s));
    io::stdout().flush().unwrap();
    process::exit(if json.is_ok() { 0 } else { 1 });
}

fn to_string_maybe_pretty<T: Serialize>(pretty_print: bool, value: &T) -> String {
    match if pretty_print {
        serde_json::to_string_pretty(value)
    } else {
        serde_json::to_string(value)
    } {
        Ok(v) => v,
        Err(_e) => String::from("{\"error\": \"error serializing value\"}"),
    }
}

fn to_json_result<T: Serialize>(pretty_print: bool, value: Result<T>) -> Result<String, String> {
    match value {
        Ok(v) => Ok(to_string_maybe_pretty(pretty_print, &v)),
        Err(e) => Err(to_string_maybe_pretty(
            pretty_print,
            &json!({ "error": &e.to_string() }),
        )),
    }
}

fn register_start(data: &str) -> Result<RegisterStartResponse> {
    let rsr: RegisterStartRequest = serde_json::from_str(data)?;
    let rp_origin = Url::parse(&rsr.rp_origin)?;
    let builder = WebauthnBuilder::new(&rsr.rp_id, &rp_origin)?;
    let webauthn = builder.build()?;
    let (creation_challenge_response, passkey_registration) = webauthn.start_passkey_registration(
        rsr.uuid,
        &rsr.user_name,
        &rsr.user_display_name,
        Some(rsr.exclude_credentials),
    )?;
    Ok(RegisterStartResponse {
        client: creation_challenge_response,
        server: passkey_registration,
    })
}

fn register_finish(data: &str) -> Result<RegisterFinishResponse> {
    let rfr: RegisterFinishRequest = serde_json::from_str(data)?;
    let pkr: PasskeyRegistration = rfr.passkey_registration;
    let rp_origin = Url::parse(&rfr.rp_origin)?;
    let rpkc: RegisterPublicKeyCredential = rfr.register_public_key_credential;
    let builder = WebauthnBuilder::new(&rfr.rp_id, &rp_origin)?;
    let webauthn = builder.build()?;
    let pk = webauthn.finish_passkey_registration(&rpkc, &pkr)?;
    Ok(RegisterFinishResponse { server: pk })
}

fn authenticate_start(data: &str) -> Result<AuthenticateStartResponse> {
    let asr: AuthenticateStartRequest = serde_json::from_str(data)?;
    let rp_origin = Url::parse(&asr.rp_origin)?;
    let builder = WebauthnBuilder::new(&asr.rp_id, &rp_origin)?;
    let webauthn = builder.build()?;
    let passkeys = asr.passkeys;
    let (request_challenge_response, passkey_authentication) =
        webauthn.start_passkey_authentication(&passkeys)?;
    Ok(AuthenticateStartResponse {
        client: request_challenge_response,
        server: passkey_authentication,
    })
}

fn authenticate_finish(data: &str) -> Result<AuthenticateFinishResponse> {
    let afr: AuthenticateFinishRequest = serde_json::from_str(data)?;
    let rp_origin = Url::parse(&afr.rp_origin)?;
    let pka: PasskeyAuthentication = afr.passkey_authentication;
    let pkc: PublicKeyCredential = afr.public_key_credential;
    let builder = WebauthnBuilder::new(&afr.rp_id, &rp_origin)?;
    let webauthn = builder.build()?;
    let ar = webauthn.finish_passkey_authentication(&pkc, &pka)?;
    Ok(AuthenticateFinishResponse { server: ar })
}

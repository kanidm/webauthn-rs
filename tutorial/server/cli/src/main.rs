use clap::{App, Arg};
use serde::{Deserialize, Serialize};
use serde_json::Result;
use std::io::{self, Read};
use uuid::Uuid;
use webauthn_rs::prelude::*;

// A simple command-line wrapper around webauthn-rs

// There are four commands, each representing a server-side step in
// the basic webauthn protocol:

// - register-start
// - register-finish
// - authenticate-start
// - authenticate-finish

// The program's --step argument specifies which step from the list
// above is being invoked.  It reads the corresponding JSON Request
// struct below from stdin, carries out the webauthn step, and writes
// the JSON Response struct to stdout if no errors occur.

// The Response structs contain fields labeled client and server.  The
// value in the client field should be sent to the browser.  The value
// in the server field should be used on the server, AND SHOULD NOT BE
// SENT TO THE CLIENT LEST SECURITY BE COMPROMISED.

// The purpose of this program is twofold: to facilitate testing, and
// to make it easy to implement webauthn in other programming
// languages by doing simple JSON I/O to this program.

#[derive(Deserialize)]
struct RegisterStartRequest {
    exclude_credentials: Vec<CredentialID>,
    rp_id: String,
    rp_origin: String,
    user_display_name: String,
    user_name: String,
    uuid: String
}

#[derive(Serialize)]
struct RegisterStartResponse {
    client: CreationChallengeResponse,
    server: PasskeyRegistration
}

#[derive(Deserialize)]
struct RegisterFinishRequest {
    register_public_key_credential: RegisterPublicKeyCredential,
    passkey_registration: PasskeyRegistration,
    rp_id: String,
    rp_origin: String
}

#[derive(Serialize)]
struct RegisterFinishResponse {
    server: Passkey
}

#[derive(Deserialize)]
struct AuthenticateStartRequest {
    passkeys: Vec<Passkey>,
    rp_id: String,
    rp_origin: String
}

#[derive(Serialize)]
struct AuthenticateStartResponse {
    client: RequestChallengeResponse,
    server: PasskeyAuthentication
}

#[derive(Deserialize)]
struct AuthenticateFinishRequest {
    passkey_authentication: PasskeyAuthentication,
    public_key_credential: PublicKeyCredential,
    rp_id: String,
    rp_origin: String
}

#[derive(Serialize)]
struct AuthenticateFinishResponse {
    server: AuthenticationResult
}

fn main() {
    let arguments = App::new("webauthn-cli")
	.arg(
	    Arg::with_name("step")
		.long("--step")
		.takes_value(true)
		.required(true)
		.possible_values(&["authenticate-start",
				   "authenticate-finish",
				   "register-start",
				   "register-finish"])
		.help("either authenticate-start, authenticate-finish, register-start, or register-finish"),
	)
	.get_matches();

    let mut buffer = String::new();

    io::stdin().read_to_string(&mut buffer).expect("Failed to read from stdin.");

    let step_value = arguments.value_of("step").unwrap();

    match step_value {
	"authenticate-start" => {let _ = authenticate_start(&buffer);}
	"authenticate-finish" => {let _ = authenticate_finish(&buffer);}
	"register-start" => {let _ = register_start(&buffer);}
	"register-finish" => {let _ = register_finish(&buffer);}
	_ => unreachable!("impossible")
    }
}

fn register_start(data: &str) -> Result<()> {
    let rsr: RegisterStartRequest = serde_json::from_str(data)?;
    let rp_origin = Url::parse(&rsr.rp_origin).expect("Invalid URL.");
    let uuid = Uuid::parse_str(&rsr.uuid).expect("Invalid UUID.");
    let builder = WebauthnBuilder::new(&rsr.rp_id, &rp_origin)
	.expect("Invalid configuration (new).");
    let webauthn = builder.build().expect("Invalid configuration (build).");
    let (creation_challenge_response, passkey_registration) = webauthn
	.start_passkey_registration(
            uuid,
            &rsr.user_name,
            &rsr.user_display_name,
            Some(rsr.exclude_credentials))
	.expect("Failed to start registration.");
    let response = RegisterStartResponse {
	client: creation_challenge_response,
	server: passkey_registration };

    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

fn register_finish(data: &str) -> Result<()> {
    let rfr: RegisterFinishRequest = serde_json::from_str(data)?;
    let pkr: PasskeyRegistration = rfr.passkey_registration;
    let rp_origin = Url::parse(&rfr.rp_origin).expect("Invalid URL.");
    let rpkc: RegisterPublicKeyCredential = rfr.register_public_key_credential;
    let builder = WebauthnBuilder::new(&rfr.rp_id, &rp_origin)
	.expect("Invalid configuration (new).");
    let webauthn = builder.build().expect("Invalid configuration (build).");
    let pk = webauthn.finish_passkey_registration(&rpkc, &pkr)
	.expect("Failed to finish registration.");
    let response = RegisterFinishResponse { server: pk };

    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

fn authenticate_start(data: &str) -> Result<()> {
    let asr: AuthenticateStartRequest = serde_json::from_str(data)?;
    let rp_origin = Url::parse(&asr.rp_origin).expect("Invalid URL.");
    let builder = WebauthnBuilder::new(&asr.rp_id, &rp_origin)
	.expect("Invalid configuration (new).");
    let webauthn = builder.build().expect("Invalid configuration (build).");
    let passkeys = asr.passkeys;
    let (request_challenge_response, passkey_authentication) = webauthn
	.start_passkey_authentication(&passkeys)
	.expect("Failed to start authentication.");
    let response = AuthenticateStartResponse {
	client: request_challenge_response,
    	server: passkey_authentication
    };

    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

fn authenticate_finish(data: &str) -> Result<()> {
    let afr: AuthenticateFinishRequest = serde_json::from_str(data)?;
    let rp_origin = Url::parse(&afr.rp_origin).expect("Invalid URL.");
    let pka: PasskeyAuthentication = afr.passkey_authentication;
    let pkc: PublicKeyCredential = afr.public_key_credential;
    let builder = WebauthnBuilder::new(&afr.rp_id, &rp_origin)
	.expect("Invalid configuration (new).");
    let webauthn = builder.build().expect("Invalid configuration (build).");
    let ar = webauthn.finish_passkey_authentication(&pkc, &pka)
	.expect("Failed to finish authentication.");
    let response = AuthenticateFinishResponse { server: ar };

    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}
use actix_files as fs;
use actix_web::{error, middleware::Logger, post, web, App, HttpResponse, HttpServer};
use dotenv::dotenv;
use std::env;
use std::sync::Mutex;
use thiserror::Error;
use webauthn_rs::{
    ephemeral::WebauthnEphemeralConfig, error::WebauthnError, proto::PublicKeyCredential,
    proto::RegisterPublicKeyCredential, Webauthn,
};

mod webauthn_store;
use webauthn_store::{
    AuthChallengeStore, MemCredentialStore, RegisterChallengeStore, WebauthnChallengeStore,
    WebauthnCredentialStore,
};

#[derive(Error, Debug)]
enum AppError {
    #[error("An Webauthen error has occured: {err}")]
    WebauthnInternalError {
        #[from]
        err: WebauthnError,
    },
    #[error("The supplied user is invalid")]
    InvalidUser,
    #[error("The challenge is invalid")]
    InvalidChallenge,
}

impl error::ResponseError for AppError {}

#[post("/challenge/register/{username}")]
async fn register_challenge(
    web::Path(username): web::Path<String>,
    reg_chall_store: web::Data<Mutex<RegisterChallengeStore>>,
    creds_store: web::Data<Mutex<MemCredentialStore>>,
    webauthn: web::Data<Webauthn<WebauthnEphemeralConfig>>,
) -> Result<HttpResponse, AppError> {
    // Users may have registered the authenticator already
    // Give the authenticator a list of credentials which are linked to the user
    // so the authenticator can decide to not register
    let creds_store = creds_store.lock().unwrap();
    let user_creds = match creds_store.for_user(&username.as_bytes().to_vec()) {
        Some(creds) => Some(creds.iter().map(|c| c.cred_id.clone()).collect()),
        None => None,
    };

    let (client_response, state) = webauthn.generate_challenge_register_options(
        username.as_bytes().to_vec(),
        username.clone(),
        username.clone(),
        user_creds,
        Some(webauthn_rs::proto::UserVerificationPolicy::Required),
    )?;

    // And we need to remember the challenge we send out we can check
    // if the client solved the challenge
    let mut reg_chall_store = reg_chall_store.lock().unwrap();
    reg_chall_store.add(&username.as_bytes().to_vec(), state);

    Ok(HttpResponse::Ok().json(client_response))
}

#[post("/challenge/login/{username}")]
async fn login_challenge(
    web::Path(username): web::Path<String>,
    auth_chall_store: web::Data<Mutex<AuthChallengeStore>>,
    creds_store: web::Data<Mutex<MemCredentialStore>>,
    webauthn: web::Data<Webauthn<WebauthnEphemeralConfig>>,
) -> Result<HttpResponse, AppError> {
    // We don't know which authenticator is present on the clientside
    // so we give him a list of all knowen credentials and the authenticator
    // then chooses the one he knows
    let creds_store = creds_store.lock().unwrap();
    let user_credentials = creds_store
        .for_user(&username.as_bytes().to_vec())
        .ok_or_else(|| AppError::InvalidUser)?;

    let (client_response, state) = webauthn.generate_challenge_authenticate(user_credentials)?;

    // And we need to remember the challenge we send out we can check
    // if the client solved the challenge
    let mut auth_chall_store = auth_chall_store.lock().unwrap();
    auth_chall_store.add(&username.as_bytes().to_vec(), state);

    Ok(HttpResponse::Ok().json(client_response))
}

#[post("/register/{username}")]
async fn register(
    web::Path(username): web::Path<String>,
    registration: web::Json<RegisterPublicKeyCredential>,
    reg_chall_store: web::Data<Mutex<RegisterChallengeStore>>,
    credential_store: web::Data<Mutex<MemCredentialStore>>,
    webauthn: web::Data<Webauthn<WebauthnEphemeralConfig>>,
) -> Result<HttpResponse, AppError> {
    // User must previously requested a challenge and now tries to send
    // the solution of the challenge to the server, so lets find out if
    // we issued this challenge and if so, remove it so it can't be used again
    let mut reg_chall_store = reg_chall_store.lock().unwrap();
    let stored_chall = reg_chall_store
        .pop(&username.as_bytes().to_vec())
        .ok_or_else(|| AppError::InvalidChallenge)?;

    // Well we issued the challenge, now lets add it to the list of registered
    // credentials and associate it with the user
    let credential = webauthn.register_credential(&registration.0, stored_chall, |_| Ok(false))?;
    let mut credential_store = credential_store.lock().unwrap();
    credential_store.add_creds(
        &username.as_bytes().to_vec(),
        credential.cred_id.clone(),
        credential,
    );

    Ok(HttpResponse::Ok().body("Registration completed"))
}

#[post("/login/{username}")]
async fn login(
    web::Path(username): web::Path<String>,
    login: web::Json<PublicKeyCredential>,
    auth_chall_store: web::Data<Mutex<AuthChallengeStore>>,
    credential_store: web::Data<Mutex<MemCredentialStore>>,
    webauthn: web::Data<Webauthn<WebauthnEphemeralConfig>>,
) -> Result<HttpResponse, AppError> {
    // User must previously requested a challenge and now tries to send
    // the solution of the challenge to the server, so lets find out if
    // we issued this challenge and if so remove it so it can't be used again
    let mut auth_chall_store = auth_chall_store.lock().unwrap();
    let stored_auth_chall = auth_chall_store
        .pop(&username.as_bytes().to_vec())
        .ok_or_else(|| AppError::InvalidChallenge)?;

    // Let's check the solution is valid and if the credential uses a counter,
    // we need to update the stored counter for the credential
    let auth_result = webauthn.authenticate_credential(&login.0, stored_auth_chall)?;
    if auth_result.is_some() {
        let (credentials_id, counter) = auth_result.unwrap();
        let mut credential_store = credential_store.lock().unwrap();
        credential_store.set_counter(&username.as_bytes().to_vec(), credentials_id, counter);
    }

    Ok(HttpResponse::Ok().body("Login completed"))
}

async fn index() -> std::io::Result<fs::NamedFile> {
    let path: std::path::PathBuf = "templates/index.html".parse().unwrap();
    Ok(fs::NamedFile::open(path)?)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::init();

    // For demonstatration purposes we use some in-memory storage for the challenges and credentials
    // In actix_web you can use app_data which gets shared between all workers
    let registration_challenge_store = web::Data::new(Mutex::new(RegisterChallengeStore::new()));
    let authentication_challenge_store = web::Data::new(Mutex::new(AuthChallengeStore::new()));
    let credentials_store = web::Data::new(Mutex::new(MemCredentialStore::new()));

    HttpServer::new(move || {
        let webauthn_conf = WebauthnEphemeralConfig::new(
            &env::var("RP_NAME").unwrap_or("localhost".to_string()),
            &env::var("RP_ORIGIN").unwrap_or("http://localhost:8080".to_string()),
            &env::var("RP_ID").unwrap_or("localhost".to_string()),
            None, // We could specifie if we want external authenticator or one that's integrated into the client
        );

        App::new()
            .wrap(Logger::default())
            .app_data(registration_challenge_store.clone())
            .app_data(authentication_challenge_store.clone())
            .app_data(credentials_store.clone())
            .data(Webauthn::new(webauthn_conf))
            .service(
                web::scope("/auth")
                    .service(register_challenge)
                    .service(login_challenge)
                    .service(register)
                    .service(login)
                    .service(fs::Files::new("/static", "./static")),
            )
            .route("/", web::get().to(index))
            .route("/index.html", web::get().to(index))
    })
    .bind(env::var("BIND").unwrap_or("localhost:8080".to_string()))?
    .run()
    .await
}

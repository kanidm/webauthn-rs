use actix::prelude::*;
use webauthn_rs::ephemeral::WebauthnEphemeralConfig;
use webauthn_rs::error::WebauthnError;
use webauthn_rs::proto::{
    CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse,
};
use webauthn_rs::Webauthn;

pub struct WebauthnActor {
    wan: Webauthn<WebauthnEphemeralConfig>,
}

impl Actor for WebauthnActor {
    type Context = Context<Self>;
}

impl WebauthnActor {
    pub fn new(config: WebauthnEphemeralConfig) -> Self {
        WebauthnActor {
            wan: Webauthn::new(config),
        }
    }
}

#[derive(Debug)]
pub struct ChallengeRegister {
    pub username: String,
}

impl Message for ChallengeRegister {
    type Result = Result<CreationChallengeResponse, WebauthnError>;
}

impl Handler<ChallengeRegister> for WebauthnActor {
    type Result = Result<CreationChallengeResponse, WebauthnError>;

    fn handle(&mut self, msg: ChallengeRegister, _: &mut Self::Context) -> Self::Result {
        debug!("handle ChallengeRegister -> {:?}", msg);
        self.wan.generate_challenge_register(msg.username)
    }
}

#[derive(Debug)]
pub struct ChallengeAuthenticate {
    pub username: String,
}

impl Message for ChallengeAuthenticate {
    type Result = Result<RequestChallengeResponse, WebauthnError>;
}

impl Handler<ChallengeAuthenticate> for WebauthnActor {
    type Result = Result<RequestChallengeResponse, WebauthnError>;

    fn handle(&mut self, msg: ChallengeAuthenticate, _: &mut Self::Context) -> Self::Result {
        debug!("handle ChallengeAuthenticate -> {:?}", msg);
        self.wan.generate_challenge_authenticate(msg.username)
    }
}

#[derive(Debug)]
pub struct Register {
    pub username: String,
    pub reg: RegisterPublicKeyCredential,
}

impl Message for Register {
    type Result = Result<(), WebauthnError>;
}

impl Handler<Register> for WebauthnActor {
    type Result = Result<(), WebauthnError>;

    fn handle(&mut self, msg: Register, _: &mut Self::Context) -> Self::Result {
        debug!("handle Register -> {:?}", msg);
        self.wan.register_credential(msg.reg, msg.username)
    }
}

#[derive(Debug)]
pub struct Authenticate {
    pub username: String,
    pub lgn: PublicKeyCredential,
}

impl Message for Authenticate {
    type Result = Result<(), WebauthnError>;
}

impl Handler<Authenticate> for WebauthnActor {
    type Result = Result<(), WebauthnError>;

    fn handle(&mut self, msg: Authenticate, _: &mut Self::Context) -> Self::Result {
        debug!("handle Authenticate -> {:?}", msg);
        self.wan.authenticate_credential(msg.lgn, msg.username)
    }
}

use async_trait::async_trait;
use uuid::Uuid;

use crate::{
    prelude::WebauthnCError, transport::solokey::SoloKeyToken, transport::Token, ui::UiCallback,
};

use super::Ctap20Authenticator;

#[async_trait]
pub trait SoloKeyAuthenticator {
    async fn get_uuid(&mut self) -> Result<Uuid, WebauthnCError>;
}

#[async_trait]
impl<'a, T: Token + SoloKeyToken, U: UiCallback> SoloKeyAuthenticator
    for Ctap20Authenticator<'a, T, U>
{
    async fn get_uuid(&mut self) -> Result<Uuid, WebauthnCError> {
        self.token.get_solokey_uuid().await
    }
}

use crate::server::{models, ServerResult};
use compact_jwt::crypto::JweA256KWEncipher;
use sea_orm::{
    ActiveModelTrait as _, ActiveValue::Set, ColumnTrait as _, DatabaseConnection,
    EntityTrait as _, ModelTrait, PaginatorTrait as _, QueryFilter as _,
};
use time::OffsetDateTime;
use webauthn_rs::prelude::*;

pub struct ServerState {
    pub webauthn: Webauthn,
    pub db: DatabaseConnection,
    pub wrap_key: JweA256KWEncipher,
    /// Server sets the `Secure` bit on Cookies.
    pub secure: bool,
}

impl ServerState {
    pub fn new(webauthn: Webauthn, db: DatabaseConnection, secure: bool) -> ServerResult<Self> {
        Ok(Self {
            webauthn,
            db,
            // TODO: load from config
            wrap_key: JweA256KWEncipher::generate_ephemeral()?,
            secure,
        })
    }

    /// Get a [User][models::account::Model] by `id`.
    pub async fn get_user_by_id(&self, id: Uuid) -> ServerResult<Option<models::account::Model>> {
        Ok(models::account::Entity::find_by_id(id)
            .one(&self.db)
            .await?)
    }

    /// Get a [User][models::account::Model] by `username`.
    pub async fn get_user_by_username(
        &self,
        username: &str,
    ) -> ServerResult<Option<models::account::Model>> {
        Ok(models::account::Entity::find()
            .filter(models::account::Column::Username.eq(username))
            .one(&self.db)
            .await?)
    }

    pub async fn get_or_create_user(
        &self,
        username: String,
    ) -> ServerResult<(models::account::Model, bool)> {
        if let Some(account) = self.get_user_by_username(&username).await? {
            return Ok((account, true));
        }

        let account = models::account::ActiveModel {
            id: Set(Uuid::new_v4()),
            created: Set(OffsetDateTime::now_utc()),
            username: Set(username),
        };

        let account = account.insert(&self.db).await?;

        Ok((account, false))
    }

    pub async fn get_passkeys_for_account(
        &self,
        account: &models::account::Model,
    ) -> ServerResult<Vec<models::passkey::Model>> {
        Ok(account
            .find_related(models::passkey::Entity)
            .all(&self.db)
            .await?)
    }

    /// Get the number of [Passkeys][Passkey] enrolled for an [Account][models::account::Model].
    pub async fn get_passkey_count_for_account(
        &self,
        account: &models::account::Model,
    ) -> ServerResult<u64> {
        Ok(account
            .find_related(models::passkey::Entity)
            .count(&self.db)
            .await?)
    }

    pub async fn add_passkey_for_account(
        &self,
        account: &models::account::Model,
        cred: Passkey,
    ) -> ServerResult<models::passkey::Model> {
        let passkey = models::passkey::ActiveModel {
            id: Set(Uuid::new_v4()),
            created: Set(OffsetDateTime::now_utc()),
            account_id: Set(account.id),
            cred: Set(cred.into()),
        };

        let passkey = passkey.insert(&self.db).await?;

        Ok(passkey)
    }

    // TODO: memory management; removing excessive entries.
}

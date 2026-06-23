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
    pub fn new(
        webauthn: Webauthn,
        db: DatabaseConnection,
        wrap_key: JweA256KWEncipher,
        secure: bool,
    ) -> ServerResult<Self> {
        Ok(Self {
            webauthn,
            db,
            wrap_key,
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

    /// Get all enrolled [Passkeys][Passkey] for an [Account][models::account::Model].
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

    /// Add a [Passkey][] as an authorised credential for an [Account][models::account::Model].
    pub async fn add_passkey_for_account(
        &self,
        account: &models::account::Model,
        cred: Passkey,
        mut label: String,
    ) -> ServerResult<models::passkey::Model> {
        const MAX_LABEL_BYTE_LENGTH: usize = 64;

        // Truncate the label to 64 bytes on a `char` boundary
        // (which may not be a grapheme boundary)
        if label.len() > MAX_LABEL_BYTE_LENGTH {
            let mut last_p = 0;
            for (p, _) in label.char_indices() {
                if p > MAX_LABEL_BYTE_LENGTH {
                    label.truncate(last_p);
                    break;
                }
                last_p = p;
            }
        }

        let passkey = models::passkey::ActiveModel {
            id: Set(Uuid::new_v4()),
            created: Set(OffsetDateTime::now_utc()),
            account_id: Set(account.id),
            cred: Set(cred.into()),
            label: Set(label),
        };

        let passkey = passkey.insert(&self.db).await?;

        Ok(passkey)
    }

    // TODO: memory management; removing excessive entries.
}

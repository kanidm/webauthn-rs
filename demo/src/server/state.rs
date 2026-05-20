use crate::server::{models, ServerResult};
use concread::CowCell;
use sea_orm::{
    ActiveModelTrait as _, ActiveValue::Set, ColumnTrait as _, DatabaseConnection,
    EntityTrait as _, ModelTrait, QueryFilter as _,
};
use std::collections::BTreeMap;
use time::OffsetDateTime;
use webauthn_rs::prelude::*;

pub struct ServerState {
    pub webauthn: Webauthn,
    pub db: DatabaseConnection,
    pub registrations: CowCell<BTreeMap<Uuid, PasskeyRegistration>>,
    pub authentications: CowCell<BTreeMap<Uuid, PasskeyAuthentication>>,
}

impl ServerState {
    pub fn new(webauthn: Webauthn, db: DatabaseConnection) -> ServerResult<Self> {
        Ok(Self {
            webauthn,
            db,
            registrations: CowCell::new(BTreeMap::new()),
            authentications: CowCell::new(BTreeMap::new()),
        })
    }

    pub async fn get_user_by_username(
        &self,
        username: &str,
    ) -> ServerResult<Option<models::account::Model>> {
        let u = models::account::Entity::find()
            .filter(models::account::Column::Username.eq(username))
            .one(&self.db)
            .await?;
        Ok(u)
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

    pub async fn add_passkey_for_user_id(
        &self,
        account_id: Uuid,
        cred: Passkey,
    ) -> ServerResult<models::passkey::Model> {
        let passkey = models::passkey::ActiveModel {
            id: Set(Uuid::new_v4()),
            created: Set(OffsetDateTime::now_utc()),
            account_id: Set(account_id),
            cred: Set(cred.into()),
        };

        let passkey = passkey.insert(&self.db).await?;

        Ok(passkey)
    }

    // TODO: memory management; removing excessive entries.
}

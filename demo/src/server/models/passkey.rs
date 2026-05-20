use sea_orm::{FromJsonQueryResult, entity::prelude::*};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;
use webauthn_rs::prelude::Passkey;

/// Wrapped [Passkey] type that serialises to/from JSON.
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, FromJsonQueryResult)]
pub struct WrappedPasskey(Passkey);

impl From<Passkey> for WrappedPasskey {
    fn from(value: Passkey) -> Self {
        Self(value)
    }
}

impl From<WrappedPasskey> for Passkey {
    fn from(value: WrappedPasskey) -> Self {
        value.0
    }
}

impl AsRef<Passkey> for WrappedPasskey {
    fn as_ref(&self) -> &Passkey {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "passkeys")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    pub created: OffsetDateTime,
    pub account_id: Uuid,
    pub cred: WrappedPasskey,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::account::Entity",
        from = "Column::AccountId",
        to = "super::account::Column::Id",
    )]
    Account,
}

impl Related<super::account::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Account.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

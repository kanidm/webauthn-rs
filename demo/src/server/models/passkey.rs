use std::ops::Deref;

use sea_orm::{entity::prelude::*, FromJsonQueryResult};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;
use webauthn_rs::prelude::Passkey;

/// [Passkey] wrapper that serialises to/from JSON with `sea-orm`.
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

impl Deref for WrappedPasskey {
    type Target = Passkey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "passkeys")]
pub struct Model {
    /// Unique identifier for the passkey
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,

    /// When this passkey was enrolled.
    pub created: OffsetDateTime,

    /// The account the passkey is enrolled for.
    pub account_id: Uuid,

    /// The serialised credential.
    pub cred: WrappedPasskey,
}

impl From<Model> for Passkey {
    fn from(value: Model) -> Self {
        value.cred.0
    }
}

impl AsRef<Passkey> for Model {
    fn as_ref(&self) -> &Passkey {
        &self.cred.0
    }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::account::Entity",
        from = "Column::AccountId",
        to = "super::account::Column::Id"
    )]
    Account,
}

impl Related<super::account::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Account.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

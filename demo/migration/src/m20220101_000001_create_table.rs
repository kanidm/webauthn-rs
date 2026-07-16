use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Accounts::Table)
                    .if_not_exists()
                    .col(pk_uuid(Accounts::Id))
                    .col(string(Accounts::Username))
                    .col(date_time(Accounts::Created))
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(Passkeys::Table)
                    .if_not_exists()
                    .col(pk_uuid(Passkeys::Id))
                    .col(uuid(Passkeys::AccountId))
                    .col(date_time(Passkeys::Created))
                    .col(json(Passkeys::Cred))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Accounts::Table).to_owned())
            .await?;

        manager
            .drop_table(Table::drop().table(Passkeys::Table).to_owned())
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum Accounts {
    Table,
    Id,
    Username,
    Created,
}

#[derive(DeriveIden)]
enum Passkeys {
    Table,
    Id,
    AccountId,
    Created,
    Cred,
}

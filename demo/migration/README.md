# Running Migrator CLI

> [!TIP]
> You can run `sea-orm-cli` from the parent directory instead of running this package directly.

Before starting, set up the database URL:

```sh
# Need `?mode=rwc` to make SeaORM to create a new database file when setting up
# for the first time. Remove the parameter for an existing database file.
export DATABASE_URL="sqlite:///path/to/state.db3?mode=rwc"
```

- Generate a new migration file
    ```sh
    cargo run -- generate MIGRATION_NAME
    ```
- Apply all pending migrations
    ```sh
    cargo run
    ```
    ```sh
    cargo run -- up
    ```
- Apply first 10 pending migrations
    ```sh
    cargo run -- up -n 10
    ```
- Rollback last applied migrations
    ```sh
    cargo run -- down
    ```
- Rollback last 10 applied migrations
    ```sh
    cargo run -- down -n 10
    ```
- Drop all tables from the database, then reapply all migrations
    ```sh
    cargo run -- fresh
    ```
- Rollback all applied migrations, then reapply all migrations
    ```sh
    cargo run -- refresh
    ```
- Rollback all applied migrations
    ```sh
    cargo run -- reset
    ```
- Check the status of all migrations
    ```sh
    cargo run -- status
    ```

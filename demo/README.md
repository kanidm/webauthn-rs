# webauthn-rs-demo v2

`webauthn-rs` demo site, built using `axum`, Leptos and SeaORM.

> [!WARNING]
> This demo has [many limitations and quirks](#demo-limitations-and-quirks), and isn't intended as
> an example of how to integrate `webauthn-rs` in a "real" web application.

## Prerequisites

> [!TIP]: These are not required when [running from Docker](#run-from-docker).

1.  Install a recent Rust toolchain for your host and `wasm32-unknown-unknown`.
2.  Install [`cargo-leptos`][1].
3.  Install [`sea-orm-cli`][2]:

    ```sh
    cargo install --locked sea-orm-cli --no-default-features --features sqlx-sqlite,codegen,runtime-tokio
    ```

[1]: https://github.com/leptos-rs/cargo-leptos
[2]: https://github.com/SeaQL/sea-orm/blob/1.1.20/sea-orm-cli/

## Server options

The server binary can be configured with command-line flags (those starting with `--`) and/or
environment variables (those in `UPPER_CASE`).

If using `cargo leptos serve` or `cargo leptos watch`, you need to put `--` between `cargo-leptos`'
flags and before any server flags ([see examples below](#over-http)).

* `--rp-origin`, `RP_ORIGIN`: (**required**) Origin URL where the application is served from,
  including port (if not using a well-known default).

  This is used for WebAuthn operations, and for the link shown in the application server's startup
  log.

  If the hostname is `localhost`, this may be a `http://` or `https://` URL, otherwise it must be a
  `https://` URL.

  The URL must not contain path, query, fragment, username or password components.

  The hostname must not be an IP address.

* `--rp-id`, `RP_ID`: (**optional**) Hostname where the relying party is served from.

  This must be the same as or a registerable domain suffix of the Origin URL.

  **If not set**, this defaults to the Origin URL's hostname.

  **If this option is changed, all credentials will be invalidated.**

* `--rp-name`, `RP_NAME`: (**optional**) Human-readable name for the relying party, which might be
  displayed to the user by their browser. If not set, defaults to the RP ID.

* `--tls-private-key`, `TLS_PRIVATE_KEY`: (**optional**) Absolute path to the server's TLS private
  key, in PEM format. This must not be encrypted.

  If this option is set, then a TLS public key chain is also required.

* `--tls-public-key`, `TLS_PUBLIC_KEY`: (**optional**) Absolute path to the server's TLS public
  key chain in PEM format. This must not be encrypted.

  If this option is set, then a TLS private key is also required.

* `--database-url`, `DATABASE_URL`: (**required**) [SeaORM database connection URL][3], eg:
  `sqlite:///path/to/state.db3`.

  This demo only supports `sqlite` as a database backend. The database file must be
  [created with the migration tool](#setup-the-database) *before* running the server.

* `--secret-key`, `SECRET_KEY`: (**recommended**) AES-256 secret key used for encrypting the session
  cookie. This is a random, 32 byte value, encoded as base16 (ie: 64 hex digits).

  You can generate this with something like: `openssl rand -hex 32`

  Changing this value will invalidate all session cookies.

  If no value is specified, a random key will be generated on server start-up. In this mode, all
  session cookies will be invalidated on service shutdown.

* `LEPTOS_SITE_ADDR` (environment variable only): The host and port to bind to when listening for
  HTTP or HTTPS connections. By default, this is `127.0.0.1:3000`.

[3]: https://www.sea-ql.org/SeaORM/docs/1.1.x/install-and-config/connection/

## Setup the database

```sh
# Need `?mode=rwc` to make SeaORM to create a new database file when setting up
# for the first time.
export DATABASE_URL="sqlite:///path/to/state.db3?mode=rwc"

# Run all migrations.
sea-orm-cli migrate
```

## Run the development server

### ...over HTTP

To run the development server over HTTP with automatic reloading:

```sh
# Change SECRET_KEY to a randomly generated value (see above).
export SECRET_KEY="..."
export DATABASE_URL="sqlite:///path/to/state.db3"

cargo leptos watch \
  -- \
  --rp-name "webauthn-rs demo" \
  --rp-origin http://localhost:3000
```

Then point your browser at http://localhost:3000

### ...over HTTPS

You'll need to serve the app over HTTPS for it to work from non-`localhost` domains.

To run the development server over HTTPS, you can either:

* Run it [in HTTP mode](#over-http), but make `--rp-origin` a HTTPS URL, and put a HTTPS reverse
  proxy in front of HTTP ports 3000 and 3001.

  This supports automatic reloading, but requires more setup work.

* Run it serving HTTPS directly, with `--tls-public-key` and `--tls-private-key`, which *doesn't*
  support automatic reloading.

  ```sh
  # Don't forget to set SECRET_KEY and DATABASE_URL as well!
  cargo leptos serve \
    -- \
    --rp-name "webauthn-rs demo" \
    --rp-origin https://localhost:3000 \
    --tls-public-key "$PWD/cert.pem" \
    --tls-private-key "$PWD/key.pem"
  ```

Then point your browser at https://localhost:3000

[`generate_self_signed_certs.sh`](./generate_self_signed_certs.sh) uses `openssl` to generate a
self-signed certificate for `localhost` which is valid for 5 days, and will only update it if it has
expired (or is close to expiry). Modify this as you need.

## Run from Docker

> [!NOTE]: This only works on Linux `aarch64` and `x86_64` systems.

The demo site can be built from the [`Dockerfile` in the repository root](../Dockerfile).

```sh
docker build -t webauthn-rs-demo .
```

By default, the container:

1. automatically sets up an SQLite database in `/data`, and runs any pending migrations
1. generates a random secret key on start-up (if none is provided)
1. listens for HTTP on port 3000

You can [configure this with environment variables](#server-options).

To run the container, storing the database in `/tmp/webauthn-rs-data` on the container host:

```sh
docker run -p 3000:3000 -v /tmp/webauthn-rs-data:/data --rm -it webauthn-rs-demo
```

Then visit http://localhost:3000 in your browser.

Press `^C` to shut down the container.

## Demo limitations and quirks

As this is a demo, there are a number of limitations which reduce the security of the application.
In a real application, you'd sort this out:

* This demo stores all accounts and credentials in an SQLite database.

* There's no "authenticated session", so anyone can enrol a credential for any username without
  prior authentication. Accounts are "created" when attempting a credential for a username that is
  not already taken.

  In a real app, you'd authenticate the user before allowing them to enrol a new credential.

* There are no rate limits to enrolling or using credentials.

  In a real app, you might want to apply a server-side per-user/IP rate limit, or issue a
  proof-of-work challenge to the client before sending a registration or login challenge.

* Username restrictions (3 - 16 characters of ASCII letters and/or numbers) to limit storage
  requirements and prevent the insertion of email addresses, and aren't a functional limitation of
  `webauthn-rs`.

  Your may wish to apply different constraints in your application.

* Passkey enrollment and authentication challenges are stored in an encrypted client-side cookie.
  This cookie may be replayed for up to 5 minutes.

  In a real application, you'd issue and store challenges in a distributed system that allows them
  to be used exactly once.

* One side-effect of using an encrypted client-side cookie is that it can only store one flow state
  (authentication `xor` registration) at a time. Starting another flow while one is in progress will
  overwrite the first one.

  However, this demo can have multiple flows running at the same time from different browsers (or
  users).

* The encryption key for the client side cookie is passed as a regular command line argument or an
  environment variable, which can leak in some environments.

  In a real application, you'd read the encryption key from a file on disk, and protect that.

* There's no way to relabel or remove an enrolled credential.

* This demo doesn't [generate fake credentials for unknown usernames][3].

[3]: https://docs.rs/webauthn-rs-core/latest/webauthn_rs_core/fake/struct.WebauthnFakeCredentialGenerator.html

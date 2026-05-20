# webauthn-rs-demo2

Work in progress rewrite of the demo site using `axum` and Leptos.

## Prerequisites

Install a recent Rust toolchain for your host and `wasm32-unknown-unknown`.

Install [`cargo-leptos`][1].

Install [`sea-orm-cli`][2]:

```sh
cargo install sea-orm-cli --no-default-features --features sqlx-sqlite,codegen,runtime-tokio
```

[1]: https://github.com/leptos-rs/cargo-leptos
[2]: https://github.com/SeaQL/sea-orm/blob/1.1.20/sea-orm-cli/

## Run the development server

### ...over HTTP

To run the development server over HTTP with automatic reloading:

```sh
cargo leptos watch \
  -- \
  --rp-name "webauthn-rs demo" \
  --rp-origin http://localhost:3000
```

Then point your browser at http://localhost:3000

### ...over HTTPS

You'll need to serve the app over HTTPS for it to work from non-`localhost` domains.

To run the development server over HTTPS, you can either:

* Run it in HTTP mode, making `--rp-origin` a HTTPS URL, and put a HTTPS reverse proxy in front of
  HTTP ports 3000 and 3001.

  This supports automatic reloading, but requires more setup work.

* Run it serving HTTPS directly, with `--tls-public-key` and `--tls-private-key`, which *doesn't*
  support automatic reloading.

  ```sh
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

## Server options

The server can be configured with command-line flags (those starting with `--`) and/or environment
variables (those in `UPPER_CASE`).

If using `cargo leptos serve` or `cargo leptos watch`, you need to put `--` between `cargo-leptos`'
flags and before any server flags ([see examples above](#over-http)).

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

## Demo limitations

As this is a demo, there are a number of limitations which reduce the security of the application.
In a real application, you'd sort this out:

* There's no "session" functionality, so anyone can enroll a credential for any username.

  In a real app, you'd authenticate the user before allowing them to enroll new credentials.

* Users and credentials are only stored in-memory, and are lost on server shut-down. It's also
  possible for a large number of registrations, registration attempts or authentication attempts to
  exhaust memory.

  In a real app, you'd persist users and have some rate limits.

* The application can only process one authentication and one registration flow per user account at
  a time. Starting another authentication or registration flow while one is in progress will
  overwrite the first one.

* There's no way to label enrolled credentials.

* There's no way to remove an enrolled credential.

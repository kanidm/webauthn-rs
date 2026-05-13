# webauthn-rs-demo2

Work in progress rewrite of the demo site using axum and leptos.

Currently does very little. :)

## Prerequisites

Install a recent Rust toolchain for your host and `wasm32-unknown-unknown`.

Install [`cargo-leptos`][1].

[1]: https://github.com/leptos-rs/cargo-leptos

## Run the development server

```sh
# WebAuthn must be served over HTTPS, so we generate some self-signed certs.
./generate_certs.sh

# Run the server without hot-reloading (as its WebSocket side-channel doesn't support HTTPS)
cargo leptos serve
```

Then point your browser at https://localhost:3000

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

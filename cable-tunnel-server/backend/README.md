# webauthn-rs cable-tunnel-server-backend

This binary provides a caBLE tunnel server, which is intended for
*non-production use only*.

The `backend` can run in two configurations:

* a single-task configuration, directly serving requests with no frontend.

  In this configuration, caBLE [Routing IDs][background] are ignored, and it is
  presumed all incoming requests can be served out of a single running task.

* a multi-task configuration, with many frontend tasks.

  In this configuration, the backend presumes it has frontend tasks in front of
  it to [handle caBLE Routing IDs][background]. However, the frontend is not yet
  fully implemented.

The `backend` is stateless, and is not capable of communicating with other
tasks on its own. Each tunnel exists within one (*and only one*) `backend` task,
and `backend` tasks never process caBLE [Routing IDs][background].

[background]: ../README.md#background

## Building

You can build the `backend` using Cargo:

```sh
cargo build
```

This will output a binary to `./target/debug/cable-tunnel-server-backend`.

You can also run the server via Cargo:

```sh
cargo run -- --help
```

## Configuring the server

The server is configured with command-line flags, which can be seen by running
the server with `--help`.

To run the server at http://127.0.0.1:8080 (for testing with
`webauthn-authenticator-rs` built with the `cable-override-tunnel` feature):

```sh
./cable-tunnel-server-backend \
    --bind-address 127.0.0.1:8080 \
    --insecure-http-server
```

To run the server with HTTPS and strict `Origin` header checks:

```sh
./cable-tunnel-server-backend \
    --bind-address 192.0.2.1:443 \
    --tls-public-key /etc/ssl/certs/cable.example.com.pem \
    --tls-private-key /etc/ssl/certs/cable.example.com.key \
    --origin cable.example.com
```

> **Important:** caBLE has an algorithm to deriving tunnel server domain names –
> you cannot host the service on an arbitrary domain name of your choosing.
>
> Run [`webauthn-authenticator-rs`' `cable_domain` example][cable_domain] to
> derive hostnames at the command line.

[cable_domain]: ../../webauthn-authenticator-rs/examples/cable_domain.rs

## Logging

By default, the server runs at log level `info`. This can be changed with the
`RUST_LOG` environment variable, using the
[log levels available in the `tracing` crate][log-levels].

The server logs the following at each level, plus all the messages in the levels
above it:

* `error`: TLS handshake errors, TCP connection errors, incorrect or unknown
  HTTP requests

* `warn`: warnings about using unencrypted HTTP

* `info`: (default) start-up messages, HTTP connection lifetime, HTTP request
  logs, WebSocket tunnel lifetime

* `debug`: n/a

* `trace`: adds complete incoming HTTP requests, WebSocket tunnel messages

[log-levels]: https://docs.rs/tracing/*/tracing/struct.Level.html

## Monitoring

The server exports some basic metrics at `/debug`:

* `server_state.strong_count`: the number of strong references to
  `Arc<ServerState>`

* `peer_map`: a `HashMap` of all pending tunnels - those where the authenticator
  has connected but the initiator has not yet connected.

  * `peer_map.capacity`: the capacity of the pending tunnels `HashMap`

  * `peer_map.len`: the number of pending tunnels

# webauthn-rs cable-tunnel-server-backend

This binary provides a caBLE tunnel server backend.

The backend is capable of running in two configurations:

* a single-task configuration, with no frontends.

  In this configuration, caBLE [Routing IDs][background] are ignored, and it is
  presumed all incoming requests can be served out of a single running task.

* a multi-task configuration, with many frontend tasks.

  In this configuration, the backend presumes it has frontend tasks in front of
  it to [handle caBLE Routing IDs][background]. However, the frontend is not yet
  fully implemented.

Backend tasks are entirely stateless, and do not communicate with one another.
Each tunnel exists within one (*and only one*) backend task.

[background]: ../README.md#background

## Building

You can build using Cargo:

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

## Logging

By default, the server assumes it is running using `RUST_LOG=info`.

## Monitoring

The server exports some basic metrics at `/debug`:

* `server_state.strong_count`: the number of strong references to `Arc<ServerState>`

* `peer_map`: a `HashMap` of all pending tunnels - those where the authenticator
  has connected but the initiator has not yet connected.

  * `peer_map.capacity`: the capacity of the pending tunnels `HashMap`

  * `peer_map.len`: the number of pending tunnels

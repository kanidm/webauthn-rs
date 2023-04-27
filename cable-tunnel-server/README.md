# webauthn-rs caBLE tunnel server

**Important:** it is only necessary for an *authenticator vendor* to run a caBLE
tunnel service for their devices. Initiators (such as browsers and client
applications) connect to a tunnel service of the *authenticator's* choosing.

**Warning:** this is still a work in progress, and not yet fully implemented.

However, you can run a single-task tunnel service with the `backend` alone:
[see `./backend/README.md` for instructions][0].

[0]: ./backend/README.md

## Background

To facilitate two-way communication between an initiator (browser) and
authenticator (mobile phone), caBLE uses a WebSocket tunnel server. There are
tunnel servers run by Apple (`cable.auth.com`) and Google (`cable.ua5v.com`),
and a facility to procedurally generate new tunnel server domain names
([run `webauthn-authenticator-rs`' `cable_domain` example][1]).

[1]: ../webauthn-authenticator-rs/examples/cable_tunnel.rs

As far as the tunnel server is concerned, what happens is:

1. The authenticator and initator choose a 16 byte tunnel ID.

2. The authenticator connects to a tunnel server of its choosing, using HTTPS.

3. The authenticator makes a WebSocket request to `/cable/new/${TUNNEL_ID}`[^new].

4. The tunnel server responds with a WebSocket handshake, and includes a 3 byte
   routing ID in the HTTP response headers to indicate which task is serving
   the request.

5. The authenticator transmits the tunnel server ID and routing ID to the
   initiator using an encrypted Bluetooth Low Energy advertisement.

6. The initiator decrypts the advertisement, and connects to the tunnel server
   using HTTPS.

7. The initiator makes a WebSocket request to
   `/cable/connect/${ROUTING_ID}/${TUNNEL_ID}`.

8. The tunnel server responds with a WebSocket handshake.

9. The tunnel server relays binary WebSocket messages between the authenticator
   and initiator.

The initiator starts a Noise channel with the authenticator for further
communication such that the tunnel server cannot read their communications, and
then does registration or authentication using the FIDO 2 protocol.

Aside from implementing some basic request filtering, message limits and session
limits, the tunnel server implementations are very simple. The tunnel server
itself does not need to concern itself with the minutae of the Noise protocol -
it only needs to pass binary messages across the tunnel verbatim.

[^new]:
  This [follows Google's caBLE URL convention][2]. The URL used to establish a
  new channel [is not part of the FIDO 2.2 specification][3].

[2]: https://source.chromium.org/chromium/chromium/src/+/main:device/fido/cable/v2_handshake.cc?q=symbol%3A%5Cbdevice%3A%3Acablev2%3A%3Atunnelserver%3A%3AGetNewTunnelURL%5Cb%20case%3Ayes
[3]: https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#ref-for-client-platform①⓪

## Design

`webauthn-rs`' caBLE tunnel server consists of three parts:

* [backend][]: serving binary which passes messages between the authenticator
  and initiator on a known tunnel ID.

* [frontend][]: serving binary which routes requests to a `backend` task based
  on the routing ID (for `connect` / initiator requests), or some other load
  balancing algorithm (for `new` / authenticator requests).

* [common][]: contains all the shared web server, TLS and caBLE components for
  the `backend` and `frontend` binaries.

[backend]: ./backend/
[frontend]: ./frontend/
[common]: ./common/

### Backend

**Source:** [`./backend/`][backend]

It should be possible to run the `backend` without a `frontend` – in this case
the routing ID will be ignored, and all tunnels exist inside of a single serving
task.

### Frontend

**Warning:** The `frontend` is not yet fully implemented, and does not yet do
everything described here. This would be necessary to operate a
high-availability caBLE tunnel service.

**Source:** [`./frontend/`][frontend]

The `frontend` needs to do some basic request processing (for routing) before
handing off the connection to a `backend`:

* For connecting to existing tunnels, the `frontend` needs to connect to
  arbitrary `backend` tasks *in any location*.

* For establishing new tunnels, the `frontend` should prefer to route to "local"
  `backend` tasks, taking into account backend availability and load balancing.

This will probably need some distributed lock service to allocate the routing
IDs.

While it would be possible to route based on the tunnel ID *alone*, this would
make tunnel create / fetch operations (in the `backend`) global.

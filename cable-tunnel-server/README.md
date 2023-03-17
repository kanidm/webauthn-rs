# webauthn-rs cable-tunnel-server

**Warning:** This is still a work in progress, and not yet fully implemented.

## Design

caBLE has authenticator-chosen 16 byte tunnel IDs. When the authenticator
connects, the tunnel server responds with a 3 byte routing ID. When the initator
connects, it uses the tunnel ID and the routing ID, and this should direct it
to the same serving task as the authenticator.

The `cable-tunnel-server` consists of three parts:

* `backend`: serving binary which passes messages between the authenticator and
  initator on a known tunnel ID.

* `frontend`: serving binary which routes requests to a `backend` task based on
  the routing ID (for the initator), or some other load balancing algorithm (for
  the authenticator).

* `common`: contains all the web server and caBLE boilerplate which is shared
  between the `backend` and `frontend` binaries.

It should be possible to run the `backend` without a `frontend` – in this case
the routing ID will be ignored.

The `frontend` should be able to handle having `backend` tasks coming and going,
and have health checks to avoid routing it to bad `backend` tasks.

This will probably need some distributed lock service to allocate the routing
IDs. It should be possible to route based on the tunnel ID _as well_, but may
not be necessary.

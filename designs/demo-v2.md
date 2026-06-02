# `webauthn-rs-demo` v2

* **Published:** 2026-05-xx
* **Last updated:** 2026-05-20

The `webauthn-rs-demo` webapp runs at https://webauthn.firstyear.id.au. The current demo (v1) has a
basic enrollment (registration) and authentication (login) flow, and a compatibility tester.

The v1 backend is written using `tide`, which is [effectively no longer maintained][0]. At least the
backend will need to be replaced or migrated to another framework.

The v1 backend and frontend no longer build due to various API changes.

## Current demo site design (v1)

The current demo site has three crates:

* `*-demo-wasm`: frontend SPA, written with `yew`.

  The built HTML / WASM artefacts are manually copied into `*-demo/pkg`, checked into `git`, and
  then served by the backend.

* `*-demo`: the RP, a `tide` HTTP backend.

  "registration state" is stored in a server-side in-memory session store. Cookies are signed with
  an ephemeral random key generated on server start-up.

  This also serves the compiled frontend assets.

* `*-demo-shared`: shared data structures between backend and frontend components, used to define
  its HTTP APIs.

These are all wrapped up into [a Docker container image][9] which serves a single HTTP / HTTPS port.

### Issues with the current demo

* `tide`'s last release was 4 years ago, and [is no longer actively developed][0] (as of 2022).

  [There are parts of its dependency tree which no longer build on current versions of Rust][5].

* Within the Kanidm org context, the demo's use of `tide` and `yew` is now a singleton:

  * `cable-tunnel-server` uses `hyper+tokio+tungstenite`, and doesn't have a browser frontend.
  * Kanidm itself uses `axum+tokio`, and [replaced `yew` with HTMX and Rust templates][1].

* The demo no longer builds: dependabot incrementally updated packages, but there were API changes
  that were never handled, and it was never tested in CI.

* The backend embeds frontend build artefacts (WASM), and these are checked into `git`, so that the
  backend doesn't require a nightly Rust WASM build toolchain.

  Due to different `rustc` versions and the inclusion of local build paths, these will compile
  differently on everyone's machine. It is impractical to audit a contributor's builds, which makes
  accepting changes tedious and failure prone.

  Properly integrating the frontend into the backend build process is difficult and would require
  extra tooling, which `yew` _doesn't_ provide (but other frameworks do).

* Credentials are stored in an in-memory server-side session cookie.

  This means each browser using the demo site has its own list of credentials, and it's impossible
  to demonstrate using the _same_ credential across different browsers or devices.

* The demo site itself has low search engine ranking, in part because the demo site is an SPA with
  no server-side rendering. `yew` now supports "experimental" server-side rendering.

  https://webauthn.firstyear.id.au was one of the first comprehensive WebAuthn demos and
  open source compatibility tests.

  Since 2019, a number of other demos have popped up with much better SEO. Unfortunately, these
  (now) all set `rk=required` or `rk=prefered` (by default, or with no option to disable it),
  [*permanently* consuming limited storage on hardware security keys][6], and entrenching
  synchronised credential managers.

* The frontend uses [yew `struct` components][3] everywhere, which are very verbose.

  This could be improved by migrating to [function components][4], but this essentially requires a
  redesign / rewrite for any component which has internal state.

* The frontend has a lot of boilerplate to make API calls to its backend.

## Requirements and scope

This work would target the 0.6 branch of `webauthn-rs`.

Initial scope:

* Migrate the backend from `tide` to `axum` ([rationale below][7]).

* Migrate the frontend from `yew` to [`leptos`][leptos] ([rationale below][7]).

* Implement basic registration and login flows _with_ user verification and _without_ attestation.

* Short-term persistence of "user" database (eg: 14 days since creation) on the server side, to
  demonstrate authentication on different devices.

* Have the demo reliably building in CI, with no checked in binaries.

* Remove `tide` related code from the `webauthn-rs` repository (v1 demo webapp, tutorial, etc.)

* Update the existing OCI / Docker container image (which exposes a HTTP/HTTPS server port).

### Future work ideas

* Show the deserialised contents of the attestation blob in the frontend.

* Add alternative login flows (attestation, [Android's WebAuthn train wreck][8], security key/U2F
  mode, etc.)

* Re-implement the compatibility tester.

## Design decisions

`webauthn-rs-demo` v2 uses [`leptos`][leptos] instead of to `yew`:

* `leptos` renders components once and hooks them to provide interactivity.

  By comparison, `yew` rebuilds components entirely on update, and then patches in changes to the
  DOM (slower).

* `leptos` has more polished server-side rendering support than `yew`:

  * This should improve SEO.

  * [Islands][islands] can minimise the amount of components that require client-side rendering,
    reducing WASM build size.

* `leptos` provides server functions (APIs) that are just a Rust `async fn` call away, with no
  API boilerplate, that integrate with other Rust HTTP servers (`actix`, `axum`).

* `leptos` has an integrated backend and WASM build process (`cargo-leptos`) that works with a
  single `cargo` package.

* `leptos` HTML syntax is a bit nicer than `yew`, particularly when integrating it with Rust code.

* `leptos` components look like [`yew` function components][4].

The backend side is served out of `axum`. Kanidm already uses `axum`, so it's a known value.

`leptos` customises the `axum` environment a fair bit to provide server-side rendering, but it's
workable.

## Alternatives considered

### Making the demo site servable entirely from GitHub Pages, without a backend

`yew` (and others) could be wrangled into being servable from blob storage if it is possible to
make `index.html` the 404 error handler. For example, GitHub Pages could do this with
`cp index.html 404.html`.

In this case, the RP side of `webauthn-rs` would be cross-compiled to run entirely out of WASM.

With the removal of OpenSSL, this is much closer to being viable.

When I attempted this, it got stuck on _at least_
[a bug that was fixed in a later version of RustCrypto][2], but we can't move to that version
without also dealing with a large number of API changes that aren't all available in non-RC builds
of those crates.

The other drawback of this approach is this would further entrench a limitation of the current demo
that "all the state is in a session cookie".

This might be viable for the compatibility tester in future, as that shouldn't need
cross-browser/device state.

### Migrate to the current version of `yew`

Migrating would involve close to a rewrite of the app anyway, particularly when migrating things
that can to [function components][4].

New versions of `yew` don't address many the limitations noted above.

### Rewrite the frontend in JS/TS

This is probably more like how `webauthn-rs` might actually be actually deployed.

However, there are a large number of framework options with their own build processes that don't
integrate well with Rust build tooling.

It'd also require writing and maintaining JS/TS, which is not our area of expertise. :)

[0]: https://github.com/http-rs/tide/discussions/888
[1]: https://github.com/kanidm/kanidm/pull/3148
[2]: https://github.com/kanidm/webauthn-rs/issues/555#issuecomment-4411681030
[3]: https://yew.rs/docs/advanced-topics/struct-components/introduction
[4]: https://yew.rs/docs/concepts/function-components
[5]: https://github.com/kanidm/webauthn-rs/issues/555#issue-4396365578
[6]: https://fy.blackhats.net.au/blog/2023-02-02-how-hype-will-turn-your-security-key-into-junk/
[7]: #design-decisions
[8]: https://github.com/kanidm/webauthn-rs/issues/365#issuecomment-1756605203
[9]: ../Dockerfile
[leptos]: https://github.com/leptos-rs/leptos
[islands]: https://book.leptos.dev/islands.html

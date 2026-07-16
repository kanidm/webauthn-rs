# webauthn-rs

The `webauthn-rs` project provides a suite of Rust WebAuthn (passkey) libraries:

* [`webauthn-rs`](https://docs.rs/webauthn-rs/): an [opinionated](#what-do-you-mean-by-opinionated),
  high-level, safe, use-case driven API for WebAuthn Relying Parties (web applications).

* [`webauthn-rs-core`](https://docs.rs/webauthn-rs-core/): low-level, unsafe, protocol-level
  interactions for WebAuthn Relying Parties.

* [`webauthn-rs-proto`](https://docs.rs/webauthn-rs-proto/): WebAuthn IDL datatypes, with WASM and
  JSON (serde) bindings.

* [`webauthn-rp-proxy`](./webauthn-rp-proxy/README.md): standalone binary for using `webauthn-rs`
  in non-Rust applications via a JSON-over-stdio API.

* [`webauthn-authenticator-rs`](https://docs.rs/webauthn-authenticator-rs/): CTAP 2 authenticator
  interface library for native applications, supporting BTLE, caBLE/Hybrid, NFC and USB
  authenticators on Linux, macOS and Windows, and safe wrappers for Windows 10's WebAuthn API.

* [`fido-key-manager`](./fido-key-manager/README.md): command-line tool for managing CTAP 2
  hardware authenticators on Linux, macOS and Windows.

* [`fido-mds`](https://docs.rs/fido-mds/): library for cryptographically verifying, parsing and
  post-processing the FIDO Metadata Service, used for attesting certified hardware FIDO
  authenticators.

* [`cable-tunnel-server`](./cable-tunnel-server/README.md): a caBLE/Hybrid WebSocket tunnel service
  demo.

This repository contains several demos and examples for these libraries.

As of v0.6.0, `webauthn-rs` uses RustCrypto for its core cryptographic operations, instead of
OpenSSL.

## About WebAuthn

WebAuthn is a modern approach to hardware-based user authentication, consisting of a user with an
authenticator device (such as a security key, SE or TPM), a browser or client that interacts with
the device, and a Relying Party (web application) that is able to generate challenges and verify the
authenticator's response.

Users can enroll their own authenticators and login through a WebAuthn-capable web browser or app.

Authenticators can provide self-contained, multi-factor authentication (user verification), using a
PIN that is only transmitted to the authenticator and/or biometrics that never leave the
authenticator device. The security certification of an authenticator can be cryptographically
attested to the Relying Party, to ensure that key material is hardware-bound, and cannot be copied.

Together, these provides a level of security allowing it to *completely replace passwords*, often
using functionality that users' devices already have (like TPMs and SEs).

This library also supports synchronised "passkey managers" (like iCloud Keychain and Google Password
Manager) that *do not* use hardware-bound keys, but credentials can be copied, and some don't even
implement user verification correctly, so they should only ever be used with a second factor.

## Code of Conduct

See our [code of conduct][].

[code of conduct]: https://github.com/kanidm/webauthn-rs/blob/master/CODE_OF_CONDUCT.md

### Blockchain Support Policy

This project does not and will not support any blockchain related use cases. We will not accept issues
from organisations (or employees thereof) whose primary business is blockchain, cryptocurrency, NFTs
or so-called “Web 3.0 technology”. This statement does not affect the rights and responsibilities
granted under the project’s open source license(s).

If you have further questions about the scope of this statement and whether it impacts you, please
email webauthn at firstyear.id.au

## Demonstration

You can test this library via our [demonstration site](https://webauthn.firstyear.id.au/)

Or you can run the demonstration your self locally with:

    cd compat_tester/webauthn-rs-demo
    cargo run

For additional configuration options for the demo site:

    cargo run -- --help

## Known Supported Keys/Harwdare

We have extensively tested a variety of keys and devices, not limited to:

* Yubico 5c / 5ci / FIPS / Bio
* Touch ID / Face ID / Optic ID (iPhone, iPad, MacBook Pro)
* Android
* Windows Hello (TPM)
* Softtokens

If your key/browser combination don't work (generally due to missing crypto routines) please run a
[compatibility test](https://webauthn.firstyear.id.au/compat_test) and then open an issue so that we
can resolve the issue!

## Known BROKEN Keys/Hardware

* Pixel 3a / Pixel 4 + Chrome - Does not send correct attestation certificates, and ignores
  requested algorithms. Not resolved.

* Windows Hello with Older TPMs - Often use `RSA-SHA1` signatures over attestation which may allow
  credential compromise/falsification.

## What do you mean by "opinionated"?

`webauthn-rs` follows the W3C WebAuthn level 3+ processing standard to ensure secure and correct
behaviour.

We support *most* major extensions and key types, but we intentionally do not support *every*
feature of the specification:

* We do not support all cryptographic algorithms - only the secure ones! ;)

* We have enforced extra constraints in the library that go above what is required by the standard,
  with safe defaults.
  
  For example, `webauthn-rs` *requires* user verification on login by default, and actually checks
  the response. Many other libraries only *prefer* user verification, or require it but do not check
  that user verification was actually performed!

* We do not support options that risk damaging a user's authenticator.

  For example, `webauthn-rs` always *discourages* resident keys, because they consume storage space,
  which is extremely limited on hardware security keys, and not all of them support storage
  management. Synchronised credential managers that always create resident keys (like iCloud
  Keychain) still work in this mode without issue.
  
  Many other WebAuthn libraries *prefer* or *require* resident keys, which are effectively the same
  thing when a user's security key *supports* resident keys, but risks *bricking* a user's security
  key.

* We do not support certain esoteric options.

  A number of WebAuthn's advertised features do not actually function in the real world (due to a
  lack of browser and/or hardware support), so they are not worth actually implementing! :)

## Security

This library has passed a security audit performed by SUSE product security.

Other security reviews are welcome - please see our [security policy](./SECURITY.md)!

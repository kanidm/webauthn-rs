Webauthn-rs
==========

Webauthn is a modern approach to hardware based authentication, consisting of
a user with an authenticator device, a browser or client that interacts with the
device, and a server that is able to generate challenges and verify the
authenticator's validity.

Users are able to enroll their own tokens through a registration process to
be associated to their accounts, and then are able to login using the token
which performas a cryptographic authentication.

This library aims to provide useful functions and frameworks allowing you to
integrate webauthn into Rust web servers. This means the library implements the
Relying Party component of the FIDO2 workflow. We provide template and
example javascript and wasm bindings to demonstrate the browser interactions required.

Documentation
-------------

This library consists of multiple major parts.

A safe, use-case driven api, which is defined in [Webauthn-RS](https://docs.rs/webauthn-rs/)

The low level, protocol level interactions which is defined in [Webauthn-Core-RS](https://docs.rs/webauthn-core-rs/)

Protocol bindings which are defined in [Webauthn-RS-proto](https://docs.rs/webauthn-rs-proto/)

The FIDO MDS (authenticator transparency) parser [FIDO-MDS](https://docs.rs/fido-mds/)

We strongly recommend you use the safe api, as webauthn has many sharp edges and ways to hold it wrong!

Demonstration
-------------

You can test this library via our [demonstration site](https://webauthn.firstyear.id.au/)

Or you can run the demonstration your self locally with:

    cd compat_tester/webauthn-rs-demo
    cargo run

For additional configuration options for the demo site:

    cargo run -- --help

Known Supported Keys/Harwdare
-----------------------------

We have extensively tested a variety of keys and devices, not limited to:

* Yubico 5c / 5ci / FIPS / Bio
* TouchID / FaceID (iPhone, iPad, MacBook Pro)
* Android
* Windows Hello (TPM)
* Softtokens

If your key/browser combination don't work (generally due to missing crypto routines)
please conduct a [compatability test](https://webauthn.firstyear.id.au/compat_test) and then open
an issue so that we can resolve the issue!

Known BROKEN Keys/Harwdare
--------------------------

### Broken

* Pixel 3a / Pixel 4 + Chrome - Does not send correct attestation certificates,
  and ignores requested algorithms. Not resolved.
* Windows Hello with Older TPMs - Often use RSA-SHA1 signatures over attestation which may allow credential compromise/falsification.

### Fixed

* Windows 10 / Windows 11 + Firefox 98 - When aaguid is meant
  to be 16 bytes of 0, it emits a single 0 byte. This should be resolved as of 2022-04-17
* BUG in Safari, NOT Apple Passkeys (was: passkeys do not identify themself as a transferable credential, and should be considered to be floating.)

Standards Compliance
--------------------

This library has been carefully implemented to follow the w3c standard for webauthn level 3+ processing
to ensure secure and correct behaviour. We support most major extensions and key types, but we do not claim
to be standards complaint because:

* We have enforced extra constraints in the library that go above and beyond the security guarantees the standard offers.
* We do not support certain esoteric options.
* We do not support all cryptographic primitive types (only limited to secure ones).
* A large number of advertised features in webauthn do not function in the real world.

This library has passed a security audit performed by SUSE product security. Other security reviews
are welcome!



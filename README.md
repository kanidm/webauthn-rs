
Webauthn-rs
==========

Webauthn is a modern approach to hardware based authentication, consisting of
a user with an authenticator device, a browser or client that interacts with the
device, and a server that is able to generate challenges and verify the
authenticators validity.

Users are able to enroll their own tokens through a registration process to
be associated to their accounts, and then are able to login using the token
which performas a cryptographic authentication.

This library aims to provide useful functions and frameworks allowing you to
integrate webauthn into Rust web servers. This means the library implements the
Relying Party component of the FIDO2 workflow. We provide template and
example javascript and wasm bindings to demonstrate the browser interactions required.

Documentation
-------------

Our docs are available on [docs rs](https://docs.rs/webauthn-rs/latest/webauthn_rs/)

Known Supported Keys/Harwdare
-----------------------------

* Yubico 5c + MacOS 10.14 + Firefox/Edge
* Yubico 5ci + iPadOS 14 + Safari/Brave
* TouchID + iPadOS + Safari
* FaceID + iPhone + Safari
* TouchID + MacOS + Edge
* Windows Hello + Windows 10 + Chrome

If your key/browser combination don't work (generally due to missing crypto routines)
please conduct a [compatability test](https://webauthn.firstyear.id.au/compat_test) and then open an issue so that we can resolve the issue!

Known BROKEN Keys/Harwdare
--------------------------

* Pixel 3a / Pixel 4 + Chrome - Does not send correct attestation certificates, and ignores requested algorithms

Standards Compliance
--------------------

This library has been carefully implemented to follow the w3c standard for webauthn level 3 processing
to ensure secure and correct behaviour. We support most major extensions and key types, but we do not claim
to be standards complaint because:

* We do not support certain esoteric options.
* We do not support all cryptographic primitive types (only limited to secure ones).
* We have enforced extra constraints in the library that go above and beyond the security guarantees the standard offers.

This library has passed a security review performed by SUSE product security. Other security reviews
are welcome!

Feedback
--------

The current design of the traits and configuration is open to feedback on how it
can be improved - please use this library and contact the project on what can be
improved!

Why OpenSSL?
------------

A question I expect is why OpenSSL rather than some other pure-Rust cryptographic
providers. There are two major justfications.

The first is that if this library will be used in corporate or major deployments,
then cryptographic audits may have to be performed. It is much easier to point
toward OpenSSL which has already undergone much more review and auditing than
using a series of Rust crates which (while still great!) have not seen the same
level of scrutiny.

The second is that OpenSSL is the only library I have found that allows us to
reconstruct an EC public key from it's X/Y points or an RSA public key from it's
n/e for use with signature verification.
Without this, we are not able to parse authenticator credentials to perform authentication.

Resources
---------

* Specification: https://www.w3.org/TR/webauthn-3
* JSON details: https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html
* Write up on interactions: https://medium.com/@herrjemand/introduction-to-webauthn-api-5fd1fb46c285




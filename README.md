
Webauthn-rs
==========

NOTE: This library has NOT received a proper security review of operations yet!!! Help
out and review this crate!

Webauthn is a modern approach to hardware based authentication, consisting of
a user with an authenticator device, a browser or client that interacts with the
device, and a server that is able to generate challenges and verify the
authenticators validity.

Users are able to enroll their own tokens through a registration process to
be associated to their accounts, and then are able to login using the token
which performas a cryptographic authentication.

This library aims to provide useful functions and frameworks allowing you to
integrate webauthn into rust web servers. This means the library implements the
Relying Party component of the FIDO2 workflow. We provide template and
example javascript to demonstrate the browser interactions required.

Examples
--------

As this library aims to be usable in a variety of contexts, we have provided
examples in the examples folder. These examples should demonstrate secure and
valid use, so please report any issues found, and we'd love to see more examples
contributed!

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
reconstruct an EC public key from it's X/Y points for signature verification.
Without this, we are not able to perform authentication of credentials.

Resources
---------

* Specification: https://w3c.github.io/webauthn/
* JSON details: https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html
* Write up on interactions: https://medium.com/@herrjemand/introduction-to-webauthn-api-5fd1fb46c285




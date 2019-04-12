
Webauthn-rs
==========

NOTE: This library is NOT production ready yet, and is under heavy changes!

NOTE: This library has NOT received a proper security review of operations yet!!!

Webauthn is a modern approach to hardware based authentication, consisting of
a user with an authenticator device, a browser or client that interacts with the
device, and a server that is able to generate challenges and verify the
authenticators validity.

Users are able to enroll their own tokens through a registration process to
be associated to their accounts, and then are able to login using the token
which performas a cryptographic authentication.

This library aims to provide useful functions and frameworks allowing you to
integrate webauthn into rust web servers. We also will provide template and
example javascript to demonstrate the browser interactions required.

This library was inspired by work on https://github.com/tiziano88/webauthn-rs,
and may end up being combined with their work.


Resources
---------

* Specification: https://w3c.github.io/webauthn/
* JSON details: https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html




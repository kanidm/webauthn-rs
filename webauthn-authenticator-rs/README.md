
Webauthn-authenticator-rs
=========================

Webauthn is a modern approach to hardware based authentication, consisting of
a user with an authenticator device, a browser or client that interacts with the
device, and a server that is able to generate challenges and verify the
authenticators validity.

Users are able to enroll their own tokens through a registration process to
be associated to their accounts, and then are able to login using the token
which performas a cryptographic authentication.

This library is the client half of the authenticator process, performing the
steps that would normally be taken by a webbrowser. Given a challenge from
a webauthn server, this library can contact a u2f device and transform the
response to a webauthn registration and authentication.

Today, this library only works with u2f devices, and there are a number of
constraints in this behaviour. More hardware devices should be supported
in the future if/when I acquire them.


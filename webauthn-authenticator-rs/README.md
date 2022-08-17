
Webauthn-authenticator-rs
=========================

Webauthn is a modern approach to hardware based authentication, consisting of
a user with an authenticator device, a browser or client that interacts with the
device, and a server that is able to generate challenges and verify the
authenticators validity.

This library is the client half of the authenticator process, performing the
steps that would normally be taken by a webbrowser. Given a challenge from
a webauthn server, this library can contact a CTAP2 device and transform the
response to a webauthn registration and authentication.

In addition for testing your applications this library provides a soft-token
implementation which allows you to test your webauthn integrations inside unit
tests, including the ability to verify attestations.



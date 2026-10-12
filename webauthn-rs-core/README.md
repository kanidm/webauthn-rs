# Webauthn Rust Core

Webauthn is a modern approach to hardware based authentication, consisting of
a user with an authenticator device, a browser or client that interacts with the
device, and a server that is able to generate challenges and verify the
authenticator's validity.

## ⚠️ WARNING ⚠️

This library implements and exposes the *raw* elements to create a Webauthn Relying
Party. Many of these components have many sharp edges and the ability to confuse
users, accidentally allow security bypasses, and more. If possible you SHOULD use
[Webauthn-RS](https://docs.rs/webauthn-rs/) instead of this crate!

However, if you want to do something truly custom or specific, and you understand the
risks, then this library is for you.

## Resources

* Specification: https://www.w3.org/TR/webauthn-3
* JSON details: https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html
* Write up on interactions: https://medium.com/@herrjemand/introduction-to-webauthn-api-5fd1fb46c285

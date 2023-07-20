# webauthn-rs Design Philosophy

* **Published:** 2023-07-21
* **Last updated:** 2023-07-21

This document describes the design philosophy of `webauthn-rs`, as well as some
of the critical design decisions we've made over time.

If you ever wondered *why* `webauthn-rs` does things a certain way, this is the
document for you.

We intend this document to evolve and expand over time with the project's
requirements.

## Introduction

The WebAuthn API which most developers use comes from the browser:

* `navigator.credentials.create` to register
* `navigator.credentials.get` to authenticate

This API has many edge cases, and is easy to use in an insecure way, or in a way
that can make your application inflexible.

Our goals are that `webauthn-rs`:

* has safe interfaces
* encourages good design choices
* is hard to use in an unsafe way
* meets (or exceeds) security requirements set by the WebAuthn specification
* allows a relying party to enforce reasonable, security-relevant policies
  (such as requiring [attestation][att] or [user verification][uv])
* [does not perform actions which harm certain types of authenticators by default][junk]
* works with as many standards-compliant authenticators as possible

[att]: https://www.w3.org/TR/webauthn-3/#attestation
[junk]: https://fy.blackhats.net.au/blog/html/2023/02/02/how_hype_will_turn_your_security_key_into_junk.html
[uv]: https://www.w3.org/TR/webauthn-3/#user-verification

**`webauthn-rs` is an "opinionated" library**: it will intentionally do some
things differently to the letter of the WebAuthn specification, or avoid
implementing problematic APIs or features.

## webauthn-rs-core: a low level interface

`webauthn-rs-core` is the low level interface upon which `webauthn-rs` is built.
This more closely follows the WebAuthn specification, and has lower level
interfaces which are less opinionated (and less safe).

However, we make **no guarantees** of API stablity.

## Example decisions

This is a non-exhaustive list of design choices we've made in the library:

### Delegate platform-specific interfaces not related to WebAuthn

We want to constrain `webauthn-rs`'s complexity, and one way we do this is to
not ship more platform-specific code than absolutely necessary.

This means we'll aim to use existing libraries for interfacing with non-WebAuthn
platform APIs, and move as much platform-specific code as possible into upstream
libraries.

For example, we delegate smart card access to the widely-supported and
cross-platform [PC/SC API][pcsc]. We would expect any proposal to add an
alternative smart card API to demonstrate why using PC/SC was not appropriate or
possible on that platform.

For WebAuthn itself, we need to implement some platform-specific code where that
platform has WebAuthn APIs (eg: on macOS and Windows), and we're okay with that.

Should existing Rust libraries not fit our needs, we'll split these into a
module which could eventually become a standalone project that `webauthn-rs`
could depend on.

For example, we ship our own USB HID library (`fido-hid-rs`), because existing
Rust USB HID libraries do not provide `async`-friendly interfaces.

[pcsc]: https://pcscworkgroup.com/

### User IDs are UUIDs

`webauthn-rs` uses the [`Uuid` type][uuid-type] to express usernames.

The most common way for a user to identify themselves is a username. Many
organisations set policies for how these should be expressed, but it is quite
often based on the person's name.

The username itself has many edge cases:

* Do you base the username on their *legal* name, or their *preferred* name?

* What happens when the user changes their name?

* Where is the username stored?

* How do you manage deletion of the username?

* Which glyphs are acceptable to use in a username? Does it allow for usernames
  in other writing systems?

The WebAuthn specification itself addresses this issue by defining
[a user entity][user] (`PublicKeyCredentialUserEntity`) with three attributes:

* `id` (`BufferSource`) a user handle for the account, comprised of an opaque
  byte sequence of up to 64 bytes, which is the *only* attribute to be used by
  an application when making authentication or authorisation decisions.

* `displayName` (`DOMString`) is a human-palatable name for the account, where
  authenticators display at least 64 bytes.

* `name`[^name] (`DOMString`) is a human-palatable identifier for the account,
  intended for determining the difference between accounts with the same
  `displayName`. This could be a username, email address or phone number.

While [the WebAuthn specification states that `id` *must not* contain personally
identifying information][id-pii] (including usernames or email addresses), the
`BufferSource` type is just a byte sequence (ie: `Vec<u8>`), and is easy to
misuse. For example, an application could put a username in there:

```rust
pub struct User {
    username: String,
    display_name: String,
    favourite_colour: Option<Srgb>,
}

impl User {
    pub fn register_credential(&self) -> Result<T, E> {
        let mut id = self.username.as_bytes().to_vec();
        id.truncate(64);

        let result = webauthn.start_passkey_registration(
            id,
            &self.username,
            &self.display_name,
            // ...
        );

        // Do something with the result...
    }
}
```

A related design weakness is a storage system which expresses record identifiers
as a monotonically-incrementing integer (eg: MySQL's `AUTO_INCREMENT`). This
mandates a single, perfectly-reliable point of authority to issue IDs. This not
only becomes a single point of failure should that authority become unavailable
or unreachable, but a replicated database which goes split-brain can end up
causing severe data consistency problems should the same identifier be assigned
to multiple records.

While there are strategies to mitigate this issue (such as using every `N`th
integer), these need constant tweaking and careful coordination should the
number of shards change, and to keep each shard's offset consistent.

To mitigate both issues, `webauthn-rs`' interfaces simply define user ID as a
[`Uuid` type][uuid-type]:

```rust
pub fn start_passkey_registration(
    &self,
    id: &Uuid,
    username: &str,
    display_name: &str,
    // (other parameters omitted)
) {
    // ...
}
```

A UUID can be completely random (122 bits), or incorporate timestamps and/or
node identifiers to provide extensible namespaces as desired. They're also
well-established, and implemented in many database systems and programming
languages. They are also sufficiently-long to have an extremely low chance of
collision, even when dealing with billions of entities.

By using a UUID type, applications are forced into that model:

```rust
pub struct User {
    id: Uuid,
    username: String,
    display_name: String,
    favourite_colour: Option<Srgb>,
}

impl User {
    pub fn create(username: String, display_name: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            username,
            display_name,
            favourite_colour: None,
        }
    }

    pub fn register_credential(&self) -> Result<T, E> {
        let result = webauthn.start_passkey_registration(
            &self.id,
            &self.username,
            &self.display_name,
            // ...
        );

        // Do something with the result...
    }
}
```

While there *are* ways to bypass this (such as converting other types into a
`Uuid`), the [`Uuid` type][uuid-type] best expresses the *intended* usage.

[^name]: [`name` is defined in `PublicKeyCredentialEntity`][name-attr].

[uuid-type]: https://docs.rs/uuid/latest/uuid/
[user]: https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialuserentity
[name-attr]: https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialentity-name
[id-pii]: https://www.w3.org/TR/webauthn-3/#sctn-user-handle-privacy

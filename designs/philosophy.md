# webauthn-rs Design Philosophy

* **Published:** 2023-02-xx
* **Last updated:** 2023-02-xx

This document describes the design philosophy of `webauthn-rs`, as well as some
of the critical design decisions we've made over time.

If you ever wondered *why* `webauthn-rs` does things a certain way, this is the
document for you.

## Introduction

`webauthn-rs` is fairly opinionated about how one should use WebAuthn.

The WebAuthn API that most developers use comes from the browser:

* `navigator.credentials.create` to register
* `navigator.credentials.get` to authenticate

This API has many edge cases, and is easy to use in an insecure way, or in a way
that can make your application inflexible.

Our goal is that `webauthn-rs`:

* has safe interfaces
* encourages good design choices
* is hard to use in an unsafe way

This means we'll intentionally do some things differently to WebAuthn, or avoid
some APIs.

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
APIs (such as Bluetooth, smart cards and USB HID), and move as much
platform-specific code as possible into upstream libraries.

For example, we delegate smart card access to PC/SC, and would expect any
proposal to add an alternative smart card API to demonstrate why using PC/SC was
not appropriate or possible on that platform.

For WebAuthn itself, we need to implement some platform-specific code where that
platform has WebAuthn APIs (eg: on macOS and Windows), and we're okay with that.

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

While the specification states that `id` *must not* contain personally
identifying information (including usernames or email addresses), the
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

        webauthn.start_passkey_registration(
            id,
            &self.username,
            &self.display_name,
            /* ... */
        )
    }
}
```

Another related design weakness is a storage system which expresses record
identifiers as an monotonically-incrementing integer (eg: MySQL's
`AUTO_INCREMENT`). This mandates a single, perfectly-reliable point of authority
to issue IDs. This not only becomes a single point of failure should that
authority become unavailable or unreachable, but a replicated database which
goes split-brain can end up causing severe data consistency problems should the
same identifier be assigned to multiple records.

While there are strategies to mitigate these issues with a numeric identifier
(such as using every `N`th integer), these need constant tweaking and careful
coordination should the number of shards change, and to keep each shard's offset
consistent.

To mitigate both issues, `webauthn-rs`' interfaces define user ID as a
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
well-established and have many implementations in database systems and
programming languages. They are also sufficiently-long to have an extremely low
chance of collision, even for huge data sets.

The application's code is then forced into that model:

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
        webauthn.start_passkey_registration(
            self.id.to_owned(),
            &self.username,
            &self.display_name,
            /* ... */
        )
    }
}
```

While there *are* ways to bypass this (such as converting other types into a
`Uuid`), the [`Uuid` type][uuid-type] better expresses the intended usage.

[^name]: [`name` is defined in `PublicKeyCredentialEntity`][name-attr].

[uuid-type]: https://docs.rs/uuid/latest/uuid/
[user]: https://w3c.github.io/webauthn/#dictionary-user-credential-params
[name-attr]: https://w3c.github.io/webauthn/#dom-publickeycredentialentity-name

## Example: avoid shipping platform specific code


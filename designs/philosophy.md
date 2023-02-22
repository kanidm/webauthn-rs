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

We have built an escape hatch: `webauthn-rs-core`. However, we don't make
guarantees about how that works.

## Example: user identifiers

As a simple example, the most common way for a user to identify themselves is a
username. Many organisations set policies for how these should be expressed, but
it is quite often based on the person's name.

The username itself has many edge cases:

* Do you base the username on their *legal* name, or their *preferred* name?

* What happens when the user changes their name?

* Where is the username stored?

* How do you manage deletion of the username?

* Which glyphs are acceptable to use in a username? Does it allow for usernames
  in other writing systems?

WebAuthn addresses this issue by describing [the user entity][user]
(`PublicKeyCredentialUserEntity`) as having three attributes:

* `id` (`BufferSource`) a user handle for the account, comprised of an opaque
  byte sequence of up to 64 bytes, which is the *only* attribute to be used by
  an application when making authentication or authorisation decisions.

* `displayName` (`DOMString`), a human-palatable name for the account, where
  authenticators display at least 64 bytes.

* `name`[^name] (`DOMString`) is a human-palatable identifier for the account,
  intended for determining the difference between accounts with the same
  `displayName`. This could be a username, email address or phone number.

While the specification states that `id` *must not* contain personally
identifying information (including usernames or email addresses), the
`BufferSource` type is just a byte sequence (ie: `Vec<u8>`), and is easy to
misuse:

```rust
pub struct PublicKeyCredentialUserEntity {
    id: Vec<u8>,
    username: String,
    display_name: String,
}

pub struct User {
    username: String,
    display_name: String,
    favourite_colour: Option<Srgb>,
}

impl User {
    pub fn to_entity(&self) -> PublicKeyCredentialUserEntity {
        let mut id = self.username.as_bytes().to_vec();
        id.truncate(64);

        PublicKeyCredentialUserEntity {
            id,
            name: self.username.to_owned(),
            display_name: self.display_name.to_owned(),
        }
    }
}
```

Another failure mode is that expressing record (`User`) identifiers as an
monotonically-incrementing integer, which requires it to have a single point of
authority to issue IDs. This not only becomes a single point of failure should
that authority become unavailable or unreachable, but a replicated database
which goes split-brain can end up causing severe data consistency problems
should the same identifier be assigned to multiple records.

While there are ways to mitigate these issues (such as using every `N`th
integer), these need constant tweaking should the number of splits change, and
to keep each split's offset consistent.

As a result, `webauthn-rs` goes a step further by defining user ID as a UUID
type:

```rust
pub struct PublicKeyCredentialUserEntity {
    id: Uuid,
    username: String,
    display_name: String,
}
```

A UUID can be completely random (122 bits), or incorporate timestamps and/or
node identifiers to provide extensible namespaces as desired. They're also
well-established and have many implementations in database systems and
programming languages. They are also sufficiently-long to have an extremely low
chance of collision, even for huge data sets.

`webauthn-rs` thus forces an application to use an opaque user identifier, which
addresses all those issues:

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

    pub fn to_entity(&self) -> PublicKeyCredentialUserEntity {
        PublicKeyCredentialUserEntity {
            id: self.id.to_owned(),
            name: self.username.to_owned(),
            display_name: self.display_name.to_owned(),
        }
    }
}
```

While there *are* ways to bypass this (such as converting other types into a
`Uuid`), the `Uuid` type better expresses the intended usage.


[^name]: [`name` is defined in `PublicKeyCredentialEntity`][name-attr].


[user]: https://w3c.github.io/webauthn/#dictionary-user-credential-params
[name-attr]: https://w3c.github.io/webauthn/#dom-publickeycredentialentity-name


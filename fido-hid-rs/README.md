# fido-hid-rs

`fido-hid-rs` is a low-level library for communicating with USB HID FIDO
authenticators.

This library currently targets:

* Linux on `x86_64` (TBC)
* macOS 13 and later on `arm64` and `x86_64`
* Windows 10 on `arm64` and `x86_64`

This is an internal implementation detail of [`webauthn-authenticator-rs`][0].
It has **no guarantees of API stability**, and is not intended for use by other
parties.

If you're looking for a general-purpose USB HID library, look at [hidapi][].

[0]: ../webauthn-authenticator-rs
[hidapi]: https://docs.rs/hidapi/latest/hidapi/

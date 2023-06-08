# fido-hid-rs

`fido-hid-rs` implements a minimal set of platform-specific USB HID bindings for
communicating with FIDO authenticators.

> **Important:** this library is an _internal implementation detail_ of
> [webauthn-authenticator-rs][0] to work around Cargo limitations.
>
> **This library has no guarantees of API stability, and is not intended for use
> by other parties.**
>
> If you want to interface with USB HID FIDO authenticators, use
> [webauthn-authenticator-rs][0] instead of this library.
>
> If you're looking for a general-purpose Rust USB HID library, try [hidapi][].

This library currently targets (and is regularly tested on):

* Linux on `x86_64` (target version TBC)
* macOS 13 and later on `arm64` (Apple silicon) and `x86_64`
* Windows 10 on `x86_64` and Windows 11 on `arm64` and `x86_64`

We only test on the **current** service pack or point release of these operating
systems.

Other platforms (and older releases of these operating systems) are supported on
a "passive" basis only: it might work, but we generally don't have the
appropriate hardware available, and rely on users to notify us when things go
wrong and provide patches! ♥️

[0]: ../webauthn-authenticator-rs
[hidapi]: https://docs.rs/hidapi/latest/hidapi/

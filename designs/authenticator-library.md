# Authenticator library

* **Published:** 2022-09-24
* **Last updated:** 2022-10-07

This describes the state of the `webauthn-authenticator-rs` library, and some
potential longer term improvements.

## Current state (Sep 2022)

At present, there are two disjoint traits provided by the `webauthn-authenticator-rs` library:

1. A authenticator-level trait (`AuthenticatorBackend`), implemented by:

   * `U2FHid`: wrapper for Mozilla's `authenticator-rs` library
   * `SoftPasskey`: our own software passkey implementation
   * `SoftToken`: our own security token implementation

2. A transport-level trait (`Transport` / `Token`), implemented by:

   * `AnyTransport` / `AnyToken`: abstraction to provide access to all transports
   * `NFCReader` / `NFCCard`: NFC tokens using the PC/SC API
   * `USBTransport` / `USBToken`: USB HID tokens using `hidapi`

   This can currently only make a credential with FIDO v2.1-pre APIs.

   This doesn't (yet) implement authenticator-level features (`AuthenticatorBackend`), and so we don't know what gaps there are for a "real" use-case.

Long term, we're going to need _both_ levels of abstraction to interface with WebAuthn security tokens:

* Android has a [FIDO API](https://developers.google.com/android/reference/com/google/android/gms/fido/Fido) provided by Google Play Services, which provides access to hardware tokens (BLE, NFC and USB), and (maybe?) platform authenticators.

  There are also Android devices without Google Play Services, which don't have this API – but they'll need greater permissions to be able to use the other transports.

* macOS and iOS have [Passkey API](https://developer.apple.com/passkeys/), which also provides access to hardware tokens (NFC, USB and Lightning) and platform authenticators.

  macOS still allows direct access to BLE, NFC and USB security tokens, but we anticipate that this may be restricted in future versions of macOS.

* Windows 10 has its own [Webauthn API](https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/webauthn-apis), which provides access to hardware tokens (BLE, NFC and USB) and platform authenticators.

  As of 2019, Windows blocks direct access to USB HID authenticators, and applications *must* use the Windows WebAuthn API.

None of these platform APIs are supported by Mozilla's `authenticator-rs` library.

## authenticator-rs

Initially, we planned to delegate transport-level issues to Mozilla's `authenticator-rs` library, which is used by Firefox.

However, over time, it has raised cause for concern:

* The library has _internally_ forked into `main`, `ctap`, and `ctap-2021` branches.  `webauthn-authenticator-rs` already depends on a fork, and it has been difficult to upstream changes, as the library primarily targets Firefox's use cases.

* The library _only_ supports USB-HID security tokens.

  While it has transport-level abstractions, it is designed to abstract access to USB on different platforms, rather than BLE or NFC tokens.  It would take significant effort to unwrap this.

* The library's USB-HID implementation ships with a large amount of its _own_ platform and architecture-specific code, rather than depending on an existing Rust library that could meet this need.

* The library does not support biometric or other special types of authentication – it only supports simple keys with a presence button.

* The library does not support platform authenticators. [Firefox has a separate abstraction layer on Windows][ffx-win10] (written in C++).

[ffx-win10]: https://hg.mozilla.org/integration/autoland/rev/828fe91e878b

## Future plans

`webauthn-authenticator-rs` should aim to make access to WebAuthn authentication platform-agnostic, and fill in the gaps were necessary:

* Where there is a platform-level WebAuthn API (macOS, Windows), provide a consistent interface (through `AuthenticatorBackend`)
* On other platforms (Linux), fill in the gaps (through `Transport`/`Token`)

```
   Applications
        │
        ↓
AuthenticatorBackend ✔︎ ──┬──→ SoftPasskey / SoftToken ✔︎
        │                ├──→ Mozilla authenticator-rs ✔︎     ──→ USB HW
        │ ★              ├──→ macOS Passkey API wrapper ★    ──→ HW + SE
        │                └──→ Windows WebAuthn API wrapper ★ ──→ HW + SE
        ↓ 
   Transport/Token ✔︎   ──┬──→ AnyTransport ✔︎
                         ├──→ BLE ★ ──→ ???
                         ├──→ NFC ✔︎ ──→ pcsc
                         └──→ USB ✔︎ ──→ hidapi

✔︎: Current webauthn-authenticator-rs functionality
★: Proposed future functionality
HW: hardware token access
SE: secure enclave / platform token
```

### Implement an `AuthenticatorBackend` for `Transport`/`Token`

This would let us validate and improve upon the `Transport` level API to a point there's something _actually usable_.

This would provide access to NFC and USB-HID tokens through our own library, and allow us to potentially replace Mozilla's library.

### Implement an `AuthenticatorBackend` for platform-specific WebAuthn APIs

- [ ] macOS Passkey API
- [x] Windows 10 WebAuthn API (added Oct 2022)

This will require `webauthn-authenticator-rs` to carry some platform-specific code.

This is _immediately_ necessary on Windows 10, and would unlock access to platform authenticators.

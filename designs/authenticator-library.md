# Authenticator library

* **Published:** 2022-09-24
* **Last updated:** 2026-09-21

This describes the state of the `webauthn-authenticator-rs` library, and some
potential longer term improvements.

## Current state (Sep 2026)

At present, there are two slightly-disjoint traits provided by the `webauthn-authenticator-rs` library:

1. A authenticator-level trait (`AuthenticatorBackend`), implemented by:

   * `connect_cable_authenticator` / `cable::Tunnel`: connector for caBLE authenticators
   * `MozillaAuthenticator`: wrapper for Mozilla's `authenticator-rs` library
   * `SoftPasskey`: our own software passkey implementation
   * `SoftToken`: our own security token implementation

2. A transport-level trait (`Transport` / `Token`), implemented by:

   * `AnyTransport` / `AnyToken`: abstraction to provide access to all transports
   * `BluetoothTransport` / `BluetoothToken`: Bluetooth Low Energy tokens using `btleplug`
   * `NFCReader` / `NFCCard`: NFC tokens using the PC/SC API
   * `USBTransport` / `USBToken`: USB HID tokens using `hidapi`

   `CtapAuthenticator` provides an `AuthenticatorBackend`-compatible interface for these transports.

Long term, we're going to need _both_ levels of abstraction to interface with WebAuthn security tokens:

* Android has two WebAuthn-shaped APIs, both provided by Google Play Services:

  * [FIDO API](https://developers.google.com/identity/fido/android/native-apps), which provides access to hardware tokens (BLE, NFC and USB), and the platform authenticator.

  * [Credential Manager API](https://developers.google.com/identity/android-credential-manager), which provides access to synchronised credential managers only.

  There are also Android devices without Google Play Services, which don't have these APIs – but they'll need greater permissions to be able to use the other transports.

* macOS and iOS have [Passkey API](https://developer.apple.com/passkeys/), which also provides access to hardware tokens (NFC, USB and Lightning), synchronised credential managers and (formerly) platform credentials.

  macOS still allows direct access to BLE, NFC and USB security tokens, but we anticipate that this may be restricted in a future version of macOS.

* Windows 10 has its own [Webauthn API](https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/webauthn-apis), which provides access to hardware tokens (BLE, NFC and USB), synchronised credential managers and platform authenticators.

  As of 2019, Windows blocks direct access to USB HID authenticators, and applications *must* use the Windows WebAuthn API.

[None of these platform APIs are supported by Mozilla's `authenticator-rs` library][ffx-plat].

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
        │                ├──→ caBLE connector ✔︎              ──→ SE + PM
        │ ✔︎              ├──→ macOS Passkey API wrapper ★    ──→ HW + SE + PM
        │                └──→ Windows WebAuthn API wrapper ✔︎ ──→ HW + SE + PM
        ↓ 
   Transport/Token ✔︎   ──┬──→ AnyTransport ✔︎
                         ├──→ BLE ✔︎ ──→ btleplug
                         ├──→ NFC ✔︎ ──→ pcsc
                         └──→ USB ✔︎ ──→ hidapi

✔︎: Current webauthn-authenticator-rs functionality
★: Proposed future functionality
HW: hardware token access
SE: secure enclave / platform token
PM: password managers / synchronised credential managers
```

### Implement an `AuthenticatorBackend` for platform-specific WebAuthn APIs

- [ ] macOS Passkey API
- [x] Windows 10 WebAuthn API (added Oct 2022)

This will require `webauthn-authenticator-rs` to carry some platform-specific code.

This is _immediately_ necessary on Windows 10, and would unlock access to platform authenticators.

### Drop authenticator-rs

Initially, we planned to delegate transport-level issues to Mozilla's `authenticator-rs` library, which is used by Firefox. However, this library targets deep integration with the Firefox/Gecko ecosystem, rather than consumption by other Rust projects.

As of v0.6.0, it now (optionally) depends on `nss-rs`, which is not published to crates.io (because it is intended for Mozilla consumption, in a similar way to BoringSSL being intended for Google consumption).

It [does not and will not support platform WebAuthn APIs][ffx-plat], and Firefox has separate XPCOM bindings for for Android, iOS, macOS and Windows platform WebAuthn APIs.

[ffx-plat]: https://github.com/mozilla/authenticator-rs/issues/170

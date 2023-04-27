# fido-key-manager

fido-key-manager is a command line tool for managing and configuring FIDO/CTAP
2-compatible authenticators (security keys), based on
[the kanidm webauthn-authenticator-rs library][0].

**Important:** FIDO 1-only (U2F) tokens are **not supported** by this tool.

[0]: ../webauthn-authenticator-rs/README.md

## Building and running

On [Linux](#linux) and [macOS](#macos):

```sh
# Build fido-key-manager
cargo build --bin fido-key-manager

# Run fido-key-manager
./target/debug/fido-key-manager --help
```

On [Windows](#windows) (PowerShell):

```powershell
# Build fido-key-manager
cargo build --bin fido-key-manager

# Either:
# A) run Windows Terminal as Administrator, or,
Start-Process "shell:AppsFolder\$((Get-StartApps Terminal | Select-Object -First 1).AppId)" -Verb RunAs
# B) run PowerShell as Administrator.
Start-Process -FilePath "powershell" -Verb RunAs

# Run fido-key-manager from the Administrator terminal:
.\target\debug\fido-key-manager.exe --help
```

## Commands

**Important:** to prevent accidents, make sure you have only **one**
authenticator connected to your computer when running `fido-key-manager`.

More information about the commands listed below can be seen by running
`fido-key-manager --help` or `fido-key-manager [command] --help`. Unless
otherwise specified below, all commands require an authenticator which supports
*at least* CTAP 2.0.

Command | Description | Requirements
------- | ----------- | ------------
`info` | get information about connected authenticators
`selection` | request user presence on a connected authenticator | CTAP 2.1
`set-pin` | sets a PIN on an authenticator which doesn't already have a PIN set
`change-pin` | changes a PIN on an authenticator which has a PIN set
`factory-reset` | resets an authenticators to factory defaults, deleting all key material
`enable-enterprise-attestation` | enables the [Enterprise Attestation][] feature | CTAP 2.1
`set-pin-policy` | set a [Minimum PIN Length][] policy, or force a PIN change before next use | CTAP 2.1
`toggle-always-uv` | toggles the [Always Require User Verification][] feature | CTAP 2.1
`bio-info` | shows information about an authenticator's fingerprint sensor | CTAP 2.1-PRE, fingerprint sensor
`list-fingerprints` | lists enrolled fingerprints | CTAP 2.1-PRE, fingerprint sensor
`enroll-fingerprint` | enroll a new fingerprint | CTAP 2.1-PRE, fingerprint sensor
`rename-fingerprint` | renames an enrolled fingerprint | CTAP 2.1-PRE, fingerprint sensor
`remove-fingerprint` | removes an enrolled fingerprint | CTAP 2.1-PRE, fingerprint sensor

[Always Require User Verification]: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-feature-descriptions-alwaysUv
[Enterprise Attestation]: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-feature-descriptions-enterp-attstn
[Minimum PIN Length]: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-feature-descriptions-minPinLength

## Platform-specific notes

### Linux

* NFC support requires [PC/SC Lite][], and a PC/SC initiator (driver) for your
  NFC transceiver (reader).

  If you're using a transceiver with an NXP PN53x-series chipset (eg: ACS
  ACR122, Sony PaSoRi), you will need to block the `pn533` and `pn533_usb`
  kernel modules (which are incompatible [all other NFC software][linuxnfc])
  from loading:

  ```sh
  echo "blacklist pn533" | sudo tee -a /etc/modprobe.d/nfc.conf
  echo "blacklist pn533_usb" | sudo tee -a /etc/modprobe.d/nfc.conf
  sudo modprobe -r pn533
  sudo modprobe -r pn533_usb
  ```

  One of those `modprobe -r` commands will fail, depending on your kernel
  version.
  
  Finally, unplug and replug the transceiver.

  If issues return after you've rebooted your computer, you may *also* need to
  rebuild your initrd to pick up the `blacklist` entries above, and then reboot
  *again*.

* USB support requires `libudev` and appropriate permissions.

  systemd (udev) v252 and later
  [automatically tag USB HID FIDO tokens][udev-tag] and set permissions
  based on the `0xf1d0` usage page, which should work with any
  FIDO-compliant authenticator.

  Systems with older versions of systemd will need a "U2F rules" package
  (eg: `libu2f-udev`). But these match FIDO authenticators using a list of known
  USB manufacturer and product IDs, which can be a problem for new or esoteric
  authenticators.

[linuxnfc]: https://ludovicrousseau.blogspot.com/2013/11/linux-nfc-driver-conflicts-with-ccid.html
[PC/SC Lite]: https://pcsclite.apdu.fr/
[udev-tag]: https://github.com/systemd/systemd/issues/11996

### macOS

* NFC should "just work", provided you've installed a PC/SC initiator
  (driver) for your transciever (if it is not supported by `libccid`).

* USB should "just work".

### Windows

**Important:** This tool has only been tested with the *current builds* of
Windows 10 and 11 on 64-bit platforms (`arm64` and `x86_64`). This tool
(intentionally) does not support older versions of Windows, and is untested on
32-bit systems (it's 2023, come on).

**Windows 10** build 1903 and later (as well as **Windows 11**) block direct
communication with FIDO authenticators (or otherwise hide the USB devices), so
this tool *must* be run as `Administrator`.

This tool has been configured with [a manifest to run as Administrator][1],
which has some caveats:

* `cargo run` will not be able to run this program
* if elevation was necessary, it won't show the output of the tool in your
  current console window

Always run this tool from within a terminal running as Administrator.

[1]: https://learn.microsoft.com/en-us/previous-versions/bb756929(v=msdn.10)

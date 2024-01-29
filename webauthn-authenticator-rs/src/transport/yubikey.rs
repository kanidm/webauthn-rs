//! YubiKey vendor-specific commands.
//!
//! This currently only supports YubiKey 5 and later. Older keys have different
//! config formats and protocols, some firmwares give bogus data.
//!
//! ## USB HID
//!
//! Commands are sent on a `U2FHIDFrame` level, and values are bitwise-OR'd
//! with `transport::TYPE_INIT` (0x80).
//!
//! Command | Description | Request | Response
//! ------- | ----------- | ------- | --------
//! `0x40`  | Set legacy device config | ... | ...
//! `0x42`  | Get device config | _none_ | [`YubiKeyConfig`]
//! `0x43`  | Set device config | [`YubiKeyConfig`] | none?
//!
//! ## NFC
//!
//! **NFC support is not yet implemented.**
//!
//! Management app AID: `a000000527471117`
//!
//! All commands sent with CLA = `0x00`, P2 = `0x00`.
//!
//! INS    | P1     | Description | Request | Response
//! ------ | ------ | ----------- | ------- | --------
//! `0x16` | `0x11` | Set legacy device config | ... | ...
//! `0x1D` | `0x00` | Get device config | _none_ | [`YubiKeyConfig`]
//! `0x1C` | `0x00` | Set device config | [`YubiKeyConfig`] | none?
//!
//! ## References
//!
//! * [DeviceInfo structure][0] (includes config)
//!
//! [0]: https://github.com/Yubico/yubikey-manager/blob/51a7ae438c923189788a1e31d3de18d452131942/yubikit/management.py#L223
use async_trait::async_trait;
use bitflags::bitflags;
use num_traits::cast::FromPrimitive;

use crate::{prelude::WebauthnCError, tlv::ber::BerTlvParser};

use super::AnyToken;

#[cfg(all(feature = "usb", feature = "vendor-yubikey"))]
pub(crate) const CMD_GET_CONFIG: u8 = super::TYPE_INIT | 0x42;

bitflags! {
    /// Bitmask of enabled / available interfaces.
    ///
    /// `ykman` calls these "Capabilities".
    ///
    /// Reference: <https://github.com/Yubico/yubikey-manager/blob/51a7ae438c923189788a1e31d3de18d452131942/yubikit/management.py#L62>
    #[derive(Default)]
    pub struct Interface: u16 {
        const OTP = 0x01;
        const CTAP1 = 0x02;
        const OPENPGP = 0x08;
        const PIV = 0x10;
        const OATH = 0x20;
        const YUBIHSM = 0x100;
        const CTAP2 = 0x200;
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, FromPrimitive, ToPrimitive)]
#[repr(u16)]
enum ConfigKey {
    #[default]
    Unknown = 0x0,
    SupportedUsbInterfaces = 0x1,
    Serial = 0x2,
    EnabledUsbInterfaces = 0x3,
    FormFactor = 0x4,
    Version = 0x5,
    AutoEjectTimeout = 0x6,
    ChallengeResponseTimeout = 0x7,
    DeviceFlags = 0x8,
    AppVersions = 0x9,
    /// 16 bytes lock code, or indicates when a device is locked
    ConfigLock = 0xa,
    /// 16 bytes unlock code, to unlock a locked device
    Unlock = 0xb,
    Reboot = 0xc,
    SupportedNfcInterfaces = 0xd,
    EnabledNfcInterfaces = 0xe,
}

/// YubiKey device form factor.
///
/// Only the lower 3 bits of the `u8` are used.
#[derive(Debug, Clone, PartialEq, Eq, Default, FromPrimitive, ToPrimitive)]
#[repr(u8)]
pub enum FormFactor {
    #[default]
    Unknown = 0x0,
    /// USB-A keychain-size device
    UsbAKeychain = 0x1,
    /// USB-A nano-size device
    UsbANano = 0x2,
    /// USB-C keychain-size device
    UsbCKeychain = 0x3,
    /// USB-C nano-size device
    UsbCNano = 0x4,
    /// USB-C + Lightning device
    UsbCLightning = 0x5,
    /// USB-A + biometric device
    UsbABio = 0x6,
    /// USB-C + biometric device
    UsbCBio = 0x7,
}

/// YubiKey device info / configuration structure
///
/// ## Payload format
///
/// * `u8`: length
/// * BER-TLV-like payload
///
/// The payload is BER-TLV-like, with some differences:
///
/// * all tags use the universal class (0x00)
/// * tag numbers are one of the values in [`ConfigKey`]
/// * values are encoded directly
#[derive(Debug, Default, PartialEq, Eq)]
pub struct YubiKeyConfig {
    /// Device serial number. This isn't available on all devices.
    pub serial: Option<u32>,
    /// Form factor of the device.
    pub form_factor: FormFactor,
    /// Firmware version of the device.
    pub version: [u8; 3],
    /// `true` if a configuration lock has been set on the device.
    pub is_locked: bool,
    /// `true` if the device is FIPS-certified.
    pub is_fips: bool,
    /// `true` if the device is a "Security Key" (CTAP-only), `false` if it is a
    /// "YubiKey".
    pub is_security_key: bool,
    pub supports_remote_wakeup: bool,
    pub supports_eject: bool,
    /// Interfaces which are supported over USB.
    pub supported_usb_interfaces: Interface,
    /// Interfaces which are enabled over USB.
    pub enabled_usb_interfaces: Interface,
    /// Interfaces which are supported over NFC. Non-NFC devices don't set any
    /// values here.
    pub supported_nfc_interfaces: Interface,
    /// Interfaces which are enabled over NFC.
    pub enabled_nfc_interfaces: Interface,
    pub auto_eject_timeout: u16,
    pub challenge_response_timeout: u16,
}

impl YubiKeyConfig {
    pub fn from_bytes(b: &[u8]) -> Result<Self, WebauthnCError> {
        if b.is_empty() {
            return Err(WebauthnCError::InvalidMessageLength);
        }
        let len = b[0];
        if b.len() - 1 != usize::from(len) {
            return Err(WebauthnCError::InvalidMessageLength);
        }

        let mut o = YubiKeyConfig {
            ..Default::default()
        };
        let parser = BerTlvParser::new(&b[1..]);

        for (cls, constructed, tag, val) in parser {
            if cls != 0 || constructed {
                continue;
            }
            let Some(key) = ConfigKey::from_u16(tag) else {
                continue;
            };

            match key {
                ConfigKey::Unknown => continue,
                ConfigKey::SupportedUsbInterfaces => {
                    if val.len() != 2 {
                        continue;
                    }
                    let v = u16::from_be_bytes(
                        val.try_into()
                            .map_err(|_| WebauthnCError::InvalidMessageLength)?,
                    );
                    if let Some(i) = Interface::from_bits(v & Interface::all().bits()) {
                        o.supported_usb_interfaces = i;
                    }
                }
                ConfigKey::Serial => {
                    if val.len() != 4 {
                        continue;
                    }
                    o.serial = val.try_into().map(u32::from_be_bytes).ok();
                }
                ConfigKey::EnabledUsbInterfaces => {
                    if val.len() != 2 {
                        continue;
                    }
                    let v = u16::from_be_bytes(
                        val.try_into()
                            .map_err(|_| WebauthnCError::InvalidMessageLength)?,
                    );
                    if let Some(i) = Interface::from_bits(v & Interface::all().bits()) {
                        o.enabled_usb_interfaces = i;
                    }
                }
                ConfigKey::FormFactor => {
                    if val.is_empty() {
                        continue;
                    }
                    if let Some(f) = FormFactor::from_u8(val[0] & 0x7) {
                        o.form_factor = f;
                    }
                    o.is_fips = val[0] & 0x80 != 0;
                    o.is_security_key = val[0] & 0x40 != 0;
                }
                ConfigKey::Version => {
                    if let Ok(v) = val.try_into() {
                        o.version = v;
                    }
                }
                ConfigKey::AutoEjectTimeout => {
                    if let Some(v) = variable_be_bytes_to_u16(val) {
                        o.auto_eject_timeout = v;
                    }
                }
                ConfigKey::ChallengeResponseTimeout => {
                    if let Some(v) = variable_be_bytes_to_u16(val) {
                        o.challenge_response_timeout = v;
                    }
                }
                ConfigKey::DeviceFlags => {
                    if val.is_empty() {
                        continue;
                    }
                    o.supports_remote_wakeup = val[0] & 0x40 != 0;
                    o.supports_eject = val[0] & 0x80 != 0;
                }
                ConfigKey::AppVersions => {
                    continue;
                }
                ConfigKey::ConfigLock => {
                    if val.is_empty() {
                        continue;
                    }
                    o.is_locked = val[0] == 1;
                }
                ConfigKey::Unlock => continue,
                ConfigKey::Reboot => continue,
                ConfigKey::SupportedNfcInterfaces => {
                    if val.len() != 2 {
                        continue;
                    }
                    let v = u16::from_be_bytes(
                        val.try_into()
                            .map_err(|_| WebauthnCError::InvalidMessageLength)?,
                    );
                    if let Some(i) = Interface::from_bits(v & Interface::all().bits()) {
                        o.supported_nfc_interfaces = i;
                    }
                }
                ConfigKey::EnabledNfcInterfaces => {
                    if val.len() != 2 {
                        continue;
                    }
                    let v = u16::from_be_bytes(
                        val.try_into()
                            .map_err(|_| WebauthnCError::InvalidMessageLength)?,
                    );
                    if let Some(i) = Interface::from_bits(v & Interface::all().bits()) {
                        o.enabled_nfc_interfaces = i;
                    }
                }
            }
        }

        Ok(o)
    }

    pub fn is_preview(&self) -> bool {
        match (self.version[0], self.version[1], self.version[2]) {
            (5, 0, _) => true,
            (5, 2, z) => z < 3,
            (5, 5, z) => z < 2,
            _ => false,
        }
    }
}

impl std::fmt::Display for YubiKeyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "Form factor: {:?}{}",
            self.form_factor,
            if self.is_security_key {
                " Security Key"
            } else {
                " YubiKey"
            }
        )?;
        writeln!(
            f,
            "Version: {}.{}.{}",
            self.version[0], self.version[1], self.version[2]
        )?;

        write!(f, "Flags: ")?;
        if self.is_preview() {
            write!(f, "preview, ")?;
        }
        if self.is_locked {
            write!(f, "config locked, ")?;
        }
        if self.is_fips {
            write!(f, "FIPS, ")?;
        }
        if self.supports_remote_wakeup {
            write!(f, "remote wake-up, ")?;
        }
        if self.supports_eject {
            write!(f, "eject, ")?;
        }
        writeln!(f)?;

        if let Some(serial) = self.serial {
            writeln!(f, "Serial: {serial}")?;
        }

        if !self.supported_usb_interfaces.is_empty() {
            writeln!(
                f,
                "Supported USB interfaces: {:?}",
                self.supported_usb_interfaces
            )?;
            writeln!(
                f,
                "Enabled USB interfaces: {:?}",
                self.enabled_usb_interfaces
            )?;
        }

        if !self.supported_nfc_interfaces.is_empty() {
            writeln!(
                f,
                "Supported NFC interfaces: {:?}",
                self.supported_nfc_interfaces
            )?;
            writeln!(
                f,
                "Enabled NFC interfaces: {:?}",
                self.enabled_nfc_interfaces
            )?;
        }

        if self.auto_eject_timeout != 0 {
            writeln!(f, "Auto-eject timeout: {}", self.auto_eject_timeout)?;
        }

        if self.challenge_response_timeout != 0 {
            writeln!(
                f,
                "Challenge-response timeout: {}",
                self.challenge_response_timeout
            )?;
        }

        Ok(())
    }
}

/// See [`YubiKeyAuthenticator`](crate::ctap2::YubiKeyAuthenticator).
#[async_trait]
pub trait YubiKeyToken {
    /// See [`SoloKeyAuthenticator::get_solokey_lock()`](crate::ctap2::SoloKeyAuthenticator::get_solokey_lock).
    async fn get_yubikey_config(&mut self) -> Result<YubiKeyConfig, WebauthnCError>;
}

#[async_trait]
#[allow(clippy::unimplemented)]
impl YubiKeyToken for AnyToken {
    async fn get_yubikey_config(&mut self) -> Result<YubiKeyConfig, WebauthnCError> {
        match self {
            AnyToken::Stub => unimplemented!(),
            #[cfg(feature = "bluetooth")]
            AnyToken::Bluetooth(_) => Err(WebauthnCError::NotSupported),
            #[cfg(feature = "nfc")]
            AnyToken::Nfc(_) => Err(WebauthnCError::NotSupported),
            #[cfg(feature = "usb")]
            AnyToken::Usb(u) => u.get_yubikey_config().await,
        }
    }
}

fn variable_be_bytes_to_u16(b: &[u8]) -> Option<u16> {
    if b.len() == 1 {
        Some(u16::from(b[0]))
    } else if b.len() == 2 {
        b.try_into().map(u16::from_be_bytes).ok()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yubikey_5c() {
        let _ = tracing_subscriber::fmt().try_init();
        let expected = YubiKeyConfig {
            serial: Some(0xcafe1234),
            form_factor: FormFactor::UsbCKeychain,
            version: [5, 1, 2],
            supported_usb_interfaces: Interface::OTP
                | Interface::CTAP1
                | Interface::CTAP2
                | Interface::OPENPGP
                | Interface::PIV
                | Interface::OATH,
            enabled_usb_interfaces: Interface::OPENPGP | Interface::PIV | Interface::CTAP2,
            supported_nfc_interfaces: Interface::empty(),
            enabled_nfc_interfaces: Interface::empty(),
            auto_eject_timeout: 0,
            challenge_response_timeout: 15,
            ..Default::default()
        };
        let v =
            hex::decode("230102023f030202180204cafe123404010305030501020602000007010f0801000a0100")
                .unwrap();
        let cfg = YubiKeyConfig::from_bytes(v.as_slice()).unwrap();
        assert_eq!(expected, cfg);
    }

    #[test]
    fn yubikey_5c_nano() {
        let _ = tracing_subscriber::fmt().try_init();
        let expected = YubiKeyConfig {
            serial: Some(0xcafe1234),
            form_factor: FormFactor::UsbCNano,
            version: [5, 2, 4],
            supported_usb_interfaces: Interface::OTP
                | Interface::CTAP1
                | Interface::CTAP2
                | Interface::OPENPGP
                | Interface::PIV
                | Interface::OATH,
            enabled_usb_interfaces: Interface::CTAP1 | Interface::CTAP2,
            supported_nfc_interfaces: Interface::empty(),
            enabled_nfc_interfaces: Interface::empty(),
            auto_eject_timeout: 0,
            challenge_response_timeout: 15,
            ..Default::default()
        };
        let v = hex::decode(
            "260102023f030202020204cafe123404010405030502040602000007010f0801000a01000f0100",
        )
        .unwrap();
        let cfg = YubiKeyConfig::from_bytes(v.as_slice()).unwrap();
        assert_eq!(expected, cfg);
    }

    #[test]
    fn yubico_security_key_c_nfc() {
        let _ = tracing_subscriber::fmt().try_init();
        let expected = YubiKeyConfig {
            version: [5, 4, 3],
            form_factor: FormFactor::UsbCKeychain,
            is_security_key: true,
            supported_usb_interfaces: Interface::CTAP1 | Interface::CTAP2,
            enabled_usb_interfaces: Interface::CTAP2,
            supported_nfc_interfaces: Interface::CTAP1 | Interface::CTAP2,
            enabled_nfc_interfaces: Interface::CTAP2,
            challenge_response_timeout: 15,
            ..Default::default()
        };

        let v = hex::decode(
            "28010202020302020004014305030504030602000007010f0801000d0202060e0202000a01000f0100",
        )
        .unwrap();
        let cfg = YubiKeyConfig::from_bytes(v.as_slice()).unwrap();
        assert_eq!(expected, cfg);
    }
}

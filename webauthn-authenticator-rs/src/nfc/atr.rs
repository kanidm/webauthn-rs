//! ISO/IEC 7816-3 _Answer-to-Reset_ and 7816-4 _Historical Bytes_ parser.
use std::collections::{HashSet, VecDeque};

#[cfg(feature = "nfc")]
use pcsc::MAX_ATR_SIZE;

use crate::WebauthnCError;

use super::tlv::*;

/// ISO/IEC 7816-3 _Answer-to-Reset_ and 7816-4 _Historical Bytes_ parser.
///
/// This intentionally incomplete, and only supports a subset of the standards
/// needed for compatibility with FIDO tokens.
///
/// References:
///
/// * "Answer-to-Reset", [ISO/IEC 7816-3:2005][iso7816-3] §8.2
/// * "Historical bytes", [ISO/IEC 7816-4:2006][iso7816-4] §8.1.1
/// * "ATR, Contactless Smart Cards", [PC/SC Specification][pcsc-spec] Part 3,
///   §3.1.3.2.3.1
/// * "ATR, Contactless Storage Cards", [PC/SC Specification][pcsc-spec] Part 3,
///   §3.1.3.2.3.2
///
/// Other resources:
///
/// * [pyscard ATR decoder](https://smartcard-atr.apdu.fr/)
/// * [Ludovic Rousseau's series about ATR bytes](https://ludovicrousseau.blogspot.com/2016/01/atr-list-study.html)
/// * [Wikipedia: Answer to reset](https://en.wikipedia.org/wiki/Answer_to_reset)
///
/// [iso7816-3]: https://www.iso.org/standard/38770.html
/// [iso7816-4]: https://www.iso.org/standard/36134.html
/// [pcsc-spec]: https://pcscworkgroup.com/specifications/download/
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Atr {
    /// Supported protocols (`T=`), specified in ISO/IEC 7816-3:2006 §8.2.3.
    pub protocols: HashSet<u8>,

    /// Historical bytes (T<sub>1</sub> .. T<sub>k</sub>), as specified in
    /// ISO/IEC 7816-4:2005 §8.1.1.
    pub t1: Vec<u8>,

    /// If `true`, this is a contactless storage card per
    /// [PC/SC Specification][pcsc-spec] Part 3, §3.1.3.2.3.2, and Part 3
    /// Supplemental Document.
    ///
    /// Further clarification is available in the historical bytes
    /// ([`Self::t1`]), but is beyond the scope of this module.
    ///
    /// FIDO tokens should always return `false`.
    pub storage_card: bool,

    /// Card issuer's data (ISO/IEC 7816-4:2005 §8.1.1.2.5). The structure of
    /// this value is defined by the card issuer. This sometimes contains a
    /// printable string identifying the card issuer (see
    /// [`Self::card_issuers_data_str()`]).
    pub card_issuers_data: Option<Vec<u8>>,

    /// Whether the card supports command chaining (ISO/IEC 7816-4:2005
    /// §5.1.1.1). This allows sending commands longer than 255 bytes using only
    /// short form L<sub>c</sub>.
    ///
    /// If this value is set to None, the card did not provide a "card
    /// capabilities" value (ISO/IEC 7816-4:2005 §8.1.1.2.7).
    pub command_chaining: Option<bool>,

    /// Whether the card supports extended (3 byte) L<sub>c</sub> and
    /// L<sub>e</sub> fields (ISO/IEC 7816-4:2005 §5.1) – which allows
    /// N<sub>c</sub> (command data length) and N<sub>e</sub> (maximum expected
    /// response length) values from 257 to 65536 bytes.
    ///
    /// If this value is set to `None`, the card did not provide a "card
    /// capabilities" value (§8.1.1.2.7), and therefore does not support
    /// extended fields (§5.1).
    ///
    /// FIDO v2.0 [requires][nfc-ext] all NFC devices support short _and_
    /// extended length encoding.
    ///
    /// See: [`ISO7816LengthForm`][crate::transport::iso7816::ISO7816LengthForm]
    ///
    /// [nfc-ext]: https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#nfc-framing
    pub extended_lc: Option<bool>,
}

const PROTOCOL_T0: [u8; 1] = [0];

/// PC/SC AID, per [PC/SC Specification][pcsc-spec] Part 3 Supplemental
/// Document.
///
/// [pcsc-spec]: https://pcscworkgroup.com/specifications/download/
const PCSC_AID: [u8; 5] = [0xa0, 0x00, 0x00, 0x03, 0x06];

/// Minimum response length for PC/SC storage card data in the ATR.
const PCSC_RESPONSE_LEN: usize = 6 + PCSC_AID.len();

/// Validates check byte TCK according to ISO/IEC 7816-3:2006 §8.2.5: XOR'ing
/// all bytes from T<sub>0</sub> to TCK inclusive should return zero.
fn checksum(i: &[u8]) -> bool {
    let o = i[1..].iter().fold(0, |a, i| a ^ i);

    #[cfg(test)]
    {
        let last = i.last().unwrap_or(&0);
        trace!("i.last == {:02x?}, expected {:02x?}", last, o ^ last);
    }
    o == 0
}

impl TryFrom<&[u8]> for Atr {
    type Error = WebauthnCError;

    /// Attempts to parse an ATR from a `&[u8]`.
    fn try_from(atr: &[u8]) -> Result<Self, Self::Error> {
        if atr.len() < 2 {
            return Err(WebauthnCError::MessageTooShort);
        }

        let mut nibbles = VecDeque::with_capacity(MAX_ATR_SIZE);
        // Byte 0 intentionally skipped

        // Calculate checksum (TCK), present unless the only protocol is T=0:
        if atr.len() >= 3 // T != 0 protocols have at least 3 bytes ATR
        && atr[1] & 0x80 != 0x00 // TD0 present, no implicit T=0 only
        && (atr[2] & 0x0F != 0x00  // First protocol is not T=0, or
            || atr[2] & 0x80 != 0x00) // there is more than one protocol
        && !checksum(atr)
        {
            return Err(WebauthnCError::Checksum);
        }

        let mut i: usize = 1;
        loop {
            let y = atr[i] >> 4;
            nibbles.push_back(atr[i] & 0x0f);
            i += 1;

            // skip Ta, Tb, Tc fields
            i += (y & 0x7).count_ones() as usize;
            if y & 0x8 == 0 {
                /* Td = 0 */
                break;
            }
        }

        let t1_len = nibbles.pop_front().unwrap_or_default() as usize;

        let protocols = if nibbles.len() >= 1 {
            HashSet::from_iter(nibbles.into_iter())
        } else {
            // If TD1 is absent, the only offer is T=0.
            HashSet::from(PROTOCOL_T0)
        };

        let mut storage_card = false;
        let mut command_chaining = None;
        let mut extended_lc = None;
        let mut card_issuers_data = None;
        if i + t1_len > atr.len() {
            return Err(WebauthnCError::MessageTooShort);
        }
        let t1 = &atr[i..i + t1_len];

        // First historical byte is the "category indicator byte".
        if t1_len == 0 {
            // No historical bytes
        } else if t1[0] == 0x00 || t1[0] == 0x80 {
            // 0x00, 0x80 = Compact-TLV payload
            let tlv_payload = if t1[0] == 0x00 {
                // 0x00: remaining historical bytes are followed by a mandatory
                // 3 byte status indicator (not in TLV)
                &t1[1..t1_len - 3]
            } else {
                // 0x80: remaining historical bytes are all TLV
                &t1[1..]
            };

            if tlv_payload.len() > PCSC_RESPONSE_LEN
                && tlv_payload[0] == 0x4f
                && tlv_payload[2..7] == PCSC_AID
            {
                // PC/SC Spec, Part 3, §3.1.3.2.3.2 (Contactless Storage Cards)
                // is incorrectly defined in Simple-TLV, not Compact-TLV. FIDO
                // tokens won't be storage cards, so we'll just ignore this.
                // This just means we don't barf on transit cards.
                storage_card = true;
            } else {
                let tlv = CompactTlv::new(tlv_payload);
                for (t, v) in tlv {
                    // trace!("tlv: {:02x?} = {:02x?}", t, v);
                    if t == 7 {
                        // 7816-4 §8.1.1.2.7 Card capabilities
                        if v.len() >= 3 {
                            command_chaining = Some((v[2] & 0x80) != 0);
                            extended_lc = Some((v[2] & 0x40) != 0);
                        }
                    } else if t == 5 {
                        // 7816-4 §8.1.1.2.5 Card issuer's data
                        card_issuers_data = Some(v.to_vec());
                    }
                }
            }
        }

        Ok(Atr {
            protocols,
            t1: t1.to_vec(),
            storage_card,
            command_chaining,
            extended_lc,
            card_issuers_data,
        })
    }
}

impl Atr {
    /// Converts [`Self::card_issuers_data`] to a UTF-8 encoded string.
    ///
    /// Returns `None` if [`Self::card_issuers_data`] is missing, or if it
    /// contains invalid UTF-8.
    pub fn card_issuers_data_str(&self) -> Option<&str> {
        std::str::from_utf8(self.card_issuers_data.as_ref()?)
            .map(Some)
            .unwrap_or(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yubikey_5_nfc() {
        let _ = tracing_subscriber::fmt().try_init();
        let input = [
            0x3b, 0x8d, 0x80, 0x01, 0x80, 0x73, 0xc0, 0x21, 0xc0, 0x57, 0x59, 0x75, 0x62, 0x69,
            0x4b, 0x65, 0xff, 0x7f,
        ];
        let expected = Atr {
            protocols: HashSet::from([0, 1]),
            t1: [
                0x80, 0x73, 0xc0, 0x21, 0xc0, 0x57, 0x59, 0x75, 0x62, 0x69, 0x4b, 0x65, 0xff,
            ]
            .to_vec(),
            storage_card: false,
            // "YubiKe\xFF"
            card_issuers_data: Some([0x59, 0x75, 0x62, 0x69, 0x4b, 0x65, 0xff].to_vec()),
            command_chaining: Some(true),
            extended_lc: Some(true),
        };

        let actual = Atr::try_from(&input[..]).expect("yubikey_5_nfc ATR");
        assert_eq!(expected, actual);
        assert_eq!(None, actual.card_issuers_data_str());
    }

    #[test]
    fn yubico_security_key_c_nfc() {
        let _ = tracing_subscriber::fmt().try_init();
        let input = [
            0x3b, 0x8d, 0x80, 0x01, 0x80, 0x73, 0xc0, 0x21, 0xc0, 0x57, 0x59, 0x75, 0x62, 0x69,
            0x4b, 0x65, 0x79, 0xf9,
        ];
        let expected = Atr {
            protocols: HashSet::from([0, 1]),
            t1: [
                0x80, 0x73, 0xc0, 0x21, 0xc0, 0x57, 0x59, 0x75, 0x62, 0x69, 0x4b, 0x65, 0x79,
            ]
            .to_vec(),
            storage_card: false,
            // "YubiKey"
            card_issuers_data: Some([0x59, 0x75, 0x62, 0x69, 0x4b, 0x65, 0x79].to_vec()),
            command_chaining: Some(true),
            extended_lc: Some(true),
        };

        let actual = Atr::try_from(&input[..]).expect("yubico_security_key_c_nfc ATR");
        assert_eq!(expected, actual);
        assert_eq!("YubiKey", actual.card_issuers_data_str().unwrap());
    }

    #[test]
    fn yubico_yubikey_5c_usb_macos() {
        let _ = tracing_subscriber::fmt().try_init();
        let input = [
            0x3b, 0xfd, 0x13, 0x00, 0x00, 0x81, 0x31, 0xfe, 0x15, 0x80, 0x73, 0xc0, 0x21, 0xc0,
            0x57, 0x59, 0x75, 0x62, 0x69, 0x4b, 0x65, 0x79, 0x40,
        ];
        let expected = Atr {
            // T=1 repeated twice
            protocols: HashSet::from([1]),
            t1: [
                0x80, 0x73, 0xc0, 0x21, 0xc0, 0x57, 0x59, 0x75, 0x62, 0x69, 0x4b, 0x65, 0x79,
            ]
            .to_vec(),
            storage_card: false,
            // "YubiKey"
            card_issuers_data: Some([0x59, 0x75, 0x62, 0x69, 0x4b, 0x65, 0x79].to_vec()),
            command_chaining: Some(true),
            extended_lc: Some(true),
        };

        let actual = Atr::try_from(&input[..]).expect("yubico_yubikey_5c_usb_macos ATR");
        assert_eq!(expected, actual);
        assert_eq!("YubiKey", actual.card_issuers_data_str().unwrap());
    }

    #[test]
    fn desfire_storage_card() {
        let input = [0x3b, 0x81, 0x80, 0x01, 0x80, 0x80];
        let expected = Atr {
            protocols: HashSet::from([0, 1]),
            t1: [0x80].to_vec(),
            storage_card: false,
            card_issuers_data: None,
            command_chaining: None,
            extended_lc: None,
        };

        let actual = Atr::try_from(&input[..]).expect("desfire_storage_card ATR");
        assert_eq!(expected, actual);
        assert_eq!(None, actual.card_issuers_data_str());
    }

    #[test]
    fn felica_storage_card() {
        let _ = tracing_subscriber::fmt().try_init();
        let input = [
            0x3b, 0x8f, 0x80, 0x01, 0x80, 0x4f, 0x0c, 0xa0, 0x00, 0x00, 0x03, 0x06, 0x11, 0x00,
            0x3b, 0x00, 0x00, 0x00, 0x00, 0x42,
        ];
        let expected = Atr {
            protocols: HashSet::from([0, 1]),
            t1: [
                0x80, 0x4f, 0x0c, 0xa0, 0x00, 0x00, 0x03, 0x06, 0x11, 0x00, 0x3b, 0x00, 0x00, 0x00,
                0x00,
            ]
            .to_vec(),
            storage_card: true,
            card_issuers_data: None,
            command_chaining: None,
            extended_lc: None,
        };

        let actual = Atr::try_from(&input[..]).expect("felica_storage_card ATR");
        assert_eq!(expected, actual);
        assert_eq!(None, actual.card_issuers_data_str());
    }

    #[test]
    fn short_capabilities() {
        let _ = tracing_subscriber::fmt().try_init();
        // These have a 1 and 2 byte tag 0x7X, so command chaining and extended
        // lc support isn't available.
        let i1 = [0x3b, 0x83, 0x80, 0x01, 0x80, 0x71, 0xc0, 0x33];
        let expected_protocols = HashSet::from([0, 1]);
        let a1 = Atr::try_from(&i1[..]).expect("short caps atr1");

        assert_eq!(expected_protocols, a1.protocols);
        assert_eq!(None, a1.command_chaining);
        assert_eq!(None, a1.extended_lc);
        assert!(!a1.storage_card);

        let i2 = [0x3b, 0x84, 0x80, 0x01, 0x80, 0x71, 0xc0, 0x21, 0x15];
        let a2 = Atr::try_from(&i2[..]).expect("short caps atr2");

        assert_eq!(expected_protocols, a2.protocols);
        assert_eq!(None, a2.command_chaining);
        assert_eq!(None, a2.extended_lc);
        assert!(!a2.storage_card);
    }

    #[test]
    fn edge_cases() {
        let _ = tracing_subscriber::fmt().try_init();
        let expected = Atr {
            protocols: HashSet::from([0]),
            t1: [].to_vec(),
            storage_card: false,
            card_issuers_data: None,
            command_chaining: None,
            extended_lc: None,
        };

        let i1 = [0x3b, 0x80, 0x00];
        let a1 = Atr::try_from(&i1[..]).expect("edge_cases T=0");
        assert_eq!(expected, a1);

        let i2 = [0x3b, 0x00];
        let a2 = Atr::try_from(&i2[..]).expect("edge_cases T=(implicit)0");
        assert_eq!(expected, a2);
    }

    #[test]
    fn error_cases() {
        let _ = tracing_subscriber::fmt().try_init();
        let i1 = [0x3b];
        let a1 = Atr::try_from(&i1[..]);
        assert_eq!(a1, Err(WebauthnCError::MessageTooShort));
    }
}

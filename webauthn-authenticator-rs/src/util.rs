use std::collections::BTreeMap;

use base64urlsafedata::Base64UrlSafeData;
use openssl::sha;
use unicode_normalization::UnicodeNormalization;
use url::Url;
use webauthn_rs_proto::CollectedClientData;

pub fn compute_sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = sha::Sha256::new();
    hasher.update(data);
    hasher.finish()
}

pub fn creation_to_clientdata(origin: Url, challenge: Base64UrlSafeData) -> CollectedClientData {
    CollectedClientData {
        type_: "webauthn.create".to_string(),
        challenge,
        origin,
        token_binding: None,
        cross_origin: None,
        unknown_keys: BTreeMap::new(),
    }
}

pub fn get_to_clientdata(origin: Url, challenge: Base64UrlSafeData) -> CollectedClientData {
    CollectedClientData {
        type_: "webauthn.get".to_string(),
        challenge,
        origin,
        token_binding: None,
        cross_origin: None,
        unknown_keys: BTreeMap::new(),
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum CheckPinResult {
    Ok(String),
    TooShort,
    TooLong,
    ContainsNull,
}

/// Checks whether a PIN meets some rules, and returns the PIN in Unicode Normal
/// Form C.
pub fn check_pin(pin: &str, min_length: usize) -> CheckPinResult {
    use CheckPinResult::*;
    // Normalize the PIN in Normal Form C
    let pin = pin.nfc().collect::<String>();
    let pin_codepoints = pin.chars().count();
    let pin_bytes = pin.len();

    if pin.contains('\0') {
        ContainsNull
    } else if pin_codepoints < min_length {
        trace!("PIN too short: {} codepoints", pin_codepoints);
        TooShort
    } else if pin_bytes > 63 {
        trace!("PIN too long: {} bytes", pin_bytes);
        TooLong
    } else {
        Ok(pin)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_check_pin() {
        let _ = tracing_subscriber::fmt().try_init();
        use CheckPinResult::*;
        let checks = vec![
            ("1234", 4, Ok("1234".to_string())),
            ("123", 4, TooShort),
            (
                "1234567890123456789012345678901234567890123456789012345678901234",
                4,
                TooLong,
            ),
            ("1234", 6, TooShort),
            ("123456", 6, Ok("123456".to_string())),
            // PINs cannot contain null
            ("\0\0\0\0", 4, ContainsNull),
            ("1234\0", 4, ContainsNull),
            ("\01234", 4, ContainsNull),
            ("1234\05678", 4, ContainsNull),
            // Full-width romaji
            // = 3 codepoints, 9 bytes
            ("\u{ff11}\u{ff12}\u{ff13}", 4, TooShort),
            // = 4 codepoints
            (
                "\u{ff11}\u{ff12}\u{ff13}\u{ff14}",
                4,
                Ok("\u{ff11}\u{ff12}\u{ff13}\u{ff14}".to_string()),
            ),
            // = 63 bytes
            (
                "１２３４５６７８９０１２３４５６７８９０１",
                4,
                Ok("１２３４５６７８９０１２３４５６７８９０１".to_string()),
            ),
            // = 64 bytes
            ("１２３４５６７８９０１２３４５６７８９０１a", 4, TooLong),
            // Decomposed ü (NFD)
            // = 4 codepoints NFD, 6 bytes => 2 codepoints NFC, 4 bytes
            ("u\u{308}u\u{308}", 4, TooShort),
            // = 8 codepoints NFD, 12 bytes => 4 codepoints NFC, 8 bytes
            (
                "u\u{308}u\u{308}u\u{308}u\u{308}",
                4,
                Ok("üüüü".to_string()),
            ),
            // Composed ü (NFC)
            // = 2 codepoints NFC, 4 bytes
            ("\u{fc}\u{fc}", 4, TooShort),
            // = 4 codepoints NFC, 8 bytes
            ("\u{fc}\u{fc}\u{fc}\u{fc}", 4, Ok("üüüü".to_string())),
        ];

        for (pin, min, expected) in checks.iter() {
            let actual = check_pin(pin, *min);
            assert_eq!(*expected, actual);
        }
    }
}

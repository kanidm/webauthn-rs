#[cfg(any(
    all(doc, not(doctest)),
    feature = "crypto",
    feature = "ctap2",
    feature = "win10"
))]
use base64urlsafedata::Base64UrlSafeData;
#[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
use unicode_normalization::UnicodeNormalization;
#[cfg(any(
    all(doc, not(doctest)),
    feature = "crypto",
    feature = "ctap2",
    feature = "win10"
))]
use url::Url;
#[cfg(any(
    all(doc, not(doctest)),
    feature = "crypto",
    feature = "ctap2",
    feature = "win10"
))]
use webauthn_rs_proto::CollectedClientData;

#[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
use crate::error::WebauthnCError;

#[cfg(any(
    all(doc, not(doctest)),
    feature = "crypto",
    feature = "ctap2",
    feature = "win10"
))]
pub fn creation_to_clientdata(origin: Url, challenge: Base64UrlSafeData) -> CollectedClientData {
    // Let collectedClientData be a new CollectedClientData instance whose fields are:
    //    type
    //        The string "webauthn.create".
    //    challenge
    //        The base64url encoding of options.challenge.
    //    origin
    //        The serialization of callerOrigin.

    //    Not Supported Yet.
    //    tokenBinding
    //        The status of Token Binding between the client and the callerOrigin, as well as the Token Binding ID associated with callerOrigin, if one is available.
    CollectedClientData {
        type_: "webauthn.create".to_string(),
        challenge,
        origin,
        token_binding: None,
        cross_origin: None,
        unknown_keys: Default::default(),
    }
}

#[cfg(any(
    all(doc, not(doctest)),
    feature = "crypto",
    feature = "ctap2",
    feature = "win10"
))]
pub fn get_to_clientdata(origin: Url, challenge: Base64UrlSafeData) -> CollectedClientData {
    CollectedClientData {
        type_: "webauthn.get".to_string(),
        challenge,
        origin,
        token_binding: None,
        cross_origin: None,
        unknown_keys: Default::default(),
    }
}

#[cfg(any(all(doc, not(doctest)), feature = "ctap2-management"))]
/// Normalises the PIN into Unicode Normal Form C, then ensures that the PIN
/// is at least `min_length` Unicode codepoints, less than 64 bytes when encoded
/// as UTF-8, and does not contain any null bytes (`\x00`).
///
/// If the PIN is valid, returns the PIN in Unicode Normal Form C.
pub fn check_pin(pin: &str, min_length: usize) -> Result<String, WebauthnCError> {
    // Normalize the PIN in Normal Form C
    let pin = pin.nfc().collect::<String>();
    let pin_codepoints = pin.chars().count();
    let pin_bytes = pin.len();

    if pin.contains('\x00') {
        Err(WebauthnCError::PinContainsNull)
    } else if pin_codepoints < min_length {
        trace!("PIN too short: {} codepoints", pin_codepoints);
        Err(WebauthnCError::PinTooShort)
    } else if pin_bytes > 63 {
        trace!("PIN too long: {} bytes", pin_bytes);
        Err(WebauthnCError::PinTooLong)
    } else {
        Ok(pin)
    }
}

#[cfg(all(test, feature = "ctap2-management"))]
mod test {
    use super::*;

    #[test]
    fn test_check_pin() {
        let _ = tracing_subscriber::fmt().try_init();
        let checks = vec![
            ("1234", 4, Ok("1234".to_string())),
            ("123", 4, Err(WebauthnCError::PinTooShort)),
            (
                "1234567890123456789012345678901234567890123456789012345678901234",
                4,
                Err(WebauthnCError::PinTooLong),
            ),
            ("1234", 6, Err(WebauthnCError::PinTooShort)),
            ("123456", 6, Ok("123456".to_string())),
            // PINs cannot contain null
            ("\x00\x00\x00\x00", 4, Err(WebauthnCError::PinContainsNull)),
            ("1234\x00", 4, Err(WebauthnCError::PinContainsNull)),
            ("\x001234", 4, Err(WebauthnCError::PinContainsNull)),
            ("1234\x005678", 4, Err(WebauthnCError::PinContainsNull)),
            // Full-width romaji
            // = 3 codepoints, 9 bytes
            ("\u{ff11}\u{ff12}\u{ff13}", 4, Err(WebauthnCError::PinTooShort)),
            // = 4 codepoints
            (
                "\u{ff11}\u{ff12}\u{ff13}\u{ff14}",
                4,
                Ok("\u{ff11}\u{ff12}\u{ff13}\u{ff14}".to_string()),
            ),
            // = 63 bytes
            (
                concat!(
                    "\u{ff11}\u{ff12}\u{ff13}\u{ff14}\u{ff15}\u{ff16}\u{ff17}\u{ff18}\u{ff19}\u{ff10}",
                    "\u{ff11}\u{ff12}\u{ff13}\u{ff14}\u{ff15}\u{ff16}\u{ff17}\u{ff18}\u{ff19}\u{ff10}",
                    "\u{ff11}"),
                4,
                Ok(concat!(
                    "\u{ff11}\u{ff12}\u{ff13}\u{ff14}\u{ff15}\u{ff16}\u{ff17}\u{ff18}\u{ff19}\u{ff10}",
                    "\u{ff11}\u{ff12}\u{ff13}\u{ff14}\u{ff15}\u{ff16}\u{ff17}\u{ff18}\u{ff19}\u{ff10}",
                    "\u{ff11}").to_string()),
            ),
            // = 64 bytes
            (
                concat!(
                    "1\u{ff11}\u{ff12}\u{ff13}\u{ff14}\u{ff15}\u{ff16}\u{ff17}\u{ff18}\u{ff19}\u{ff10}",
                    "\u{ff11}\u{ff12}\u{ff13}\u{ff14}\u{ff15}\u{ff16}\u{ff17}\u{ff18}\u{ff19}\u{ff10}",
                    "\u{ff11}"),
                4,
                Err(WebauthnCError::PinTooLong),
            ),
            // Decomposed ü (NFD)
            // = 4 codepoints NFD, 6 bytes => 2 codepoints NFC, 4 bytes
            ("u\u{308}u\u{308}", 4, Err(WebauthnCError::PinTooShort)),
            // = 8 codepoints NFD, 12 bytes => 4 codepoints NFC, 8 bytes
            (
                "u\u{308}u\u{308}u\u{308}u\u{308}",
                4,
                Ok("üüüü".to_string()),
            ),
            // Composed ü (NFC)
            // = 2 codepoints NFC, 4 bytes
            ("\u{fc}\u{fc}", 4, Err(WebauthnCError::PinTooShort)),
            // = 4 codepoints NFC, 8 bytes
            ("\u{fc}\u{fc}\u{fc}\u{fc}", 4, Ok("üüüü".to_string())),
        ];

        for (pin, min, expected) in checks.iter() {
            let actual = check_pin(pin, *min);
            assert_eq!(*expected, actual);
        }
    }
}

//! caBLE Base10 encoder.
//!
//! QR codes store arbitrary binary data very inefficiently, but it has
//! alternate modes (such as numeric and alphanumeric) which can store it more
//! efficiently.
//!
//! While [RFC 9285] presents an encoding for efficiently encoding binary data
//! in QR's alphanumeric mode, there are additional issues:
//!
//! * caBLE pairing codes must be valid URLs (for mobile intent handling)
//!
//! * QR's alphanumeric mode does not allow all [URL-safe characters][url-chars],
//!   reducing efficiency
//!
//! * QR's alphanumeric mode allows [non-URL-safe characters][url-chars],
//!   reducing efficiency
//!
//! As a result, caBLE uses a novel Base10 encoding for the payload, which
//! achieves comparable density (in QR code bits), though with longer URLs.
//!
//! In absence of a publicly-published caBLE specification, this is a port of
//! [Chromium's `BytesToDigits` and `DigitsToBytes` functions][crbase10].
//!
//! [crbase10]: https://source.chromium.org/chromium/chromium/src/+/main:device/fido/cable/v2_handshake.cc;l=471-568;drc=6767131b3528fefd866f604b32ebbb278c35d395
//! [RFC 9285]: https://www.rfc-editor.org/rfc/rfc9285.html
//! [url-chars]: https://www.rfc-editor.org/rfc/rfc3986.html#section-2.3

use std::fmt::Write;
/// Size of a chunk of data in its original form
const CHUNK_SIZE: usize = 7;

/// Size of a chunk of data in its encoded form
const CHUNK_DIGITS: usize = 17;

/// Encodes binary data into Base10 format.
///
/// See Chromium's `BytesToDigits`.
pub fn encode(i: &[u8]) -> String {
    i.chunks(CHUNK_SIZE).fold(String::new(), |mut out, c| {
        let chunk_len = c.len();
        let w = match chunk_len {
            CHUNK_SIZE => CHUNK_DIGITS,
            6 => 15,
            5 => 13,
            4 => 10,
            3 => 8,
            2 => 5,
            1 => 3,
            // This should never happen
            _ => 0,
        };

        let mut chunk: [u8; 8] = [0; 8];
        chunk[0..chunk_len].copy_from_slice(c);
        let v = u64::from_le_bytes(chunk);
        let _ = write!(out, "{:0width$}", v, width = w);
        out
    })
}

#[derive(Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The input value contained non-ASCII-digit characters.
    ContainsNonDigitChars,
    /// The input value was not a valid length.
    InvalidLength,
    /// The input value contained a value which was out of range.
    OutOfRange,
}

/// Decodes Base10 formatted data into binary form.
///
/// See Chromium's `DigitsToBytes`.
pub fn decode(i: &str) -> Result<Vec<u8>, DecodeError> {
    // Check that i only contains ASCII digits
    if i.chars().any(|c| !c.is_ascii_digit()) {
        return Err(DecodeError::ContainsNonDigitChars);
    }

    // It's safe to operate on the string in bytes now because:
    //
    // - we've previously thrown an error for anything containing non-ASCII digits.
    // - each ASCII digit is exactly 1 byte in UTF-8.
    // - &str is always valid UTF-8.
    let mut o = Vec::with_capacity(((i.len() + CHUNK_DIGITS - 1) / CHUNK_DIGITS) * CHUNK_SIZE);

    i.as_bytes()
        .chunks(CHUNK_DIGITS)
        .map(|b| unsafe { std::str::from_utf8_unchecked(b) })
        .try_for_each(|s| {
            let d = s
                .parse::<u64>()
                .map_err(|_| DecodeError::ContainsNonDigitChars)?;
            let w = match s.len() {
                CHUNK_DIGITS => CHUNK_SIZE,
                15 => 6,
                13 => 5,
                10 => 4,
                8 => 3,
                5 => 2,
                3 => 1,
                _ => return Err(DecodeError::InvalidLength),
            };

            if d >> (w * 8) != 0 {
                return Err(DecodeError::OutOfRange);
            }

            o.extend_from_slice(&d.to_le_bytes()[..w]);
            Ok(())
        })?;

    Ok(o)
}

#[cfg(test)]
mod test {
    use super::*;

    fn decoder_err_test(i: &str, e: DecodeError) {
        assert_eq!(Err(e), decode(i), "decode({:?})", i);
    }

    #[test]
    fn invalid_decode() {
        use DecodeError::*;
        // Non-digit characters
        decoder_err_test("abc", ContainsNonDigitChars);
        decoder_err_test("abc1234", ContainsNonDigitChars);

        // Full-width romaji digits
        decoder_err_test("\u{ff11}\u{ff12}\u{ff13}", ContainsNonDigitChars);

        // Digits with umlauts (decomposed combining diacriticals on digits)
        decoder_err_test("1\u{308}2\u{308}3\u{308}", ContainsNonDigitChars);

        // Incorrect lengths
        decoder_err_test("1", InvalidLength);
        decoder_err_test("12", InvalidLength);
        decoder_err_test("1234", InvalidLength);
        decoder_err_test("123456789012345678", InvalidLength);

        // Valid length, but results in bytes > 0xff
        decoder_err_test("999", OutOfRange);
        decoder_err_test("99999999999999999", OutOfRange);
    }

    #[test]
    fn decoding_zero() {
        let lengths = [
            (0, 0),
            (1, 3),
            (2, 5),
            (3, 8),
            (4, 10),
            (5, 13),
            (6, 15),
            (7, 17),
            (8, 20),
        ];
        for (bl, dl) in lengths {
            let bytes = vec![0; bl];
            let digits = "0".repeat(dl);

            assert_eq!(encode(bytes.as_slice()), digits);
            assert_eq!(decode(&digits), Ok(bytes));
        }
    }

    #[test]
    fn encoding_survives_roundtrips() {
        let i: Vec<u8> = (0..255).collect();

        for len in 0..i.len() {
            let i = &i[0..len];
            assert_eq!(decode(&encode(i)), Ok(i.to_vec()), "length = {}", len);
        }
    }

    #[test]
    fn encoding_should_not_change() {
        let i: [u8; 3] = [0x61, 0x62, 0xff];
        assert_eq!(encode(&i), "16736865");
        assert_eq!(decode("16736865").expect("unexpected error"), i);
    }
}

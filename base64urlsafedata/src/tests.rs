use super::*;
use std::convert::TryFrom;

#[test]
fn test_try_from() {
    assert!(Base64UrlSafeData::try_from("aGVsbG8=").is_ok());
    assert!(Base64UrlSafeData::try_from("abcdefghij").is_err());
}

macro_rules! from_json_test {
    ($($name:ident: $value:expr,)*) => {
        $(
            #[test]
            fn $name() {
                let (input, expected): (&str, &[u8]) = $value;
                assert_eq!(serde_json::from_str::<Base64UrlSafeData>(input).unwrap(), expected);
                assert_eq!(serde_json::from_str::<HumanBinaryData>(input).unwrap(), expected);
            }
        )*
    };
}

macro_rules! from_cbor_test {
    ($($name:ident: $value:expr,)*) => {
        $(
            #[test]
            fn $name() {
                let (input, expected): (&[u8], &[u8]) = $value;
                assert_eq!(serde_cbor_2::from_slice::<Base64UrlSafeData>(input).unwrap(), expected);
                assert_eq!(serde_cbor_2::from_slice::<HumanBinaryData>(input).unwrap(), expected);
            }
        )*
    };
}

from_json_test! {
    from_json_as_array_number: ("[0,1,2,255]", &[0x00, 0x01, 0x02, 0xFF]),
    from_json_as_array_number_whitespace: ("[0, 1, 2, 255]", &[0x00, 0x01, 0x02, 0xFF]),
    from_json_b64_urlsafe_nonpadded: ("\"AAEC_w\"", &[0x00, 0x01, 0x02, 0xFF]),
    from_json_b64_urlsafe_padded: ("\"AAEC_w==\"", &[0x00, 0x01, 0x02, 0xFF]),
    from_json_b64_standard_nonpadded: ("\"AAEC/w\"", &[0x00, 0x01, 0x02, 0xFF]),
    from_json_b64_standard_padded: ("\"AAEC/w==\"", &[0x00, 0x01, 0x02, 0xFF]),
}

from_cbor_test! {
    from_cbor_bytes: (&[
        0x44, // bytes(4)
        0x00, 0x01, 0x02, 0xFF,
    ], &[0x00, 0x01, 0x02, 0xFF]),
    from_cbor_array: (&[
        0x84, // array(4)
        0x00, // 0
        0x01, // 1
        0x02, // 2
        0x18, 0xff, // 0xff
    ], &[0x00, 0x01, 0x02, 0xFF]),
    from_cbor_string_b64_urlsafe_nonpadded: (&[
        0x66, // text(6)
        0x41, 0x41, 0x45, 0x43, 0x5F, 0x77, // "AAEC_w"
    ], &[0x00, 0x01, 0x02, 0xFF]),
    from_cbor_string_b64_urlsafe_padded: (&[
        0x68, // text(8)
        0x41, 0x41, 0x45, 0x43, 0x5F, 0x77, 0x3D, 0x3D // "AAEC_w=="
    ], &[0x00, 0x01, 0x02, 0xFF]),
    from_cbor_string_b64_standard_nonpadded: (&[
        0x66, // text(6)
        0x41, 0x41, 0x45, 0x43, 0x2F, 0x77, // "AAEC/w"
    ], &[0x00, 0x01, 0x02, 0xFF]),
    from_cbor_string_b64_standard_padded: (&[
        0x68, // text(8)
        0x41, 0x41, 0x45, 0x43, 0x2F, 0x77, 0x3D, 0x3D // "AAEC/w=="
    ], &[0x00, 0x01, 0x02, 0xFF]),
}

#[test]
fn to_json() {
    let input = [0x00, 0x01, 0x02, 0xff];

    // JSON output should always be a base64 string
    assert_eq!(
        serde_json::to_string(&Base64UrlSafeData::from(input)).unwrap(),
        "\"AAEC_w\"",
    );
    assert_eq!(
        serde_json::to_string(&HumanBinaryData::from(input)).unwrap(),
        "\"AAEC_w\"",
    );
}

#[test]
fn to_cbor() {
    let input = [0x00, 0x01, 0x02, 0xff];

    // Base64UrlSafeData CBOR output should be a base64 encoded string
    assert_eq!(
        serde_cbor_2::to_vec(&Base64UrlSafeData::from(input)).unwrap(),
        vec![
            0x66, // text(6)
            0x41, 0x41, 0x45, 0x43, 0x5F, 0x77 // "AAEC_w"
        ]
    );

    // HumanBinaryData CBOR output should be a bytes
    assert_eq!(
        serde_cbor_2::to_vec(&HumanBinaryData::from(input)).unwrap(),
        vec![
            0x44, // bytes(4)
            0x00, 0x01, 0x02, 0xff
        ]
    );
}

#[test]
fn interop() {}

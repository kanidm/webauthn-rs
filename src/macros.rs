macro_rules! cbor_try_map {
    (
        $v:expr
    ) => {{
        match $v {
            serde_cbor::Value::Map(m) => Ok(m),
            _ => Err(WebauthnError::COSEKeyInvalidCBORValue),
        }
    }};
}

macro_rules! cbor_try_array {
    (
        $v:expr
    ) => {{
        match $v {
            serde_cbor::Value::Array(m) => Ok(m),
            _ => Err(WebauthnError::COSEKeyInvalidCBORValue),
        }
    }};
}

macro_rules! cbor_try_string {
    (
        $v:expr
    ) => {{
        match $v {
            serde_cbor::Value::Text(m) => Ok(m),
            _ => Err(WebauthnError::COSEKeyInvalidCBORValue),
        }
    }};
}

macro_rules! cbor_try_bytes {
    (
        $v:expr
    ) => {{
        match $v {
            serde_cbor::Value::Bytes(m) => Ok(m),
            _ => Err(WebauthnError::COSEKeyInvalidCBORValue),
        }
    }};
}

macro_rules! cbor_try_i128 {
    (
        $v:expr
    ) => {{
        match $v {
            serde_cbor::Value::Integer(m) => Ok(*m),
            _ => Err(WebauthnError::COSEKeyInvalidCBORValue),
        }
    }};
}

/*
#[macro_export]
macro_rules! cbor_try_u64 {
    (
        $v:expr
    ) => {{
        match $v {
            serde_cbor::Value::Integer(m) =>
                u64::try_from(m)
                    .map_err(|_| WebauthnError::COSEKeyInvalidCBORValue),
            Ok(m),
            _ => Err(WebauthnError::COSEKeyInvalidCBORValue),
        }
    }}
}

#[macro_export]
macro_rules! cbor_try_i64 {
    (
        $v:expr
    ) => {{
        match $v {
            serde_cbor::Value::Integer(m) =>
                i64::try_from(m)
                    .map_err(|_| WebauthnError::COSEKeyInvalidCBORValue),
            Ok(m),
            _ => Err(WebauthnError::COSEKeyInvalidCBORValue),
        }
    }}
}
*/

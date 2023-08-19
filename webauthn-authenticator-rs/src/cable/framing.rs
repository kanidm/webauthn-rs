//! caBLE message framing types

use crate::{
    ctap2::{
        commands::{GetAssertionRequest, MakeCredentialRequest},
        CBORCommand, CBORResponse,
    },
    error::WebauthnCError,
};

/// Prefix byte for messages sent to the authenticator
///
/// Not used for protocol version 0
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CableFrameType {
    /// caBLE shutdown message
    Shutdown = 0,
    /// CTAP 2.x command
    Ctap = 1,
    /// Linking information
    Update = 2,
    Unknown,
}

impl From<u8> for CableFrameType {
    fn from(v: u8) -> Self {
        use CableFrameType::*;
        match v {
            0 => Shutdown,
            1 => Ctap,
            2 => Update,
            _ => Unknown,
        }
    }
}

pub const SHUTDOWN_COMMAND: CableFrame = CableFrame {
    protocol_version: 1,
    message_type: CableFrameType::Shutdown,
    data: vec![],
};

/// caBLE request and response framing.
///
/// These frames are encrypted ([Crypter][super::noise::Crypter])
/// and sent as binary Websocket messages.
///
/// ## Protocol description
///
/// ### Version 0
///
/// All frames are of the type [CableFrameType::Ctap], and the wire format is the
/// same as CTAP 2.0.
///
/// ### Version 1
///
/// Version 1 adds an initial [CableFrameType] byte before the payload (`data`):
///
/// * [CableFrameType::Shutdown]: no payload
/// * [CableFrameType::Ctap]: payload is CTAP 2.0 command / response
/// * [CableFrameType::Update]: payload is linking information (not implemented)
#[derive(Debug, PartialEq, Eq)]
pub struct CableFrame {
    pub protocol_version: u32,
    pub message_type: CableFrameType,
    pub data: Vec<u8>,
}

#[derive(Debug)]
pub enum RequestType {
    MakeCredential(MakeCredentialRequest),
    GetAssertion(GetAssertionRequest),
}

impl CableFrame {
    /// Serialises a [CableFrame] into bytes.
    ///
    /// Returns `None` if the `protocol_version` or `message_type` is not
    /// supported, or invalid.
    pub fn to_bytes(&self) -> Option<Vec<u8>> {
        if self.protocol_version == 0 && self.message_type == CableFrameType::Ctap {
            Some(self.data.to_owned())
        } else if self.protocol_version == 1 && self.message_type != CableFrameType::Unknown {
            let mut o = self.data.to_owned();
            o.insert(0, self.message_type as u8);
            Some(o)
        } else {
            warn!(
                "Unsupported caBLE protocol version {} or message type {:?}",
                self.protocol_version, self.message_type
            );
            None
        }
    }

    /// Deserialises a [CableFrame] from bytes.
    pub fn from_bytes(protocol_version: u32, i: &[u8]) -> Self {
        let message_type: CableFrameType = if protocol_version > 0 {
            i[0].into()
        } else {
            CableFrameType::Ctap
        };

        let data = if protocol_version == 0 { i } else { &i[1..] }.to_vec();

        Self {
            protocol_version,
            message_type,
            data,
        }
    }

    /// Parses a [CableFrame] (from an initiator) as a CBOR request type.
    ///
    /// Returns [WebauthnCError::NotSupported] on unknown command types, or if
    /// `message_type` is not [CableFrameType::Ctap].
    pub fn parse_request(&self) -> Result<RequestType, WebauthnCError> {
        if self.message_type != CableFrameType::Ctap {
            return Err(WebauthnCError::NotSupported);
        }
        match self.data[0] {
            MakeCredentialRequest::CMD => Ok(RequestType::MakeCredential(
                <MakeCredentialRequest as CBORResponse>::try_from(&self.data[1..])?,
            )),
            GetAssertionRequest::CMD => Ok(RequestType::GetAssertion(
                <GetAssertionRequest as CBORResponse>::try_from(&self.data[1..])?,
            )),
            _ => Err(WebauthnCError::NotSupported),
        }
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod test {
    use std::collections::BTreeMap;

    use base64urlsafedata::Base64UrlSafeData;
    use serde_cbor_2::Value;
    use webauthn_rs_proto::{PubKeyCredParams, RelyingParty, User};

    use crate::ctap2::commands::MakeCredentialResponse;

    use super::*;

    #[test]
    fn sample_make_credential_request() {
        let _ = tracing_subscriber::fmt::try_init();
        // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#example-1a030b94
        /*
        {
        Integer(1): Bytes([104, 113, 52, 150, 130, 34, 236, 23, 32, 46, 66, 80, 95, 142, 210, 177, 106, 226, 47, 22, 187, 5, 184, 140, 37, 219, 158, 96, 38, 69, 241, 65]),
        Integer(2): Map({Text("id"): Text("test.ctap"), Text("name"): Text("test.ctap")}),
        Integer(3): Map({Text("id"): Bytes([43, 102, 137, 187, 24, 244, 22, 159, 6, 159, 188, 223, 80, 203, 110, 163, 198, 10, 134, 27, 154, 123, 99, 148, 105, 131, 224, 181, 119, 183, 140, 112]),
            Text("name"): Text("testctap@ctap.com"), Text("displayName"): Text("Test Ctap")}),
        Integer(4): Array([
            Map({Text("alg"): Integer(-7), Text("type"): Text("public-key")}),
            Map({Text("alg"): Integer(-257), Text("type"): Text("public-key")}),
            Map({Text("alg"): Integer(-37), Text("type"): Text("public-key")})]),
        Integer(7): Map({Text("rk"): Bool(true)}),
        }
         */
        let request = vec![
            1, // CableFrameType::Cbor
            1, // Command
            // Extensions not yet supported, PIN/UV not relevant for caBLE
            // 168,
            165, //
            // ClientDataHash
            1, 88, 32, 104, 113, 52, 150, 130, 34, 236, 23, 32, 46, 66, 80, 95, 142, 210, 177, 106,
            226, 47, 22, 187, 5, 184, 140, 37, 219, 158, 96, 38, 69, 241, 65, //
            // RelyingParty
            2, 162, 98, 105, 100, 105, 116, 101, 115, 116, 46, 99, 116, 97, 112, 100, 110, 97, 109,
            101, 105, 116, 101, 115, 116, 46, 99, 116, 97, 112, //
            // User
            3, 163, 98, 105, 100, 88, 32, 43, 102, 137, 187, 24, 244, 22, 159, 6, 159, 188, 223, 80,
            203, 110, 163, 198, 10, 134, 27, 154, 123, 99, 148, 105, 131, 224, 181, 119, 183, 140,
            112, 100, 110, 97, 109, 101, 113, 116, 101, 115, 116, 99, 116, 97, 112, 64, 99, 116,
            97, 112, 46, 99, 111, 109, 107, 100, 105, 115, 112, 108, 97, 121, 78, 97, 109, 101,
            105, 84, 101, 115, 116, 32, 67, 116, 97, 112, //
            // PubKeyCredParams
            4, 131, 162, 99, 97, 108, 103, 38, 100, 116, 121, 112, 101, 106, 112, 117, 98, 108, 105,
            99, 45, 107, 101, 121, 162, 99, 97, 108, 103, 57, 1, 0, 100, 116, 121, 112, 101, 106,
            112, 117, 98, 108, 105, 99, 45, 107, 101, 121, 162, 99, 97, 108, 103, 56, 36, 100, 116,
            121, 112, 101, 106, 112, 117, 98, 108, 105, 99, 45, 107, 101, 121,
            // Extensions not yet supported
            // 6, 161, 107, 104, 109, 97, 99, 45, 115, 101, 99, 114, 101, 116, 245,
            // Options
            7, 161, 98, 114, 107, 245, //
        ];

        let expected_request = MakeCredentialRequest {
            client_data_hash: vec![
                104, 113, 52, 150, 130, 34, 236, 23, 32, 46, 66, 80, 95, 142, 210, 177, 106, 226,
                47, 22, 187, 5, 184, 140, 37, 219, 158, 96, 38, 69, 241, 65,
            ],
            rp: RelyingParty {
                name: "test.ctap".to_owned(),
                id: "test.ctap".to_owned(),
            },
            user: User {
                id: Base64UrlSafeData(vec![
                    43, 102, 137, 187, 24, 244, 22, 159, 6, 159, 188, 223, 80, 203, 110, 163, 198,
                    10, 134, 27, 154, 123, 99, 148, 105, 131, 224, 181, 119, 183, 140, 112,
                ]),
                name: "testctap@ctap.com".to_owned(),
                display_name: "Test Ctap".to_owned(),
            },
            pub_key_cred_params: vec![
                PubKeyCredParams {
                    type_: "public-key".to_owned(),
                    alg: -7,
                },
                PubKeyCredParams {
                    type_: "public-key".to_owned(),
                    alg: -257,
                },
                PubKeyCredParams {
                    type_: "public-key".to_owned(),
                    alg: -37,
                },
            ],
            exclude_list: vec![],
            options: Some(BTreeMap::from([("rk".to_owned(), true)])),
            pin_uv_auth_param: None,
            pin_uv_auth_proto: None,
            enterprise_attest: None,
        };

        let expected_response = MakeCredentialResponse {
            fmt: Some("packed".to_owned()),
            auth_data: Some(Value::Bytes(vec![
                0, 33, 245, 252, 11, 133, 205, 34, 230, 6, 35, 188, 215, 209, 202, 72, 148, 137, 9,
                36, 155, 71, 118, 235, 81, 81, 84, 229, 123, 102, 174, 18, 197, 0, 0, 0, 85, 248,
                160, 17, 243, 140, 10, 77, 21, 128, 6, 23, 17, 31, 158, 220, 125, 0, 16, 244, 213,
                123, 35, 221, 12, 183, 133, 104, 12, 218, 167, 247, 228, 79, 96, 165, 1, 2, 3, 38,
                32, 1, 33, 88, 32, 223, 1, 125, 11, 40, 103, 149, 190, 161, 83, 209, 102, 160, 161,
                91, 79, 107, 103, 163, 175, 74, 16, 30, 16, 232, 73, 111, 61, 211, 197, 209, 169,
                34, 88, 32, 148, 178, 37, 81, 230, 50, 93, 119, 51, 196, 27, 178, 245, 166, 66,
                173, 238, 65, 124, 151, 224, 144, 97, 151, 181, 176, 205, 139, 141, 108, 107, 167,
                161, 107, 104, 109, 97, 99, 45, 115, 101, 99, 114, 101, 116, 245,
            ])),
            att_stmt: Some(Value::Map(BTreeMap::from([
                (Value::Text("alg".to_owned()), Value::Integer(-7)),
                (
                    Value::Text("sig".to_owned()),
                    Value::Bytes(vec![
                        48, 69, 2, 32, 124, 202, 197, 122, 30, 67, 223, 36, 176, 132, 126, 235,
                        241, 25, 210, 141, 205, 197, 4, 143, 125, 205, 142, 221, 121, 231, 151, 33,
                        196, 27, 207, 45, 2, 33, 0, 216, 158, 199, 91, 146, 206, 143, 249, 228,
                        111, 231, 248, 200, 121, 149, 105, 74, 99, 229, 183, 138, 184, 92, 71, 185,
                        218, 28, 88, 10, 142, 200, 58,
                    ]),
                ),
                (
                    Value::Text("x5c".to_owned()),
                    Value::Array(vec![Value::Bytes(vec![
                        48, 130, 1, 147, 48, 130, 1, 56, 160, 3, 2, 1, 2, 2, 9, 0, 133, 155, 114,
                        108, 178, 75, 76, 41, 48, 10, 6, 8, 42, 134, 72, 206, 61, 4, 3, 2, 48, 71,
                        49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83, 49, 20, 48, 18, 6, 3, 85, 4,
                        10, 12, 11, 89, 117, 98, 105, 99, 111, 32, 84, 101, 115, 116, 49, 34, 48,
                        32, 6, 3, 85, 4, 11, 12, 25, 65, 117, 116, 104, 101, 110, 116, 105, 99, 97,
                        116, 111, 114, 32, 65, 116, 116, 101, 115, 116, 97, 116, 105, 111, 110, 48,
                        30, 23, 13, 49, 54, 49, 50, 48, 52, 49, 49, 53, 53, 48, 48, 90, 23, 13, 50,
                        54, 49, 50, 48, 50, 49, 49, 53, 53, 48, 48, 90, 48, 71, 49, 11, 48, 9, 6,
                        3, 85, 4, 6, 19, 2, 85, 83, 49, 20, 48, 18, 6, 3, 85, 4, 10, 12, 11, 89,
                        117, 98, 105, 99, 111, 32, 84, 101, 115, 116, 49, 34, 48, 32, 6, 3, 85, 4,
                        11, 12, 25, 65, 117, 116, 104, 101, 110, 116, 105, 99, 97, 116, 111, 114,
                        32, 65, 116, 116, 101, 115, 116, 97, 116, 105, 111, 110, 48, 89, 48, 19, 6,
                        7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61, 3, 1, 7, 3, 66,
                        0, 4, 173, 17, 235, 14, 136, 82, 229, 58, 213, 223, 237, 134, 180, 30, 97,
                        52, 161, 142, 196, 225, 175, 143, 34, 26, 60, 125, 110, 99, 108, 128, 234,
                        19, 195, 213, 4, 255, 46, 118, 33, 27, 180, 69, 37, 177, 150, 196, 76, 180,
                        132, 153, 121, 207, 111, 137, 110, 205, 43, 184, 96, 222, 27, 244, 55, 107,
                        163, 13, 48, 11, 48, 9, 6, 3, 85, 29, 19, 4, 2, 48, 0, 48, 10, 6, 8, 42,
                        134, 72, 206, 61, 4, 3, 2, 3, 73, 0, 48, 70, 2, 33, 0, 233, 163, 159, 27,
                        3, 25, 117, 37, 247, 55, 62, 16, 206, 119, 231, 128, 33, 115, 27, 148, 208,
                        192, 63, 63, 218, 31, 210, 45, 179, 208, 48, 231, 2, 33, 0, 196, 250, 236,
                        52, 69, 168, 32, 207, 67, 18, 156, 219, 0, 170, 190, 253, 154, 226, 216,
                        116, 249, 197, 211, 67, 203, 47, 17, 61, 162, 55, 35, 243,
                    ])]),
                ),
            ]))),
            ..Default::default()
        };

        let frame = CableFrame::from_bytes(1, &request);
        trace!(?frame);
        let decoded = frame.parse_request().unwrap();
        let decoded = if let RequestType::MakeCredential(req) = decoded {
            req
        } else {
            panic!("Unexpected request type: {:?}", decoded);
        };

        // re-serialising these should have some result
        assert_eq!(expected_request.cbor().unwrap(), decoded.cbor().unwrap());
        let frame = CableFrame {
            protocol_version: 1,
            message_type: CableFrameType::Ctap,
            data: expected_request.cbor().unwrap(),
        };
        assert_eq!(frame.to_bytes().unwrap(), request);

        let response = vec![
            1, 163, 1, 102, 112, 97, 99, 107, 101, 100, 2, 88, 162, 0, 33, 245, 252, 11, 133, 205,
            34, 230, 6, 35, 188, 215, 209, 202, 72, 148, 137, 9, 36, 155, 71, 118, 235, 81, 81, 84,
            229, 123, 102, 174, 18, 197, 0, 0, 0, 85, 248, 160, 17, 243, 140, 10, 77, 21, 128, 6,
            23, 17, 31, 158, 220, 125, 0, 16, 244, 213, 123, 35, 221, 12, 183, 133, 104, 12, 218,
            167, 247, 228, 79, 96, 165, 1, 2, 3, 38, 32, 1, 33, 88, 32, 223, 1, 125, 11, 40, 103,
            149, 190, 161, 83, 209, 102, 160, 161, 91, 79, 107, 103, 163, 175, 74, 16, 30, 16, 232,
            73, 111, 61, 211, 197, 209, 169, 34, 88, 32, 148, 178, 37, 81, 230, 50, 93, 119, 51,
            196, 27, 178, 245, 166, 66, 173, 238, 65, 124, 151, 224, 144, 97, 151, 181, 176, 205,
            139, 141, 108, 107, 167, 161, 107, 104, 109, 97, 99, 45, 115, 101, 99, 114, 101, 116,
            245, 3, 163, 99, 97, 108, 103, 38, 99, 115, 105, 103, 88, 71, 48, 69, 2, 32, 124, 202,
            197, 122, 30, 67, 223, 36, 176, 132, 126, 235, 241, 25, 210, 141, 205, 197, 4, 143,
            125, 205, 142, 221, 121, 231, 151, 33, 196, 27, 207, 45, 2, 33, 0, 216, 158, 199, 91,
            146, 206, 143, 249, 228, 111, 231, 248, 200, 121, 149, 105, 74, 99, 229, 183, 138, 184,
            92, 71, 185, 218, 28, 88, 10, 142, 200, 58, 99, 120, 53, 99, 129, 89, 1, 151, 48, 130,
            1, 147, 48, 130, 1, 56, 160, 3, 2, 1, 2, 2, 9, 0, 133, 155, 114, 108, 178, 75, 76, 41,
            48, 10, 6, 8, 42, 134, 72, 206, 61, 4, 3, 2, 48, 71, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19,
            2, 85, 83, 49, 20, 48, 18, 6, 3, 85, 4, 10, 12, 11, 89, 117, 98, 105, 99, 111, 32, 84,
            101, 115, 116, 49, 34, 48, 32, 6, 3, 85, 4, 11, 12, 25, 65, 117, 116, 104, 101, 110,
            116, 105, 99, 97, 116, 111, 114, 32, 65, 116, 116, 101, 115, 116, 97, 116, 105, 111,
            110, 48, 30, 23, 13, 49, 54, 49, 50, 48, 52, 49, 49, 53, 53, 48, 48, 90, 23, 13, 50,
            54, 49, 50, 48, 50, 49, 49, 53, 53, 48, 48, 90, 48, 71, 49, 11, 48, 9, 6, 3, 85, 4, 6,
            19, 2, 85, 83, 49, 20, 48, 18, 6, 3, 85, 4, 10, 12, 11, 89, 117, 98, 105, 99, 111, 32,
            84, 101, 115, 116, 49, 34, 48, 32, 6, 3, 85, 4, 11, 12, 25, 65, 117, 116, 104, 101,
            110, 116, 105, 99, 97, 116, 111, 114, 32, 65, 116, 116, 101, 115, 116, 97, 116, 105,
            111, 110, 48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61,
            3, 1, 7, 3, 66, 0, 4, 173, 17, 235, 14, 136, 82, 229, 58, 213, 223, 237, 134, 180, 30,
            97, 52, 161, 142, 196, 225, 175, 143, 34, 26, 60, 125, 110, 99, 108, 128, 234, 19, 195,
            213, 4, 255, 46, 118, 33, 27, 180, 69, 37, 177, 150, 196, 76, 180, 132, 153, 121, 207,
            111, 137, 110, 205, 43, 184, 96, 222, 27, 244, 55, 107, 163, 13, 48, 11, 48, 9, 6, 3,
            85, 29, 19, 4, 2, 48, 0, 48, 10, 6, 8, 42, 134, 72, 206, 61, 4, 3, 2, 3, 73, 0, 48, 70,
            2, 33, 0, 233, 163, 159, 27, 3, 25, 117, 37, 247, 55, 62, 16, 206, 119, 231, 128, 33,
            115, 27, 148, 208, 192, 63, 63, 218, 31, 210, 45, 179, 208, 48, 231, 2, 33, 0, 196,
            250, 236, 52, 69, 168, 32, 207, 67, 18, 156, 219, 0, 170, 190, 253, 154, 226, 216, 116,
            249, 197, 211, 67, 203, 47, 17, 61, 162, 55, 35, 243,
        ];

        // Deserialise response in caBLE v2.1
        let frame = CableFrame::from_bytes(1, &response);
        let v1_response = <MakeCredentialResponse as CBORResponse>::try_from(&frame.data)
            .expect("Failed to decode message");
        trace!(?v1_response);
        assert_eq!(expected_response, v1_response);

        // Serialise expected response
        let resp: BTreeMap<u32, Value> = expected_response.clone().into();
        let resp = serde_cbor_2::ser::to_vec_packed(&resp).unwrap();
        let frame = CableFrame {
            protocol_version: 1,
            message_type: CableFrameType::Ctap,
            data: resp.clone(),
        };

        assert_eq!(frame.to_bytes().unwrap(), response);

        // Cable v2.0 should omit header byte
        let frame = CableFrame::from_bytes(0, &response[1..]);
        let v0_response = <MakeCredentialResponse as CBORResponse>::try_from(&frame.data)
            .expect("Failed to decode message");
        trace!(?v0_response);
        assert_eq!(expected_response, v0_response);

        // Serialise expected response
        let frame = CableFrame {
            protocol_version: 0,
            message_type: CableFrameType::Ctap,
            data: resp,
        };
        assert_eq!(frame.to_bytes().unwrap(), &response[1..]);
    }

    #[test]
    fn shutdown() {
        let shutdown_bytes = vec![0];
        assert_eq!(shutdown_bytes, SHUTDOWN_COMMAND.to_bytes().unwrap());
        assert_eq!(SHUTDOWN_COMMAND, CableFrame::from_bytes(1, &shutdown_bytes));
    }

    #[test]
    fn update() {
        let update_bytes = vec![2, 1, 2, 3, 4];
        let update = CableFrame {
            protocol_version: 1,
            message_type: CableFrameType::Update,
            data: vec![1, 2, 3, 4],
        };

        assert_eq!(update_bytes, update.to_bytes().unwrap());
        assert_eq!(update, CableFrame::from_bytes(1, &update_bytes));
    }

    #[test]
    fn unknown_frame_type() {
        let unknown_bytes = [0xff; 16];
        let unknown = CableFrame::from_bytes(1, &unknown_bytes);
        assert_eq!(unknown.protocol_version, 1);
        assert_eq!(unknown.message_type, CableFrameType::Unknown);
        assert_eq!(&unknown.data, &[0xff; 15]);
        assert_eq!(unknown.to_bytes(), None);
    }
}

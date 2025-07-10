use crate::attest::RegisterPublicKeyCredential;

#[test]
fn parse_cred_props() {
    // Old format (extensions)
    let rsp_d: RegisterPublicKeyCredential = serde_json::from_str(r#"{
    "id": "AfJfonHsXY_f7_gFmV1dI473Ce--_g0tHhdXUoh7JmMn0gzhYUtU9bFqpCgSljjwJxEXkjzb-11ulePZyI0RiyQ",
    "rawId": "AfJfonHsXY_f7_gFmV1dI473Ce--_g0tHhdXUoh7JmMn0gzhYUtU9bFqpCgSljjwJxEXkjzb-11ulePZyI0RiyQ",
    "response": {
        "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjFarm78N-aFvkduzO7sTL6-dF8eCxIJsbscOzuWNl-9SpFAAAAAAAAAAAAAAAAAAAAAAAAAAAAQQHyX6Jx7F2P3-_4BZldXSOO9wnvvv4NLR4XV1KIeyZjJ9IM4WFLVPWxaqQoEpY48CcRF5I82_tdbpXj2ciNEYskpQECAyYgASFYIE_9awy66uhXZ6hIzPAW2AzIrTMZ7kyC2jtZe0zuH_pOIlggFbNKhOSt8-prIx0snKRqcxULtc2u1rzUUf47g1PxTcU",
        "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoidF9XZTEzMU5wd2xseVBMMHgyNmJ6WmdrRjVmX1h2QTdPY2I0Yjk4emx4TSIsIm9yaWdpbiI6Imh0dHBzOlwvXC93ZWJhdXRobi5maXJzdHllYXIuaWQuYXUiLCJhbmRyb2lkUGFja2FnZU5hbWUiOiJvcmcubW96aWxsYS5maXJlZm94In0"
    },
    "type": "public-key",
    "extensions": {"credProps":{"rk":false}}
    }"#).unwrap();

    assert!(rsp_d.extensions.cred_props.is_some());

    // mdn compat format (clientExtensionResults)
    let _rsp_d: RegisterPublicKeyCredential = serde_json::from_str(r#"{
    "id": "AfJfonHsXY_f7_gFmV1dI473Ce--_g0tHhdXUoh7JmMn0gzhYUtU9bFqpCgSljjwJxEXkjzb-11ulePZyI0RiyQ",
    "rawId": "AfJfonHsXY_f7_gFmV1dI473Ce--_g0tHhdXUoh7JmMn0gzhYUtU9bFqpCgSljjwJxEXkjzb-11ulePZyI0RiyQ",
    "response": {
        "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjFarm78N-aFvkduzO7sTL6-dF8eCxIJsbscOzuWNl-9SpFAAAAAAAAAAAAAAAAAAAAAAAAAAAAQQHyX6Jx7F2P3-_4BZldXSOO9wnvvv4NLR4XV1KIeyZjJ9IM4WFLVPWxaqQoEpY48CcRF5I82_tdbpXj2ciNEYskpQECAyYgASFYIE_9awy66uhXZ6hIzPAW2AzIrTMZ7kyC2jtZe0zuH_pOIlggFbNKhOSt8-prIx0snKRqcxULtc2u1rzUUf47g1PxTcU",
        "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoidF9XZTEzMU5wd2xseVBMMHgyNmJ6WmdrRjVmX1h2QTdPY2I0Yjk4emx4TSIsIm9yaWdpbiI6Imh0dHBzOlwvXC93ZWJhdXRobi5maXJzdHllYXIuaWQuYXUiLCJhbmRyb2lkUGFja2FnZU5hbWUiOiJvcmcubW96aWxsYS5maXJlZm94In0"
    },
    "type": "public-key",
    "clientExtensionResults": {"credProps":{"rk":false}}
    }"#).unwrap();

    assert!(rsp_d.extensions.cred_props.is_some());
}

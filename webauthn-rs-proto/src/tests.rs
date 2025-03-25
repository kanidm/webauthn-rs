use crate::RegistrationExtensionsClientOutputs;

#[test]
fn parse_cred_props() {
    let input = r#"{"credProps":{"rk":false}}"#;

    let _parsed_extn: RegistrationExtensionsClientOutputs = serde_json::from_str(input).unwrap();
}

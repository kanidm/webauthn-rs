use std::collections::BTreeMap;

use base64urlsafedata::Base64UrlSafeData;
use openssl::sha;
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

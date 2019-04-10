"use strict";
const cose_alg_ECDSA_w_SHA256 = -7;
const cose_alg_ECDSA_w_SHA512 = -36;

// Need to manage the username better here?
const CHALLENGE_URL = "/auth/challenge/xxx";
const REGISTER_URL = "/auth/register";
const LOGIN_URL = "/auth/login";

function register() {
  fetch(CHALLENGE_URL, {method: "POST"})
    .then(res => res.json())
    .then(challenge => {
      console.log("challenge");
      console.log(challenge);
      challenge.publicKey.challenge = fromBase64(challenge.publicKey.challenge);
      challenge.publicKey.user.id = fromBase64(challenge.publicKey.user.id);
      return navigator.credentials.create(challenge)
    .then(newCredential => {
      console.log("PublicKeyCredential Created");
      console.log(newCredential);
      console.log(typeof(newCredential));
      const cc = {};
      cc.id = newCredential.id;
      cc.rawId = toBase64(newCredential.rawId);
      cc.response = {};
      cc.response.attestationObject = toBase64(newCredential.response.attestationObject);
      cc.response.clientDataJSON = toBase64(newCredential.response.clientDataJSON);
      cc.type = newCredential.type;
      console.log(cc);
      return fetch(REGISTER_URL, {method: "POST", body: JSON.stringify(cc)})
    })
    .catch(err => console.log(err));
  });
}

function login() {
  fetch(CHALLENGE_URL, {method: "POST"})
    .then(res => res.json())
    .then(challenge => {
      console.log("challenge");
      console.log(challenge);
      const req = {};
      req.publicKey = {};
      req.publicKey.challenge = fromBase64(challenge.publicKey.challenge);
      req.publicKey.timeout = 6000;
      req.publicKey.allowCredentials = challenge.publicKey.allowCredentials.map(c =>
        {
          c.id = fromBase64(c.id)
          return c
        })
      console.log("req");
      console.log(req);
      return navigator.credentials.get(req)
    .then(credentials => {
      console.log("PublicKeyCredential Get");
      console.log(credentials);
      const req = {};
      req.response = {};
      req.response.authenticatorData = toBase64(credentials.response.authenticatorData);
      req.response.clientDataJSON = toBase64(credentials.response.clientDataJSON);
      req.response.signature = toBase64(credentials.response.signature);
      return fetch(LOGIN_URL, {method: "POST", body: JSON.stringify(req)})
    })
    .catch(err => console.log(err));
  });
}


function toBase64(data) {
  return btoa(String.fromCharCode.apply(null, new Uint8Array(data)))
}

function fromBase64(data) {
  return Uint8Array.from(atob(data), c => c.charCodeAt(0))
}

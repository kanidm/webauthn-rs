"use strict";
const cose_alg_ECDSA_w_SHA256 = -7;
const cose_alg_ECDSA_w_SHA512 = -36;

// Need to manage the username better here?
const REG_CHALLENGE_URL = "/auth/challenge/register/xxx";
const LGN_CHALLENGE_URL = "/auth/challenge/login/xxx";
const REGISTER_URL = "/auth/register";
const LOGIN_URL = "/auth/login";

function register() {
  fetch(REG_CHALLENGE_URL, {method: "POST"})
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
          console.log("Sending RegisterResponse");
          console.log(cc);
          return fetch(REGISTER_URL, {
            method: "POST",
            body: JSON.stringify(cc),
            headers: {
              "Content-Type": "application/json",
            },
          })
        }) // then(newC
        .catch(err => console.log(err))
    }); // then(chal
}

function login() {
  fetch(LGN_CHALLENGE_URL, {method: "POST"})
    .then(res => res.json())
    .then(challenge => {
      console.log("challenge");
      console.log(challenge);
      const allowCredentials = challenge.publicKey.allowCredentials.map(c => {
          c.id = fromBase64(c.id)
          return c
      });
      const req = {
        publicKey: {
            challenge: fromBase64(challenge.publicKey.challenge),
            timeout: 6000,
            allowCredentials: allowCredentials,
        }
      };
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
          console.log("Sending LoginRequest");
          console.log(req);
          return fetch(LOGIN_URL, {
            method: "POST",
            body: JSON.stringify(req),
            headers: {
              "Content-Type": "application/json",
            },
          })
        }) // then(creds
        // https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/get
        .catch(err => console.log(err)) // display errors in getting credentials
  }); //then(chal
}


function toBase64(data) {
  return btoa(String.fromCharCode.apply(null, new Uint8Array(data)))
}

function fromBase64(data) {
  return Uint8Array.from(atob(data), c => c.charCodeAt(0))
}

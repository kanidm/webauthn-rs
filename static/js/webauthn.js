"use strict";
const cose_alg_ECDSA_w_SHA256 = -7;
const cose_alg_ECDSA_w_SHA512 = -36;

// Need to manage the username better here?
const REG_CHALLENGE_URL = "/auth/challenge/register/";
const LGN_CHALLENGE_URL = "/auth/challenge/login/";
const REGISTER_URL = "/auth/register/";
const LOGIN_URL = "/auth/login/";

PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
  .then(function(available){
        console.log('platform auth -> ' + available);
      if(available){
            // We can proceed with the creation of a PublicKeyCredential
            // with this authenticator
       } else {
            // Use another kind of authenticator or a classical login/password
            // workflow
       }
 }).catch(function(err){
    // Something went wrong
    console.error(err);
 });

function toast_o_matic(message) {
    var toast_arena = document.getElementById("toast_arena");

    toast_arena.innerHTML = `
<div id="error_toast" class="toast" role="alert" aria-live="assertive" aria-atomic="true" data-autohide="false"  >
  <div class="toast-header">
    <button type="button" class="ml-2 mb-1 close" data-dismiss="toast" aria-label="Close">
      <span aria-hidden="true">&times;</span>
    </button>
  </div>
  <div class="toast-body">
    ${message}
  </div>
</div>`

    $('#error_toast').toast('show')
}

function register() {
  var username = document.getElementById("username").value;

  fetch(REG_CHALLENGE_URL + username, {method: "POST"})
    .then(res => {
        // Handle error?
        if (res.status != 200) {
            toast_o_matic("Oppsie Whoopsie");
            // Update a element on page to say we broke.
            throw new Error("Opps");
            // How to exit properly?
        } else {
            return res;
        }
    })
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
          return fetch(REGISTER_URL + username, {
            method: "POST",
            body: JSON.stringify(cc),
            headers: {
              "Content-Type": "application/json",
            },
          })
        }) // then(newC
        // So act on the return fetch(REG_URL) now ...
        .then(res => {
            // Handle error?
            if (res.status != 200) {
                // Update a element on page to say we broke.
                console.log(res);
                toast_o_matic("Oppsie Whoopsie");
                throw new Error("Opps");
                // How to exit properly?
            } else {
                toast_o_matic("Registration Success");
                return res;
            }
        })
    }) // then(chal
    .catch(err => console.log(err, err.stack))
}

function login(mevent) {
  var username = document.getElementById("username").value;
  fetch(LGN_CHALLENGE_URL + username, {method: "POST"})
    .then(res => {
        // Handle error?
        if (res.status != 200) {
            toast_o_matic("Oppsie Whoopsie Spaghettios");
            // Update a element on page to say we broke.
            throw new Error("Opps");
            // How to exit properly?
        } else {
            return res;
        }
    })
    .then(res => res.json())
    .then(challenge => {
      console.log("challenge");
      console.log(challenge);
      challenge.publicKey.challenge = fromBase64(challenge.publicKey.challenge);
      challenge.publicKey.allowCredentials = challenge.publicKey.allowCredentials.map(c => {
          c.id = fromBase64(c.id)
          return c
      });
      console.log(challenge);
      return navigator.credentials.get(challenge)
        .then(credentials => {
        // https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/get
          /*
          console.log("PublicKeyCredential Get");
          console.log(credentials);
          credentials.response.authenticatorData = toBase64(credentials.response.authenticatorData);
          credentials.response.clientDataJSON = toBase64(credentials.response.clientDataJSON);
          credentials.response.signature = toBase64(credentials.response.signature);
          */
          const pk = {};
          pk.id = credentials.id;
          pk.rawId = toBase64(credentials.rawId);
          pk.response = {};
          pk.response.authenticatorData = toBase64(credentials.response.authenticatorData);
          pk.response.clientDataJSON = toBase64(credentials.response.clientDataJSON);
          pk.response.signature = toBase64(credentials.response.signature);
          pk.response.userHandle = toBase64(credentials.response.userHandle);
          pk.type = credentials.type;

          return fetch(LOGIN_URL + username, {
            method: "POST",
            body: JSON.stringify(pk),
            headers: {
              "Content-Type": "application/json",
            },
          })
        }) // then(creds
        // So act on the return fetch(LGN_URL) now ...
        .then(res => {
            // Handle error?
            if (res.status != 200) {
                // Update a element on page to say we broke.
                console.log(res);
                toast_o_matic("Oppsie Whoopsie Spaghettios");
                throw new Error("Opps");
                // How to exit properly?
            } else {
                toast_o_matic("Login Success");
                console.log($.cookie("webauthnrs"));
                return res;
            }
        })
    }) // then(chal
    .catch(err => console.log(err, err.stack))
}

function toBase64(data) {
    let b64val = btoa(String.fromCharCode.apply(null, new Uint8Array(data)));
    return b64val.replace(/\//g, '_').replace(/\+/g, '-').replace(/=/g, '');
}

function fromBase64(data) {
    let fixed = data.replace(/_/g, '/').replace(/-/g, '+');
    while (fixed.length % 4 !== 0) {
        fixed += "=";
    }
    return toArray(atob(fixed));
}

function toArray(str) {
    return Uint8Array.from(str, c => c.charCodeAt(0));
}


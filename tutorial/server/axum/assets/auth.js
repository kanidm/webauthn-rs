function register () {
    let username = document.getElementById('username').value;
    if (username === "") {
        alert("Please enter a username");
        return;
    }

    fetch('http://localhost:8080/register_start/' + username, {
        method: 'POST'
    })
    .then(response => response.json() )
    .then(credentialCreationOptions => {
        credentialCreationOptions.publicKey.challenge = Base64.toUint8Array(credentialCreationOptions.publicKey.challenge);
        credentialCreationOptions.publicKey.user.id = Base64.toUint8Array(credentialCreationOptions.publicKey.user.id);

        return navigator.credentials.create({
            publicKey: credentialCreationOptions.publicKey
        });
    })
    .then((credential) => {
        fetch('http://localhost:8080/register_finish', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                id: credential.id,
                rawId: Base64.fromUint8Array(new Uint8Array(credential.rawId), true),
                type: credential.type,
                response: {
                    attestationObject: Base64.fromUint8Array(new Uint8Array(credential.response.attestationObject), true),
                    clientDataJSON: Base64.fromUint8Array(new Uint8Array(credential.response.clientDataJSON), true),
                },
            })
        })
        .then((response) => {
            if (response.ok){
                console.log("Registered!");
            } else {
                console.log("Error");
            }
        });
    })
}

function login() {
    let username = document.getElementById('username').value;
    if (username === "") {
        alert("Please enter a username");
        return;
    }

    fetch('http://localhost:8080/login_start/' + username, {
        method: 'POST'
    })
    .then(response => response.json())
    .then((credentialRequestOptions) => {
        credentialRequestOptions.publicKey.challenge = Base64.toUint8Array(credentialRequestOptions.publicKey.challenge);
        credentialRequestOptions.publicKey.allowCredentials.forEach(function (listItem) {
            listItem.id = Base64.toUint8Array(listItem.id)
        });

        return navigator.credentials.get({
            publicKey: credentialRequestOptions.publicKey
        });
    })
    .then((assertion) => {
        fetch('http://localhost:8080/login_finish', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                id: assertion.id,
                rawId: Base64.fromUint8Array(new Uint8Array(assertion.rawId), true),
                type: assertion.type,
                response: {
                    authenticatorData: Base64.fromUint8Array(new Uint8Array(assertion.response.authenticatorData), true),
                    clientDataJSON: Base64.fromUint8Array(new Uint8Array(assertion.response.clientDataJSON), true),
                    signature: Base64.fromUint8Array(new Uint8Array(assertion.response.signature), true),
                    userHandle: assertion.response.userHandle
                },
            }),
        })
        .then((response) => {
            if (response.ok){
                console.log("Logged In!");
            } else {
                console.log("Error");
            }
        });
    });
}
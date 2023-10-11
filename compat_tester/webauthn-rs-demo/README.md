# webauthn-rs-demo

This is the demo site which powers https://webauthn.firstyear.id.au/

## Running it locally

```
cargo run --
```

Then navigate to "http://localhost:8080/" as the server prints out.

### HTTPS/TLS support

TLS support is [enabled by default][0] with the `tls` feature. You can _disable_
it with `--no-default-features`.

[0]: https://doc.rust-lang.org/cargo/reference/features.html#the-default-feature

Provide the TLS public and private keys in PEM format, and specify an Origin
(`--origin`) and relying party ID (`--id`):

```sh
cargo run -- \
    --bind 192.0.2.1:443 \
    --tls-public-key /etc/ssl/certs/demo.example.com.pem \
    --tls-private-key /etc/ssl/certs/demo.example.com.key \
    --origin https://demo.example.com \
    --id demo.example.com
```

If you're testing locally, you can build a short-lived self-signed certificate
(which won't be trusted by browsers) with `openssl`:

```sh
openssl genrsa -out /tmp/demo.key
openssl req -new -x509 -key /tmp/demo.key -out /tmp/demo.pem -days 5 -subj "/CN=localhost/" -addext "subjectAltName = DNS:localhost"
```

Configuring and managing certificates properly is outside the scope of this
document. :)

## Troubleshooting

If your system can't find `localhost`, this could be a failure in name
resolution. You should check your system's `/etc/hosts` file for this.

If you navigate to `http://127.0.0.1:8080/`, this example **WILL FAIL** as the
Origin is set to `localhost`, not `127.0.0.1`.

## TODO

* Improve the Javascript to use the username field correcly.
* Make it prettier and sparkly.
* Add cookie handling example.

## Building Yew:

```sh
cargo install wasm-pack
npm install --global rollup
cd ../webauthn-rs-demo-wasm
./build_wasm.sh
```

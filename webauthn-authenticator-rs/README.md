
# webauthn-authenticator-rs

WebAuthn is a modern approach to hardware based authentication, consisting of
a user with an authenticator device, a browser or client that interacts with the
device, and a server that is able to generate challenges and verify the
authenticator's validity.

This library is the client half of the authenticator process, performing the
steps that would normally be taken by a web browser. Given a challenge from
a Webauthn server, this library can interface with a CTAP2 device and transform
the response to a Webauthn registration or assertion (authentication).

## Development

### Building docs

This library contains extensive documentation in `rustdoc` format. You can build
this with:

```sh
cargo doc --no-deps --document-private-items
```

This library includes many references to _module-private_ items to explain how
protocols work, so we use `--document-private-items`.

By default, this won't add any features, so you'll want to add them with
`--features ...`, or use `--all-features` (which pulls in many dependencies).

To build all docs in a way that
[annotates which modules and functions are avaliable with which features][doc_cfg]:

1.  Install [Rust nightly][]:

    ```sh
    rustup toolchain install nightly
    ```

2.  Build the documentation with:

    ```sh
    RUSTDOCFLAGS="--cfg docsrs" cargo +nightly doc --no-deps --document-private-items
    ```

    Or with PowerShell (Windows):

    ```ps1
    $Env:RUSTDOCFLAGS = "--cfg docsrs"
    cargo +nightly doc --no-deps --document-private-items
    ```

[Rust nightly]: https://doc.rust-lang.org/book/appendix-07-nightly-rust.html
[doc_cfg]: https://doc.rust-lang.org/beta/unstable-book/language-features/doc-cfg.html

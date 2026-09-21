use leptos::prelude::*;

/// Renders the home page of your application.
#[component]
pub fn HomePage() -> impl IntoView {
    view! {
        <h1>"webauthn-rs demo"</h1>

        <p>
            "WebAuthn is a modern approach to public-key-based web authentication, \
            consisting of:"
        </p>

        <ul>
            <li>
                "a user-provided authenticator, which may be their device's built-in security \
                processor, a removable authenticator device, or a synchronised credential manager,"
            </li>
            <li>"a browser or client that interacts with the authenticator,"</li>
            <li>
                "a server that is able to generate challenges and verify the authenticator's \
                validity."
            </li>
        </ul>

        <p>
            "Users are able to enrol their own authenticators through a registration process to \
            be associated to their accounts, and then are able to login using the authenticator \
            to sign a server-issued challenge using public-key cryptography."
        </p>

        <p>
            <a
                href="https://github.com/kanidm/webauthn-rs"
                target="_blank"
            >
                <code>"webauthn-rs"</code>
            </a>
            " is a Rust WebAuthn Relying Party library, allowing you to add WebAuthn support to \
            Rust web applications. We provide template and example JavaScript and WASM bindings \
            to demonstrate the browser interactions required."
        </p>

        <p>
            "To show you how it works, let's "
            <a href="/register">
                "start the registration flow"
            </a>
            "."
        </p>
    }
}

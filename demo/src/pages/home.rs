use leptos::prelude::*;

/// Renders the home page of your application.
#[component]
pub fn HomePage() -> impl IntoView {
    view! {
        <h1>"webauthn-rs demo"</h1>

        <p>
            "WebAuthn is a modern approach to hardware based authentication, consisting of
            a user-provided authenticator device, a browser or client that interacts with the
            authenticator, and a server that is able to generate challenges and verify the
            authenticator's validity."
        </p>

        <p>
            "Users are able to enroll their own authenticators through a registration process to
            be associated to their accounts, and then are able to login using the token
            which performs a cryptographic authentication."
        </p>

        <p>
            <code>"webauthn-rs"</code>
            " implements the Relying Party component of the Webauthn/FIDO2 workflow, allowing you to
            add WebAuthn support to Rust web applications. We provide template and example
            JavaScript and WASM bindings to demonstrate the browser interactions required."
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

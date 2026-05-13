use leptos::prelude::*;

/// Top navigation bar component.
#[component]
pub fn Navbar() -> impl IntoView {
    // TODO: tracking active links etc.
    view! {
        <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
            <div class="container">
                <span class="navbar-brand mb-0 h1">"webauthn-rs demo"</span>

                <button
                    class="navbar-toggler"
                    type="button"
                    data-bs-toggle="collapse"
                    data-bs-target="#navbarcontent"
                    aria-controls="navbarcontent"
                    aria-expanded="false"
                    aria-label="Toggle navigation"
                >
                    <span class="navbar-toggler-icon"></span>
                </button>

                <div class="collapse navbar-collapse" id="navbarcontent">
                    <ul class="navbar-nav me-auto mb-2 mb-lg-0">
                        <li class="nav-item">
                            <a class="nav-link" href="#">"Demo"</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="#">"Compatibility tests"</a>
                        </li>
                    </ul>
                </div>

                <ul class="navbar-nav me-auto mb-2 mb-lg-0">
                    <li class="nav-item">
                        <a
                            class="nav-link"
                            href="https://github.com/kanidm/webauthn-rs"
                            target="_blank"
                        >
                            "View on GitHub"
                        </a>
                    </li>
                </ul>
            </div>
        </nav>
    }
}

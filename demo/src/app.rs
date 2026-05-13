use leptos::prelude::*;
use leptos_meta::{provide_meta_context, MetaTags, Stylesheet, Title};
use leptos_router::{
    components::{Route, Router, Routes},
    StaticSegment,
};

use crate::{components::*, pages::*};

pub fn shell(options: LeptosOptions) -> impl IntoView {
    view! {
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8"/>
                <meta name="viewport" content="width=device-width, initial-scale=1"/>
                <AutoReload options=options.clone() />
                <HydrationScripts options />
                <link
                    href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css"
                    rel="stylesheet"
                    integrity="sha384-sRIl4kxILFvY47J16cr9ZwB07vP4J8+LH7qKQnuqkuIAvNWLzeN8tE5YBujZqJLB"
                    crossorigin="anonymous"
                />
                <MetaTags />
            </head>
            <body>
                <App />
                <script
                    src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/js/bootstrap.min.js"
                    integrity="sha384-G/EV+4j2dNv+tEPo3++6LCgdCROaejBqfUeNjuKAiuXbjrxilcCdDz6ZAVfHWe1Y"
                    crossorigin="anonymous"
                />
            </body>
        </html>
    }
}

#[component]
pub fn App() -> impl IntoView {
    // Provides context that manages stylesheets, titles, meta tags, etc.
    provide_meta_context();

    view! {
        // injects a stylesheet into the document <head>
        // id=leptos means cargo-leptos will hot-reload this stylesheet
        <Stylesheet id="leptos" href="/pkg/webauthn-rs-demo2.css" />

        // sets the document title
        <Title text="webauthn-rs-demo2" />

        <Navbar />

        <Router>
            <div class="container mt-1">
                <Routes fallback=NotFoundPage>
                    <Route path=StaticSegment("/register") view=RegisterPage />
                    <Route path=StaticSegment("/login") view=LoginPage />
                    <Route path=StaticSegment("") view=HomePage />
                </Routes>
            </div>
        </Router>
    }
}

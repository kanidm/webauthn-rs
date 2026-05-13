use axum::Router;
use leptos::logging::log;
use leptos::prelude::*;
use leptos_axum::{generate_route_list, LeptosRoutes};
use std::sync::Arc;
use webauthn_rs::prelude::*;
use webauthn_rs_demo2::{app::*, state::DemoState};

#[tokio::main]
pub async fn main() {
    let conf = get_configuration(None).unwrap();
    let rp_origin = Url::parse("http://localhost:3000").expect("URL parse error");
    let webauthn = WebauthnBuilder::new("localhost", &rp_origin)
        .expect("WebauthnBuilder err")
        .rp_name("webauthn-rs demo")
        .build()
        .expect("WebauthnBuilder setup error");

    let state = Arc::new(DemoState::new(webauthn));

    let leptos_options = conf.leptos_options;
    let addr = leptos_options.site_addr;
    // Generate the list of routes in your Leptos App
    let routes = generate_route_list(App);

    let app = Router::new()
        .leptos_routes_with_context(
            &leptos_options,
            routes,
            move || provide_context(state.clone()),
            {
                let leptos_options = leptos_options.clone();
                move || shell(leptos_options.clone())
            },
        )
        .fallback(leptos_axum::file_and_error_handler(shell))
        .with_state(leptos_options);

    // run our app with hyper
    // `axum::Server` is a re-export of `hyper::Server`
    log!("listening on http://{}", &addr);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();
}

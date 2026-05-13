use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use leptos::logging::log;
use leptos::prelude::*;
use leptos_axum::{generate_route_list, LeptosRoutes};
use std::{path::PathBuf, sync::Arc};
use webauthn_rs::prelude::*;
use webauthn_rs_demo2::{app::*, state::DemoState};

#[tokio::main]
pub async fn main() {
    let conf = get_configuration(None).unwrap();
    let rp_origin = Url::parse("https://localhost:3000").expect("URL parse error");
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

    let tls_config =
        RustlsConfig::from_pem_file(PathBuf::from("./demo/cert.pem"), PathBuf::from("./demo/key.pem"))
            .await
            .expect("Failure loading TLS certificates");

    log!("listening on https://{addr}");

    axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

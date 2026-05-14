use axum::Router;
use clap::Parser;
use leptos::prelude::*;
use leptos_axum::{generate_route_list, LeptosRoutes};
use std::sync::Arc;
use tracing::{info, warn};
use tracing_subscriber::{filter::LevelFilter, fmt::format::FmtSpan, EnvFilter};
use webauthn_rs_demo2::{
    app::*,
    server::{config::ServerArgs, state::DemoState},
};

#[tokio::main]
pub async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .with_span_events(FmtSpan::CLOSE | FmtSpan::NEW)
        .with_thread_ids(true)
        .compact()
        .init();

    let args = ServerArgs::parse();
    let conf = get_configuration(None).unwrap();
    let webauthn = args.setup_webauthn().expect("WebauthnBuilder setup error");

    let state = Arc::new(DemoState::new(webauthn));

    let leptos_options = conf.leptos_options;
    let addr = leptos_options.site_addr;
    // Generate the list of routes in your Leptos App
    let routes: Vec<leptos_axum::AxumRouteListing> = generate_route_list(App);

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

    let tls_config = args
        .rustls_config()
        .await
        .expect("Failure loading TLS certificates");

    info!(
        "Listening on {}, visit {} in your browser",
        addr,
        args.rp_origin().as_str()
    );

    if tls_config.is_some() != (args.rp_origin().scheme() == "https") {
        warn!(
            "Application is serving over http{}, but the RP origin's scheme is {}. If this is \
            intentional, you will need a reverse proxy for this to work!",
            if tls_config.is_some() { "s" } else { "" },
            args.rp_origin().scheme(),
        );
    }

    match tls_config {
        Some(tls_config) => axum_server::bind_rustls(addr, tls_config)
            .serve(app.into_make_service())
            .await
            .expect("started"),
        None => axum_server::bind(addr)
            .serve(app.into_make_service())
            .await
            .expect("started"),
    };
}

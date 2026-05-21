use axum::{
    http::{HeaderValue, Method},
    Router,
};
use clap::Parser;
use leptos::prelude::*;
use leptos_axum::{generate_route_list, LeptosRoutes};
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer},
    ServiceBuilderExt,
};
use tracing::{info, warn};
use tracing_subscriber::{filter::LevelFilter, fmt::format::FmtSpan, EnvFilter};
use webauthn_rs_demo2::{
    app::*,
    server::{config::ServerArgs, state::ServerState, RandomUuidRequestId, ServerResult},
};

#[tokio::main]
pub async fn main() -> ServerResult {
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
    let conf = get_configuration(None)?;
    let webauthn = args.setup_webauthn()?;
    let sqlite = args.connect_sqlite().await?;

    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST])
        .allow_origin(AllowOrigin::list(
            webauthn
                .get_allowed_origins()
                .iter()
                .filter_map(|u| HeaderValue::from_str(u.as_str()).ok()),
        ));

    let rp_is_https = args.rp_origin().scheme() == "https";

    let state = Arc::new(ServerState::new(
        webauthn,
        sqlite,
        args.wrap_key(),
        rp_is_https,
    )?);

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
        .with_state(leptos_options)
        .layer(
            ServiceBuilder::new()
                .set_x_request_id(RandomUuidRequestId)
                .layer(
                    TraceLayer::new_for_http()
                        .make_span_with(DefaultMakeSpan::new().include_headers(true))
                        .on_response(DefaultOnResponse::new().include_headers(true)),
                )
                .propagate_x_request_id()
                .layer(cors),
        );

    // run our app with hyper
    // `axum::Server` is a re-export of `hyper::Server`

    let tls_config = args.rustls_config().await?;

    info!(
        "Listening on {}, visit {} in your browser",
        addr,
        args.rp_origin().as_str()
    );

    if tls_config.is_some() != rp_is_https {
        warn!(
            "Application is serving over http{}, but the RP origin's scheme is {}. If this is \
            intentional, you will need a reverse proxy for this to work!",
            if tls_config.is_some() { "s" } else { "" },
            args.rp_origin().scheme(),
        );
    }

    match tls_config {
        Some(tls_config) => {
            axum_server::bind_rustls(addr, tls_config)
                .serve(app.into_make_service())
                .await?
        }
        None => {
            axum_server::bind(addr)
                .serve(app.into_make_service())
                .await?
        }
    };

    Ok(())
}

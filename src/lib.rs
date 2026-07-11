//! Saros — inex's hosted firmware registry: content-addressed blobs plus
//! per-version manifests, served over ConnectRPC (`inex.saros.v1`).

use std::sync::Arc;

use tower_http::cors::CorsLayer;

use inex_protobufs::connect::inex::saros::v1::{
    AuthServiceExt as _, BlobServiceExt as _, FirmwareServiceExt as _,
};

/// Browser-facing config for [`app`]: the web origin (CORS + cookie site) and
/// session-cookie attributes. Dev leaves the domain empty (`Domain` on
/// `localhost` is rejected).
pub struct WebConfig {
    pub origin: String,
    pub cookie_domain: Option<String>,
    pub cookie_secure: bool,
}

pub mod auth;
pub mod db;
pub mod events;
pub mod login;
pub mod metrics;
pub mod mirror;
pub mod passkey;
pub mod ratelimit;
pub mod services;
pub mod store;

use auth::Auth;
use db::Db;
use events::Events;
use login::Logins;
use metrics::Metrics;
use passkey::Passkeys;
use services::{ConnectAuthService, ConnectBlobService, ConnectFirmwareService};
use store::Store;

/// The full service router: the Connect services (fallback), plus `/healthz`,
/// `/readyz` and `/version`. CORS is locked to the web origin with credentials.
pub fn app(
    store: Arc<Store>,
    auth: Arc<Auth>,
    passkeys: Arc<Passkeys>,
    logins: Arc<Logins>,
    metrics: Arc<Metrics>,
    db: Arc<Db>,
    web: WebConfig,
) -> axum::Router {
    let events = Arc::new(Events::new(db.clone(), metrics.clone()));
    let connect = connectrpc::Router::new();
    let connect = Arc::new(ConnectBlobService::new(
        store.clone(),
        auth.clone(),
        db.clone(),
        events.clone(),
    ))
    .register(connect);
    let connect = Arc::new(ConnectFirmwareService::new(
        store.clone(),
        auth.clone(),
        metrics.clone(),
        db.clone(),
        events.clone(),
    ))
    .register(connect);
    let connect = Arc::new(ConnectAuthService::new(
        auth.clone(),
        passkeys,
        logins,
        db,
        events,
        web.cookie_domain,
        web.cookie_secure,
    ))
    .register(connect);
    let connect = connect.into_axum_service();

    // Credentialed CORS: the origin must be the exact web origin (never `*`).
    let cors = CorsLayer::new()
        .allow_origin(
            http::HeaderValue::from_str(&web.origin)
                .expect("SAROS_RP_ORIGIN must be a valid origin header value"),
        )
        .allow_credentials(true)
        .allow_methods(tower_http::cors::AllowMethods::mirror_request())
        .allow_headers(tower_http::cors::AllowHeaders::mirror_request());

    let ready_store = store.clone();

    axum::Router::new()
        .route("/healthz", axum::routing::get(|| async { "ok\n" }))
        .route(
            "/readyz",
            axum::routing::get(move || {
                let store = ready_store.clone();
                async move { readyz(&store).await }
            }),
        )
        .route(
            "/version",
            axum::routing::get(|| async {
                axum::Json(serde_json::json!({
                    "name": env!("CARGO_PKG_NAME"),
                    "version": env!("CARGO_PKG_VERSION"),
                }))
            }),
        )
        .fallback_service(connect)
        // A handler panic becomes a 500 instead of dropping the connection.
        .layer(tower_http::catch_panic::CatchPanicLayer::new())
        .layer(cors)
}

/// Readiness: a cheap store/db reachability probe (200/503). Deliberately does
/// NOT touch the S3 mirror, so egress latency never marks the app not-ready.
async fn readyz(store: &Store) -> axum::response::Response {
    use axum::response::IntoResponse as _;
    match store.stats().await {
        Ok(_) => (http::StatusCode::OK, "ready\n").into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "readiness probe failed");
            (http::StatusCode::SERVICE_UNAVAILABLE, "unavailable\n").into_response()
        }
    }
}

/// `n` random bytes as lowercase hex — flow ids, device codes, session ids.
pub(crate) fn random_hex(n: usize) -> Result<String, getrandom::Error> {
    let mut raw = vec![0u8; n];
    getrandom::fill(&mut raw)?;
    Ok(hex::encode(raw))
}

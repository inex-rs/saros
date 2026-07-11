use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use saros::store::Store;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Auto-load services/saros/.env in dev (CARGO_MANIFEST_DIR = source dir, so
    // `cargo run` finds it from any cwd); absent in the container.
    let _ = dotenvy::from_filename(concat!(env!("CARGO_MANIFEST_DIR"), "/.env"));
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    serve(ServeArgs::parse()).await
}

/// Fixed per build profile: debug serves the repo's dev data tree (compile-time
/// path, so `cargo run` works from any cwd); release serves the container volume.
#[cfg(debug_assertions)]
const DATA_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../private/registry-data");
#[cfg(not(debug_assertions))]
const DATA_DIR: &str = "/data";

#[cfg(debug_assertions)]
const DEFAULT_LISTEN: &str = "127.0.0.1:7171";
#[cfg(not(debug_assertions))]
const DEFAULT_LISTEN: &str = "0.0.0.0:8080";

/// Saros — inex's hosted firmware registry server (ConnectRPC).
#[derive(Parser)]
#[command(version, about)]
struct ServeArgs {
    /// Address to listen on.
    #[arg(long, default_value = DEFAULT_LISTEN)]
    listen: std::net::SocketAddr,

    /// Service bearer token (CI, dump pipelines) — full access.
    #[arg(long, env = "SAROS_TOKEN")]
    service_token: Option<String>,

    /// Admin usernames — may publish live and approve staged uploads.
    #[arg(long, env = "SAROS_ADMIN_USERS", value_delimiter = ',')]
    admin_users: Vec<String>,

    /// WebAuthn origin — the browser URL the site is served from. The passkey
    /// rp-id and the session-cookie `Domain=` are its host; `https` implies
    /// `Secure` cookies.
    #[arg(long, default_value = "http://localhost:5173", env = "SAROS_RP_ORIGIN")]
    rp_origin: String,
}

/// Per-blob size cap; also sets the request-body ceiling.
const MAX_BLOB_BYTES: usize = 5 * 1024 * 1024;
/// Per-IP request budgets per minute (global tier / anonymous auth-ceremony tier).
const RATE_LIMIT_PER_MIN: u32 = 120;
const AUTH_RATE_LIMIT_PER_MIN: u32 = 10;
/// Reclaim unreferenced abandoned uploads older than this.
const INCOMING_GC_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(24 * 3600);

fn build_mirror(cfg: &saros::mirror::S3Config) -> anyhow::Result<saros::mirror::Mirror> {
    let public_base = std::env::var("SAROS_BLOB_PUBLIC_BASE")
        .ok()
        .filter(|s| !s.is_empty());
    tracing::info!(
        endpoint = %cfg.endpoint,
        bucket = %cfg.bucket,
        public = public_base.is_some(),
        "s3 egress mirror ({})",
        if public_base.is_some() { "public URLs" } else { "presigned URLs" }
    );
    saros::mirror::Mirror::new(cfg, public_base)
}

async fn serve(args: ServeArgs) -> anyhow::Result<()> {
    let ServeArgs {
        listen,
        service_token,
        admin_users,
        rp_origin,
    } = args;
    let data = PathBuf::from(DATA_DIR);
    if service_token.is_none() && admin_users.is_empty() {
        tracing::warn!(
            "no service token or admin users — sign-ins can only stage; nothing can publish live"
        );
    }
    let db = Arc::new(saros::db::Db::open(data.join("meta.db")).await?);
    let auth = Arc::new(saros::auth::Auth::new(
        service_token.as_deref(),
        admin_users,
        db.clone(),
    ));
    let rp_origin_url = url::Url::parse(&rp_origin)
        .map_err(|e| anyhow::anyhow!("bad SAROS_RP_ORIGIN {rp_origin:?}: {e}"))?;
    // The origin's host is the passkey rp-id AND the cookie Domain (set from
    // the API subdomain, a parent Domain spans both hosts). localhost/IPs get
    // no Domain (rejected by browsers) and any-port tolerance for dev.
    let rp_id = rp_origin_url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("SAROS_RP_ORIGIN {rp_origin:?} has no host"))?
        .to_string();
    let allow_any_port = rp_id == "localhost";
    let cookie_domain =
        (!allow_any_port && rp_id.parse::<std::net::IpAddr>().is_err()).then(|| rp_id.clone());
    let passkeys = Arc::new(saros::passkey::Passkeys::new(
        &rp_id,
        &rp_origin_url,
        allow_any_port,
        db.clone(),
    )?);
    tracing::info!(rp_id = %rp_id, rp_origin = %rp_origin, "passkey sign-in ready");
    let logins = Arc::new(saros::login::Logins::new(rp_origin.clone()));
    // The S3/Tigris egress mirror activates iff SAROS_S3_* is configured;
    // otherwise blob bytes are served inline from disk.
    let mirror = match saros::mirror::S3Config::from_env() {
        Some(cfg) => Some(build_mirror(&cfg)?),
        None => None,
    };
    let metrics = Arc::new(saros::metrics::Metrics::new(mirror.is_some()));
    // Seed lifetime counters from the last run so totals survive restarts.
    match db.stats().load_totals().await {
        Ok(t) => metrics.seed(&t),
        Err(e) => {
            tracing::warn!(error = %e, "could not restore metric totals — counters start at zero")
        }
    }
    // Db handle for the persist task / shutdown flush / GetMetricsHistory RPC.
    let metrics_db = db.clone();
    let store = Arc::new(Store::open(&data, MAX_BLOB_BYTES, db, mirror)?);

    let _fs_watch = spawn_fs_watch(data.clone(), store.clone());
    spawn_metrics_persist(metrics_db.clone(), store.clone(), metrics.clone());
    spawn_incoming_gc(store.clone(), INCOMING_GC_MAX_AGE);

    // Deploy middleware lives here, not in app() — the router stays embeddable/testable.
    let rate_limit = saros::ratelimit::RateLimit::new(RATE_LIMIT_PER_MIN, AUTH_RATE_LIMIT_PER_MIN);
    saros::ratelimit::spawn_prune(rate_limit.clone());
    tracing::info!(
        global_per_min = RATE_LIMIT_PER_MIN,
        auth_per_min = AUTH_RATE_LIMIT_PER_MIN,
        "per-IP rate limiting"
    );

    let web = saros::WebConfig {
        origin: rp_origin.clone(),
        cookie_domain,
        cookie_secure: rp_origin.starts_with("https://"),
    };
    let app = saros::app(
        store.clone(),
        auth.clone(),
        passkeys,
        logins,
        metrics.clone(),
        metrics_db.clone(),
        web,
    )
    // Reject over-cap bodies at the transport, before the RPC layer buffers them.
    .layer(tower_http::limit::RequestBodyLimitLayer::new(
        MAX_BLOB_BYTES.saturating_add(1 << 20),
    ))
    // serve()-only (not app()): deploy concerns stay out of the pure router.
    .layer(axum::middleware::from_fn_with_state(auth, touch_session))
    .layer(axum::middleware::from_fn_with_state(
        rate_limit,
        saros::ratelimit::enforce,
    ));

    let listener = tokio::net::TcpListener::bind(listen).await?;
    tracing::info!(listen = %listen, data = %data.display(), "saros serving");
    // No graceful drain: Watch RPCs are infinite streams and would block forever.
    // Connect info lets the rate limiter key off the peer socket in local dev.
    tokio::select! {
        r = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        ) => r?,
        _ = tokio::signal::ctrl_c() => tracing::info!("shutting down"),
    }
    // Final flush so a deploy loses at most the sub-interval tail.
    persist_metrics(&metrics_db, &store, &metrics).await;
    Ok(())
}

/// ~5-minute metrics persist task; the immediate first tick is consumed so the
/// first write lands one interval in, not at boot.
fn spawn_metrics_persist(
    db: Arc<saros::db::Db>,
    store: Arc<Store>,
    metrics: Arc<saros::metrics::Metrics>,
) {
    const PERSIST_SECS: u64 = 300;
    // Reclaim expired session rows hourly — off the session-put hot path.
    const SESSION_SWEEP_EVERY_TICK: u64 = 3600 / PERSIST_SECS;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(PERSIST_SECS));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        interval.tick().await; // consume the immediate first tick
        let mut ticks = 0u64;
        loop {
            interval.tick().await;
            ticks += 1;
            persist_metrics(&db, &store, &metrics).await;
            if ticks.is_multiple_of(SESSION_SWEEP_EVERY_TICK) {
                match db.sessions().sweep_expired().await {
                    Ok(n) if n > 0 => tracing::info!(removed = n, "swept expired sessions"),
                    Ok(_) => {}
                    Err(e) => tracing::warn!(error = %e, "session sweep failed"),
                }
            }
        }
    });
}

/// ~6h incoming-pool GC (first tick fires at boot). `max_age` zero disables it;
/// best-effort — errors are logged, never fatal.
fn spawn_incoming_gc(store: Arc<Store>, max_age: std::time::Duration) {
    if max_age.is_zero() {
        tracing::info!("incoming-pool GC disabled (max-age 0)");
        return;
    }
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(6 * 3600));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await; // first tick is immediate — sweep at boot
            // GC does blocking fs work — run off the reactor.
            let store = store.clone();
            match tokio::task::spawn_blocking(move || store.gc_incoming(max_age)).await {
                Ok(Ok(n)) if n > 0 => {
                    tracing::info!(reclaimed = n, "incoming-pool GC swept stale uploads")
                }
                Ok(Ok(_)) => {}
                Ok(Err(e)) => tracing::warn!(error = %e, "incoming-pool GC failed"),
                Err(e) => tracing::warn!(error = %e, "incoming-pool GC task panicked"),
            }
        }
    });
}

/// Snapshot store + counters into the durable metrics tables (hour bucket +
/// lifetime totals). Best-effort — a store/db hiccup is logged, never fatal.
async fn persist_metrics(db: &saros::db::Db, store: &Store, metrics: &saros::metrics::Metrics) {
    let m = metrics.snapshot();
    match store.stats().await {
        Ok(s) => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let rec = saros::db::MetricsSampleRecord {
                at: now,
                users: s.users,
                devices: s.devices,
                firmware: s.firmware,
                downloads: m.downloads,
                uploads: m.uploads,
                submissions: m.submissions,
                sign_ins: m.sign_ins,
            };
            if let Err(e) = db.stats().record_sample(&rec).await {
                tracing::warn!(error = %e, "recording metrics sample failed");
            }
        }
        Err(e) => tracing::warn!(error = %e, "metrics sample skipped — stats read failed"),
    }
    if let Err(e) = db.stats().save_totals(&metrics.totals()).await {
        tracing::warn!(error = %e, "flushing metric totals failed");
    }
}

/// Middleware: for a `Bearer` request, record the session's last-seen / IP /
/// device off the reactor (throttled ~hourly in the store), then pass through.
async fn touch_session(
    axum::extract::State(auth): axum::extract::State<Arc<saros::auth::Auth>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if let Some(authorization) = request
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .filter(|v| v.starts_with("Bearer "))
        .map(str::to_string)
    {
        // Resolve the client IP as the rate limiter does (Fly-first).
        let peer = request
            .extensions()
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .map(|info| info.0);
        let ip = saros::ratelimit::client_ip(request.headers(), peer)
            .map(|ip| ip.to_string())
            .unwrap_or_default();
        let device = request
            .headers()
            .get(http::header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .map(parse_user_agent)
            .unwrap_or_default();
        // Detach the touch so it never blocks the response.
        let auth = auth.clone();
        tokio::spawn(async move { auth.touch(Some(&authorization), &ip, &device).await });
    }
    next.run(request).await
}

/// `User-Agent` → coarse device string (e.g. "Chrome on macOS", "saros CLI").
/// `woothee` does the detection; empty/unrecognised UAs yield "".
fn parse_user_agent(ua: &str) -> String {
    let ua = ua.trim();
    if ua.is_empty() {
        return String::new();
    }
    // woothee can't detect our headless clients — name them first.
    let lower = ua.to_ascii_lowercase();
    if lower.contains("saros") || lower.contains("reqwest") {
        return "saros CLI".to_string();
    }
    let Some(r) = woothee::parser::Parser::new().parse(ua) else {
        return String::new();
    };
    let known = |s: &str| !s.is_empty() && s != "UNKNOWN";
    let browser = known(r.name).then(|| r.name.to_string());
    let os = known(r.os).then(|| tidy_os(r.os));
    match (browser, os) {
        (Some(b), Some(o)) => format!("{b} on {o}"),
        (Some(b), None) => b,
        (None, Some(o)) => o,
        (None, None) => String::new(),
    }
}

/// Collapse woothee's OS name to a clean family label.
fn tidy_os(os: &str) -> String {
    let l = os.to_ascii_lowercase();
    if l.contains("windows") {
        "Windows"
    } else if l.contains("mac") {
        "macOS"
    } else if l.contains("iphone") || l.contains("ipad") || l.contains("ios") {
        "iOS"
    } else if l.contains("android") {
        "Android"
    } else if l.contains("chrome os") || l.contains("chromeos") {
        "ChromeOS"
    } else if l.contains("linux") || l.contains("bsd") {
        "Linux"
    } else {
        return os.to_string();
    }
    .to_string()
}

/// Watch firmware/staging and reindex on external drops (rsync/git/hand-copied)
/// without a restart; a setup failure degrades to "restart to pick up".
fn spawn_fs_watch(data: PathBuf, store: Arc<Store>) -> Option<notify::RecommendedWatcher> {
    use notify::{RecursiveMode, Watcher};
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<()>();
    let mut watcher = match notify::recommended_watcher(
        move |res: notify::Result<notify::Event>| {
            // React only to structural changes (create / write / remove / rename).
            // Reads and atime bumps are ignored — otherwise our own reindex reads
            // would re-trigger the watcher in a tight loop.
            if let Ok(event) = res
                && matches!(
                    event.kind,
                    notify::EventKind::Create(_)
                        | notify::EventKind::Remove(_)
                        | notify::EventKind::Modify(
                            notify::event::ModifyKind::Data(_) | notify::event::ModifyKind::Name(_)
                        )
                )
            {
                let _ = tx.send(());
            }
        },
    ) {
        Ok(w) => w,
        Err(e) => {
            tracing::warn!(error = %e, "fs-watch unavailable — restart to pick up external drops");
            return None;
        }
    };
    for sub in ["firmware", "staging"] {
        let dir = data.join(sub);
        if let Err(e) = watcher.watch(&dir, RecursiveMode::Recursive) {
            tracing::warn!(dir = %dir.display(), error = %e, "fs-watch setup failed");
        }
    }
    tokio::spawn(async move {
        while rx.recv().await.is_some() {
            // Coalesce a burst into one reindex once the tree is quiet ~300ms.
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_millis(300)) => break,
                    m = rx.recv() => if m.is_none() { return },
                }
            }
            match store.reload() {
                Ok(true) => tracing::info!("firmware tree changed on disk — reindexed"),
                Ok(false) => {}
                Err(e) => tracing::warn!(error = %e, "reindex after fs change failed"),
            }
        }
    });
    Some(watcher)
}

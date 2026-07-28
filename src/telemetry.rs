//! Prometheus instrumentation: the [`metrics`] facade records, a
//! [`metrics_exporter_prometheus`] recorder owns the registry, and
//! [`axum_prometheus`] supplies the HTTP middleware.
//!
//! The exposition gets its own listener rather than a route on the public
//! router, so Fly's scraper reaches it over the private network and the
//! internet never does. Host-level series (CPU, memory, disk, network, volume)
//! come free from Fly's `fly_instance_*` / `fly_volume_*`.

use std::net::SocketAddr;
use std::time::Duration;

use axum_prometheus::{EndpointLabel, PrometheusMetricLayer, PrometheusMetricLayerBuilder};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};

use crate::metrics::Counter;
use crate::store::Stats;

const PREFIX: &str = "saros";

const EVENTS: &str = "saros_events_total";
const RATE_LIMITED: &str = "saros_rate_limited_total";
const MIRROR_OPS: &str = "saros_mirror_operations_total";
const MIRROR_DURATION: &str = "saros_mirror_operation_duration_seconds";
const BUILD_INFO: &str = "saros_build_info";

const USERS: &str = "saros_users";
const DEVICES: &str = "saros_devices";
const FIRMWARE: &str = "saros_firmware_versions";
const STAGED: &str = "saros_firmware_staged";
const BLOBS: &str = "saros_blobs";
const BLOB_BYTES: &str = "saros_blob_bytes";

/// Applied to every `*_duration_seconds` metric. Without an explicit bucket
/// list the exporter renders summaries, which don't aggregate across instances.
const DURATION_BUCKETS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// `install_recorder` leaves histogram-window rotation to the caller.
const UPKEEP_INTERVAL: Duration = Duration::from_secs(5);

/// Install the global recorder and return the router's HTTP middleware. Call
/// once, from inside the tokio runtime; a second call panics.
pub fn install() -> (PrometheusMetricLayer<'static>, PrometheusHandle) {
    let (layer, handle) = PrometheusMetricLayerBuilder::new()
        .with_prefix(PREFIX)
        .with_endpoint_label_type(EndpointLabel::MatchedPathWithFallbackFn(endpoint_label))
        .with_metrics_from_fn(|| {
            PrometheusBuilder::new()
                .set_buckets_for_metric(
                    Matcher::Suffix("_duration_seconds".to_string()),
                    DURATION_BUCKETS,
                )
                .expect("the bucket list is non-empty")
                .install_recorder()
                .expect("no other global metrics recorder is installed")
        })
        .build_pair();
    describe();
    metrics::gauge!(BUILD_INFO, "version" => env!("CARGO_PKG_VERSION")).set(1.0);
    let upkeep = handle.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(UPKEEP_INTERVAL);
        loop {
            tick.tick().await;
            upkeep.run_upkeep();
        }
    });
    (layer, handle)
}

/// Serve the exposition on `addr` until shutdown.
pub async fn spawn_exporter(addr: SocketAddr, handle: PrometheusHandle) -> std::io::Result<()> {
    let render = move || {
        let handle = handle.clone();
        async move {
            (
                [(
                    http::header::CONTENT_TYPE,
                    "text/plain; version=0.0.4; charset=utf-8",
                )],
                handle.render(),
            )
        }
    };
    let app = axum::Router::new().route("/metrics", axum::routing::get(render));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            tracing::warn!(error = %e, "prometheus exporter stopped");
        }
    });
    Ok(())
}

pub(crate) fn event(c: Counter) {
    metrics::counter!(EVENTS, "event" => <&'static str>::from(c)).increment(1);
}

pub(crate) fn rate_limited(tier: &'static str) {
    metrics::counter!(RATE_LIMITED, "tier" => tier).increment(1);
}

/// Every caller falls back off a mirror failure silently — without this a dead
/// bucket looks like healthy inline serving.
pub(crate) fn mirror_op(op: &'static str, ok: bool, elapsed: Duration) {
    let outcome = if ok { "ok" } else { "error" };
    metrics::counter!(MIRROR_OPS, "op" => op, "outcome" => outcome).increment(1);
    metrics::histogram!(MIRROR_DURATION, "op" => op).record(elapsed.as_secs_f64());
}

pub fn catalogue(s: &Stats) {
    metrics::gauge!(USERS).set(s.users as f64);
    metrics::gauge!(DEVICES).set(s.devices as f64);
    metrics::gauge!(FIRMWARE).set(s.firmware as f64);
    metrics::gauge!(STAGED).set(s.staged as f64);
    metrics::gauge!(BLOBS).set(s.blobs as f64);
    metrics::gauge!(BLOB_BYTES).set(s.blob_bytes as f64);
}

/// Endpoint label for requests with no matched route — everything the Connect
/// fallback serves. RPC paths are a bounded set and pass through; scanner noise
/// collapses into one series, which is what bounds label cardinality.
fn endpoint_label(path: &str) -> String {
    const RPC_PREFIX: &str = "/inex.saros.v1.";
    let ident = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric());
    match path
        .strip_prefix(RPC_PREFIX)
        .and_then(|r| r.split_once('/'))
    {
        Some((service, method)) if ident(service) && ident(method) => path.to_string(),
        _ => "other".to_string(),
    }
}

/// The `saros_http_*` trio is redescribed here because `axum-prometheus`
/// describes it while building the layer — before our recorder exists, so those
/// descriptions land in the facade's no-op and never reach a scrape.
fn describe() {
    use axum_prometheus::utils::{
        requests_duration_name, requests_pending_name, requests_total_name,
    };
    use metrics::Unit;

    metrics::describe_counter!(
        requests_total_name(),
        Unit::Count,
        "HTTP requests handled, by endpoint, method and status."
    );
    metrics::describe_histogram!(
        requests_duration_name(),
        Unit::Seconds,
        "HTTP request latency."
    );
    metrics::describe_gauge!(
        requests_pending_name(),
        Unit::Count,
        "HTTP requests currently in flight."
    );
    metrics::describe_counter!(EVENTS, Unit::Count, "Registry domain events by kind.");
    metrics::describe_counter!(
        RATE_LIMITED,
        Unit::Count,
        "Requests refused by the per-IP rate limiter, by bucket tier."
    );
    metrics::describe_counter!(
        MIRROR_OPS,
        Unit::Count,
        "S3/Tigris egress-mirror calls by operation and outcome."
    );
    metrics::describe_histogram!(
        MIRROR_DURATION,
        Unit::Seconds,
        "S3/Tigris egress-mirror round-trip latency."
    );
    metrics::describe_gauge!(
        BUILD_INFO,
        Unit::Count,
        "Always 1; carries the build version."
    );
    metrics::describe_gauge!(USERS, Unit::Count, "Registered accounts.");
    metrics::describe_gauge!(
        DEVICES,
        Unit::Count,
        "Catalogue devices with published firmware."
    );
    metrics::describe_gauge!(FIRMWARE, Unit::Count, "Published firmware versions.");
    metrics::describe_gauge!(STAGED, Unit::Count, "Firmware versions awaiting review.");
    metrics::describe_gauge!(
        BLOBS,
        Unit::Count,
        "Distinct blobs referenced by a manifest."
    );
    metrics::describe_gauge!(BLOB_BYTES, Unit::Bytes, "Total size of referenced blobs.");
}

#[cfg(test)]
mod tests {
    use super::endpoint_label;

    #[test]
    fn rpc_paths_survive_and_everything_else_collapses() {
        assert_eq!(
            endpoint_label("/inex.saros.v1.BlobService/Download"),
            "/inex.saros.v1.BlobService/Download"
        );

        for probe in [
            "/wp-login.php",
            "/inex.saros.v1.BlobService/Download/../etc",
            "/inex.saros.v1.BlobService/",
            "/other.pkg.v1.Service/Method",
            "/inex.saros.v1.Blob-Service/Download",
        ] {
            assert_eq!(endpoint_label(probe), "other", "{probe}");
        }
    }
}

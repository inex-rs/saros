//! Per-client-IP rate limiting: a strict bucket for the anonymous auth/login
//! ceremony starts and a generous global one for everything else. An axum
//! middleware applied in `serve()`, not [`crate::app`] — the router stays unthrottled
//! for embedding and tests.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use governor::clock::{Clock, DefaultClock};
use governor::{DefaultKeyedRateLimiter, Quota};

/// RPC method-path suffixes on the strict bucket — the unauthenticated
/// account/login starts a bot would hammer. Matched as a `Service/Method` suffix.
const STRICT_SUFFIXES: [&str; 3] = [
    "AuthService/BeginPasskey",
    "AuthService/BeginLogin",
    "AuthService/FinishPasskey",
];

/// Shared key when no client IP resolves — fail-closed to *limited*, not unlimited.
const UNRESOLVED_KEY: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

pub struct RateLimit {
    /// The anonymous ceremony starts — tight (bot-signup / brute surface).
    strict: Option<Arc<DefaultKeyedRateLimiter<IpAddr>>>,
    /// Everything else — generous.
    global: Option<Arc<DefaultKeyedRateLimiter<IpAddr>>>,
    clock: DefaultClock,
}

impl RateLimit {
    /// Build the limiter from the per-minute budgets; `0` on either disables that tier.
    pub fn new(global_per_min: u32, auth_per_min: u32) -> Arc<Self> {
        Arc::new(Self {
            strict: bucket(auth_per_min),
            global: bucket(global_per_min),
            clock: DefaultClock::default(),
        })
    }

    fn bucket_for(&self, path: &str) -> Option<&Arc<DefaultKeyedRateLimiter<IpAddr>>> {
        if STRICT_SUFFIXES.iter().any(|suffix| path.ends_with(suffix)) {
            self.strict.as_ref()
        } else {
            self.global.as_ref()
        }
    }

    /// Charge one request from `ip`; `Err(retry_after)` = over budget (→ `429`).
    pub fn check(&self, ip: IpAddr, path: &str) -> Result<(), Duration> {
        let Some(bucket) = self.bucket_for(path) else {
            return Ok(());
        };
        bucket
            .check_key(&ip)
            .map_err(|denied| denied.wait_time_from(self.clock.now()))
    }

    /// Drop buckets for caught-up IPs so the keyed map tracks the active IP set.
    pub fn prune(&self) {
        for bucket in [self.strict.as_ref(), self.global.as_ref()]
            .into_iter()
            .flatten()
        {
            bucket.retain_recent();
            bucket.shrink_to_fit();
        }
    }
}

/// A per-minute keyed bucket, or `None` when `per_min == 0` (tier disabled).
fn bucket(per_min: u32) -> Option<Arc<DefaultKeyedRateLimiter<IpAddr>>> {
    let quota = Quota::per_minute(NonZeroU32::new(per_min)?);
    Some(Arc::new(DefaultKeyedRateLimiter::keyed(quota)))
}

/// Resolve the client's IP, Fly-first: `Fly-Client-IP`, then the first
/// `X-Forwarded-For` hop, then the `ConnectInfo` peer (local dev). `None` if none.
pub fn client_ip(headers: &HeaderMap, peer: Option<SocketAddr>) -> Option<IpAddr> {
    if let Some(ip) = header_ip(headers, "fly-client-ip") {
        return Some(ip);
    }
    if let Some(forwarded) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok())
        && let Some(ip) = forwarded
            .split(',')
            .next()
            .and_then(|s| s.trim().parse().ok())
    {
        return Some(ip);
    }
    peer.map(|addr| addr.ip())
}

fn header_ip(headers: &HeaderMap, name: &str) -> Option<IpAddr> {
    headers.get(name)?.to_str().ok()?.trim().parse().ok()
}

/// axum middleware: charge each request against its per-IP bucket, returning
/// `429` (+ `Retry-After`) when over budget.
pub async fn enforce(
    State(limiter): State<Arc<RateLimit>>,
    request: Request,
    next: Next,
) -> Response {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0);
    let ip = client_ip(request.headers(), peer).unwrap_or(UNRESOLVED_KEY);
    // Scope the path borrow so `next.run` can move the request.
    let decision = limiter.check(ip, request.uri().path());
    match decision {
        Ok(()) => next.run(request).await,
        Err(retry_after) => too_many(retry_after),
    }
}

/// The `429` response, `Retry-After` floored to at least 1 second.
fn too_many(retry_after: Duration) -> Response {
    let seconds = retry_after.as_secs().max(1);
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(header::RETRY_AFTER, seconds.to_string())],
        "429 too many requests — slow down\n",
    )
        .into_response()
}

/// Periodically prune stale IP buckets, bounding memory to the active IP set.
pub fn spawn_prune(limiter: Arc<RateLimit>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(300));
        // interval fires immediately on the first tick — skip that one.
        tick.tick().await;
        loop {
            tick.tick().await;
            limiter.prune();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("ip")
    }

    #[test]
    fn allows_the_budget_then_limits_per_ip() {
        let rl = RateLimit::new(3, 0);
        let path = "/inex.saros.v1.BlobService/Download";
        let client = ip("203.0.113.7");

        for i in 0..3 {
            assert!(rl.check(client, path).is_ok(), "request {i} within budget");
        }
        let retry = rl.check(client, path).expect_err("over budget");
        assert!(retry > Duration::ZERO, "429 carries a wait time");

        assert!(
            rl.check(ip("203.0.113.8"), path).is_ok(),
            "a different IP is unaffected"
        );
    }

    #[test]
    fn strict_tier_covers_only_ceremony_starts() {
        let rl = RateLimit::new(0, 2);
        let client = ip("198.51.100.5");
        let begin = "/inex.saros.v1.AuthService/BeginPasskey";

        assert!(rl.check(client, begin).is_ok());
        assert!(rl.check(client, begin).is_ok());
        assert!(
            rl.check(client, begin).is_err(),
            "the 3rd ceremony start is over budget"
        );
        assert!(
            rl.check(client, "/inex.saros.v1.FirmwareService/WatchFirmware")
                .is_ok(),
            "the generous tier is off, so a normal RPC still flows"
        );
    }

    #[test]
    fn client_ip_resolution_is_fly_first() {
        let peer = "10.1.2.3:5555".parse::<SocketAddr>().unwrap();

        let mut headers = HeaderMap::new();
        headers.insert("fly-client-ip", "1.2.3.4".parse().unwrap());
        headers.insert("x-forwarded-for", "5.6.7.8, 9.9.9.9".parse().unwrap());
        assert_eq!(client_ip(&headers, Some(peer)), Some(ip("1.2.3.4")));

        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "5.6.7.8, 9.9.9.9".parse().unwrap());
        assert_eq!(client_ip(&headers, Some(peer)), Some(ip("5.6.7.8")));

        assert_eq!(
            client_ip(&HeaderMap::new(), Some(peer)),
            Some(ip("10.1.2.3"))
        );

        assert_eq!(client_ip(&HeaderMap::new(), None), None);
    }
}

//! End-to-end: the real `saros::app` router on an ephemeral port, driven by the
//! generated Connect clients — upload → publish (staged) → review → watch the
//! catalogue → download, the bearer/cookie auth gates, logout, and the plain
//! HTTP probes (`/healthz`, `/readyz`, `/version`).

use std::sync::Arc;

use connectrpc::ErrorCode;
use connectrpc::client::{CallOptions, ClientConfig, HttpClient};
use inex_protobufs::buffa::inex::saros::v1::{
    DownloadRequest, Firmware, FirmwareBlob, LogoutRequest, PublishFirmwareRequest,
    ReviewStagedFirmwareRequest, StatRequest, UploadRequest, WatchDevicesRequest,
    WatchFirmwareRequest, WatchStagedFirmwareRequest, WhoAmIRequest,
};
use inex_protobufs::connect::inex::saros::v1::{
    AuthServiceClient, BlobServiceClient, FirmwareServiceClient,
};
use saros::auth::{Auth, SESSION_COOKIE};
use saros::store::{Sha256Hex, Store};

const SERVICE_TOKEN: &str = "hunter2";
const DEVICE: &str = "pocket-debug";
const ORIGIN: &str = "http://localhost:5173";

struct Server {
    addr: std::net::SocketAddr,
    auth: Arc<Auth>,
    _dir: tempfile::TempDir,
}

async fn spawn_server() -> Server {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = Arc::new(
        saros::db::Db::open(dir.path().join("meta.db"))
            .await
            .expect("db"),
    );
    let auth = Arc::new(Auth::new(
        Some(SERVICE_TOKEN),
        vec!["boss".into()],
        db.clone(),
    ));
    let origin = url::Url::parse(ORIGIN).expect("origin");
    let passkeys = Arc::new(
        saros::passkey::Passkeys::new("localhost", &origin, true, db.clone()).expect("passkeys"),
    );
    let logins = Arc::new(saros::login::Logins::new(ORIGIN));
    let metrics = Arc::new(saros::metrics::Metrics::new(false));
    let store = Arc::new(Store::open(dir.path(), 1024 * 1024, db.clone(), None).expect("store"));
    let app = saros::app(
        store,
        auth.clone(),
        passkeys,
        logins,
        metrics,
        db,
        saros::WebConfig {
            origin: ORIGIN.into(),
            cookie_domain: None,
            cookie_secure: false,
        },
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    Server {
        addr,
        auth,
        _dir: dir,
    }
}

struct Clients {
    blob: BlobServiceClient<HttpClient>,
    fw: FirmwareServiceClient<HttpClient>,
    auth: AuthServiceClient<HttpClient>,
}

fn clients(addr: std::net::SocketAddr) -> Clients {
    let transport = HttpClient::plaintext();
    let config = ClientConfig::new(format!("http://{addr}").parse().expect("uri"));
    Clients {
        blob: BlobServiceClient::new(transport.clone(), config.clone()),
        fw: FirmwareServiceClient::new(transport.clone(), config.clone()),
        auth: AuthServiceClient::new(transport, config),
    }
}

fn bearer(token: &str) -> CallOptions {
    CallOptions::default().with_header(http::header::AUTHORIZATION, format!("Bearer {token}"))
}

fn cookie(token: &str) -> CallOptions {
    CallOptions::default().with_header(http::header::COOKIE, format!("{SESSION_COOKIE}={token}"))
}

fn manifest(version: &str, sha256: &str, size: u64) -> Firmware {
    Firmware {
        device_id: Some(DEVICE.into()),
        version: Some(version.into()),
        tags: vec!["e2e".into()],
        blobs: vec![FirmwareBlob {
            slot: Some(0),
            filename: Some(format!("{DEVICE}-v{version}.bin")),
            size_bytes: Some(size),
            sha256: Some(sha256.into()),
            ..Default::default()
        }],
        ..Default::default()
    }
}

fn publish_req(fw: Firmware) -> PublishFirmwareRequest {
    PublishFirmwareRequest {
        firmware: fw.into(),
        ..Default::default()
    }
}

fn review_req(version: &str, approve: bool) -> ReviewStagedFirmwareRequest {
    ReviewStagedFirmwareRequest {
        device_id: Some(DEVICE.into()),
        version: Some(version.into()),
        approve: Some(approve),
        ..Default::default()
    }
}

async fn upload(c: &Clients, opts: CallOptions, bytes: &[u8]) -> String {
    let up = c
        .blob
        .upload_with_options(
            UploadRequest {
                content: Some(bytes.to_vec()),
                ..Default::default()
            },
            opts,
        )
        .await
        .expect("upload")
        .into_owned();
    assert_eq!(up.size_bytes, Some(bytes.len() as u64));
    up.sha256.expect("sha256")
}

/// Every unwrap of a stream message is bounded, so a stalled watch fails the
/// test instead of hanging it.
async fn next<T>(fut: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(std::time::Duration::from_secs(10), fut)
        .await
        .expect("stream message timed out")
}

#[tokio::test]
async fn full_publish_review_fetch_flow() {
    let server = spawn_server().await;
    let c = clients(server.addr);
    let image = b"pocket firmware image bytes";

    // Blob RPCs need a signed-in caller.
    let denied = c
        .blob
        .upload(UploadRequest {
            content: Some(image.to_vec()),
            ..Default::default()
        })
        .await
        .expect_err("anonymous upload must fail");
    assert_eq!(denied.code, ErrorCode::Unauthenticated, "{denied}");

    // Upload is content-addressed and idempotent.
    let sha = upload(&c, bearer(SERVICE_TOKEN), image).await;
    assert_eq!(sha, Sha256Hex::digest_of(image).as_str());
    assert_eq!(upload(&c, bearer(SERVICE_TOKEN), image).await, sha);
    let stat = c
        .blob
        .stat_with_options(
            StatRequest {
                sha256: Some(sha.clone()),
                ..Default::default()
            },
            bearer(SERVICE_TOKEN),
        )
        .await
        .expect("stat")
        .into_owned();
    assert_eq!(stat.exists, Some(true));
    assert_eq!(stat.size_bytes, Some(image.len() as u64));

    // Publish: anonymous → Unauthenticated, an unknown token reads as anonymous.
    let req = || publish_req(manifest("0.2.0", &sha, image.len() as u64));
    let denied =
        c.fw.publish_firmware(req())
            .await
            .expect_err("no token must fail");
    assert_eq!(denied.code, ErrorCode::Unauthenticated, "{denied}");
    let denied =
        c.fw.publish_firmware_with_options(req(), bearer("wrong"))
            .await
            .expect_err("bad token must fail");
    assert_eq!(denied.code, ErrorCode::Unauthenticated, "{denied}");

    // Validation gates: never-uploaded blob / unknown device are FailedPrecondition.
    let missing = Sha256Hex::digest_of(b"never uploaded");
    let bogus =
        c.fw.publish_firmware_with_options(
            publish_req(manifest("9.9.9", missing.as_str(), 1)),
            bearer(SERVICE_TOKEN),
        )
        .await
        .expect_err("missing blob must fail");
    assert_eq!(bogus.code, ErrorCode::FailedPrecondition, "{bogus}");
    let mut unknown = manifest("9.9.9", &sha, image.len() as u64);
    unknown.device_id = Some("no-such-device".into());
    let bogus =
        c.fw.publish_firmware_with_options(publish_req(unknown), bearer(SERVICE_TOKEN))
            .await
            .expect_err("unknown device must fail");
    assert_eq!(bogus.code, ErrorCode::FailedPrecondition, "{bogus}");
    let bogus =
        c.fw.publish_firmware_with_options(
            publish_req(manifest("1.0-rc1", &sha, image.len() as u64)),
            bearer(SERVICE_TOKEN),
        )
        .await
        .expect_err("non-numeric version must fail");
    assert_eq!(bogus.code, ErrorCode::InvalidArgument, "{bogus}");

    // Everyone's publish stages; nothing is live until reviewed.
    let staged =
        c.fw.publish_firmware_with_options(req(), bearer(SERVICE_TOKEN))
            .await
            .expect("publish")
            .into_owned();
    let staged = staged.firmware.as_option().expect("staged manifest");
    assert_eq!(staged.version.as_deref(), Some("0.2.0"));

    let mut watch_staged =
        c.fw.watch_staged_firmware_with_options(
            WatchStagedFirmwareRequest::default(),
            bearer(SERVICE_TOKEN),
        )
        .await
        .expect("watch staged");
    let pending = next(watch_staged.message())
        .await
        .expect("staged snapshot")
        .expect("stream open")
        .to_owned_message();
    assert_eq!(pending.staged.len(), 1);
    assert_eq!(pending.staged[0].submitted_by.as_deref(), Some("service"));

    let mut watch_fw =
        c.fw.watch_firmware(WatchFirmwareRequest {
            device_id: Some(DEVICE.into()),
            ..Default::default()
        })
        .await
        .expect("watch firmware");
    let snapshot = next(watch_fw.message())
        .await
        .expect("firmware snapshot")
        .expect("stream open")
        .to_owned_message();
    assert!(snapshot.firmware.is_empty(), "staged must not be live");

    // Approve → live; the open watches see the change.
    let approved =
        c.fw.review_staged_firmware_with_options(review_req("0.2.0", true), bearer(SERVICE_TOKEN))
            .await
            .expect("approve")
            .into_owned();
    assert_eq!(
        approved
            .firmware
            .as_option()
            .expect("approved manifest")
            .version
            .as_deref(),
        Some("0.2.0")
    );
    let added = next(watch_fw.message())
        .await
        .expect("firmware delta")
        .expect("stream open")
        .to_owned_message();
    assert_eq!(added.firmware.len(), 1);
    assert_eq!(added.firmware[0].version.as_deref(), Some("0.2.0"));
    let pending = next(watch_staged.message())
        .await
        .expect("staged resend")
        .expect("stream open")
        .to_owned_message();
    assert!(pending.staged.is_empty(), "approved leaves staging");

    // Versions are immutable once live.
    let dup =
        c.fw.publish_firmware_with_options(req(), bearer(SERVICE_TOKEN))
            .await
            .expect_err("re-publish must fail");
    assert_eq!(dup.code, ErrorCode::AlreadyExists, "{dup}");

    // A second version, rejected: never goes live.
    let image2 = b"pocket firmware image bytes v2";
    let sha2 = upload(&c, bearer(SERVICE_TOKEN), image2).await;
    c.fw.publish_firmware_with_options(
        publish_req(manifest("0.10.0", &sha2, image2.len() as u64)),
        bearer(SERVICE_TOKEN),
    )
    .await
    .expect("publish v2");
    c.fw.review_staged_firmware_with_options(review_req("0.10.0", false), bearer(SERVICE_TOKEN))
        .await
        .expect("reject");
    let gone =
        c.fw.review_staged_firmware_with_options(review_req("0.10.0", true), bearer(SERVICE_TOKEN))
            .await
            .expect_err("rejected entry is gone");
    assert_eq!(gone.code, ErrorCode::NotFound, "{gone}");

    // Catalogue views: a fresh watch's first frame is the full set.
    let mut devices =
        c.fw.watch_devices(WatchDevicesRequest::default())
            .await
            .expect("watch devices");
    let devices = next(devices.message())
        .await
        .expect("devices snapshot")
        .expect("stream open")
        .to_owned_message();
    assert_eq!(devices.devices.len(), 1);
    assert_eq!(devices.devices[0].id.as_deref(), Some(DEVICE));
    assert_eq!(devices.devices[0].firmware_count, Some(1));
    let mut all =
        c.fw.watch_firmware(WatchFirmwareRequest::default())
            .await
            .expect("watch all firmware");
    let all = next(all.message())
        .await
        .expect("firmware snapshot")
        .expect("stream open")
        .to_owned_message();
    let versions: Vec<_> = all
        .firmware
        .iter()
        .filter_map(|f| f.version.as_deref())
        .collect();
    assert_eq!(versions, ["0.2.0"]);

    // Bytes come back intact (no mirror → inline content).
    let down = c
        .blob
        .download_with_options(
            DownloadRequest {
                sha256: Some(sha.clone()),
                ..Default::default()
            },
            bearer(SERVICE_TOKEN),
        )
        .await
        .expect("download")
        .into_owned();
    assert_eq!(down.content.as_deref(), Some(image.as_slice()));
    let missing_dl = c
        .blob
        .download_with_options(
            DownloadRequest {
                sha256: Some(missing.to_string()),
                ..Default::default()
            },
            bearer(SERVICE_TOKEN),
        )
        .await
        .expect_err("unknown blob");
    assert_eq!(missing_dl.code, ErrorCode::NotFound, "{missing_dl}");

    // Plain HTTP probes.
    assert_eq!(raw_get(server.addr, "/healthz").await, b"ok\n");
    assert_eq!(raw_get(server.addr, "/readyz").await, b"ready\n");
    let v = raw_get(server.addr, "/version").await;
    let v: serde_json::Value = serde_json::from_slice(&v).expect("version json");
    assert_eq!(v["name"], "saros");
}

/// The web's credential: the httpOnly session cookie authenticates the same
/// RPCs a bearer does, non-admins can stage but not review, and logout
/// revokes the session and clears the cookie.
#[tokio::test]
async fn cookie_session_auth() {
    let server = spawn_server().await;
    let c = clients(server.addr);

    let anon = c
        .auth
        .who_am_i(WhoAmIRequest::default())
        .await
        .expect("whoami anonymous")
        .into_owned();
    assert_eq!(anon.username.as_deref(), Some(""));
    assert_eq!(anon.admin, Some(false));

    let alice = server.auth.mint_session("alice").await.expect("session");
    let me = c
        .auth
        .who_am_i_with_options(WhoAmIRequest::default(), cookie(&alice))
        .await
        .expect("whoami cookie")
        .into_owned();
    assert_eq!(me.username.as_deref(), Some("alice"));
    assert_eq!(me.admin, Some(false));

    let boss = server
        .auth
        .mint_session("boss")
        .await
        .expect("admin session");
    let me = c
        .auth
        .who_am_i_with_options(WhoAmIRequest::default(), cookie(&boss))
        .await
        .expect("whoami admin cookie")
        .into_owned();
    assert_eq!(me.admin, Some(true));

    // A signed-in member submits via cookie; review is admin-only.
    let image = b"alice's build";
    let sha = upload(&c, cookie(&alice), image).await;
    c.fw.publish_firmware_with_options(
        publish_req(manifest("1.0.0", &sha, image.len() as u64)),
        cookie(&alice),
    )
    .await
    .expect("member publish stages");
    let denied =
        c.fw.review_staged_firmware_with_options(review_req("1.0.0", true), cookie(&alice))
            .await
            .expect_err("member cannot review");
    assert_eq!(denied.code, ErrorCode::PermissionDenied, "{denied}");
    // A streaming error may frame at the call or on the first message.
    let denied = match c
        .fw
        .watch_staged_firmware_with_options(WatchStagedFirmwareRequest::default(), cookie(&alice))
        .await
    {
        Err(e) => e,
        Ok(mut s) => next(s.message())
            .await
            .expect_err("member cannot list staged"),
    };
    assert_eq!(denied.code, ErrorCode::PermissionDenied, "{denied}");
    c.fw.review_staged_firmware_with_options(review_req("1.0.0", true), cookie(&boss))
        .await
        .expect("admin approves via cookie");

    // Logout via cookie: Set-Cookie clears it, and the session is dead.
    let out = c
        .auth
        .logout_with_options(LogoutRequest::default(), cookie(&alice))
        .await
        .expect("logout");
    let set_cookie = out
        .headers()
        .get(http::header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .expect("Set-Cookie on logout")
        .to_string();
    assert!(
        set_cookie.starts_with(&format!("{SESSION_COOKIE}=;")) && set_cookie.contains("Max-Age=0"),
        "{set_cookie}"
    );
    let after = c
        .auth
        .who_am_i_with_options(WhoAmIRequest::default(), cookie(&alice))
        .await
        .expect("whoami after logout")
        .into_owned();
    assert_eq!(after.username.as_deref(), Some(""));
    let denied = c
        .blob
        .upload_with_options(
            UploadRequest {
                content: Some(b"x".to_vec()),
                ..Default::default()
            },
            cookie(&alice),
        )
        .await
        .expect_err("revoked cookie must fail");
    assert_eq!(denied.code, ErrorCode::Unauthenticated, "{denied}");
}

/// Minimal HTTP/1.1 GET over a raw TcpStream — keeps the probe checks
/// dependency-free (no reqwest).
async fn raw_get(addr: std::net::SocketAddr, path: &str) -> Vec<u8> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let req = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await.expect("write");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.expect("read");
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("header end")
        + 4;
    let head = String::from_utf8_lossy(&raw[..split]);
    assert!(
        head.starts_with("HTTP/1.1 200"),
        "unexpected response: {head}"
    );
    raw[split..].to_vec()
}

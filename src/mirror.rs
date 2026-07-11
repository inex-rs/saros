//! Egress mirror: a content-addressed, deduplicated copy of published blobs in
//! object storage (S3/Tigris) — serve-only, never a source of truth or listed.

use std::time::Duration;

use object_store::aws::{AmazonS3, AmazonS3Builder};
use object_store::signer::Signer as _;
use object_store::{ObjectStoreExt as _, PutPayload, path::Path as ObjPath};

const URL_TTL: Duration = Duration::from_secs(15 * 60);

#[derive(Debug, Clone)]
pub struct S3Config {
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    pub access_key_id: String,
    pub secret_access_key: String,
}

impl S3Config {
    pub fn from_env() -> Option<Self> {
        let get = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        Some(Self {
            endpoint: get("SAROS_S3_ENDPOINT")?,
            bucket: get("SAROS_S3_BUCKET")?,
            region: get("SAROS_S3_REGION").unwrap_or_else(|| "auto".into()),
            access_key_id: get("SAROS_S3_ACCESS_KEY_ID")?,
            secret_access_key: get("SAROS_S3_SECRET_ACCESS_KEY")?,
        })
    }
}

/// S3/Tigris egress mirror. `public_base` set ⇒ public/CDN URLs; unset ⇒ presigned GETs.
pub struct Mirror {
    s3: AmazonS3,
    public_base: Option<String>,
}

impl Mirror {
    pub fn new(cfg: &S3Config, public_base: Option<String>) -> anyhow::Result<Self> {
        let s3 = AmazonS3Builder::new()
            .with_endpoint(&cfg.endpoint)
            .with_bucket_name(&cfg.bucket)
            .with_region(&cfg.region)
            .with_access_key_id(&cfg.access_key_id)
            .with_secret_access_key(&cfg.secret_access_key)
            .with_virtual_hosted_style_request(false)
            .with_allow_http(cfg.endpoint.starts_with("http://"))
            // Bound timeouts: the mirror is an egress optimization the caller always
            // falls back off, so a slow/flapping one must not stall a download handler.
            .with_client_options(
                object_store::ClientOptions::new()
                    .with_timeout(Duration::from_secs(30))
                    .with_connect_timeout(Duration::from_secs(5)),
            )
            .with_retry(object_store::RetryConfig {
                max_retries: 2,
                retry_timeout: Duration::from_secs(20),
                ..Default::default()
            })
            .build()?;
        Ok(Self {
            s3,
            public_base: public_base.filter(|s| !s.is_empty()),
        })
    }

    fn key(sha: &str) -> ObjPath {
        ObjPath::from(format!("blobs/{sha}"))
    }

    /// Is the blob already mirrored? A single keyed HEAD — never a list.
    pub async fn has(&self, sha: &str) -> std::io::Result<bool> {
        match self.s3.head(&Self::key(sha)).await {
            Ok(_) => Ok(true),
            Err(object_store::Error::NotFound { .. }) => Ok(false),
            Err(e) => Err(io(e)),
        }
    }

    pub async fn put_if_absent(&self, sha: &str, content: &[u8]) -> std::io::Result<()> {
        if self.has(sha).await? {
            return Ok(());
        }
        self.s3
            .put(&Self::key(sha), PutPayload::from(content.to_vec()))
            .await
            .map_err(io)?;
        Ok(())
    }

    pub async fn url(&self, sha: &str) -> std::io::Result<String> {
        match &self.public_base {
            Some(base) => Ok(format!("{}/blobs/{sha}", base.trim_end_matches('/'))),
            None => self
                .s3
                .signed_url(http::Method::GET, &Self::key(sha), URL_TTL)
                .await
                .map(|u| u.to_string())
                .map_err(io),
        }
    }
}

fn io(e: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

//! `BlobService`: content-addressed blob upload/download.

use super::*;

use crate::store::Sha256Hex;

async fn record_download(db: &Arc<Db>, sha: &str) {
    if let Err(e) = db.stats().bump_download(sha).await {
        tracing::error!(error = %e, "record download failed");
    }
}

pub struct ConnectBlobService {
    store: Arc<Store>,
    auth: Arc<Auth>,
    db: Arc<Db>,
    events: Arc<Events>,
}

impl ConnectBlobService {
    pub fn new(store: Arc<Store>, auth: Arc<Auth>, db: Arc<Db>, events: Arc<Events>) -> Self {
        Self {
            store,
            auth,
            db,
            events,
        }
    }
}

#[allow(refining_impl_trait_internal, refining_impl_trait_reachable)]
impl BlobService for ConnectBlobService {
    async fn upload(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::UploadRequest>,
    ) -> ServiceResult<pb::UploadResponse> {
        require_signed_in(&caller_of(&self.auth, &ctx).await, "upload blobs")?;
        let content = request.to_owned_message().content.unwrap_or_default();
        let size_bytes = content.len() as u64;
        let sha256 = self.store.put_blob(&content).await?;
        self.events.upload().await;
        Response::ok(pb::UploadResponse {
            sha256: Some(sha256.into()),
            size_bytes: Some(size_bytes),
            ..Default::default()
        })
    }

    async fn stat(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::StatRequest>,
    ) -> ServiceResult<pb::StatResponse> {
        require_signed_in(&caller_of(&self.auth, &ctx).await, "stat blobs")?;
        let sha256 = request.to_owned_message().sha256.unwrap_or_default();
        let sha = Sha256Hex::try_from(sha256.as_str())?;
        let size = self.store.stat_blob(&sha).await?;
        Response::ok(pb::StatResponse {
            exists: Some(size.is_some()),
            size_bytes: size,
            ..Default::default()
        })
    }

    async fn download(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::DownloadRequest>,
    ) -> ServiceResult<pb::DownloadResponse> {
        require_signed_in(&caller_of(&self.auth, &ctx).await, "download blobs")?;
        let sha256 = request.to_owned_message().sha256.unwrap_or_default();
        let sha = Sha256Hex::try_from(sha256.as_str())?;
        let resp = match self
            .store
            .download(&sha)
            .await?
            .ok_or_else(|| ConnectError::not_found(format!("blob not found: {sha256}")))?
        {
            crate::store::DownloadOutcome::Url(url) => pb::DownloadResponse {
                url: Some(url),
                ..Default::default()
            },
            crate::store::DownloadOutcome::Bytes(content) => pb::DownloadResponse {
                content: Some(content),
                ..Default::default()
            },
        };
        self.events.download().await;
        record_download(&self.db, &sha256).await;
        Response::ok(resp)
    }
}

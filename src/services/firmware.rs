//! `FirmwareService`: catalogue, publish/stage/review, watches, admin stats.

use super::*;

async fn record_submission(db: &Arc<Db>, username: &str, device: &str, version: &str) {
    if let Err(e) = db.submissions().record(username, device, version).await {
        tracing::error!(error = %e, "record submission failed");
    }
}

async fn mark_submission(
    db: &Arc<Db>,
    username: &str,
    device: &str,
    version: &str,
    status: pb::SubmissionStatus,
) {
    if let Err(e) = db
        .submissions()
        .mark(username, device, version, status as u8)
        .await
    {
        tracing::error!(error = %e, "mark submission failed");
    }
}

pub struct ConnectFirmwareService {
    store: Arc<Store>,
    auth: Arc<Auth>,
    /// For ServerStats snapshots; counter bumps go through [`Events`].
    metrics: Arc<Metrics>,
    /// Metadata store for the metrics series (`Store` keeps its own `Db` private).
    db: Arc<Db>,
    events: Arc<Events>,
}

impl ConnectFirmwareService {
    pub fn new(
        store: Arc<Store>,
        auth: Arc<Auth>,
        metrics: Arc<Metrics>,
        db: Arc<Db>,
        events: Arc<Events>,
    ) -> Self {
        Self {
            store,
            auth,
            metrics,
            db,
            events,
        }
    }
}

fn metrics_sample(r: MetricsSampleRecord) -> pb::MetricsSample {
    pb::MetricsSample {
        at: ts(r.at),
        users: Some(r.users),
        devices: Some(r.devices),
        firmware: Some(r.firmware),
        downloads: Some(r.downloads),
        uploads: Some(r.uploads),
        submissions: Some(r.submissions),
        sign_ins: Some(r.sign_ins),
        ..Default::default()
    }
}
#[allow(refining_impl_trait_internal, refining_impl_trait_reachable)]
impl FirmwareService for ConnectFirmwareService {
    async fn watch_devices(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::WatchDevicesRequest>,
    ) -> ServiceResult<ServiceStream<pb::WatchDevicesResponse>> {
        // Full catalogue first, then only changed/new devices; client merges by id.
        let rx = self.store.subscribe();
        Response::stream_ok(futures::stream::unfold(
            (self.store.clone(), rx, HashMap::<String, u32>::new(), true),
            |(store, mut rx, mut sent, first)| async move {
                loop {
                    if !first {
                        rx.changed().await.ok()?;
                    }
                    let mut changed = Vec::new();
                    for dev in store.devices() {
                        let count = dev.firmware_count.unwrap_or(0);
                        if sent.insert(dev.id.clone().unwrap_or_default(), count) != Some(count) {
                            changed.push(dev);
                        }
                    }
                    // Always emit the first (full) snapshot; after that skip a spurious wake with no change.
                    if first || !changed.is_empty() {
                        let resp = pb::WatchDevicesResponse {
                            devices: changed,
                            ..Default::default()
                        };
                        return Some((Ok(resp), (store, rx, sent, false)));
                    }
                }
            },
        ))
    }

    async fn watch_firmware(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, pb::WatchFirmwareRequest>,
    ) -> ServiceResult<ServiceStream<pb::WatchFirmwareResponse>> {
        let device = request
            .to_owned_message()
            .device_id
            .filter(|d| !d.is_empty());
        // Full set first, then only new versions (firmware is immutable) — merge by key.
        let rx = self.store.subscribe();
        Response::stream_ok(futures::stream::unfold(
            (
                self.store.clone(),
                rx,
                device,
                HashSet::<(String, String)>::new(),
                true,
            ),
            |(store, mut rx, device, mut sent, first)| async move {
                loop {
                    if !first {
                        rx.changed().await.ok()?;
                    }
                    let mut additions = Vec::new();
                    for fw in store.list(device.as_deref()).await {
                        let key = (
                            fw.device_id.clone().unwrap_or_default(),
                            fw.version.clone().unwrap_or_default(),
                        );
                        if sent.insert(key) {
                            additions.push(fw);
                        }
                    }
                    // Always emit the first (full) snapshot; after that skip a spurious wake that added nothing.
                    if first || !additions.is_empty() {
                        let resp = pb::WatchFirmwareResponse {
                            firmware: additions,
                            ..Default::default()
                        };
                        return Some((Ok(resp), (store, rx, device, sent, false)));
                    }
                }
            },
        ))
    }

    async fn publish_firmware(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::PublishFirmwareRequest>,
    ) -> ServiceResult<pb::PublishFirmwareResponse> {
        let caller = caller_of(&self.auth, &ctx).await;
        require_signed_in(&caller, "publish firmware")?;
        let fw = request
            .to_owned_message()
            .firmware
            .take()
            .ok_or_else(|| ConnectError::invalid_argument("firmware manifest required"))?;
        // One path for everyone: staged as pending for admin review — nothing goes straight live.
        let staged = self.store.stage(fw, caller.username()).await?;
        self.events
            .submitted(
                caller.username(),
                staged.device_id.as_deref().unwrap_or(""),
                staged.version.as_deref().unwrap_or(""),
            )
            .await;
        record_submission(
            &self.db,
            caller.username(),
            staged.device_id.as_deref().unwrap_or(""),
            staged.version.as_deref().unwrap_or(""),
        )
        .await;
        Response::ok(pb::PublishFirmwareResponse {
            firmware: staged.into(),
            ..Default::default()
        })
    }

    async fn watch_staged_firmware(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, pb::WatchStagedFirmwareRequest>,
    ) -> ServiceResult<ServiceStream<pb::WatchStagedFirmwareResponse>> {
        // Reject up front so the error frames before the first stream message.
        require_admin(
            &caller_of(&self.auth, &ctx).await,
            "listing staged firmware",
        )?;
        // Re-sent whole on every change: items vanish on review, which a delta feed couldn't express.
        let store = self.store.clone();
        resend_stream(self.store.subscribe(), move || {
            let store = store.clone();
            Box::pin(async move {
                Some(pb::WatchStagedFirmwareResponse {
                    staged: store.staged(),
                    ..Default::default()
                })
            })
        })
    }

    async fn review_staged_firmware(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::ReviewStagedFirmwareRequest>,
    ) -> ServiceResult<pb::ReviewStagedFirmwareResponse> {
        let caller = caller_of(&self.auth, &ctx).await;
        require_admin(&caller, "reviewing staged firmware")?;
        let req = request.to_owned_message();
        let (device_id, version) = (
            req.device_id.as_deref().unwrap_or(""),
            req.version.as_deref().unwrap_or(""),
        );
        let approved = req.approve.unwrap_or(false);
        // Capture the submitter before review — the staged entry vanishes on approve/reject.
        let submitter = self.store.staged_submitter(device_id, version);
        let firmware = if approved {
            Some(self.store.approve(device_id, version).await?)
        } else {
            self.store.reject(device_id, version).await?;
            None
        };
        self.events
            .reviewed(
                caller.username(),
                &format!("{device_id}/{version}"),
                approved,
            )
            .await;
        if approved {
            let link = format!("/saros/{device_id}/{version}");
            if let Some(submitter) = &submitter {
                notify(
                    &self.db,
                    submitter,
                    pb::NotificationKind::SubmissionApproved,
                    "Firmware approved",
                    &format!("{device_id} {version} is now live"),
                    &link,
                )
                .await;
            }
            if let Ok(followers) = self.db.notifications().followers(device_id).await {
                let detail = format!("{device_id} {version} was published");
                for follower in followers {
                    if submitter.as_deref() == Some(follower.as_str()) {
                        continue; // already notified as the submitter
                    }
                    notify(
                        &self.db,
                        &follower,
                        pb::NotificationKind::NewFirmware,
                        "New firmware",
                        &detail,
                        &link,
                    )
                    .await;
                }
            }
        } else if let Some(submitter) = &submitter {
            notify(
                &self.db,
                submitter,
                pb::NotificationKind::SubmissionRejected,
                "Firmware not accepted",
                &format!("{device_id} {version} wasn't approved"),
                "/account",
            )
            .await;
        }
        if let Some(submitter) = &submitter {
            let status = if approved {
                pb::SubmissionStatus::Approved
            } else {
                pb::SubmissionStatus::Rejected
            };
            mark_submission(&self.db, submitter, device_id, version, status).await;
        }
        Response::ok(pb::ReviewStagedFirmwareResponse {
            firmware: firmware.map(Into::into).unwrap_or_default(),
            ..Default::default()
        })
    }

    async fn watch_server_stats(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, pb::WatchServerStatsRequest>,
    ) -> ServiceResult<ServiceStream<pb::WatchServerStatsResponse>> {
        require_admin(&caller_of(&self.auth, &ctx).await, "server stats")?;
        // tokio's first interval.tick() fires immediately, so stats emit instantly, then every ~2s; infinite (client aborts).
        let interval = tokio::time::interval(std::time::Duration::from_secs(2));
        Response::stream_ok(futures::stream::unfold(
            (
                self.store.clone(),
                self.metrics.clone(),
                self.db.clone(),
                interval,
                0u64,
                Vec::new(),
            ),
            |(store, metrics, db, mut interval, tick, mut history)| async move {
                interval.tick().await;
                let s = store.stats().await.ok()?;
                let m = metrics.snapshot();
                // Trend series changes at most hourly, so re-read it only every ~60s (30 ticks), caching between.
                if tick.is_multiple_of(30) {
                    history = db
                        .stats()
                        .history()
                        .await
                        .map(|h| h.into_iter().map(metrics_sample).collect())
                        .unwrap_or_default();
                }
                let resp = pb::WatchServerStatsResponse {
                    users: Some(s.users),
                    devices: Some(s.devices),
                    firmware: Some(s.firmware),
                    staged: Some(s.staged),
                    blobs: Some(s.blobs),
                    blob_bytes: Some(s.blob_bytes),
                    uptime_seconds: Some(m.uptime_seconds),
                    downloads: Some(m.downloads),
                    uploads: Some(m.uploads),
                    submissions: Some(m.submissions),
                    reviews: Some(m.reviews),
                    sign_ins: Some(m.sign_ins),
                    mirror_configured: Some(m.mirror_configured),
                    history: history.clone(),
                    ..Default::default()
                };
                Some((
                    Ok(resp),
                    (store, metrics, db, interval, tick.wrapping_add(1), history),
                ))
            },
        ))
    }

    async fn get_metrics_history(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, pb::GetMetricsHistoryRequest>,
    ) -> ServiceResult<pb::GetMetricsHistoryResponse> {
        require_admin(&caller_of(&self.auth, &ctx).await, "server metrics history")?;
        let history = self.db.stats().history().await?;
        Response::ok(pb::GetMetricsHistoryResponse {
            samples: history.into_iter().map(metrics_sample).collect(),
            ..Default::default()
        })
    }

    async fn watch_audit_log(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::WatchAuditLogRequest>,
    ) -> ServiceResult<ServiceStream<pb::WatchAuditLogResponse>> {
        require_admin(&caller_of(&self.auth, &ctx).await, "reading the audit log")?;
        let req = request.to_owned_message();
        // 0 → default; clamp the ceiling so a huge limit can't pin memory.
        let limit = match req.limit.unwrap_or(0) {
            0 => 200,
            n => (n as usize).min(1000),
        };
        let category = req
            .category
            .and_then(|c| c.as_known())
            .filter(|c| *c != pb::AuditCategory::Unspecified);
        let actor = req.actor.filter(|a| !a.is_empty());
        audit_stream(self.db.clone(), limit, actor, category, |entries| {
            pb::WatchAuditLogResponse {
                entries,
                ..Default::default()
            }
        })
    }

    async fn list_audit_log(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::ListAuditLogRequest>,
    ) -> ServiceResult<pb::ListAuditLogResponse> {
        require_admin(&caller_of(&self.auth, &ctx).await, "reading the audit log")?;
        let req = request.to_owned_message();
        let limit = match req.limit.unwrap_or(0) {
            0 => 100,
            n => (n as usize).min(1000),
        };
        let before = req.before_cursor.unwrap_or(0);
        let actor = req.actor.filter(|a| !a.is_empty());
        let category = req
            .category
            .and_then(|c| c.as_known())
            .filter(|c| *c != pb::AuditCategory::Unspecified);
        // Actor filter goes to the store; category is applied here. The cursor
        // advances across the filtered span, so paging past it works.
        let (page, next_cursor) = self
            .db
            .audit()
            .page(before, limit, actor.as_deref())
            .await?;
        let entries = page
            .into_iter()
            .map(|(_, r)| audit_entry(r))
            .filter(|e| audit_matches(e, None, category))
            .collect();
        Response::ok(pb::ListAuditLogResponse {
            entries,
            next_cursor: Some(next_cursor),
            ..Default::default()
        })
    }

    async fn follow_device(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::FollowDeviceRequest>,
    ) -> ServiceResult<pb::FollowDeviceResponse> {
        let caller = caller_of(&self.auth, &ctx).await;
        require_signed_in(&caller, "follow a device")?;
        let req = request.to_owned_message();
        let device_id = req.device_id.unwrap_or_default();
        let follow = req.follow.unwrap_or(false);
        // Only catalogue devices can be followed — bounds the follow set to the
        // fixed catalogue, not attacker-chosen keys. Unfollowing is always allowed.
        if follow && inex_devices::by_id(&device_id).is_none() {
            return Err(ConnectError::not_found(format!(
                "unknown device: {device_id}"
            )));
        }
        self.db
            .notifications()
            .set_follow(caller.username(), &device_id, follow)
            .await?;
        Response::ok(pb::FollowDeviceResponse {
            following: Some(follow),
            ..Default::default()
        })
    }

    async fn list_follows(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, pb::ListFollowsRequest>,
    ) -> ServiceResult<pb::ListFollowsResponse> {
        let caller = caller_of(&self.auth, &ctx).await;
        require_signed_in(&caller, "list your follows")?;
        let device_ids = self
            .db
            .notifications()
            .follows_of(caller.username())
            .await?;
        Response::ok(pb::ListFollowsResponse {
            device_ids,
            ..Default::default()
        })
    }

    async fn watch_my_submissions(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, pb::WatchMySubmissionsRequest>,
    ) -> ServiceResult<ServiceStream<pb::WatchMySubmissionsResponse>> {
        let caller = caller_of(&self.auth, &ctx).await;
        require_signed_in(&caller, "read your submissions")?;
        let username = caller.username().to_string();
        let db = self.db.clone();
        resend_stream(self.db.subscribe(Topic::Submissions), move || {
            let db = db.clone();
            let username = username.clone();
            Box::pin(async move {
                let mut list = db.submissions().list(&username).await.ok()?;
                list.sort_by_key(|s| std::cmp::Reverse(s.submitted_at));
                Some(pb::WatchMySubmissionsResponse {
                    submissions: list.into_iter().map(submission).collect(),
                    ..Default::default()
                })
            })
        })
    }
}

//! Connect handler impls for `inex.saros.v1` — thin RPC shells over [`Store`];
//! all rules live in the store so this layer stays translation-only.

mod auth;
mod blob;
mod firmware;

pub use auth::ConnectAuthService;
pub use blob::ConnectBlobService;
pub use firmware::ConnectFirmwareService;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use connectrpc::{
    ConnectError, RequestContext, Response, ServiceRequest, ServiceResult, ServiceStream,
};
use inex_protobufs::buffa::inex::saros::v1 as pb;
use inex_protobufs::buffa_types::google::protobuf::Timestamp;
use inex_protobufs::connect::inex::saros::v1::{AuthService, BlobService, FirmwareService};

use crate::auth::{Auth, Caller};
use crate::db::{Db, DbError, MetricsSampleRecord, Topic};
use crate::events::Events;
use crate::login::Approve;
use crate::metrics::Metrics;
use crate::passkey::{PasskeyError, Passkeys};
use crate::store::{Store, StoreError};

fn ts(secs: i64) -> inex_protobufs::buffa_rt::MessageField<Timestamp> {
    Timestamp {
        seconds: secs,
        ..Default::default()
    }
    .into()
}

/// The caller's credential as a `Bearer <token>` string: the `Authorization`
/// header, else the httpOnly session cookie adapted to the same shape.
fn request_token(ctx: &RequestContext) -> Option<String> {
    if let Some(auth) = ctx
        .header(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        return Some(auth.to_string());
    }
    ctx.header(http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(crate::auth::cookie_session_token)
        .map(|tok| format!("Bearer {tok}"))
}

async fn caller_of(auth: &Auth, ctx: &RequestContext) -> Caller {
    auth.caller(request_token(ctx).as_deref()).await
}

fn require_signed_in(caller: &Caller, what: &str) -> Result<(), ConnectError> {
    if caller.signed_in() {
        Ok(())
    } else {
        Err(ConnectError::unauthenticated(format!(
            "sign in to {what} (Authorization: Bearer <token>)"
        )))
    }
}

fn require_admin(caller: &Caller, what: &str) -> Result<(), ConnectError> {
    require_signed_in(caller, what)?;
    if caller.admin() {
        Ok(())
    } else {
        Err(ConnectError::permission_denied(format!(
            "{what} is admin-only"
        )))
    }
}

impl From<StoreError> for ConnectError {
    fn from(e: StoreError) -> Self {
        let msg = e.to_string();
        match e {
            StoreError::InvalidArgument(_) => ConnectError::invalid_argument(msg),
            StoreError::NotFound(..) => ConnectError::not_found(msg),
            StoreError::AlreadyExists(..) => ConnectError::already_exists(msg),
            StoreError::UnknownDevice(..) => ConnectError::failed_precondition(msg),
            StoreError::MissingBlob { .. } => ConnectError::failed_precondition(msg),
            StoreError::Quota(_) => ConnectError::resource_exhausted(msg),
            // Generic message so no io/db/decode internals leak; log the detail.
            StoreError::Io(_) | StoreError::Db(_) | StoreError::Decode(_) => {
                tracing::error!(error = %msg, "store failure");
                ConnectError::internal("internal error")
            }
        }
    }
}
/// Kept exhaustive so a new proto action fails to compile here rather than
/// silently reading as `Unspecified`.
fn wire_action(action: u8) -> pb::AuditAction {
    use pb::AuditAction as A;
    match action as i32 {
        x if x == A::FirmwareSubmitted as i32 => A::FirmwareSubmitted,
        x if x == A::FirmwareApproved as i32 => A::FirmwareApproved,
        x if x == A::FirmwareRejected as i32 => A::FirmwareRejected,
        x if x == A::AccountRegistered as i32 => A::AccountRegistered,
        x if x == A::SignedIn as i32 => A::SignedIn,
        x if x == A::TokenCreated as i32 => A::TokenCreated,
        x if x == A::SessionRevoked as i32 => A::SessionRevoked,
        x if x == A::CredentialAdded as i32 => A::CredentialAdded,
        x if x == A::CredentialRemoved as i32 => A::CredentialRemoved,
        x if x == A::EmailChanged as i32 => A::EmailChanged,
        _ => A::Unspecified,
    }
}

fn wire_category(action: pb::AuditAction) -> pb::AuditCategory {
    use pb::AuditAction as A;
    use pb::AuditCategory as C;
    match action {
        A::AccountRegistered
        | A::SignedIn
        | A::TokenCreated
        | A::SessionRevoked
        | A::CredentialAdded
        | A::CredentialRemoved
        | A::EmailChanged => C::Security,
        A::FirmwareSubmitted | A::FirmwareApproved | A::FirmwareRejected => C::Moderation,
        A::Unspecified => C::Routine,
    }
}

fn audit_entry(r: crate::db::AuditRecord) -> pb::AuditEntry {
    let action = wire_action(r.action);
    pb::AuditEntry {
        at: ts(r.at),
        actor: Some(r.actor),
        action: Some(action.into()),
        target: Some(r.target),
        category: Some(wire_category(action).into()),
        ..Default::default()
    }
}

fn audit_matches(
    e: &pb::AuditEntry,
    actor: Option<&str>,
    category: Option<pb::AuditCategory>,
) -> bool {
    actor.is_none_or(|a| e.actor.as_deref() == Some(a))
        && category.is_none_or(|c| e.category.and_then(|k| k.as_known()) == Some(c))
}
/// Watch stream: emit `build()` now, then re-emit the whole set on every change;
/// `build` → `None` (read error) or a dropped sender ends it cleanly. `build`
/// returns a boxed future so the (async) db reads run per emission.
fn resend_stream<T, F>(
    rx: tokio::sync::watch::Receiver<u64>,
    build: F,
) -> ServiceResult<ServiceStream<T>>
where
    T: Send + 'static,
    F: FnMut() -> futures::future::BoxFuture<'static, Option<T>> + Send + 'static,
{
    Response::stream_ok(futures::stream::unfold(
        (rx, build, true),
        |(mut rx, mut build, first)| async move {
            if !first {
                rx.changed().await.ok()?;
            }
            let resp = build().await?;
            Some((Ok(resp), (rx, build, false)))
        },
    ))
}

/// Newest-first snapshot of `limit`, then each new entry (client prepends),
/// filtered by `actor`/`category`. Subscribes before the snapshot so an append
/// landing in the gap is picked up by the next `since`.
fn audit_stream<T, W>(
    db: Arc<Db>,
    limit: usize,
    actor: Option<String>,
    category: Option<pb::AuditCategory>,
    wrap: W,
) -> ServiceResult<ServiceStream<T>>
where
    T: Send + 'static,
    W: Fn(Vec<pb::AuditEntry>) -> T + Send + 'static,
{
    let rx = db.subscribe(Topic::Audit);
    Response::stream_ok(futures::stream::unfold(
        (db, rx, 0u64, true, actor, category, wrap),
        move |(db, mut rx, mut last_seq, first, actor, category, wrap)| async move {
            let records = if first {
                let (recs, max) = db.audit().snapshot(limit).await.ok()?;
                last_seq = max;
                recs
            } else {
                rx.changed().await.ok()?;
                let pairs = db.audit().since(last_seq).await.ok()?;
                if let Some((seq, _)) = pairs.first() {
                    last_seq = *seq; // newest-first
                }
                pairs.into_iter().map(|(_, r)| r).collect()
            };
            let entries = records
                .into_iter()
                .map(audit_entry)
                .filter(|e| audit_matches(e, actor.as_deref(), category))
                .collect();
            Some((
                Ok(wrap(entries)),
                (db, rx, last_seq, false, actor, category, wrap),
            ))
        },
    ))
}
/// Push a notification, awaited for durability. Best-effort: a hiccup is
/// swallowed, never sinking the RPC it rides on. The `record_*` helpers in
/// the service impls share this pattern.
async fn notify(
    db: &Arc<Db>,
    username: &str,
    kind: pb::NotificationKind,
    title: &str,
    detail: &str,
    link: &str,
) {
    if let Err(e) = db
        .notifications()
        .push(username, kind as u8, title, detail, link)
        .await
    {
        tracing::error!(error = %e, "notification push failed");
    }
}

fn wire_submission_status(status: u8) -> pb::SubmissionStatus {
    use pb::SubmissionStatus as S;
    match status as i32 {
        x if x == S::Pending as i32 => S::Pending,
        x if x == S::Approved as i32 => S::Approved,
        x if x == S::Rejected as i32 => S::Rejected,
        _ => S::Unspecified,
    }
}

fn submission(r: crate::db::SubmissionRecord) -> pb::Submission {
    pb::Submission {
        device_id: Some(r.device),
        version: Some(r.version),
        status: Some(wire_submission_status(r.status).into()),
        submitted_at: ts(r.submitted_at),
        reviewed_at: if r.reviewed_at == 0 {
            Default::default()
        } else {
            ts(r.reviewed_at)
        },
        ..Default::default()
    }
}

impl From<DbError> for ConnectError {
    fn from(e: DbError) -> Self {
        tracing::error!(error = %e, "metadata store failure");
        ConnectError::internal("internal error")
    }
}

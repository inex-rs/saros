//! The metadata store: everything except blobs, on one SQLite file driven by
//! the Toasty ORM (rusqlite underneath) — schema and queries are Toasty
//! models/macros, no handwritten SQL.
//!
//! The pool is pinned to a single connection (deliberate single-writer
//! discipline; the write rate here is trivial), so statements never contend
//! for SQLite's write lock. Each domain lives in its own repository, reached
//! through an accessor (`db.sessions()`, `db.audit()`, …). Relational columns
//! carry the data; the one exception is the account record ([`StoredUser`])
//! whose nested webauthn credentials stay a `[version byte] ++ serde_json`
//! blob.

mod audit;
mod notifications;
mod sessions;
mod stats;
mod submissions;
#[cfg(test)]
mod tests;
mod users;

pub use audit::{Audit, AuditRecord};
pub use notifications::{NotificationRecord, Notifications};
pub(crate) use sessions::session_id;
pub use sessions::{KIND_API, KIND_WEB, SessionRecord, Sessions};
pub use stats::{MetricTotals, MetricsSampleRecord, Stats};
pub use submissions::{SubmissionRecord, Submissions};
pub use users::{CreateOutcome, EmailOutcome, Users};

use std::path::PathBuf;

use crate::passkey::StoredUser;

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error(transparent)]
    Sql(#[from] toasty::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("unknown record version {0}")]
    UnknownVersion(u8),
    #[error("internal: {0}")]
    Internal(String),
}

/// Watch topics — one generation counter per streamed domain. Subscribers
/// re-read on each bump.
#[derive(Debug, Clone, Copy)]
pub enum Topic {
    Sessions,
    Audit,
    Notifications,
    Submissions,
}

/// Runtime-free `watch` fan-out, safe to bump from CLI paths off any reactor.
struct Notifier {
    chans: [tokio::sync::watch::Sender<u64>; 4],
}

impl Notifier {
    fn new() -> Self {
        Self {
            chans: std::array::from_fn(|_| tokio::sync::watch::channel(0).0),
        }
    }

    fn bump(&self, topic: Topic) {
        self.chans[topic as usize].send_modify(|g| *g = g.wrapping_add(1));
    }

    fn subscribe(&self, topic: Topic) -> tokio::sync::watch::Receiver<u64> {
        self.chans[topic as usize].subscribe()
    }
}

/// The account record's blob codec: `[version byte] ++ serde_json`. Only
/// [`StoredUser`] still uses it — its webauthn credentials are deep foreign
/// structs that would gain nothing from columns.
const USER_V1: u8 = 1;

pub(crate) fn encode_user(user: &StoredUser) -> Result<Vec<u8>, DbError> {
    let mut buf = Vec::with_capacity(128);
    buf.push(USER_V1);
    serde_json::to_writer(&mut buf, user)?;
    Ok(buf)
}

/// Strict: a version mismatch is an error, not a skip — silently dropping an
/// account would be wrong.
pub(crate) fn decode_user(bytes: &[u8]) -> Result<StoredUser, DbError> {
    match bytes.split_first() {
        Some((&USER_V1, rest)) => Ok(serde_json::from_slice(rest)?),
        Some((&v, _)) => Err(DbError::UnknownVersion(v)),
        None => Err(DbError::UnknownVersion(0)),
    }
}

/// The metadata database: one SQLite file behind a single-connection Toasty pool.
pub struct Db {
    inner: toasty::Db,
    notifier: Notifier,
}

impl Db {
    /// Open (or create) the db. Toasty's `push_schema` is CREATE TABLE without
    /// IF NOT EXISTS, so it runs only on first boot (file absent) — never
    /// against an existing database.
    pub async fn open(path: impl Into<PathBuf>) -> Result<Self, DbError> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let fresh = !path.exists();
        let inner = toasty::Db::builder()
            .models(toasty::models!(
                users::UserRow,
                sessions::SessionRow,
                audit::AuditRow,
                notifications::NotificationRow,
                notifications::FollowRow,
                submissions::SubmissionRow,
                stats::DownloadRow,
                stats::TotalsRow,
                stats::SeriesRow,
            ))
            .max_pool_size(1)
            .build(toasty_driver_sqlite::Sqlite::open(&path))
            .await?;
        if fresh {
            inner.push_schema().await?;
        }
        Ok(Self {
            inner,
            notifier: Notifier::new(),
        })
    }

    pub fn users(&self) -> Users<'_> {
        Users(self)
    }

    pub fn sessions(&self) -> Sessions<'_> {
        Sessions(self)
    }

    pub fn audit(&self) -> Audit<'_> {
        Audit(self)
    }

    pub fn notifications(&self) -> Notifications<'_> {
        Notifications(self)
    }

    pub fn submissions(&self) -> Submissions<'_> {
        Submissions(self)
    }

    pub fn stats(&self) -> Stats<'_> {
        Stats(self)
    }

    /// Subscribe to a topic's generation counter; re-read on each change.
    pub fn subscribe(&self, topic: Topic) -> tokio::sync::watch::Receiver<u64> {
        self.notifier.subscribe(topic)
    }

    /// A cheap executor handle (clones share the pool) — Toasty's `exec` wants
    /// `&mut dyn Executor`.
    fn handle(&self) -> toasty::Db {
        self.inner.clone()
    }

    fn bump(&self, topic: Topic) {
        self.notifier.bump(topic);
    }
}

/// `Query::limit` panics above `i64::MAX` — clamp caller-supplied limits.
fn clamp_limit(limit: usize) -> usize {
    limit.min(i64::MAX as usize)
}

pub(crate) fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

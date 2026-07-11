//! Per-user notification inboxes + the device-follow fan-out rows.

use super::{Db, DbError, Topic, clamp_limit, now_secs};

/// Cap on a user's retained notifications; the oldest beyond this are pruned
/// on the next push.
const MAX_PER_USER: u64 = 200;

/// The auto-increment id is the wire `id`: unique across users, ascending in
/// time, so per-user id order is oldest→newest.
#[derive(Debug, toasty::Model)]
#[table = "notifications"]
pub(super) struct NotificationRow {
    #[key]
    #[auto]
    id: i64,
    #[index]
    username: String,
    at: i64,
    kind: i64,
    read: bool,
    title: String,
    detail: String,
    link: String,
}

/// One (device, follower) edge; queried in both directions.
#[derive(Debug, toasty::Model)]
#[table = "follows"]
#[key(partition = device_id, local = username)]
pub(super) struct FollowRow {
    device_id: String,
    username: String,
}

/// `kind` is a `NotificationKind` proto value (RPC owns the mapping). The wire
/// `id` is the row's global id, returned alongside, not stored here.
#[derive(Debug, Clone)]
pub struct NotificationRecord {
    pub at: i64,
    pub kind: u8,
    pub read: bool,
    pub title: String,
    pub detail: String,
    pub link: String,
}

impl From<NotificationRow> for NotificationRecord {
    fn from(r: NotificationRow) -> Self {
        Self {
            at: r.at,
            kind: r.kind as u8,
            read: r.read,
            title: r.title,
            detail: r.detail,
            link: r.link,
        }
    }
}

pub struct Notifications<'a>(pub(super) &'a Db);

impl Notifications<'_> {
    /// Append to `username`'s inbox under a fresh global id, then trim to
    /// [`MAX_PER_USER`], dropping the oldest.
    pub async fn push(
        &self,
        username: &str,
        kind: u8,
        title: &str,
        detail: &str,
        link: &str,
    ) -> Result<(), DbError> {
        let mut db = self.0.handle();
        toasty::create!(NotificationRow {
            username: username.to_string(),
            at: now_secs(),
            kind: kind as i64,
            read: false,
            title: title.to_string(),
            detail: detail.to_string(),
            link: link.to_string(),
        })
        .exec(&mut db)
        .await?;
        let count = NotificationRow::filter_by_username(username)
            .count()
            .exec(&mut db)
            .await?;
        if count > MAX_PER_USER {
            let extra = (count - MAX_PER_USER) as usize;
            let oldest = NotificationRow::filter_by_username(username)
                .order_by(NotificationRow::fields().id().asc())
                .limit(extra)
                .exec(&mut db)
                .await?;
            if let Some(last) = oldest.last() {
                NotificationRow::filter_by_username(username)
                    .filter(NotificationRow::fields().id().le(last.id))
                    .delete()
                    .exec(&mut db)
                    .await?;
            }
        }
        self.0.bump(Topic::Notifications);
        Ok(())
    }

    /// `username`'s most recent `limit` notifications, newest-first as
    /// `(id, record)`.
    pub async fn list(
        &self,
        username: &str,
        limit: usize,
    ) -> Result<Vec<(u64, NotificationRecord)>, DbError> {
        let mut db = self.0.handle();
        let rows = NotificationRow::filter_by_username(username)
            .order_by(NotificationRow::fields().id().desc())
            .limit(clamp_limit(limit))
            .exec(&mut db)
            .await?;
        Ok(rows.into_iter().map(|r| (r.id as u64, r.into())).collect())
    }

    /// Mark `username`'s notification `id` read; owner-scoped. True if a row
    /// was flipped.
    pub async fn mark_read(&self, username: &str, id: u64) -> Result<bool, DbError> {
        let mut db = self.0.handle();
        let id = id as i64;
        let current = NotificationRow::filter_by_id(id)
            .first()
            .exec(&mut db)
            .await?;
        let flipped = match current {
            Some(row) if row.username == username && !row.read => {
                toasty::update!(NotificationRow::filter_by_id(id) { read: true })
                    .exec(&mut db)
                    .await?;
                true
            }
            _ => false,
        };
        self.0.bump(Topic::Notifications);
        Ok(flipped)
    }

    /// Mark all of `username`'s unread notifications read; returns how many
    /// were flipped.
    pub async fn mark_all_read(&self, username: &str) -> Result<u32, DbError> {
        let mut db = self.0.handle();
        let unread = || {
            NotificationRow::filter_by_username(username)
                .filter(NotificationRow::fields().read().eq(false))
        };
        let count = unread().count().exec(&mut db).await? as u32;
        toasty::update!(unread() { read: true })
            .exec(&mut db)
            .await?;
        self.0.bump(Topic::Notifications);
        Ok(count)
    }

    /// Follow/unfollow `device_id` as `username`; both are idempotent.
    pub async fn set_follow(
        &self,
        username: &str,
        device_id: &str,
        follow: bool,
    ) -> Result<(), DbError> {
        let mut db = self.0.handle();
        if follow {
            let present = FollowRow::filter_by_device_id_and_username(device_id, username)
                .count()
                .exec(&mut db)
                .await?
                > 0;
            if !present {
                toasty::create!(FollowRow {
                    device_id: device_id.to_string(),
                    username: username.to_string(),
                })
                .exec(&mut db)
                .await?;
            }
        } else {
            FollowRow::filter_by_device_id_and_username(device_id, username)
                .delete()
                .exec(&mut db)
                .await?;
        }
        Ok(())
    }

    /// The usernames following `device_id`.
    pub async fn followers(&self, device_id: &str) -> Result<Vec<String>, DbError> {
        let mut db = self.0.handle();
        let rows = FollowRow::filter(FollowRow::fields().device_id().eq(device_id))
            .exec(&mut db)
            .await?;
        Ok(rows.into_iter().map(|r| r.username).collect())
    }

    /// The device ids `username` follows.
    pub async fn follows_of(&self, username: &str) -> Result<Vec<String>, DbError> {
        let mut db = self.0.handle();
        let rows = FollowRow::filter(FollowRow::fields().username().eq(username))
            .exec(&mut db)
            .await?;
        Ok(rows.into_iter().map(|r| r.device_id).collect())
    }
}

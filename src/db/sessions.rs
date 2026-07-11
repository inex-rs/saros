//! Bearer sessions, keyed by sha256(token).

use super::{Db, DbError, Topic, now_secs};

/// A session's last-seen/ip/device is refreshed at most this often.
const TOUCH_THROTTLE_SECS: i64 = 3600;

pub const KIND_WEB: u8 = 1;
pub const KIND_API: u8 = 2;

/// sha256(bearer token) → session row.
#[derive(Debug, toasty::Model)]
#[table = "sessions"]
pub(super) struct SessionRow {
    #[key]
    digest: Vec<u8>,
    #[index]
    username: String,
    kind: i64,
    created_at: i64,
    expires_at: i64,
    label: String,
    last_seen: i64,
    ip: String,
    device: String,
}

#[derive(Debug, Clone)]
pub struct SessionRecord {
    pub username: String,
    /// [`KIND_WEB`] or [`KIND_API`].
    pub kind: u8,
    pub created_at: i64,
    pub expires_at: i64,
    pub label: String,
    /// Refreshed at most ~hourly; starts at `created_at`.
    pub last_seen: i64,
    pub ip: String,
    /// Coarse UA-parsed string (e.g. "Chrome on macOS"); empty until first touch.
    pub device: String,
}

impl From<SessionRow> for SessionRecord {
    fn from(r: SessionRow) -> Self {
        Self {
            username: r.username,
            kind: r.kind as u8,
            created_at: r.created_at,
            expires_at: r.expires_at,
            label: r.label,
            last_seen: r.last_seen,
            ip: r.ip,
            device: r.device,
        }
    }
}

pub struct Sessions<'a>(pub(super) &'a Db);

impl Sessions<'_> {
    /// Insert a fresh session (digests are 256-bit random — no collision path).
    pub async fn put(&self, digest: &[u8; 32], rec: &SessionRecord) -> Result<(), DbError> {
        let mut db = self.0.handle();
        toasty::create!(SessionRow {
            digest: digest.to_vec(),
            username: rec.username.clone(),
            kind: rec.kind as i64,
            created_at: rec.created_at,
            expires_at: rec.expires_at,
            label: rec.label.clone(),
            last_seen: rec.last_seen,
            ip: rec.ip.clone(),
            device: rec.device.clone(),
        })
        .exec(&mut db)
        .await?;
        self.0.bump(Topic::Sessions);
        Ok(())
    }

    /// The session's username, or `None` if absent or expired.
    pub async fn username(&self, digest: &[u8; 32]) -> Result<Option<String>, DbError> {
        let mut db = self.0.handle();
        Ok(SessionRow::filter_by_digest(digest.to_vec())
            .first()
            .exec(&mut db)
            .await?
            .filter(|r| r.expires_at > now_secs())
            .map(|r| r.username))
    }

    /// A user's live sign-ins, each with an opaque id (a hex prefix of its
    /// token digest — one-way, never the token).
    pub async fn list(&self, username: &str) -> Result<Vec<(String, SessionRecord)>, DbError> {
        let mut db = self.0.handle();
        let rows = SessionRow::filter_by_username(username)
            .filter(SessionRow::fields().expires_at().gt(now_secs()))
            .exec(&mut db)
            .await?;
        Ok(rows
            .into_iter()
            .map(|r| (session_id(&r.digest), r.into()))
            .collect())
    }

    pub async fn delete(&self, digest: &[u8; 32]) -> Result<bool, DbError> {
        let mut db = self.0.handle();
        let present = SessionRow::filter_by_digest(digest.to_vec())
            .count()
            .exec(&mut db)
            .await?
            > 0;
        if present {
            SessionRow::delete_by_digest(&mut db, digest.to_vec()).await?;
        }
        self.0.bump(Topic::Sessions);
        Ok(present)
    }

    /// Revoke `username`'s session by opaque id; owner-scoped, so one user
    /// can't revoke another's (the id is matched within the user's own rows).
    /// True if one was removed.
    pub async fn delete_by_id(&self, username: &str, id: &str) -> Result<bool, DbError> {
        let mut db = self.0.handle();
        let rows = SessionRow::filter_by_username(username)
            .exec(&mut db)
            .await?;
        let removed = match rows.into_iter().find(|r| session_id(&r.digest) == id) {
            Some(row) => {
                SessionRow::delete_by_digest(&mut db, row.digest).await?;
                true
            }
            None => false,
        };
        self.0.bump(Topic::Sessions);
        Ok(removed)
    }

    /// "Sign out everywhere but here": revoke all of `username`'s sessions
    /// except opaque id `keep_id`. Returns how many were removed.
    pub async fn delete_others(&self, username: &str, keep_id: &str) -> Result<u32, DbError> {
        let mut db = self.0.handle();
        let rows = SessionRow::filter_by_username(username)
            .exec(&mut db)
            .await?;
        let mut n = 0u32;
        for row in rows {
            if session_id(&row.digest) != keep_id {
                SessionRow::delete_by_digest(&mut db, row.digest).await?;
                n += 1;
            }
        }
        self.0.bump(Topic::Sessions);
        Ok(n)
    }

    /// Throttled record of a session's last use: refresh `last_seen`/`ip`/
    /// `device` only if ≥[`TOUCH_THROTTLE_SECS`] since the last touch. The
    /// write is a keyed UPDATE (no insert path), so a row revoked between the
    /// read and the write is never resurrected.
    pub async fn touch(
        &self,
        digest: &[u8; 32],
        ip: &str,
        device: &str,
        now: i64,
    ) -> Result<(), DbError> {
        let mut db = self.0.handle();
        let current = SessionRow::filter_by_digest(digest.to_vec())
            .first()
            .exec(&mut db)
            .await?;
        if current.is_none_or(|r| now - r.last_seen < TOUCH_THROTTLE_SECS) {
            return Ok(());
        }
        toasty::update!(SessionRow::filter_by_digest(digest.to_vec()) {
            last_seen: now,
            ip: ip.to_string(),
            device: device.to_string(),
        })
        .exec(&mut db)
        .await?;
        self.0.bump(Topic::Sessions);
        Ok(())
    }

    /// Reclaim expired rows in one pass; runs periodically, not per insert —
    /// reads already filter on `expires_at`. Returns how many were removed.
    pub async fn sweep_expired(&self) -> Result<usize, DbError> {
        let now = now_secs();
        let mut db = self.0.handle();
        let dead = SessionRow::filter(SessionRow::fields().expires_at().le(now))
            .count()
            .exec(&mut db)
            .await? as usize;
        if dead > 0 {
            SessionRow::filter(SessionRow::fields().expires_at().le(now))
                .delete()
                .exec(&mut db)
                .await?;
            self.0.bump(Topic::Sessions);
        }
        Ok(dead)
    }
}

/// An opaque, one-way session handle: a hex prefix of the token digest —
/// enough to disambiguate, reveals nothing invertible.
pub(crate) fn session_id(digest: &[u8]) -> String {
    hex::encode(digest.get(..8).unwrap_or(digest))
}

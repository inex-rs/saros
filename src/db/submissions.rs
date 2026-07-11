//! A submitter's ledger: one row per (device, version) coordinate.

use super::{Db, DbError, Topic, now_secs};

/// Cap on a submitter's ledger rows; the oldest (by `submitted_at`) beyond
/// this are pruned on the next record.
const MAX_PER_USER: u64 = 200;

/// `SubmissionStatus::PENDING` proto value — the only status the ledger
/// self-stamps (on submit); reviews pass APPROVED/REJECTED in.
const PENDING: u8 = 1;

/// One (username, device, version) coordinate; a re-submit updates in place.
#[derive(Debug, toasty::Model)]
#[table = "submissions"]
#[key(partition = [username, device], local = version)]
pub(super) struct SubmissionRow {
    username: String,
    device: String,
    version: String,
    status: i64,
    submitted_at: i64,
    reviewed_at: i64,
}

/// `status` is a `SubmissionStatus` proto value (RPC owns the mapping);
/// `reviewed_at` is `0` until reviewed.
#[derive(Debug, Clone)]
pub struct SubmissionRecord {
    pub device: String,
    pub version: String,
    pub status: u8,
    pub submitted_at: i64,
    pub reviewed_at: i64,
}

impl From<SubmissionRow> for SubmissionRecord {
    fn from(r: SubmissionRow) -> Self {
        Self {
            device: r.device,
            version: r.version,
            status: r.status as u8,
            submitted_at: r.submitted_at,
            reviewed_at: r.reviewed_at,
        }
    }
}

pub struct Submissions<'a>(pub(super) &'a Db);

impl Submissions<'_> {
    /// Upsert `username`'s `(device, version)` row to PENDING (fresh
    /// `submitted_at`, cleared `reviewed_at`) — a re-submit flips the same
    /// row, no duplicate. Then trims to [`MAX_PER_USER`].
    pub async fn record(&self, username: &str, device: &str, version: &str) -> Result<(), DbError> {
        let now = now_secs();
        let mut db = self.0.handle();
        let present =
            SubmissionRow::filter_by_username_and_device_and_version(username, device, version)
                .count()
                .exec(&mut db)
                .await?
                > 0;
        if present {
            toasty::update!(
                SubmissionRow::filter_by_username_and_device_and_version(username, device, version) {
                    status: PENDING as i64,
                    submitted_at: now,
                    reviewed_at: 0,
                }
            )
            .exec(&mut db)
            .await?;
        } else {
            toasty::create!(SubmissionRow {
                username: username.to_string(),
                device: device.to_string(),
                version: version.to_string(),
                status: PENDING as i64,
                submitted_at: now,
                reviewed_at: 0,
            })
            .exec(&mut db)
            .await?;
        }
        // Rows key on coordinate not time: drop the oldest by submitted_at
        // beyond the cap.
        let count = SubmissionRow::filter(SubmissionRow::fields().username().eq(username))
            .count()
            .exec(&mut db)
            .await?;
        if count > MAX_PER_USER {
            let extra = (count - MAX_PER_USER) as usize;
            let oldest = SubmissionRow::filter(SubmissionRow::fields().username().eq(username))
                .order_by(SubmissionRow::fields().submitted_at().asc())
                .limit(extra)
                .exec(&mut db)
                .await?;
            for row in oldest {
                SubmissionRow::delete_by_username_and_device_and_version(
                    &mut db,
                    row.username.as_str(),
                    row.device.as_str(),
                    row.version.as_str(),
                )
                .await?;
            }
        }
        self.0.bump(Topic::Submissions);
        Ok(())
    }

    /// Stamp a review verdict on `username`'s `(device, version)` row. No-op
    /// if absent — a service-token/seed submission may have no ledger row.
    pub async fn mark(
        &self,
        username: &str,
        device: &str,
        version: &str,
        status: u8,
    ) -> Result<(), DbError> {
        let mut db = self.0.handle();
        let present =
            SubmissionRow::filter_by_username_and_device_and_version(username, device, version)
                .count()
                .exec(&mut db)
                .await?
                > 0;
        if present {
            toasty::update!(
                SubmissionRow::filter_by_username_and_device_and_version(username, device, version) {
                    status: status as i64,
                    reviewed_at: now_secs(),
                }
            )
            .exec(&mut db)
            .await?;
            self.0.bump(Topic::Submissions);
        }
        Ok(())
    }

    /// `username`'s ledger; handler sorts newest-first.
    pub async fn list(&self, username: &str) -> Result<Vec<SubmissionRecord>, DbError> {
        let mut db = self.0.handle();
        let rows = SubmissionRow::filter(SubmissionRow::fields().username().eq(username))
            .exec(&mut db)
            .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }
}

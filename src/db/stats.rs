//! Operational stats: download counters, persisted lifetime totals, and the
//! hourly metrics series.

use super::{Db, DbError};

/// Retained series rows (one/hour ≈ 30 days); the oldest beyond this are
/// pruned on the next sample.
const SERIES_RETENTION: u64 = 720;

/// Content-addressed download counter: blob `sha256` → cumulative count. A
/// blob shared across versions accrues one total, summed into each version on
/// read.
#[derive(Debug, toasty::Model)]
#[table = "downloads"]
pub(super) struct DownloadRow {
    #[key]
    sha: String,
    count: u64,
}

/// The single lifetime-totals row (`id` fixed at 0): in-process atomics reset
/// each boot, so they're flushed here + seeded back at startup.
#[derive(Debug, toasty::Model)]
#[table = "metrics_totals"]
pub(super) struct TotalsRow {
    #[key]
    id: i64,
    downloads: u64,
    uploads: u64,
    submissions: u64,
    reviews: u64,
    sign_ins: u64,
}

/// One hourly sample, keyed by its hour bucket (within-hour samples upsert).
#[derive(Debug, toasty::Model)]
#[table = "metrics_series"]
pub(super) struct SeriesRow {
    #[key]
    bucket: i64,
    at: i64,
    users: u64,
    devices: u64,
    firmware: u64,
    downloads: u64,
    uploads: u64,
    submissions: u64,
    sign_ins: u64,
}

/// Persisted lifetime counters, mirroring the in-process metric atomics.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MetricTotals {
    pub downloads: u64,
    pub uploads: u64,
    pub submissions: u64,
    pub reviews: u64,
    pub sign_ins: u64,
}

/// One hourly sample: catalogue counts plus operational counters at the
/// instant taken. `at` is the sample instant.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MetricsSampleRecord {
    pub at: i64,
    pub users: u64,
    pub devices: u64,
    pub firmware: u64,
    pub downloads: u64,
    pub uploads: u64,
    pub submissions: u64,
    pub sign_ins: u64,
}

impl From<SeriesRow> for MetricsSampleRecord {
    fn from(r: SeriesRow) -> Self {
        Self {
            at: r.at,
            users: r.users,
            devices: r.devices,
            firmware: r.firmware,
            downloads: r.downloads,
            uploads: r.uploads,
            submissions: r.submissions,
            sign_ins: r.sign_ins,
        }
    }
}

pub struct Stats<'a>(pub(super) &'a Db);

impl Stats<'_> {
    /// Increment a blob's download counter. The read-modify-write runs inside
    /// a transaction so concurrent bumps can't lose an increment. Bumps no
    /// watch: counts are enriched on read, never streamed.
    pub async fn bump_download(&self, sha: &str) -> Result<(), DbError> {
        let mut db = self.0.handle();
        let mut tx = db.transaction().await?;
        let current = DownloadRow::filter_by_sha(sha)
            .first()
            .exec(&mut tx)
            .await?;
        match current {
            Some(row) => {
                let count = row.count.saturating_add(1);
                toasty::update!(DownloadRow::filter_by_sha(sha) { count })
                    .exec(&mut tx)
                    .await?;
            }
            None => {
                toasty::create!(DownloadRow {
                    sha: sha.to_string(),
                    count: 1u64,
                })
                .exec(&mut tx)
                .await?;
            }
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn download_count(&self, sha: &str) -> Result<u64, DbError> {
        let mut db = self.0.handle();
        Ok(DownloadRow::filter_by_sha(sha)
            .first()
            .exec(&mut db)
            .await?
            .map(|r| r.count)
            .unwrap_or(0))
    }

    /// The persisted lifetime counters (zeros when never saved).
    pub async fn load_totals(&self) -> Result<MetricTotals, DbError> {
        let mut db = self.0.handle();
        Ok(TotalsRow::filter_by_id(0)
            .first()
            .exec(&mut db)
            .await?
            .map(|r| MetricTotals {
                downloads: r.downloads,
                uploads: r.uploads,
                submissions: r.submissions,
                reviews: r.reviews,
                sign_ins: r.sign_ins,
            })
            .unwrap_or_default())
    }

    /// Flush the lifetime counters (overwrites). Called periodically + at
    /// shutdown, so a restart doesn't lose them.
    pub async fn save_totals(&self, totals: &MetricTotals) -> Result<(), DbError> {
        let mut db = self.0.handle();
        let present = TotalsRow::filter_by_id(0).count().exec(&mut db).await? > 0;
        if present {
            toasty::update!(TotalsRow::filter_by_id(0) {
                downloads: totals.downloads,
                uploads: totals.uploads,
                submissions: totals.submissions,
                reviews: totals.reviews,
                sign_ins: totals.sign_ins,
            })
            .exec(&mut db)
            .await?;
        } else {
            toasty::create!(TotalsRow {
                id: 0i64,
                downloads: totals.downloads,
                uploads: totals.uploads,
                submissions: totals.submissions,
                reviews: totals.reviews,
                sign_ins: totals.sign_ins,
            })
            .exec(&mut db)
            .await?;
        }
        Ok(())
    }

    /// Upsert `rec` into its hour bucket, then prune to [`SERIES_RETENTION`]
    /// (oldest-first).
    pub async fn record_sample(&self, rec: &MetricsSampleRecord) -> Result<(), DbError> {
        let bucket = (rec.at.max(0)) / 3600 * 3600;
        let mut db = self.0.handle();
        let present = SeriesRow::filter_by_bucket(bucket)
            .count()
            .exec(&mut db)
            .await?
            > 0;
        if present {
            toasty::update!(SeriesRow::filter_by_bucket(bucket) {
                at: rec.at,
                users: rec.users,
                devices: rec.devices,
                firmware: rec.firmware,
                downloads: rec.downloads,
                uploads: rec.uploads,
                submissions: rec.submissions,
                sign_ins: rec.sign_ins,
            })
            .exec(&mut db)
            .await?;
        } else {
            toasty::create!(SeriesRow {
                bucket,
                at: rec.at,
                users: rec.users,
                devices: rec.devices,
                firmware: rec.firmware,
                downloads: rec.downloads,
                uploads: rec.uploads,
                submissions: rec.submissions,
                sign_ins: rec.sign_ins,
            })
            .exec(&mut db)
            .await?;
        }
        let count = SeriesRow::all().count().exec(&mut db).await?;
        if count > SERIES_RETENTION {
            let extra = (count - SERIES_RETENTION) as usize;
            let oldest = toasty::query!(SeriesRow ORDER BY .bucket ASC LIMIT #extra)
                .exec(&mut db)
                .await?;
            if let Some(last) = oldest.last() {
                let upto = last.bucket;
                toasty::query!(SeriesRow FILTER .bucket <= #upto)
                    .delete()
                    .exec(&mut db)
                    .await?;
            }
        }
        Ok(())
    }

    /// The series, oldest-first — the trend-chart history.
    pub async fn history(&self) -> Result<Vec<MetricsSampleRecord>, DbError> {
        let mut db = self.0.handle();
        let rows = toasty::query!(SeriesRow ORDER BY .bucket ASC)
            .exec(&mut db)
            .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }
}

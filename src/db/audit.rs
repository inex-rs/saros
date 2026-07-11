//! Append-only audit trail with retention pruning folded into each append.

use super::{Db, DbError, Topic, clamp_limit, now_secs};

/// Max entries in one [`Audit::since`] batch — caps a pathological append
/// burst (newest kept).
const SINCE_CAP: usize = 500;
/// Entries older than this are pruned on the next append (90-day window).
const RETENTION_SECS: i64 = 90 * 24 * 3600;
/// Hard ceiling on rows; the oldest beyond this are pruned on append even
/// within the retention window.
const MAX_ROWS: u64 = 50_000;

/// The auto-increment seq doubles as the newest-first sort key and the
/// `since`/`page` cursor.
#[derive(Debug, toasty::Model)]
#[table = "audit"]
pub(super) struct AuditRow {
    #[key]
    #[auto]
    seq: i64,
    at: i64,
    #[index]
    actor: String,
    action: i64,
    target: String,
}

/// `action` is an `AuditAction` proto value; the RPC layer owns the mapping.
#[derive(Debug, Clone)]
pub struct AuditRecord {
    pub at: i64,
    pub actor: String,
    pub action: u8,
    pub target: String,
}

impl From<AuditRow> for AuditRecord {
    fn from(r: AuditRow) -> Self {
        Self {
            at: r.at,
            actor: r.actor,
            action: r.action as u8,
            target: r.target,
        }
    }
}

pub struct Audit<'a>(pub(super) &'a Db);

impl Audit<'_> {
    /// Append under a fresh seq, then prune stale rows in the same logical
    /// operation: the retention window first, then the row cap (oldest-first).
    pub async fn append(&self, actor: &str, action: u8, target: &str) -> Result<(), DbError> {
        let now = now_secs();
        let mut db = self.0.handle();
        toasty::create!(AuditRow {
            at: now,
            actor: actor.to_string(),
            action: action as i64,
            target: target.to_string(),
        })
        .exec(&mut db)
        .await?;
        let cutoff = now - RETENTION_SECS;
        toasty::query!(AuditRow FILTER .at < #cutoff)
            .delete()
            .exec(&mut db)
            .await?;
        // Still over the cap: drop the oldest surplus (by seq).
        let remaining = AuditRow::all().count().exec(&mut db).await?;
        if remaining > MAX_ROWS {
            let extra = (remaining - MAX_ROWS) as usize;
            let oldest = toasty::query!(AuditRow ORDER BY .seq ASC LIMIT #extra)
                .exec(&mut db)
                .await?;
            if let Some(last) = oldest.last() {
                let upto = last.seq;
                toasty::query!(AuditRow FILTER .seq <= #upto)
                    .delete()
                    .exec(&mut db)
                    .await?;
            }
        }
        self.0.bump(Topic::Audit);
        Ok(())
    }

    /// The most recent `limit` entries, newest first.
    pub async fn list(&self, limit: usize) -> Result<Vec<AuditRecord>, DbError> {
        let mut db = self.0.handle();
        let limit = clamp_limit(limit);
        let rows = toasty::query!(AuditRow ORDER BY .seq DESC LIMIT #limit)
            .exec(&mut db)
            .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// Newest-first snapshot of `limit` entries plus the highest seq (0 when
    /// empty) — the cursor [`since`](Self::since) resumes from. Newest-first
    /// means the first row carries the table's max seq.
    pub async fn snapshot(&self, limit: usize) -> Result<(Vec<AuditRecord>, u64), DbError> {
        let mut db = self.0.handle();
        let limit = clamp_limit(limit);
        let rows = toasty::query!(AuditRow ORDER BY .seq DESC LIMIT #limit)
            .exec(&mut db)
            .await?;
        let max = rows.first().map(|r| r.seq as u64).unwrap_or(0);
        Ok((rows.into_iter().map(Into::into).collect(), max))
    }

    /// Entries with seq > `after`, newest-first as `(seq, record)` — the
    /// incremental feed after a snapshot. Capped at [`SINCE_CAP`].
    pub async fn since(&self, after: u64) -> Result<Vec<(u64, AuditRecord)>, DbError> {
        let mut db = self.0.handle();
        let after = after as i64;
        let rows =
            toasty::query!(AuditRow FILTER .seq > #after ORDER BY .seq DESC LIMIT #SINCE_CAP)
                .exec(&mut db)
                .await?;
        Ok(rows.into_iter().map(|r| (r.seq as u64, r.into())).collect())
    }

    /// A newest-first page: entries with `seq < before` (`0` ⇒ from the
    /// newest), optional `actor` filter, capped at `limit`. Returns the page's
    /// smallest seq as the next cursor, or `0` once exhausted.
    pub async fn page(
        &self,
        before: u64,
        limit: usize,
        actor: Option<&str>,
    ) -> Result<(Vec<(u64, AuditRecord)>, u64), DbError> {
        let mut db = self.0.handle();
        let mut q = AuditRow::all();
        if before > 0 {
            q = q.filter(AuditRow::fields().seq().lt(before as i64));
        }
        if let Some(actor) = actor {
            q = q.filter(AuditRow::fields().actor().eq(actor));
        }
        let rows = q
            .order_by(AuditRow::fields().seq().desc())
            .limit(clamp_limit(limit))
            .exec(&mut db)
            .await?;
        let out: Vec<(u64, AuditRecord)> =
            rows.into_iter().map(|r| (r.seq as u64, r.into())).collect();
        // Short page ⇒ exhausted (cursor 0); a full page resumes from its
        // smallest seq.
        let next_cursor = if out.len() < limit {
            0
        } else {
            out.last().map(|(seq, _)| *seq).unwrap_or(0)
        };
        Ok((out, next_cursor))
    }
}

//! In-process operational counters for the admin dashboard: enum-indexed
//! atomics seeded from + flushed to the store, so they read as lifetime
//! totals across restarts (only `uptime_seconds` is since-boot).

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use strum::{EnumCount, IntoEnumIterator};

use crate::db::MetricTotals;

/// One lifetime counter. Adding a variant is the whole change — seed, flush,
/// and snapshot iterate the enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::EnumCount, strum::EnumIter)]
pub enum Counter {
    Downloads,
    Uploads,
    Submissions,
    Reviews,
    SignIns,
}

pub struct Metrics {
    start: Instant,
    counters: [AtomicU64; Counter::COUNT],
    /// Whether an egress mirror is configured (the single source on the stats path).
    mirror_configured: bool,
}

pub struct Snapshot {
    pub uptime_seconds: u64,
    pub downloads: u64,
    pub uploads: u64,
    pub submissions: u64,
    pub reviews: u64,
    pub sign_ins: u64,
    pub mirror_configured: bool,
}

impl Metrics {
    pub fn new(mirror_configured: bool) -> Self {
        Self {
            start: Instant::now(),
            counters: std::array::from_fn(|_| AtomicU64::new(0)),
            mirror_configured,
        }
    }

    pub fn inc(&self, c: Counter) {
        self.counters[c as usize].fetch_add(1, Ordering::Relaxed);
    }

    fn get(&self, c: Counter) -> u64 {
        self.counters[c as usize].load(Ordering::Relaxed)
    }

    /// Seed from persisted lifetime totals, once at startup before the
    /// serving path bumps anything.
    pub fn seed(&self, t: &MetricTotals) {
        for c in Counter::iter() {
            self.counters[c as usize].store(field(t, c), Ordering::Relaxed);
        }
    }

    /// The current counters as the persisted-totals record (the flush shape).
    pub fn totals(&self) -> MetricTotals {
        MetricTotals {
            downloads: self.get(Counter::Downloads),
            uploads: self.get(Counter::Uploads),
            submissions: self.get(Counter::Submissions),
            reviews: self.get(Counter::Reviews),
            sign_ins: self.get(Counter::SignIns),
        }
    }

    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            uptime_seconds: self.start.elapsed().as_secs(),
            downloads: self.get(Counter::Downloads),
            uploads: self.get(Counter::Uploads),
            submissions: self.get(Counter::Submissions),
            reviews: self.get(Counter::Reviews),
            sign_ins: self.get(Counter::SignIns),
            mirror_configured: self.mirror_configured,
        }
    }
}

fn field(t: &MetricTotals, c: Counter) -> u64 {
    match c {
        Counter::Downloads => t.downloads,
        Counter::Uploads => t.uploads,
        Counter::Submissions => t.submissions,
        Counter::Reviews => t.reviews,
        Counter::SignIns => t.sign_ins,
    }
}

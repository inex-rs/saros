//! Domain events: one emit per action; the sink owns the side effects
//! (counter bump + audit row + notification fan-out), each best-effort —
//! an instrumentation failure never fails the RPC it rides on.

use std::sync::Arc;

use inex_protobufs::buffa::inex::saros::v1 as pb;

use crate::db::Db;
use crate::metrics::{Counter, Metrics};

pub struct Events {
    db: Arc<Db>,
    metrics: Arc<Metrics>,
}

impl Events {
    pub fn new(db: Arc<Db>, metrics: Arc<Metrics>) -> Self {
        Self { db, metrics }
    }

    /// A blob was uploaded.
    pub async fn upload(&self) {
        self.metrics.inc(Counter::Uploads);
    }

    /// A blob was downloaded.
    pub async fn download(&self) {
        self.metrics.inc(Counter::Downloads);
    }

    /// A session/token was minted: `action` distinguishes register / sign-in /
    /// token creation at the call sites.
    pub async fn sign_in(&self, actor: &str, action: pb::AuditAction, target: &str) {
        self.metrics.inc(Counter::SignIns);
        self.audit(actor, action, target).await;
    }

    /// Firmware was submitted for review (the submitter's ledger row stays at
    /// the call site).
    pub async fn submitted(&self, actor: &str, device: &str, version: &str) {
        self.metrics.inc(Counter::Submissions);
        self.audit(
            actor,
            pb::AuditAction::FirmwareSubmitted,
            &format!("{device}/{version}"),
        )
        .await;
    }

    /// A staged submission was approved or rejected.
    pub async fn reviewed(&self, actor: &str, target: &str, approved: bool) {
        self.metrics.inc(Counter::Reviews);
        let action = if approved {
            pb::AuditAction::FirmwareApproved
        } else {
            pb::AuditAction::FirmwareRejected
        };
        self.audit(actor, action, target).await;
    }

    /// Audit-only account event (credential add/remove, email change, session
    /// revokes, …).
    pub async fn account(&self, action: pb::AuditAction, actor: &str, target: &str) {
        self.audit(actor, action, target).await;
    }

    /// Append the audit row, awaited for durability.
    async fn audit(&self, actor: &str, action: pb::AuditAction, target: &str) {
        if let Err(e) = self.db.audit().append(actor, action as u8, target).await {
            tracing::error!(error = %e, "audit append failed");
        }
    }
}

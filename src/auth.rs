//! The token authority: opaque random bearer tokens, resolved by a SHA-256
//! digest lookup in [`Db`] — the session row is authoritative for both
//! validity and revocation (no offline-verifiable crypto layer to keep in
//! sync, no signing key to lose). Everything else (sessions, audit,
//! notifications, …) lives on the [`Db`] repositories.

use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::db::{Db, DbError, KIND_API, KIND_WEB, SessionRecord, now_secs, session_id};

pub const SESSION_TTL: Duration = Duration::from_secs(30 * 24 * 3600);
pub const API_TOKEN_TTL: Duration = Duration::from_secs(365 * 24 * 3600);

pub const SESSION_COOKIE: &str = "saros_session";

/// `SameSite=Lax` is the CSRF defense (web + API are same-site); a `Domain` on
/// `localhost` is rejected, so it's omitted in dev.
pub fn set_session_cookie(token: &str, domain: Option<&str>, secure: bool) -> String {
    let mut c = format!(
        "{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}",
        SESSION_TTL.as_secs(),
    );
    if secure {
        c.push_str("; Secure");
    }
    if let Some(d) = domain.filter(|d| !d.is_empty()) {
        c.push_str("; Domain=");
        c.push_str(d);
    }
    c
}

pub fn clear_session_cookie(domain: Option<&str>, secure: bool) -> String {
    let mut c = format!("{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0");
    if secure {
        c.push_str("; Secure");
    }
    if let Some(d) = domain.filter(|d| !d.is_empty()) {
        c.push_str("; Domain=");
        c.push_str(d);
    }
    c
}

pub fn cookie_session_token(cookie_header: &str) -> Option<&str> {
    let prefix = format!("{SESSION_COOKIE}=");
    cookie_header
        .split(';')
        .find_map(|c| c.trim().strip_prefix(prefix.as_str()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Caller {
    Anonymous,
    User { username: String, admin: bool },
    Service,
}

impl Caller {
    pub fn signed_in(&self) -> bool {
        !matches!(self, Caller::Anonymous)
    }

    pub fn admin(&self) -> bool {
        matches!(self, Caller::Service | Caller::User { admin: true, .. })
    }

    pub fn username(&self) -> &str {
        match self {
            Caller::User { username, .. } => username,
            Caller::Service => "service",
            Caller::Anonymous => "",
        }
    }
}

pub struct Auth {
    service_token_digest: Option<[u8; 32]>,
    admin_users: Vec<String>,
    db: Arc<Db>,
}

impl Auth {
    pub fn new(service_token: Option<&str>, admin_users: Vec<String>, db: Arc<Db>) -> Self {
        Self {
            service_token_digest: service_token.map(|t| Sha256::digest(t).into()),
            admin_users,
            db,
        }
    }

    pub async fn mint_session(&self, username: &str) -> Result<String, DbError> {
        self.mint(username, SESSION_TTL, KIND_WEB, "web session")
            .await
    }

    pub async fn mint_api_token(&self, username: &str, label: &str) -> Result<String, DbError> {
        self.mint(username, API_TOKEN_TTL, KIND_API, label).await
    }

    /// A fresh 256-bit random token; only its digest is stored, so the token
    /// itself is unrecoverable and the row is the single source of validity.
    async fn mint(
        &self,
        username: &str,
        ttl: Duration,
        kind: u8,
        label: &str,
    ) -> Result<String, DbError> {
        let token = crate::random_hex(32)
            .map_err(|e| DbError::Internal(format!("token rng failed: {e}")))?;
        let digest: [u8; 32] = Sha256::digest(&token).into();
        let now = now_secs();
        self.db
            .sessions()
            .put(
                &digest,
                &SessionRecord {
                    username: username.to_string(),
                    kind,
                    created_at: now,
                    expires_at: now.saturating_add(ttl.as_secs() as i64),
                    label: label.to_string(),
                    last_seen: now,
                    ip: String::new(),
                    device: String::new(),
                },
            )
            .await?;
        Ok(token)
    }

    /// Opaque id of the session behind this request, matching
    /// [`Sessions::list`](crate::db::Sessions::list).
    pub fn current_session_id(&self, authorization: Option<&str>) -> Option<String> {
        let token = authorization.and_then(|v| v.strip_prefix("Bearer "))?;
        let digest: [u8; 32] = Sha256::digest(token).into();
        Some(session_id(&digest))
    }

    /// Telemetry, never a gate: errors are swallowed so a touch never fails
    /// the request it rides along with.
    pub async fn touch(&self, authorization: Option<&str>, ip: &str, device: &str) {
        let Some(token) = authorization.and_then(|v| v.strip_prefix("Bearer ")) else {
            return;
        };
        let digest: [u8; 32] = Sha256::digest(token).into();
        if let Err(e) = self
            .db
            .sessions()
            .touch(&digest, ip, device, now_secs())
            .await
        {
            tracing::error!(error = %e, "session touch failed");
        }
    }

    /// Revoke the presented session (the service token is config, not revocable).
    pub async fn revoke(&self, authorization: Option<&str>) -> bool {
        let Some(token) = authorization.and_then(|v| v.strip_prefix("Bearer ")) else {
            return false;
        };
        let digest: [u8; 32] = Sha256::digest(token).into();
        self.db
            .sessions()
            .delete(&digest)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, "session revoke failed");
                false
            })
    }

    /// Fails closed (Anonymous) on any store error — an unreadable store must
    /// not grant access.
    pub async fn caller(&self, authorization: Option<&str>) -> Caller {
        let Some(token) = authorization.and_then(|v| v.strip_prefix("Bearer ")) else {
            return Caller::Anonymous;
        };
        let digest: [u8; 32] = Sha256::digest(token).into();
        // Service token is an opaque configured string; match by digest first.
        if self.service_token_digest == Some(digest) {
            return Caller::Service;
        }
        // The session row is the whole gate: present + unexpired, or nothing.
        match self.db.sessions().username(&digest).await {
            Ok(Some(username)) => Caller::User {
                admin: self
                    .admin_users
                    .iter()
                    .any(|a| a.eq_ignore_ascii_case(&username)),
                username,
            },
            Ok(None) => Caller::Anonymous,
            Err(e) => {
                tracing::error!(error = %e, "session lookup failed");
                Caller::Anonymous
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! The security boundary: caller resolution, revocation surviving
    //! restarts, and fail-closed defaults.

    use super::*;

    async fn db(dir: &std::path::Path) -> Arc<Db> {
        Arc::new(Db::open(dir.join("meta.db")).await.unwrap())
    }

    #[tokio::test]
    async fn resolves_callers() {
        let dir = tempfile::tempdir().unwrap();
        let a = Auth::new(Some("svc"), vec!["boss".into()], db(dir.path()).await);
        assert_eq!(a.caller(None).await, Caller::Anonymous);
        assert_eq!(a.caller(Some("Bearer nope")).await, Caller::Anonymous);
        assert_eq!(a.caller(Some("Bearer svc")).await, Caller::Service);

        let admin = a.mint_session("boss").await.unwrap();
        let user = a.mint_session("member").await.unwrap();
        assert!(matches!(
            a.caller(Some(&format!("Bearer {admin}"))).await,
            Caller::User { admin: true, .. }
        ));
        assert!(matches!(
            a.caller(Some(&format!("Bearer {user}"))).await,
            Caller::User { admin: false, .. }
        ));
    }

    /// A token stays valid across a restart (store-backed), and revocation
    /// deletes the row — the only source of validity.
    #[tokio::test]
    async fn mint_persist_revoke_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("meta.db");
        let a = Auth::new(None, vec![], Arc::new(Db::open(&path).await.unwrap()));
        let token = a.mint_session("who").await.unwrap();
        assert!(a.caller(Some(&format!("Bearer {token}"))).await.signed_in());

        drop(a);
        let b = Auth::new(None, vec![], Arc::new(Db::open(&path).await.unwrap()));
        assert!(b.caller(Some(&format!("Bearer {token}"))).await.signed_in());

        assert!(b.revoke(Some(&format!("Bearer {token}"))).await);
        assert!(!b.caller(Some(&format!("Bearer {token}"))).await.signed_in());
    }

    /// No service token configured ⇒ nothing is privileged.
    #[tokio::test]
    async fn secure_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let a = Auth::new(None, vec![], db(dir.path()).await);
        assert_eq!(a.caller(None).await, Caller::Anonymous);
        assert_eq!(a.caller(Some("Bearer anything")).await, Caller::Anonymous);
    }
}

//! WebAuthn/passkey sign-in: usernameless via discoverable (resident) keys;
//! accounts in [`Db`], in-flight ceremonies in a `flow_id`-keyed pending map.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use url::Url;
use webauthn_rs::prelude::*;
use webauthn_rs_proto::{AuthenticatorSelectionCriteria, ResidentKeyRequirement};

use crate::db::{Db, DbError, now_secs};

const PENDING_TTL: Duration = Duration::from_secs(300);
/// `begin` is unauthenticated, so bound in-flight ceremonies.
const MAX_PENDING: usize = 4096;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Credential {
    pub passkey: Passkey,
    pub label: String,
    pub added_at: i64,
}

impl Credential {
    /// Stable hex handle = the WebAuthn credential id.
    pub fn id(&self) -> String {
        hex::encode(self.passkey.cred_id().as_ref())
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredUser {
    pub uuid: Uuid,
    pub username: String,
    pub credentials: Vec<Credential>,
    pub email: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CredentialInfo {
    pub id: String,
    pub label: String,
    pub added_at: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum PasskeyError {
    #[error("username must be 1-32 chars of [a-z0-9._-]")]
    InvalidUsername,
    #[error("that doesn't look like an email address")]
    InvalidEmail,
    #[error("username is taken")]
    UsernameTaken,
    #[error("that email is already linked to another account")]
    EmailTaken,
    #[error("unknown or expired sign-in — start again")]
    UnknownFlow,
    #[error("no account for that passkey")]
    NoSuchUser,
    #[error("no such passkey on this account")]
    NoSuchCredential,
    #[error("can't remove your only passkey — add another first")]
    LastCredential,
    #[error("too many in-flight sign-ins — try again shortly")]
    TooManyPending,
    #[error("webauthn: {0}")]
    Webauthn(#[from] WebauthnError),
    #[error("credential json: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Db(#[from] DbError),
    #[error("rng: {0}")]
    Rng(#[from] getrandom::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasskeyMode {
    Register,
    Authenticate,
}

enum Ceremony {
    Register(Uuid, String, PasskeyRegistration),
    Authenticate(DiscoverableAuthentication),
    AddCredential(String, PasskeyRegistration),
}

struct Pending {
    created: Instant,
    ceremony: Ceremony,
}

pub struct Passkeys {
    webauthn: Webauthn,
    db: Arc<Db>,
    pending: Mutex<HashMap<String, Pending>>,
}

impl Passkeys {
    /// `rp_id` is the registrable domain passkeys bind to; `rp_origin` is the
    /// browser origin.
    pub fn new(
        rp_id: &str,
        rp_origin: &Url,
        allow_any_port: bool,
        db: Arc<Db>,
    ) -> anyhow::Result<Self> {
        let mut builder = WebauthnBuilder::new(rp_id, rp_origin)?.rp_name("Saros");
        if allow_any_port {
            builder = builder.allow_any_port(true);
        }
        Ok(Self {
            webauthn: builder.build()?,
            db,
            pending: Mutex::new(HashMap::new()),
        })
    }

    /// Empty `username` signs in (usernameless); a non-empty one registers.
    pub async fn begin(
        &self,
        username: &str,
    ) -> Result<(String, String, PasskeyMode), PasskeyError> {
        self.sweep_pending();
        if self.pending.lock().expect("pending poisoned").len() >= MAX_PENDING {
            return Err(PasskeyError::TooManyPending);
        }
        let username = username.trim();
        let flow_id = crate::random_hex(16)?;
        if username.is_empty() {
            let (rcr, state) = self.webauthn.start_discoverable_authentication()?;
            self.insert_pending(flow_id.clone(), Ceremony::Authenticate(state));
            Ok((
                flow_id,
                serde_json::to_string(&rcr)?,
                PasskeyMode::Authenticate,
            ))
        } else {
            if !valid_username(username) {
                return Err(PasskeyError::InvalidUsername);
            }
            if self.db.users().exists(username).await? {
                return Err(PasskeyError::UsernameTaken);
            }
            let uuid = Uuid::new_v4();
            let (mut ccr, state) = self
                .webauthn
                .start_passkey_registration(uuid, username, username, None)?;
            // Usernameless sign-in needs a discoverable credential; the default
            // requests residentKey "discouraged", so force it to required.
            let want_resident = AuthenticatorSelectionCriteria {
                resident_key: Some(ResidentKeyRequirement::Required),
                require_resident_key: true,
                ..ccr
                    .public_key
                    .authenticator_selection
                    .take()
                    .unwrap_or_default()
            };
            ccr.public_key.authenticator_selection = Some(want_resident);
            self.insert_pending(
                flow_id.clone(),
                Ceremony::Register(uuid, username.to_string(), state),
            );
            Ok((flow_id, serde_json::to_string(&ccr)?, PasskeyMode::Register))
        }
    }

    /// Verify a pending flow's credential. `email` (recovery address) is honoured
    /// only on Register.
    pub async fn finish(
        &self,
        flow_id: &str,
        credential_json: &str,
        email: Option<&str>,
    ) -> Result<(String, PasskeyMode), PasskeyError> {
        let pending = self
            .pending
            .lock()
            .expect("pending poisoned")
            .remove(flow_id)
            .ok_or(PasskeyError::UnknownFlow)?;
        match pending.ceremony {
            Ceremony::Register(uuid, username, state) => {
                let reg: RegisterPublicKeyCredential = serde_json::from_str(credential_json)?;
                let passkey = self.webauthn.finish_passkey_registration(&reg, &state)?;
                // Kept as typed (case matters for delivery); lowercased only when
                // hashed for Gravatar.
                let email = match email.map(str::trim).filter(|e| !e.is_empty()) {
                    Some(e) if valid_email(e) => Some(e.to_string()),
                    Some(_) => return Err(PasskeyError::InvalidEmail),
                    None => None,
                };
                // Check-and-create (constraint-backstopped) closes the
                // two-concurrent-finish race.
                use crate::db::CreateOutcome;
                match self
                    .db
                    .users()
                    .create_if_absent(&StoredUser {
                        uuid,
                        username: username.clone(),
                        credentials: vec![Credential {
                            passkey,
                            label: "passkey".into(),
                            added_at: now_secs(),
                        }],
                        email,
                    })
                    .await?
                {
                    CreateOutcome::Created => Ok((username, PasskeyMode::Register)),
                    CreateOutcome::UsernameTaken => Err(PasskeyError::UsernameTaken),
                    CreateOutcome::EmailTaken => Err(PasskeyError::EmailTaken),
                }
            }
            Ceremony::Authenticate(state) => {
                let cred: PublicKeyCredential = serde_json::from_str(credential_json)?;
                let (uuid, _cred_id) = self.webauthn.identify_discoverable_authentication(&cred)?;
                let user = self
                    .db
                    .users()
                    .by_uuid(uuid)
                    .await?
                    .ok_or(PasskeyError::NoSuchUser)?;
                let keys: Vec<DiscoverableKey> = user
                    .credentials
                    .iter()
                    .map(|c| DiscoverableKey::from(&c.passkey))
                    .collect();
                self.webauthn
                    .finish_discoverable_authentication(&cred, state, &keys)?;
                Ok((user.username, PasskeyMode::Authenticate))
            }
            // finish_add handles this; a bare finish for it is a client mistake.
            Ceremony::AddCredential(..) => Err(PasskeyError::UnknownFlow),
        }
    }

    pub async fn email(&self, username: &str) -> Result<Option<String>, PasskeyError> {
        Ok(self.db.users().get(username).await?.and_then(|u| u.email))
    }

    /// `None`/blank clears it; validated + unique across accounts.
    pub async fn set_email(&self, username: &str, email: Option<&str>) -> Result<(), PasskeyError> {
        let email = match email.map(str::trim).filter(|e| !e.is_empty()) {
            Some(e) if valid_email(e) => Some(e.to_string()),
            Some(_) => return Err(PasskeyError::InvalidEmail),
            None => None,
        };
        use crate::db::EmailOutcome;
        match self.db.users().set_email(username, email).await? {
            EmailOutcome::Updated => Ok(()),
            EmailOutcome::Taken => Err(PasskeyError::EmailTaken),
            EmailOutcome::NoSuchUser => Err(PasskeyError::NoSuchUser),
        }
    }

    /// An accountless caller (e.g. the service token) has none.
    pub async fn credentials(&self, username: &str) -> Result<Vec<CredentialInfo>, PasskeyError> {
        let Some(user) = self.db.users().get(username).await? else {
            return Ok(Vec::new());
        };
        Ok(user
            .credentials
            .iter()
            .map(|c| CredentialInfo {
                id: c.id(),
                label: c.label.clone(),
                added_at: c.added_at,
            })
            .collect())
    }

    /// Register an additional passkey. Current credentials are excluded so an
    /// authenticator already on file can't be double-registered.
    pub async fn begin_add(&self, username: &str) -> Result<(String, String), PasskeyError> {
        self.sweep_pending();
        if self.pending.lock().expect("pending poisoned").len() >= MAX_PENDING {
            return Err(PasskeyError::TooManyPending);
        }
        let user = self
            .db
            .users()
            .get(username)
            .await?
            .ok_or(PasskeyError::NoSuchUser)?;
        let exclude: Vec<CredentialID> = user
            .credentials
            .iter()
            .map(|c| c.passkey.cred_id().clone())
            .collect();
        let (mut ccr, state) = self.webauthn.start_passkey_registration(
            user.uuid,
            &user.username,
            &user.username,
            Some(exclude),
        )?;
        // Same discoverable-credential requirement as fresh registration.
        let want_resident = AuthenticatorSelectionCriteria {
            resident_key: Some(ResidentKeyRequirement::Required),
            require_resident_key: true,
            ..ccr
                .public_key
                .authenticator_selection
                .take()
                .unwrap_or_default()
        };
        ccr.public_key.authenticator_selection = Some(want_resident);
        let flow_id = crate::random_hex(16)?;
        self.insert_pending(
            flow_id.clone(),
            Ceremony::AddCredential(user.username, state),
        );
        Ok((flow_id, serde_json::to_string(&ccr)?))
    }

    pub async fn finish_add(
        &self,
        flow_id: &str,
        credential_json: &str,
        label: &str,
        caller: &str,
    ) -> Result<CredentialInfo, PasskeyError> {
        let pending = self
            .pending
            .lock()
            .expect("pending poisoned")
            .remove(flow_id)
            .ok_or(PasskeyError::UnknownFlow)?;
        let Ceremony::AddCredential(username, state) = pending.ceremony else {
            return Err(PasskeyError::UnknownFlow);
        };
        // A leaked flow_id can't graft a passkey onto another account.
        if username != caller {
            return Err(PasskeyError::UnknownFlow);
        }
        let reg: RegisterPublicKeyCredential = serde_json::from_str(credential_json)?;
        let passkey = self.webauthn.finish_passkey_registration(&reg, &state)?;
        let mut user = self
            .db
            .users()
            .get(&username)
            .await?
            .ok_or(PasskeyError::NoSuchUser)?;
        let credential = Credential {
            passkey,
            label: clean_label(label),
            added_at: now_secs(),
        };
        let info = CredentialInfo {
            id: credential.id(),
            label: credential.label.clone(),
            added_at: credential.added_at,
        };
        // Idempotency guard: never store a duplicate id.
        if user.credentials.iter().any(|c| c.id() == info.id) {
            return Ok(info);
        }
        user.credentials.push(credential);
        self.db.users().upsert(&user).await?;
        Ok(info)
    }

    /// Refused if it's the account's last one (would lock the user out).
    pub async fn remove(&self, username: &str, id: &str) -> Result<(), PasskeyError> {
        let mut user = self
            .db
            .users()
            .get(username)
            .await?
            .ok_or(PasskeyError::NoSuchUser)?;
        if !user.credentials.iter().any(|c| c.id() == id) {
            return Err(PasskeyError::NoSuchCredential);
        }
        if user.credentials.len() <= 1 {
            return Err(PasskeyError::LastCredential);
        }
        user.credentials.retain(|c| c.id() != id);
        self.db.users().upsert(&user).await?;
        Ok(())
    }

    fn insert_pending(&self, flow_id: String, ceremony: Ceremony) {
        self.pending.lock().expect("pending poisoned").insert(
            flow_id,
            Pending {
                created: Instant::now(),
                ceremony,
            },
        );
    }

    fn sweep_pending(&self) {
        self.pending
            .lock()
            .expect("pending poisoned")
            .retain(|_, p| p.created.elapsed() < PENDING_TTL);
    }
}

fn valid_username(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 32
        && s.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
}

/// Light `local@domain.tld` sanity check, not full RFC 5322.
fn valid_email(s: &str) -> bool {
    let s = s.trim();
    if s.is_empty() || s.len() > 254 || s.contains(char::is_whitespace) {
        return false;
    }
    let mut parts = s.splitn(2, '@');
    let local = parts.next().unwrap_or("");
    let domain = parts.next().unwrap_or("");
    !local.is_empty()
        && domain.len() >= 3
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
}

fn clean_label(label: &str) -> String {
    let label = label.trim();
    if label.is_empty() {
        "passkey".to_string()
    } else {
        label.chars().take(64).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_validation() {
        for ok in ["a@b.co", "First.Last@Example.com", "x@sub.domain.io"] {
            assert!(valid_email(ok), "{ok} should be valid");
        }
        for bad in ["", "nope", "@b.co", "a@b", "a@.com", "a b@c.co", "a@b."] {
            assert!(!valid_email(bad), "{bad:?} should be rejected");
        }
    }
}

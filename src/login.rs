//! Device-flow sign-in for tools: `begin` -> browser `describe`/`approve` ->
//! the tool's next `poll` gets a minted token. All in-memory and short-lived.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const EXPIRES_IN: Duration = Duration::from_secs(600);
pub const POLL_INTERVAL_SECS: i32 = 3;
/// `begin` is unauthenticated, so bound the memory it can pin.
const MAX_PENDING: usize = 4096;
const MAX_LABEL: usize = 128;

#[derive(Debug)]
pub enum BeginError {
    TooManyPending,
    Rng(getrandom::Error),
}

#[derive(Clone)]
enum State {
    Pending,
    Approved { token: String, username: String },
    Denied,
}

struct Pending {
    user_code: String,
    label: String,
    created: Instant,
    state: State,
}

impl Pending {
    fn expired(&self) -> bool {
        self.created.elapsed() > EXPIRES_IN
    }
}

pub enum Poll {
    Pending,
    Approved { token: String, username: String },
    Denied,
    Expired,
}

pub struct Describe {
    pub label: String,
    /// One of `pending` / `approved` / `denied` / `expired`.
    pub status: &'static str,
}

pub enum Approve<E> {
    Approved,
    /// Unknown / expired / already-decided code — nothing was minted.
    NotPending,
    /// Mint closure failed; nothing stored, request left pending for retry.
    MintFailed(E),
}

pub struct Logins {
    verification_base: String,
    by_device: Mutex<HashMap<String, Pending>>,
    /// `user_code` -> `device_code`.
    by_user: Mutex<HashMap<String, String>>,
    /// Generation counter; `WatchLogin` re-polls on each bump. (`gen` is a
    /// reserved keyword in edition 2024.)
    decision_gen: tokio::sync::watch::Sender<u64>,
}

pub struct Begun {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub interval_secs: i32,
    pub expires_in_secs: i32,
}

impl Logins {
    /// `verification_base` is the browser origin (approval page at `<base>/authorize`).
    pub fn new(verification_base: impl Into<String>) -> Self {
        let (decision_gen, _) = tokio::sync::watch::channel(0);
        Self {
            verification_base: verification_base.into(),
            by_device: Mutex::new(HashMap::new()),
            by_user: Mutex::new(HashMap::new()),
            decision_gen,
        }
    }

    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<u64> {
        self.decision_gen.subscribe()
    }

    fn bump(&self) {
        self.decision_gen.send_modify(|g| *g = g.wrapping_add(1));
    }

    pub fn begin(&self, label: &str) -> Result<Begun, BeginError> {
        self.sweep_expired();
        if self.by_device.lock().expect("login store poisoned").len() >= MAX_PENDING {
            return Err(BeginError::TooManyPending);
        }
        let device_code = crate::random_hex(32).map_err(BeginError::Rng)?;
        let user_code = user_code().map_err(BeginError::Rng)?;
        let label = label.trim();
        let label = if label.is_empty() {
            "a device".to_string()
        } else {
            label.chars().take(MAX_LABEL).collect()
        };
        let base = self.verification_base.trim_end_matches('/');
        let verification_uri = format!("{base}/authorize?code={user_code}");
        // Track by the normalized code so lookups always match.
        let key = normalize(&user_code);
        self.by_user
            .lock()
            .expect("login store poisoned")
            .insert(key.clone(), device_code.clone());
        self.by_device.lock().expect("login store poisoned").insert(
            device_code.clone(),
            Pending {
                user_code: key,
                label,
                created: Instant::now(),
                state: State::Pending,
            },
        );
        Ok(Begun {
            device_code,
            user_code,
            verification_uri,
            interval_secs: POLL_INTERVAL_SECS,
            expires_in_secs: EXPIRES_IN.as_secs() as i32,
        })
    }

    /// An approved request yields its token exactly once (the record is consumed).
    pub fn poll(&self, device_code: &str) -> Poll {
        let mut by_device = self.by_device.lock().expect("login store poisoned");
        let Some(pending) = by_device.get(device_code) else {
            return Poll::Expired;
        };
        if pending.expired() {
            let user_code = pending.user_code.clone();
            by_device.remove(device_code);
            self.by_user
                .lock()
                .expect("login store poisoned")
                .remove(&user_code);
            return Poll::Expired;
        }
        match &pending.state {
            State::Pending => Poll::Pending,
            State::Denied => Poll::Denied,
            State::Approved { token, username } => {
                let out = Poll::Approved {
                    token: token.clone(),
                    username: username.clone(),
                };
                let user_code = pending.user_code.clone();
                by_device.remove(device_code);
                self.by_user
                    .lock()
                    .expect("login store poisoned")
                    .remove(&user_code);
                out
            }
        }
    }

    pub fn describe(&self, user_code: &str) -> Option<Describe> {
        let device_code = self
            .by_user
            .lock()
            .expect("login store poisoned")
            .get(&normalize(user_code))?
            .clone();
        let by_device = self.by_device.lock().expect("login store poisoned");
        let pending = by_device.get(&device_code)?;
        let status = if pending.expired() {
            "expired"
        } else {
            match pending.state {
                State::Pending => "pending",
                State::Approved { .. } => "approved",
                State::Denied => "denied",
            }
        };
        Some(Describe {
            label: pending.label.clone(),
            status,
        })
    }

    /// `mint` runs exactly once, only after the entry is confirmed pending and
    /// live, so a bad/expired/decided code never mints an orphan token.
    pub fn approve<F, E>(&self, user_code: &str, username: String, mint: F) -> Approve<E>
    where
        F: FnOnce() -> Result<String, E>,
    {
        let Some(device_code) = self
            .by_user
            .lock()
            .expect("login store poisoned")
            .get(&normalize(user_code))
            .cloned()
        else {
            return Approve::NotPending;
        };
        let mut by_device = self.by_device.lock().expect("login store poisoned");
        match by_device.get_mut(&device_code) {
            Some(p) if !p.expired() && matches!(p.state, State::Pending) => {
                // Mint only now the transition is assured; on failure store nothing.
                let token = match mint() {
                    Ok(t) => t,
                    Err(e) => return Approve::MintFailed(e),
                };
                p.state = State::Approved { token, username };
                drop(by_device);
                self.bump();
                Approve::Approved
            }
            _ => Approve::NotPending,
        }
    }

    /// Returns `true` if it was pending and live.
    pub fn deny(&self, user_code: &str) -> bool {
        let denied = self.set_state(user_code, State::Denied);
        if denied {
            self.bump();
        }
        denied
    }

    fn set_state(&self, user_code: &str, next: State) -> bool {
        let Some(device_code) = self
            .by_user
            .lock()
            .expect("login store poisoned")
            .get(&normalize(user_code))
            .cloned()
        else {
            return false;
        };
        let mut by_device = self.by_device.lock().expect("login store poisoned");
        match by_device.get_mut(&device_code) {
            Some(p) if !p.expired() && matches!(p.state, State::Pending) => {
                p.state = next;
                true
            }
            _ => false,
        }
    }

    fn sweep_expired(&self) {
        let mut by_device = self.by_device.lock().expect("login store poisoned");
        let mut by_user = self.by_user.lock().expect("login store poisoned");
        by_device.retain(|_, p| {
            let keep = !p.expired();
            if !keep {
                by_user.remove(&p.user_code);
            }
            keep
        });
    }
}

/// Short code like `WDJB-MJHT` from an unambiguous alphabet (no 0/O/1/I).
fn user_code() -> Result<String, getrandom::Error> {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut raw = [0u8; 8];
    getrandom::fill(&mut raw)?;
    let mut s = String::with_capacity(9);
    for (i, b) in raw.iter().enumerate() {
        if i == 4 {
            s.push('-');
        }
        s.push(ALPHABET[(*b as usize) % ALPHABET.len()] as char);
    }
    Ok(s)
}

fn normalize(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn begin_describe_approve_poll_roundtrip() {
        let logins = Logins::new("https://saros.inex.rs");
        let begun = logins.begin("studio on box").unwrap();
        assert!(begun.verification_uri.contains(&begun.user_code));
        assert!(matches!(logins.poll(&begun.device_code), Poll::Pending));

        let d = logins.describe(&begun.user_code.to_lowercase()).unwrap();
        assert_eq!(d.label, "studio on box");
        assert_eq!(d.status, "pending");
        assert!(matches!(
            logins.approve(&begun.user_code, "sacha".into(), || Ok::<_, ()>(
                "tok".into()
            )),
            Approve::Approved
        ));

        match logins.poll(&begun.device_code) {
            Poll::Approved { token, username } => {
                assert_eq!(token, "tok");
                assert_eq!(username, "sacha");
            }
            _ => panic!("expected approved"),
        }
        assert!(matches!(logins.poll(&begun.device_code), Poll::Expired));
    }

    #[test]
    fn deny_is_reported() {
        let logins = Logins::new("http://localhost:5173");
        let begun = logins.begin("cli").unwrap();
        assert!(logins.deny(&begun.user_code));
        assert!(matches!(logins.poll(&begun.device_code), Poll::Denied));
        let mut minted = false;
        assert!(matches!(
            logins.approve(&begun.user_code, "u".into(), || {
                minted = true;
                Ok::<_, ()>("t".into())
            }),
            Approve::NotPending
        ));
        assert!(!minted, "a non-pending approve must not mint");
    }

    #[test]
    fn unknown_device_reads_as_expired() {
        let logins = Logins::new("http://localhost:5173");
        assert!(matches!(logins.poll("nope"), Poll::Expired));
        assert!(logins.describe("ZZZZ-ZZZZ").is_none());
    }
}

//! The firmware store: disk is the source of truth. Each version is a
//! self-contained dir (`manifest.json` = the protojson `Firmware` wire body +
//! its blobs); an in-memory [`Index`](index::Index) serves reads, the optional
//! S3/Tigris [`Mirror`] serves blob egress, and the auth [`Db`] enriches
//! download counts. Split by concern: [`blobs`] (content-addressed pool +
//! egress + GC), [`catalog`] (validate/publish/stage/review), [`index`]
//! (scan/reload + atomic fs plumbing).
//!
//! Untrusted strings are parsed into [`Sha256Hex`] / [`DeviceId`] /
//! [`Version`] at the boundary — anything that reaches a filesystem path or
//! bucket key is valid by construction.

mod blobs;
mod catalog;
mod index;
#[cfg(test)]
mod tests;

pub use blobs::DownloadOutcome;

use std::path::PathBuf;
use std::sync::Arc;

use parking_lot::RwLock;
use sha2::{Digest, Sha256};

use inex_protobufs::buffa::inex::saros::v1::Firmware;

use crate::db::{Db, DbError};
use crate::mirror::Mirror;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("{0}")]
    InvalidArgument(String),
    #[error("firmware {0} not found")]
    NotFound(Key),
    #[error("firmware {0} is already published (versions are immutable)")]
    AlreadyExists(Key),
    #[error("device {0} is not in the device catalogue")]
    UnknownDevice(String),
    #[error("blob {sha256} ({file}) is not uploaded — upload it before publishing")]
    MissingBlob { sha256: Sha256Hex, file: String },
    #[error("{0}")]
    Quota(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Db(#[from] DbError),
    #[error("manifest decode: {0}")]
    Decode(String),
}

/// A validated 64-char lowercase-hex SHA-256 — the only form that may touch a
/// blob path or bucket key (the traversal guard lives in the constructor).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Sha256Hex(String);

impl Sha256Hex {
    /// The digest of `data` — construction from actual bytes, always valid.
    pub fn digest_of(data: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(data)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for Sha256Hex {
    type Error = StoreError;
    fn try_from(s: &str) -> Result<Self, StoreError> {
        if s.len() != 64
            || !s
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(StoreError::InvalidArgument(format!(
                "sha256 must be 64 lowercase hex chars, got {s:?}"
            )));
        }
        Ok(Self(s.to_string()))
    }
}

impl std::fmt::Display for Sha256Hex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<Sha256Hex> for String {
    fn from(s: Sha256Hex) -> String {
        s.0
    }
}

/// A catalogue device id, restricted to the path-safe id alphabet.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DeviceId(String);

impl DeviceId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for DeviceId {
    type Error = StoreError;
    fn try_from(s: &str) -> Result<Self, StoreError> {
        let ok = !s.is_empty()
            && s.len() <= 100
            && !s.starts_with('.')
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-');
        if ok {
            Ok(Self(s.to_string()))
        } else {
            Err(StoreError::InvalidArgument(format!(
                "{s:?} must be 1-100 chars of [a-zA-Z0-9._-], not starting with '.'"
            )))
        }
    }
}

impl std::fmt::Display for DeviceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A dotted-numeric firmware version (`3.23`, `0.2.1`) — unambiguous ordering
/// and path-safe; pre-release/channel info belongs in tags.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version(String);

impl Version {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for Version {
    type Error = StoreError;
    fn try_from(v: &str) -> Result<Self, StoreError> {
        let ok = !v.is_empty()
            && v.len() <= 100
            && v.split('.')
                .all(|seg| !seg.is_empty() && seg.bytes().all(|b| b.is_ascii_digit()));
        if ok {
            Ok(Self(v.to_string()))
        } else {
            Err(StoreError::InvalidArgument(format!(
                "version {v:?} must be dotted-numeric (e.g. 3.23) — use tags for channels"
            )))
        }
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A published firmware's immutable coordinates, valid by construction.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Key {
    pub device: DeviceId,
    pub version: Version,
}

impl Key {
    pub fn of(device: &str, version: &str) -> Result<Self, StoreError> {
        Ok(Self {
            device: DeviceId::try_from(device)?,
            version: Version::try_from(version)?,
        })
    }

    /// The coordinates a manifest claims, parsed and validated.
    fn parse(fw: &Firmware) -> Result<Self, StoreError> {
        let get = |s: &Option<String>| s.clone().filter(|s| !s.is_empty());
        let (device, version) = get(&fw.device_id).zip(get(&fw.version)).ok_or_else(|| {
            StoreError::InvalidArgument("firmware.device_id/version are required".into())
        })?;
        Self::of(&device, &version)
    }
}

impl std::fmt::Display for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} v{}", self.device, self.version)
    }
}

/// Catalogue-wide counts for the admin panel.
#[derive(Debug, Clone, Default)]
pub struct Stats {
    pub users: u64,
    /// Distinct catalogue devices with at least one published firmware.
    pub devices: u64,
    pub firmware: u64,
    pub staged: u64,
    /// Distinct blob shas referenced by live or staged firmware.
    pub blobs: u64,
    pub blob_bytes: u64,
}

pub struct Store {
    root: PathBuf,
    max_blob_bytes: usize,
    index: RwLock<index::Index>,
    notify: tokio::sync::watch::Sender<u64>,
    db: Arc<Db>,
    /// Optional S3/Tigris egress mirror; when set, blob bytes are served from it.
    mirror: Option<Mirror>,
}

impl Store {
    pub fn open(
        root: impl Into<PathBuf>,
        max_blob_bytes: usize,
        db: Arc<Db>,
        mirror: Option<Mirror>,
    ) -> Result<Self, StoreError> {
        let root = root.into();
        for sub in ["firmware", "staging", "incoming"] {
            std::fs::create_dir_all(root.join(sub))?;
        }
        index::gc_tmp_artifacts(&root);
        let index = index::scan(&root)?;
        Ok(Self {
            root,
            max_blob_bytes,
            index: RwLock::new(index),
            notify: tokio::sync::watch::Sender::new(0),
            db,
            mirror,
        })
    }

    /// Firmware-change notifications (generation counter; re-snapshot on change).
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<u64> {
        self.notify.subscribe()
    }

    fn bump(&self) {
        self.notify.send_modify(|g| *g = g.wrapping_add(1));
    }

    fn firmware_dir(&self, key: &Key) -> PathBuf {
        self.root
            .join("firmware")
            .join(key.device.as_str())
            .join(key.version.as_str())
    }
    fn staging_dir(&self, key: &Key) -> PathBuf {
        self.root
            .join("staging")
            .join(key.device.as_str())
            .join(key.version.as_str())
    }
    fn incoming(&self, sha: &Sha256Hex) -> PathBuf {
        self.root.join("incoming").join(sha.as_str())
    }
}

/// A blob `file` must be a plain filename — no separators or `..` traversal.
pub(crate) fn check_basename(file: &str) -> Result<(), StoreError> {
    let ok = !file.is_empty()
        && file.len() <= 200
        && file != "manifest.json"
        && file != "submitted-by"
        && !file.contains('/')
        && !file.contains('\\')
        && !file.contains("..");
    if ok {
        Ok(())
    } else {
        Err(StoreError::InvalidArgument(format!(
            "blob file {file:?} must be a plain filename (no separators, not a reserved name)"
        )))
    }
}

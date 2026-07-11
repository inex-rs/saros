//! The content-addressed blob pool: uploads land in `incoming/<sha>`, egress
//! goes via the mirror when configured, and two GC paths reclaim strictly
//! bounded sets (owned incoming copies after publish; old unreferenced uploads).

use std::collections::HashSet;
use std::time::{Duration, SystemTime};

use super::index::{rebuild_blob_paths, write_atomic};
use super::{Sha256Hex, Store, StoreError};

/// How a blob's bytes reach the client: inline, or a mirror URL to fetch.
pub enum DownloadOutcome {
    Bytes(Vec<u8>),
    Url(String),
}

impl Store {
    pub async fn put_blob(&self, content: &[u8]) -> Result<Sha256Hex, StoreError> {
        if content.is_empty() {
            return Err(StoreError::InvalidArgument("content required".into()));
        }
        if content.len() > self.max_blob_bytes {
            return Err(StoreError::InvalidArgument(format!(
                "content exceeds {}-byte cap",
                self.max_blob_bytes
            )));
        }
        let sha = Sha256Hex::digest_of(content);
        let path = self.incoming(&sha);
        if !path.exists() {
            let (dst, data) = (path.clone(), content.to_vec());
            tokio::task::spawn_blocking(move || write_atomic(&dst, &data))
                .await
                .map_err(|e| std::io::Error::other(e.to_string()))??;
        }
        self.index
            .write()
            .blob_paths
            .entry(sha.clone())
            .or_insert(path);
        Ok(sha)
    }

    pub async fn get_blob(&self, sha: &Sha256Hex) -> Result<Option<Vec<u8>>, StoreError> {
        let path = self.index.read().blob_paths.get(sha).cloned();
        let Some(path) = path else { return Ok(None) };
        let want = sha.clone();
        let bytes = tokio::task::spawn_blocking(move || -> Result<Vec<u8>, StoreError> {
            let bytes = std::fs::read(&path)?;
            // Re-verify content-addressing on serve: refuse mismatched bytes so bit-rot
            // or a lying external manifest can't poison downloads (or the mirror).
            if Sha256Hex::digest_of(&bytes) != want {
                return Err(StoreError::Io(std::io::Error::other(format!(
                    "blob {want} failed content verification (on-disk bytes don't match its sha)"
                ))));
            }
            Ok(bytes)
        })
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))??;
        Ok(Some(bytes))
    }

    pub async fn stat_blob(&self, sha: &Sha256Hex) -> Result<Option<u64>, StoreError> {
        let path = self.index.read().blob_paths.get(sha).cloned();
        match path {
            Some(p) => Ok(Some(std::fs::metadata(p)?.len())),
            None => Ok(None),
        }
    }

    /// Authorize a download of a referenced blob: a mirror URL (lazily mirroring
    /// first) when a mirror is set, else inline bytes. `None` = not referenced.
    pub async fn download(&self, sha: &Sha256Hex) -> Result<Option<DownloadOutcome>, StoreError> {
        // Serve only blobs a live/staged manifest points at — no minting a mirror
        // URL for an arbitrary bucket key.
        if self.stat_blob(sha).await?.is_none() {
            return Ok(None);
        }
        let Some(mirror) = &self.mirror else {
            return self.local_bytes(sha).await;
        };
        // The mirror is an optimization: on ANY mirror error, fall back to the
        // authoritative local bytes inline.
        match mirror.has(sha.as_str()).await {
            Ok(true) => {}
            Ok(false) => {
                // get_blob re-verifies content-addressing, so only verified bytes
                // are ever mirrored (the mirror can't be poisoned).
                match self.get_blob(sha).await? {
                    Some(bytes) => {
                        if let Err(e) = mirror.put_if_absent(sha.as_str(), &bytes).await {
                            tracing::warn!(sha = %sha, error = %e, "mirror put failed; serving local bytes");
                            return Ok(Some(DownloadOutcome::Bytes(bytes)));
                        }
                    }
                    None => return Ok(None),
                }
            }
            Err(e) => {
                tracing::warn!(sha = %sha, error = %e, "mirror head failed; serving local bytes");
                return self.local_bytes(sha).await;
            }
        }
        match mirror.url(sha.as_str()).await {
            Ok(url) => Ok(Some(DownloadOutcome::Url(url))),
            Err(e) => {
                tracing::warn!(sha = %sha, error = %e, "mirror url failed; serving local bytes");
                self.local_bytes(sha).await
            }
        }
    }

    /// Serve the authoritative local bytes inline. `None` = absent locally.
    async fn local_bytes(&self, sha: &Sha256Hex) -> Result<Option<DownloadOutcome>, StoreError> {
        Ok(self.get_blob(sha).await?.map(DownloadOutcome::Bytes))
    }

    /// Drop incoming-pool blobs now owned by a live/staged version dir.
    pub(super) fn sweep_incoming(&self) {
        let incoming = self.root.join("incoming");
        let Ok(entries) = std::fs::read_dir(&incoming) else {
            return;
        };
        let owned: HashSet<Sha256Hex> = {
            let index = self.index.read();
            index
                .blob_paths
                .iter()
                .filter(|(_, p)| !p.starts_with(&incoming))
                .map(|(sha, _)| sha.clone())
                .collect()
        };
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str()
                && let Ok(sha) = Sha256Hex::try_from(name)
                && owned.contains(&sha)
            {
                let _ = std::fs::remove_file(entry.path());
            }
        }
        let mut index = self.index.write();
        rebuild_blob_paths(&mut index, &self.root);
    }

    /// Reclaim abandoned uploads: remove an incoming file only when it is BOTH
    /// older than `max_age` AND unreferenced by a live/staged manifest (a staged
    /// submission holds its blobs here until approved). Best-effort; returns the count.
    pub fn gc_incoming(&self, max_age: Duration) -> Result<usize, StoreError> {
        // Saturate to the epoch for an absurd max_age (→ keep everything, the safe direction).
        let cutoff = SystemTime::now()
            .checked_sub(max_age)
            .unwrap_or(SystemTime::UNIX_EPOCH);
        self.gc_incoming_before(cutoff)
    }

    /// [`gc_incoming`](Self::gc_incoming) with the cutoff supplied directly (tests drive it deterministically).
    pub(super) fn gc_incoming_before(&self, cutoff: SystemTime) -> Result<usize, StoreError> {
        let incoming = self.root.join("incoming");
        // Reference set = manifest blobs only; blob_paths also indexes bare incoming
        // files, which would wrongly protect every upload.
        let referenced: HashSet<String> = {
            let index = self.index.read();
            index
                .live
                .values()
                .flat_map(|fw| fw.blobs.iter())
                .chain(index.staged.values().flat_map(|s| s.firmware.blobs.iter()))
                .filter_map(|b| b.sha256.clone())
                .collect()
        };
        let entries = match std::fs::read_dir(&incoming) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e.into()),
        };
        let mut deleted = 0;
        for entry in entries.flatten() {
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            if name.contains(".tmp-") {
                continue;
            }
            if referenced.contains(&name) {
                continue;
            }
            let path = entry.path();
            let meta = match entry.metadata() {
                Ok(m) if m.is_file() => m,
                Ok(_) => continue,
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e, "gc-incoming: stat failed — keeping");
                    continue;
                }
            };
            // Recent → in-flight upload; keep. Absent mtime treated as recent (never delete on missing metadata).
            match meta.modified() {
                Ok(mtime) if mtime >= cutoff => continue,
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e, "gc-incoming: mtime unavailable — keeping");
                    continue;
                }
                Ok(_) => {}
            }
            match std::fs::remove_file(&path) {
                Ok(()) => {
                    deleted += 1;
                    tracing::info!(path = %path.display(), "gc-incoming: reclaimed abandoned upload");
                }
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e, "gc-incoming: remove failed")
                }
            }
        }
        if deleted > 0 {
            let mut index = self.index.write();
            rebuild_blob_paths(&mut index, &self.root);
        }
        Ok(deleted)
    }
}

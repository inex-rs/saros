//! The in-memory index of the on-disk tree, the scan that (re)builds it, and
//! the atomic-write/fsync plumbing everything durable goes through. External
//! drops are untrusted: dir names and manifest blob fields are parsed on scan,
//! and anything that fails validation is skipped with a warning.

use std::collections::{BTreeMap, HashMap};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use inex_protobufs::buffa::inex::saros::v1::Firmware;

use super::{Key, Sha256Hex, Store, StoreError, check_basename};

#[derive(Clone)]
pub(super) struct Staged {
    pub(super) firmware: Firmware,
    pub(super) submitted_by: String,
}

#[derive(Default)]
pub(super) struct Index {
    pub(super) live: BTreeMap<Key, Firmware>,
    pub(super) staged: BTreeMap<Key, Staged>,
    /// sha256 → some on-disk copy of those bytes (any copy; content-addressed).
    pub(super) blob_paths: HashMap<Sha256Hex, PathBuf>,
}

impl Store {
    /// Re-scan disk and swap in a fresh index so externally-dropped versions go
    /// live without a restart; returns whether the live/staged set changed
    /// (bumps watchers if so).
    pub fn reload(&self) -> Result<bool, StoreError> {
        // Hold the write lock across scan+swap so a concurrent publish's rename+insert
        // is never transiently dropped by the swap.
        let mut index = self.index.write();
        let fresh = scan(&self.root)?;
        let changed = !index.live.keys().eq(fresh.live.keys())
            || !index.staged.keys().eq(fresh.staged.keys());
        *index = fresh;
        drop(index);
        if changed {
            self.bump();
        }
        Ok(changed)
    }
}

pub(super) fn scan(root: &Path) -> Result<Index, StoreError> {
    let mut index = Index::default();
    for (key, dir) in version_dirs(&root.join("firmware")) {
        match read_manifest(&dir.join("manifest.json")) {
            Ok(fw) => {
                index.live.insert(key, fw);
            }
            Err(e) => tracing::warn!(dir = %dir.display(), error = %e, "skipping bad manifest"),
        }
    }
    for (key, dir) in version_dirs(&root.join("staging")) {
        match read_manifest(&dir.join("manifest.json")) {
            Ok(fw) => {
                let submitted_by = std::fs::read_to_string(dir.join("submitted-by"))
                    .unwrap_or_default()
                    .trim()
                    .to_string();
                index.staged.insert(
                    key,
                    Staged {
                        firmware: fw,
                        submitted_by,
                    },
                );
            }
            Err(e) => {
                tracing::warn!(dir = %dir.display(), error = %e, "skipping bad staged manifest")
            }
        }
    }
    rebuild_blob_paths(&mut index, root);
    Ok(index)
}

/// Rebuild the sha→path map: version-dir copies (authoritative) win over
/// incoming-pool copies. Manifest blob fields are external input — entries
/// with an invalid sha or filename are skipped, never mapped to a path.
pub(super) fn rebuild_blob_paths(index: &mut Index, root: &Path) {
    let mut map: HashMap<Sha256Hex, PathBuf> = HashMap::new();
    if let Ok(entries) = std::fs::read_dir(root.join("incoming")) {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str()
                && let Ok(sha) = Sha256Hex::try_from(name)
            {
                map.insert(sha, entry.path());
            }
        }
    }
    let mut add = |kind: &str, key: &Key, fw: &Firmware| {
        let dir = root
            .join(kind)
            .join(key.device.as_str())
            .join(key.version.as_str());
        for b in &fw.blobs {
            let (Ok(sha), Some(file)) = (
                Sha256Hex::try_from(b.sha256.as_deref().unwrap_or_default()),
                b.filename.as_deref(),
            ) else {
                tracing::warn!(key = %key, "manifest blob with invalid sha/filename — not indexed");
                continue;
            };
            if check_basename(file).is_err() {
                tracing::warn!(key = %key, file, "manifest blob with unsafe filename — not indexed");
                continue;
            }
            map.insert(sha, dir.join(file));
        }
    };
    for (key, fw) in &index.live {
        add("firmware", key, fw);
    }
    for (key, s) in &index.staged {
        add("staging", key, &s.firmware);
    }
    index.blob_paths = map;
}

/// `<base>/<device>/<version>/` dirs that contain a `manifest.json`, with the
/// dir names parsed into a [`Key`] (invalid names are skipped with a warning).
fn version_dirs(base: &Path) -> Vec<(Key, PathBuf)> {
    let mut out = Vec::new();
    let Ok(devices) = std::fs::read_dir(base) else {
        return out;
    };
    for dev in devices.flatten().filter(|e| e.path().is_dir()) {
        let Some(device) = dev.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let Ok(versions) = std::fs::read_dir(dev.path()) else {
            continue;
        };
        for ver in versions.flatten().filter(|e| e.path().is_dir()) {
            let Some(version) = ver.file_name().to_str().map(str::to_string) else {
                continue;
            };
            if version.starts_with(".tmp-") {
                continue;
            }
            if !ver.path().join("manifest.json").is_file() {
                continue;
            }
            match Key::of(&device, &version) {
                Ok(key) => out.push((key, ver.path())),
                Err(e) => {
                    tracing::warn!(dir = %ver.path().display(), error = %e, "skipping invalid version dir")
                }
            }
        }
    }
    out
}

fn read_manifest(path: &Path) -> Result<Firmware, StoreError> {
    let bytes = std::fs::read(path)?;
    serde_json::from_slice(&bytes).map_err(|e| StoreError::Decode(e.to_string()))
}

/// Write via temp file + rename (no torn reads), fsync'd (file then dir) so an
/// acked write survives a crash.
pub(super) fn write_atomic(path: &Path, content: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension(format!("tmp-{}", uuid::Uuid::new_v4()));
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(content)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    if let Some(parent) = path.parent() {
        fsync_dir(parent)?;
    }
    Ok(())
}

/// fsync a directory so a `rename` into/out of it is durable, not just file
/// contents. No-op on non-unix (opening a dir for fsync isn't portable).
#[cfg(unix)]
pub(super) fn fsync_dir(path: &Path) -> std::io::Result<()> {
    std::fs::File::open(path)?.sync_all()
}
#[cfg(not(unix))]
pub(super) fn fsync_dir(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

pub(super) fn fsync_file(path: &Path) -> std::io::Result<()> {
    std::fs::File::open(path)?.sync_all()
}

/// Reap crash-left `.tmp-*` version dirs and `incoming/<sha>.tmp-*` files.
/// Open-time only (single-threaded → can't race a live publish's temp dir).
pub(super) fn gc_tmp_artifacts(root: &Path) {
    for base in ["firmware", "staging"] {
        let Ok(devices) = std::fs::read_dir(root.join(base)) else {
            continue;
        };
        for dev in devices.flatten().filter(|e| e.path().is_dir()) {
            let Ok(entries) = std::fs::read_dir(dev.path()) else {
                continue;
            };
            for entry in entries.flatten() {
                if entry
                    .file_name()
                    .to_str()
                    .is_some_and(|n| n.starts_with(".tmp-"))
                    && let Err(e) = std::fs::remove_dir_all(entry.path())
                {
                    tracing::warn!(path = %entry.path().display(), error = %e, "gc: stale tmp version dir");
                }
            }
        }
    }
    if let Ok(entries) = std::fs::read_dir(root.join("incoming")) {
        for entry in entries.flatten() {
            if entry
                .file_name()
                .to_str()
                .is_some_and(|n| n.contains(".tmp-"))
                && let Err(e) = std::fs::remove_file(entry.path())
            {
                tracing::warn!(path = %entry.path().display(), error = %e, "gc: stale incoming tmp");
            }
        }
    }
}

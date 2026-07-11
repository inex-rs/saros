//! The catalogue and its state machine: validate → publish (or stage → review),
//! plus the read side (list/devices/stats). Version dirs are written as atomic
//! units; approval is an atomic dir rename.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

use inex_protobufs::buffa::inex::saros::v1::{
    BlobSlot, Device, Firmware, FirmwareBlob, Platform, StagedFirmware,
};

use super::index::{Staged, fsync_dir, fsync_file, rebuild_blob_paths, write_atomic};
use super::{Key, Sha256Hex, Stats, Store, StoreError, check_basename};

const MAX_STAGED_PER_USER: usize = 32;

/// A manifest's blob list, parsed: `(sha, filename)` both validated.
type ParsedBlobs = Vec<(Sha256Hex, String)>;

impl Store {
    fn validate(
        &self,
        fw: &Firmware,
        reject_if_live: bool,
    ) -> Result<(Key, ParsedBlobs), StoreError> {
        let key = Key::parse(fw)?;
        let cat = inex_devices::by_id(key.device.as_str())
            .ok_or_else(|| StoreError::UnknownDevice(key.device.as_str().to_string()))?;
        if fw.blobs.is_empty() {
            return Err(StoreError::InvalidArgument(
                "firmware must reference at least one blob".into(),
            ));
        }
        if fw.blobs.len() > cat.firmware_slots.len() {
            return Err(StoreError::InvalidArgument(format!(
                "firmware has {} blobs but {} has only {} slot(s)",
                fw.blobs.len(),
                key.device,
                cat.firmware_slots.len()
            )));
        }
        let index = self.index.read();
        let mut blobs = ParsedBlobs::with_capacity(fw.blobs.len());
        for blob in &fw.blobs {
            let slot = blob.slot.unwrap_or(0) as usize;
            if slot >= cat.firmware_slots.len() {
                return Err(StoreError::InvalidArgument(format!(
                    "blob slot {slot} is outside {}'s {}-slot layout",
                    key.device,
                    cat.firmware_slots.len()
                )));
            }
            let sha = Sha256Hex::try_from(blob.sha256.as_deref().unwrap_or_default())?;
            let file = blob.filename.clone().unwrap_or_default();
            check_basename(&file)?;
            if !index.blob_paths.contains_key(&sha) {
                return Err(StoreError::MissingBlob { sha256: sha, file });
            }
            blobs.push((sha, file));
        }
        if reject_if_live && index.live.contains_key(&key) {
            return Err(StoreError::AlreadyExists(key.clone()));
        }
        Ok((key, blobs))
    }

    pub async fn publish(&self, fw: Firmware) -> Result<Firmware, StoreError> {
        let (key, blobs) = self.validate(&fw, true)?;
        let dir = self.firmware_dir(&key);
        self.write_version_dir(&dir, &fw, &blobs, None)?;
        {
            let mut index = self.index.write();
            index.live.insert(key.clone(), fw.clone());
            index.staged.remove(&key);
            rebuild_blob_paths(&mut index, &self.root);
        }
        self.sweep_incoming();
        self.bump();
        // Eager-mirror the new blobs (best-effort; a failure defers to lazy mirror).
        if let Some(mirror) = &self.mirror {
            for (sha, _) in &blobs {
                if let Ok(Some(bytes)) = self.get_blob(sha).await
                    && let Err(e) = mirror.put_if_absent(sha.as_str(), &bytes).await
                {
                    tracing::warn!(sha = %sha, error = %e, "eager mirror failed (will lazy-mirror)");
                }
            }
        }
        tracing::info!(key = %key, blobs = fw.blobs.len(), "published");
        Ok(fw)
    }

    pub async fn stage(&self, fw: Firmware, submitted_by: &str) -> Result<Firmware, StoreError> {
        let (key, blobs) = self.validate(&fw, true)?;
        {
            let index = self.index.read();
            let owned = |s: &&Staged| s.submitted_by == submitted_by;
            let owns_key = index
                .staged
                .get(&key)
                .is_some_and(|s| s.submitted_by == submitted_by);
            if !owns_key && index.staged.values().filter(owned).count() >= MAX_STAGED_PER_USER {
                return Err(StoreError::Quota(format!(
                    "you already have {MAX_STAGED_PER_USER} submissions awaiting review"
                )));
            }
        }
        let dir = self.staging_dir(&key);
        self.write_version_dir(&dir, &fw, &blobs, Some(submitted_by))?;
        {
            let mut index = self.index.write();
            index.staged.insert(
                key.clone(),
                Staged {
                    firmware: fw.clone(),
                    submitted_by: submitted_by.to_string(),
                },
            );
            rebuild_blob_paths(&mut index, &self.root);
        }
        self.sweep_incoming();
        self.bump();
        tracing::info!(key = %key, by = %submitted_by, "staged");
        Ok(fw)
    }

    pub fn staged(&self) -> Vec<StagedFirmware> {
        self.index
            .read()
            .staged
            .values()
            .map(|s| StagedFirmware {
                firmware: s.firmware.clone().into(),
                submitted_by: Some(s.submitted_by.clone()),
                ..Default::default()
            })
            .collect()
    }

    /// The username recorded on a pending staged entry, so a producer can notify
    /// the submitter. `None` if no such pending coordinate.
    pub fn staged_submitter(&self, device: &str, version: &str) -> Option<String> {
        let key = Key::of(device, version).ok()?;
        self.index
            .read()
            .staged
            .get(&key)
            .map(|s| s.submitted_by.clone())
    }

    pub async fn approve(&self, device: &str, version: &str) -> Result<Firmware, StoreError> {
        let key = Key::of(device, version)?;
        // Decide under the lock, then release it before any .await/IO — never hold the guard across await.
        enum Plan {
            AlreadyLive,
            NotFound,
            Approve(Firmware),
        }
        let plan = {
            let index = self.index.read();
            if index.live.contains_key(&key) {
                Plan::AlreadyLive
            } else if let Some(s) = index.staged.get(&key) {
                Plan::Approve(s.firmware.clone())
            } else {
                Plan::NotFound
            }
        };
        let fw = match plan {
            Plan::AlreadyLive => {
                let _ = self.reject(device, version).await;
                return Err(StoreError::AlreadyExists(key));
            }
            Plan::NotFound => return Err(StoreError::NotFound(key)),
            Plan::Approve(fw) => fw,
        };
        let from = self.staging_dir(&key);
        let to = self.firmware_dir(&key);
        if let Some(parent) = to.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::rename(&from, &to)?;
        // fsync both parents so the rename survives a crash (the fs tree is the only copy).
        if let Some(parent) = to.parent() {
            fsync_dir(parent)?;
        }
        if let Some(parent) = from.parent() {
            let _ = fsync_dir(parent);
        }
        let _ = std::fs::remove_file(to.join("submitted-by"));
        {
            let mut index = self.index.write();
            index.staged.remove(&key);
            index.live.insert(key.clone(), fw.clone());
            rebuild_blob_paths(&mut index, &self.root);
        }
        self.bump();
        tracing::info!(key = %key, "approved");
        Ok(fw)
    }

    pub async fn reject(&self, device: &str, version: &str) -> Result<(), StoreError> {
        let key = Key::of(device, version)?;
        {
            let index = self.index.read();
            if !index.staged.contains_key(&key) {
                return Err(StoreError::NotFound(key));
            }
        }
        let dir = self.staging_dir(&key);
        if dir.exists() {
            std::fs::remove_dir_all(&dir)?;
        }
        {
            let mut index = self.index.write();
            index.staged.remove(&key);
            rebuild_blob_paths(&mut index, &self.root);
        }
        self.bump();
        Ok(())
    }

    pub async fn list(&self, device: Option<&str>) -> Vec<Firmware> {
        let mut firmware: Vec<Firmware> = self
            .index
            .read()
            .live
            .values()
            .filter(|fw| device.is_none_or(|want| fw.device_id.as_deref() == Some(want)))
            .cloned()
            .collect();
        // Enrich on read so `downloads` is always fresh (never trusted from disk).
        // Shared blobs count toward every version referencing them.
        for fw in &mut firmware {
            let mut total = 0u64;
            for sha in fw.blobs.iter().filter_map(|b| b.sha256.as_deref()) {
                total += self.db.stats().download_count(sha).await.unwrap_or(0);
            }
            fw.downloads = Some(total);
        }
        firmware
    }

    pub fn devices(&self) -> Vec<Device> {
        let index = self.index.read();
        let mut counts: BTreeMap<String, u32> = BTreeMap::new();
        for fw in index.live.values() {
            if let Some(dev) = fw.device_id.as_deref() {
                *counts.entry(dev.to_string()).or_default() += 1;
            }
        }
        counts
            .into_iter()
            .filter_map(|(id, count)| Some(catalogue_device(inex_devices::by_id(&id)?, count)))
            .collect()
    }

    /// Catalogue-wide counts for the admin panel (users from the auth Db, the
    /// rest from the index).
    pub async fn stats(&self) -> Result<Stats, StoreError> {
        let users = self.db.users().count().await?;
        let index = self.index.read();
        let mut sizes: HashMap<String, u64> = HashMap::new();
        let mut collect = |blobs: &[FirmwareBlob]| {
            for b in blobs {
                if let Some(sha) = b.sha256.clone() {
                    sizes.insert(sha, b.size_bytes.unwrap_or(0));
                }
            }
        };
        for fw in index.live.values() {
            collect(&fw.blobs);
        }
        for s in index.staged.values() {
            collect(&s.firmware.blobs);
        }
        let devices = index
            .live
            .values()
            .filter_map(|f| f.device_id.clone())
            .filter(|d| inex_devices::by_id(d).is_some())
            .collect::<HashSet<_>>()
            .len() as u64;
        Ok(Stats {
            users,
            devices,
            firmware: index.live.len() as u64,
            staged: index.staged.len() as u64,
            blobs: sizes.len() as u64,
            blob_bytes: sizes.values().sum(),
        })
    }

    /// Write a complete version dir as an atomic unit: build in a sibling
    /// `.tmp-<uuid>` dir, then `rename` into place (the rename is the commit).
    fn write_version_dir(
        &self,
        dir: &Path,
        fw: &Firmware,
        blobs: &ParsedBlobs,
        submitted_by: Option<&str>,
    ) -> Result<(), StoreError> {
        let parent = dir.parent().expect("version dir has a parent");
        std::fs::create_dir_all(parent)?;
        let mut tmp = TmpDir::create(parent)?;
        for (sha, file) in blobs {
            let src = self
                .index
                .read()
                .blob_paths
                .get(sha)
                .cloned()
                .ok_or_else(|| StoreError::MissingBlob {
                    sha256: sha.clone(),
                    file: file.clone(),
                })?;
            let dst = tmp.path().join(file);
            std::fs::copy(&src, &dst)?;
            fsync_file(&dst)?;
        }
        let json = serde_json::to_vec_pretty(fw)
            .map_err(|e| StoreError::Decode(format!("manifest encode: {e}")))?;
        write_atomic(&tmp.path().join("manifest.json"), &json)?;
        if let Some(who) = submitted_by {
            write_atomic(&tmp.path().join("submitted-by"), who.as_bytes())?;
        }
        // fsync the temp dir before the rename that publishes it (the fs tree is the only copy).
        fsync_dir(tmp.path())?;
        if dir.exists() {
            std::fs::remove_dir_all(dir)?;
        }
        std::fs::rename(tmp.path(), dir)?;
        tmp.commit();
        fsync_dir(parent)?;
        Ok(())
    }
}

/// A `.tmp-<uuid>` build dir, removed on drop unless committed — cleanup on
/// every early `?` return and on panic, with no closure ceremony.
struct TmpDir {
    path: PathBuf,
    committed: bool,
}

impl TmpDir {
    fn create(parent: &Path) -> std::io::Result<Self> {
        let path = parent.join(format!(".tmp-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&path)?;
        Ok(Self {
            path,
            committed: false,
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    /// The dir has been renamed away — nothing to clean up.
    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        if !self.committed {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

pub(crate) fn catalogue_device(cat: &inex_devices::Device, firmware_count: u32) -> Device {
    Device {
        id: Some(cat.id.to_owned()),
        name: Some(cat.name.to_owned()),
        description: Some(cat.summary.to_owned()),
        slots: cat
            .firmware_slots
            .iter()
            .map(|s| BlobSlot {
                name: Some(s.name.to_owned()),
                description: Some(s.description.to_owned()),
                ..Default::default()
            })
            .collect(),
        firmware_count: Some(firmware_count),
        colour: Some(cat.colour.to_owned()),
        // Wire carries the coarse generations; fine-grained models stay in the catalogue.
        platforms: cat
            .generations()
            .into_iter()
            .map(|p| wire_platform(p).into())
            .collect(),
        ..Default::default()
    }
}

fn wire_platform(p: inex_devices::Platform) -> Platform {
    use inex_devices::Platform as P;
    match p {
        P::Dmg => Platform::Dmg,
        P::Cgb => Platform::Cgb,
        P::Agb => Platform::Agb,
        P::Ntr => Platform::Ntr,
        P::Twl => Platform::Twl,
        P::Ctr => Platform::Ctr,
    }
}

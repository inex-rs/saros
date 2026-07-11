//! Critical-correctness tests: validation gates + immutability, the staging
//! state machine, rescan recovery, content-verification on serve, and both
//! deletion paths' scoping (tmp-artifact reaping, incoming GC).

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use inex_protobufs::buffa::inex::saros::v1::{Firmware, FirmwareBlob};

use super::*;
use crate::db::Db;

async fn open(dir: &Path, cap: usize) -> Store {
    let db = Arc::new(Db::open(dir.join("meta.db")).await.unwrap());
    Store::open(dir, cap, db, None).unwrap()
}

fn fw(device: &str, version: &str, sha: &Sha256Hex) -> Firmware {
    Firmware {
        device_id: Some(device.into()),
        version: Some(version.into()),
        blobs: vec![FirmwareBlob {
            slot: Some(0),
            filename: Some(format!("{device}-v{version}.bin")),
            size_bytes: Some(4),
            sha256: Some(sha.to_string()),
            ..Default::default()
        }],
        ..Default::default()
    }
}

#[test]
fn versions_must_be_numeric() {
    assert!(Version::try_from("3.23").is_ok());
    assert!(Version::try_from("0.2.1").is_ok());
    for bad in ["", "1.0-rc1", "v1.2", "1..2", "1.2."] {
        assert!(
            Version::try_from(bad).is_err(),
            "{bad:?} should be rejected"
        );
    }
}

#[tokio::test]
async fn publish_requires_device_blobs_and_is_immutable() {
    let dir = tempfile::tempdir().unwrap();
    let s = open(dir.path(), 1024).await;
    let sha = s.put_blob(b"fw!!").await.unwrap();

    assert!(matches!(
        s.publish(fw("no-such-device", "0.1.0", &sha)).await,
        Err(StoreError::UnknownDevice(..))
    ));
    let missing = Sha256Hex::digest_of(b"never-uploaded");
    assert!(matches!(
        s.publish(fw("pocket-debug", "0.1.0", &missing)).await,
        Err(StoreError::MissingBlob { .. })
    ));
    let mut bad = fw("pocket-debug", "0.1.0", &sha);
    bad.blobs[0].slot = Some(3);
    assert!(matches!(
        s.publish(bad).await,
        Err(StoreError::InvalidArgument(..))
    ));

    s.publish(fw("pocket-debug", "0.1.0", &sha)).await.unwrap();
    assert!(matches!(
        s.publish(fw("pocket-debug", "0.1.0", &sha)).await,
        Err(StoreError::AlreadyExists(..))
    ));
    assert!(s.publish(fw("../evil", "0.1.0", &sha)).await.is_err());
}

#[tokio::test]
async fn stage_approve_reject_flow() {
    let dir = tempfile::tempdir().unwrap();
    let s = open(dir.path(), 1024).await;
    let sha = s.put_blob(b"fw!!").await.unwrap();

    s.stage(fw("pocket-debug", "0.1.0", &sha), "alice")
        .await
        .unwrap();
    assert_eq!(s.staged().len(), 1);
    assert_eq!(
        s.staged_submitter("pocket-debug", "0.1.0").as_deref(),
        Some("alice")
    );
    assert!(s.list(None).await.is_empty());
    assert!(
        dir.path()
            .join("staging/pocket-debug/0.1.0/submitted-by")
            .is_file()
    );

    s.approve("pocket-debug", "0.1.0").await.unwrap();
    assert_eq!(s.list(Some("pocket-debug")).await.len(), 1);
    assert!(s.staged().is_empty());
    assert!(!dir.path().join("staging/pocket-debug/0.1.0").exists());
    assert!(
        dir.path()
            .join("firmware/pocket-debug/0.1.0/manifest.json")
            .is_file()
    );

    let sha2 = s.put_blob(b"beta").await.unwrap();
    s.stage(fw("pocket-debug", "0.2.0", &sha2), "bob")
        .await
        .unwrap();
    s.reject("pocket-debug", "0.2.0").await.unwrap();
    assert!(s.staged().is_empty());
    assert!(!dir.path().join("staging/pocket-debug/0.2.0").exists());
}

#[tokio::test]
async fn rescan_from_disk_recovers_everything() {
    let dir = tempfile::tempdir().unwrap();
    {
        let s = open(dir.path(), 1024).await;
        let mut rx = s.subscribe();
        let g0 = *rx.borrow_and_update();
        let sha = s.put_blob(b"fw!!").await.unwrap();
        s.publish(fw("is-nitro-emulator", "3.23", &sha))
            .await
            .unwrap();
        s.publish(fw("is-nitro-emulator", "3.18", &sha))
            .await
            .unwrap();
        assert!(*rx.borrow_and_update() > g0);
    }
    let s = open(dir.path(), 1024).await;
    let listed = s.list(Some("is-nitro-emulator")).await;
    let has = |v: &str| listed.iter().any(|f| f.version.as_deref() == Some(v));
    assert!(has("3.23") && has("3.18"));
    let devices = s.devices();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].id.as_deref(), Some("is-nitro-emulator"));
    assert_eq!(devices[0].slots.len(), 4);
    assert_eq!(devices[0].firmware_count, Some(2));
    let sha = Sha256Hex::digest_of(b"fw!!");
    assert_eq!(s.get_blob(&sha).await.unwrap().unwrap(), b"fw!!");
}

#[tokio::test]
async fn get_blob_refuses_content_that_doesnt_match_its_sha() {
    let dir = tempfile::tempdir().unwrap();
    let s = open(dir.path(), 1024).await;
    let vdir = dir.path().join("firmware/pocket-debug/0.9.0");
    std::fs::create_dir_all(&vdir).unwrap();
    std::fs::write(vdir.join("app.bin"), b"tampered").unwrap();
    let claimed = Sha256Hex::digest_of(b"honest");
    std::fs::write(
        vdir.join("manifest.json"),
        format!(
            r#"{{"deviceId":"pocket-debug","version":"0.9.0","blobs":[{{"slot":0,"filename":"app.bin","sizeBytes":"8","sha256":"{claimed}"}}]}}"#
        ),
    )
    .unwrap();
    s.reload().unwrap();
    let err = s.get_blob(&claimed).await.unwrap_err();
    assert!(matches!(err, StoreError::Io(_)));
    assert!(err.to_string().contains("content verification"));
}

#[tokio::test]
async fn open_reaps_orphaned_tmp_artifacts() {
    let dir = tempfile::tempdir().unwrap();
    let tmp_ver = dir.path().join("firmware/pocket-debug/.tmp-deadbeef");
    std::fs::create_dir_all(&tmp_ver).unwrap();
    std::fs::write(tmp_ver.join("junk.bin"), b"x").unwrap();
    let incoming = dir.path().join("incoming");
    std::fs::create_dir_all(&incoming).unwrap();
    let tmp_blob = incoming.join(format!("{}.tmp-deadbeef", Sha256Hex::digest_of(b"z")));
    std::fs::write(&tmp_blob, b"x").unwrap();
    std::fs::write(incoming.join("not-a-sha"), b"y").unwrap();

    let s = open(dir.path(), 1024).await;
    assert!(!tmp_ver.exists());
    assert!(!tmp_blob.exists());
    assert!(s.list(None).await.is_empty());
}

#[tokio::test]
async fn gc_incoming_reclaims_only_old_unreferenced_blobs() {
    let dir = tempfile::tempdir().unwrap();
    let s = open(dir.path(), 1024).await;
    let incoming = dir.path().join("incoming");

    let referenced = s.put_blob(b"referenced").await.unwrap();
    s.stage(fw("pocket-debug", "0.1.0", &referenced), "alice")
        .await
        .unwrap();
    std::fs::write(incoming.join(referenced.as_str()), b"referenced").unwrap();

    let old = s.put_blob(b"old-abandoned").await.unwrap();
    let recent = s.put_blob(b"recent-abandoned").await.unwrap();

    assert!(incoming.join(referenced.as_str()).exists());
    assert!(incoming.join(old.as_str()).exists());
    assert!(incoming.join(recent.as_str()).exists());

    std::fs::File::options()
        .write(true)
        .open(incoming.join(old.as_str()))
        .unwrap()
        .set_modified(SystemTime::now() - Duration::from_secs(2 * 24 * 3600))
        .unwrap();

    let cutoff = SystemTime::now() - Duration::from_secs(24 * 3600);
    let deleted = s.gc_incoming_before(cutoff).unwrap();

    assert_eq!(deleted, 1, "only the old, unreferenced blob is reclaimed");
    assert!(
        incoming.join(referenced.as_str()).exists(),
        "a staged manifest's blob survives regardless of age"
    );
    assert!(
        !incoming.join(old.as_str()).exists(),
        "the old, unreferenced upload is reclaimed"
    );
    assert!(
        incoming.join(recent.as_str()).exists(),
        "a recent unreferenced upload is protected (publish may be moments away)"
    );
}

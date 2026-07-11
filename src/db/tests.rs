//! Critical-correctness tests only: codec compatibility (protects existing
//! databases), uniqueness races, security-scoped revocation, and prune/cursor
//! arithmetic. Plain CRUD is not tested — the type system and the repos' own
//! callers cover it.

use uuid::Uuid;

use super::*;
use crate::passkey::StoredUser;

async fn open() -> (tempfile::TempDir, std::sync::Arc<Db>) {
    let dir = tempfile::tempdir().unwrap();
    let db = std::sync::Arc::new(Db::open(dir.path().join("meta.db")).await.unwrap());
    (dir, db)
}

fn user(name: &str, email: Option<&str>) -> StoredUser {
    StoredUser {
        uuid: Uuid::new_v4(),
        username: name.into(),
        credentials: vec![],
        email: email.map(Into::into),
    }
}

/// The version byte is the only guard between a new binary and an old
/// database: same version round-trips, any other version fails closed.
#[test]
fn versioned_codec_compatibility() {
    let u = user("alice", Some("a@x.io"));
    let bytes = encode_user(&u).unwrap();
    assert_eq!(bytes[0], USER_V1);
    let back = decode_user(&bytes).unwrap();
    assert_eq!(back.username, "alice");
    assert_eq!(back.email.as_deref(), Some("a@x.io"));

    let mut wrong = bytes.clone();
    wrong[0] = 99;
    assert!(matches!(
        decode_user(&wrong),
        Err(DbError::UnknownVersion(99))
    ));
    assert!(matches!(decode_user(&[]), Err(DbError::UnknownVersion(0))));
}

/// Username and email uniqueness: the checks gate the insert and the DB
/// constraints backstop them — the invariant that makes concurrent
/// registrations safe.
#[tokio::test]
async fn create_user_uniqueness() {
    let (_d, db) = open().await;
    let users = db.users();
    assert_eq!(
        users
            .create_if_absent(&user("alice", Some("A@x.io")))
            .await
            .unwrap(),
        CreateOutcome::Created
    );
    assert_eq!(
        users.create_if_absent(&user("alice", None)).await.unwrap(),
        CreateOutcome::UsernameTaken
    );
    // Email compares normalised (trim + lowercase).
    assert_eq!(
        users
            .create_if_absent(&user("bob", Some(" a@X.IO ")))
            .await
            .unwrap(),
        CreateOutcome::EmailTaken
    );
}

/// Changing an email must free the old unique value and claim the new one —
/// a stale claim would let two accounts share an address.
#[tokio::test]
async fn set_email_maintains_unique_index() {
    let (_d, db) = open().await;
    let users = db.users();
    users
        .create_if_absent(&user("alice", Some("a@x.io")))
        .await
        .unwrap();
    users.create_if_absent(&user("bob", None)).await.unwrap();

    // Bob can't take Alice's address; Alice keeping her own is fine.
    assert_eq!(
        users.set_email("bob", Some("A@x.io".into())).await.unwrap(),
        EmailOutcome::Taken
    );
    assert_eq!(
        users
            .set_email("alice", Some("a@x.io".into()))
            .await
            .unwrap(),
        EmailOutcome::Updated
    );
    // Alice moves; the old value frees for Bob.
    assert_eq!(
        users
            .set_email("alice", Some("new@x.io".into()))
            .await
            .unwrap(),
        EmailOutcome::Updated
    );
    assert_eq!(
        users.set_email("bob", Some("a@x.io".into())).await.unwrap(),
        EmailOutcome::Updated
    );
    assert_eq!(
        users.set_email("ghost", None).await.unwrap(),
        EmailOutcome::NoSuchUser
    );
}

/// Expiry gates lookups, and revocation is owner-scoped: one user's opaque
/// session id must not revoke another's row.
#[tokio::test]
async fn session_expiry_and_owner_scoped_revocation() {
    let (_d, db) = open().await;
    let sessions = db.sessions();
    let now = now_secs();
    let rec = |name: &str, exp: i64| SessionRecord {
        username: name.into(),
        kind: KIND_WEB,
        created_at: now,
        expires_at: exp,
        label: "t".into(),
        last_seen: now,
        ip: String::new(),
        device: String::new(),
    };

    sessions
        .put(&[1u8; 32], &rec("alice", now + 60))
        .await
        .unwrap();
    sessions
        .put(&[2u8; 32], &rec("alice", now - 1)) // expired
        .await
        .unwrap();
    sessions
        .put(&[3u8; 32], &rec("bob", now + 60))
        .await
        .unwrap();

    assert_eq!(
        sessions.username(&[1u8; 32]).await.unwrap().as_deref(),
        Some("alice")
    );
    assert_eq!(sessions.username(&[2u8; 32]).await.unwrap(), None);

    // Bob cannot revoke Alice's session via her id.
    let alice_id = session_id(&[1u8; 32]);
    assert!(!sessions.delete_by_id("bob", &alice_id).await.unwrap());
    assert!(sessions.delete_by_id("alice", &alice_id).await.unwrap());

    // Sweep reclaims only dead rows.
    assert_eq!(sessions.sweep_expired().await.unwrap(), 1);
    assert_eq!(
        sessions.username(&[3u8; 32]).await.unwrap().as_deref(),
        Some("bob")
    );
}

/// The inbox cap prunes oldest-first — an off-by-one here silently eats the
/// newest notification instead of the oldest.
#[tokio::test]
async fn notification_cap_prunes_oldest() {
    let (_d, db) = open().await;
    let notifs = db.notifications();
    for i in 0..205 {
        notifs.push("u", 1, &format!("n{i}"), "", "").await.unwrap();
    }
    let list = notifs.list("u", usize::MAX).await.unwrap();
    assert_eq!(list.len(), 200);
    // Newest-first; the five oldest (n0..n4) are gone.
    assert_eq!(list.first().unwrap().1.title, "n204");
    assert_eq!(list.last().unwrap().1.title, "n5");
}

/// Page-cursor arithmetic: full pages chain by smallest seq, a short page
/// signals exhaustion with cursor 0, and the actor filter applies.
#[tokio::test]
async fn audit_page_cursor_chain() {
    let (_d, db) = open().await;
    let audit = db.audit();
    for i in 0..5 {
        audit
            .append(if i % 2 == 0 { "even" } else { "odd" }, 1, &format!("t{i}"))
            .await
            .unwrap();
    }
    let (p1, c1) = audit.page(0, 2, None).await.unwrap();
    assert_eq!(
        p1.iter()
            .map(|(_, r)| r.target.as_str())
            .collect::<Vec<_>>(),
        ["t4", "t3"]
    );
    let (p2, c2) = audit.page(c1, 2, None).await.unwrap();
    assert_eq!(
        p2.iter()
            .map(|(_, r)| r.target.as_str())
            .collect::<Vec<_>>(),
        ["t2", "t1"]
    );
    let (p3, c3) = audit.page(c2, 2, None).await.unwrap();
    assert_eq!(p3.len(), 1);
    assert_eq!(c3, 0, "short page signals exhaustion");

    let (evens, _) = audit.page(0, 10, Some("even")).await.unwrap();
    assert!(evens.iter().all(|(_, r)| r.actor == "even"));
    assert_eq!(evens.len(), 3);
}

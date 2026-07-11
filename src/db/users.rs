//! Accounts: relational uuid/email uniqueness columns around the versioned
//! [`StoredUser`] blob (the blob is authoritative; the columns exist for
//! constraints and lookups and are rewritten with it on every write).

use uuid::Uuid;

use super::{Db, DbError, decode_user, encode_user};
use crate::passkey::StoredUser;

/// One account row. `record` is the versioned blob; `email` is the normalised
/// form, DB-enforced unique (NULLs coexist).
#[derive(Debug, toasty::Model)]
#[table = "users"]
pub(super) struct UserRow {
    #[key]
    username: String,
    #[index]
    uuid: String,
    #[unique]
    email: Option<String>,
    record: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CreateOutcome {
    Created,
    UsernameTaken,
    EmailTaken,
}

#[derive(Debug, PartialEq, Eq)]
pub enum EmailOutcome {
    Updated,
    Taken,
    NoSuchUser,
}

pub struct Users<'a>(pub(super) &'a Db);

impl Users<'_> {
    /// Upsert an account, keeping the uuid/email columns in step with the blob.
    pub async fn upsert(&self, user: &StoredUser) -> Result<(), DbError> {
        let record = encode_user(user)?;
        let email = email_key(user);
        let uuid = user.uuid.to_string();
        let mut db = self.0.handle();
        let present = UserRow::filter_by_username(&user.username)
            .count()
            .exec(&mut db)
            .await?
            > 0;
        if present {
            toasty::update!(UserRow::filter_by_username(&user.username) { uuid, email, record })
                .exec(&mut db)
                .await?;
        } else {
            toasty::create!(UserRow {
                username: user.username.clone(),
                uuid,
                email,
                record,
            })
            .exec(&mut db)
            .await?;
        }
        Ok(())
    }

    /// Create only if the username and email are both free. The checks are the
    /// primary gate; the PK and unique-email constraints backstop a lost race,
    /// whose insert error is re-classified into the Taken outcomes.
    pub async fn create_if_absent(&self, user: &StoredUser) -> Result<CreateOutcome, DbError> {
        let record = encode_user(user)?;
        let email = email_key(user);
        let mut db = self.0.handle();
        if let Some(outcome) = taken(&mut db, &user.username, email.as_deref()).await? {
            return Ok(outcome);
        }
        let insert = toasty::create!(UserRow {
            username: user.username.clone(),
            uuid: user.uuid.to_string(),
            email: email.clone(),
            record,
        })
        .exec(&mut db)
        .await;
        match insert {
            Ok(_) => Ok(CreateOutcome::Created),
            Err(e) => match taken(&mut db, &user.username, email.as_deref()).await? {
                Some(outcome) => Ok(outcome),
                None => Err(e.into()),
            },
        }
    }

    /// Change/clear an account's recovery email, unique across accounts.
    /// Stored as given (in the blob); uniqueness compares the normalised form
    /// (the column).
    pub async fn set_email(
        &self,
        username: &str,
        email: Option<String>,
    ) -> Result<EmailOutcome, DbError> {
        let new_key = email.as_deref().map(normalize_email);
        let mut db = self.0.handle();
        let Some(row) = UserRow::filter_by_username(username)
            .first()
            .exec(&mut db)
            .await?
        else {
            return Ok(EmailOutcome::NoSuchUser);
        };
        // Free, or already this account's.
        if let Some(key) = &new_key {
            let taken = UserRow::filter_by_email(Some(key.clone()))
                .filter(UserRow::fields().username().ne(username))
                .count()
                .exec(&mut db)
                .await?
                > 0;
            if taken {
                return Ok(EmailOutcome::Taken);
            }
        }
        let mut user = decode_user(&row.record)?;
        user.email = email;
        let record = encode_user(&user)?;
        toasty::update!(UserRow::filter_by_username(username) { email: new_key, record })
            .exec(&mut db)
            .await?;
        Ok(EmailOutcome::Updated)
    }

    pub async fn get(&self, username: &str) -> Result<Option<StoredUser>, DbError> {
        let mut db = self.0.handle();
        match UserRow::filter_by_username(username)
            .first()
            .exec(&mut db)
            .await?
        {
            Some(row) => Ok(Some(decode_user(&row.record)?)),
            None => Ok(None),
        }
    }

    pub async fn exists(&self, username: &str) -> Result<bool, DbError> {
        let mut db = self.0.handle();
        Ok(UserRow::filter_by_username(username)
            .count()
            .exec(&mut db)
            .await?
            > 0)
    }

    pub async fn by_uuid(&self, uuid: Uuid) -> Result<Option<StoredUser>, DbError> {
        let mut db = self.0.handle();
        match UserRow::filter_by_uuid(uuid.to_string())
            .first()
            .exec(&mut db)
            .await?
        {
            Some(row) => Ok(Some(decode_user(&row.record)?)),
            None => Ok(None),
        }
    }

    pub async fn count(&self) -> Result<u64, DbError> {
        let mut db = self.0.handle();
        Ok(UserRow::all().count().exec(&mut db).await?)
    }
}

/// `Some(outcome)` if the username or normalised email is already claimed.
async fn taken(
    db: &mut toasty::Db,
    username: &str,
    email: Option<&str>,
) -> Result<Option<CreateOutcome>, DbError> {
    if UserRow::filter_by_username(username)
        .count()
        .exec(db)
        .await?
        > 0
    {
        return Ok(Some(CreateOutcome::UsernameTaken));
    }
    if let Some(email) = email
        && UserRow::filter_by_email(Some(email.to_string()))
            .count()
            .exec(db)
            .await?
            > 0
    {
        return Ok(Some(CreateOutcome::EmailTaken));
    }
    Ok(None)
}

fn email_key(user: &StoredUser) -> Option<String> {
    user.email.as_deref().map(normalize_email)
}

/// Trim + lowercase — the form uniqueness compares on and the Gravatar hash
/// is taken over.
pub(crate) fn normalize_email(email: &str) -> String {
    email.trim().to_ascii_lowercase()
}

//! `AuthService`: passkey ceremonies, sessions, device-flow login, account.

use super::*;

const MAX_API_TOKENS_PER_USER: usize = 20;

fn wire_notification_kind(kind: u8) -> pb::NotificationKind {
    use pb::NotificationKind as K;
    match kind as i32 {
        x if x == K::SubmissionApproved as i32 => K::SubmissionApproved,
        x if x == K::SubmissionRejected as i32 => K::SubmissionRejected,
        x if x == K::NewFirmware as i32 => K::NewFirmware,
        x if x == K::NewSignIn as i32 => K::NewSignIn,
        _ => K::Unspecified,
    }
}

fn notification(id: u64, r: crate::db::NotificationRecord) -> pb::Notification {
    pb::Notification {
        id: Some(id),
        at: ts(r.at),
        kind: Some(wire_notification_kind(r.kind).into()),
        read: Some(r.read),
        title: Some(r.title),
        detail: Some(r.detail),
        link: Some(r.link),
        ..Default::default()
    }
}

pub struct ConnectAuthService {
    auth: Arc<Auth>,
    passkeys: Arc<Passkeys>,
    logins: Arc<crate::login::Logins>,
    db: Arc<Db>,
    events: Arc<Events>,
    /// Session-cookie attrs: `Domain=` in prod (spans `inex.rs` subdomains),
    /// `Secure` off only for http dev.
    cookie_domain: Option<String>,
    cookie_secure: bool,
}

impl ConnectAuthService {
    pub fn new(
        auth: Arc<Auth>,
        passkeys: Arc<Passkeys>,
        logins: Arc<crate::login::Logins>,
        db: Arc<Db>,
        events: Arc<Events>,
        cookie_domain: Option<String>,
        cookie_secure: bool,
    ) -> Self {
        Self {
            auth,
            passkeys,
            logins,
            db,
            events,
            cookie_domain,
            cookie_secure,
        }
    }
}

fn login_status(status: &str) -> pb::LoginStatus {
    match status {
        "pending" => pb::LoginStatus::Pending,
        "approved" => pb::LoginStatus::Approved,
        "denied" => pb::LoginStatus::Denied,
        "expired" => pb::LoginStatus::Expired,
        _ => pb::LoginStatus::Unspecified,
    }
}

/// `poll` consumes an approved record — a re-poll after approval reads as expired.
fn poll_login_status(
    logins: &crate::login::Logins,
    device_code: &str,
) -> (pb::LoginStatus, Option<String>, Option<String>) {
    use crate::login::Poll;
    match logins.poll(device_code) {
        Poll::Pending => (pb::LoginStatus::Pending, None, None),
        Poll::Denied => (pb::LoginStatus::Denied, None, None),
        Poll::Expired => (pb::LoginStatus::Expired, None, None),
        Poll::Approved { token, username } => {
            (pb::LoginStatus::Approved, Some(token), Some(username))
        }
    }
}

impl From<PasskeyError> for ConnectError {
    fn from(e: PasskeyError) -> Self {
        match e {
            PasskeyError::InvalidUsername | PasskeyError::InvalidEmail => {
                ConnectError::invalid_argument(e.to_string())
            }
            PasskeyError::UsernameTaken | PasskeyError::EmailTaken => {
                ConnectError::already_exists(e.to_string())
            }
            PasskeyError::UnknownFlow | PasskeyError::NoSuchUser | PasskeyError::LastCredential => {
                ConnectError::failed_precondition(e.to_string())
            }
            PasskeyError::NoSuchCredential => ConnectError::not_found(e.to_string()),
            PasskeyError::TooManyPending => ConnectError::resource_exhausted(e.to_string()),
            // Failed ceremony (bad attestation/assertion) = client error.
            PasskeyError::Webauthn(_) | PasskeyError::Json(_) => {
                ConnectError::invalid_argument(e.to_string())
            }
            PasskeyError::Db(_) | PasskeyError::Rng(_) => {
                tracing::error!(error = %e, "passkey store failure");
                ConnectError::internal("internal error")
            }
        }
    }
}
#[allow(refining_impl_trait_internal, refining_impl_trait_reachable)]
impl AuthService for ConnectAuthService {
    async fn who_am_i(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, pb::WhoAmIRequest>,
    ) -> ServiceResult<pb::WhoAmIResponse> {
        let caller = caller_of(&self.auth, &ctx).await;
        let email = if caller.signed_in() {
            self.passkeys
                .email(caller.username())
                .await
                .ok()
                .flatten()
                .unwrap_or_default()
        } else {
            String::new()
        };
        Response::ok(pb::WhoAmIResponse {
            username: Some(caller.username().to_string()),
            admin: Some(caller.admin()),
            email: Some(email),
            ..Default::default()
        })
    }

    async fn begin_passkey(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, pb::BeginPasskeyRequest>,
    ) -> ServiceResult<pb::BeginPasskeyResponse> {
        let username = request.to_owned_message().username.unwrap_or_default();
        let (flow_id, options_json, mode) = self.passkeys.begin(&username).await?;
        let mode = match mode {
            crate::passkey::PasskeyMode::Register => pb::PasskeyMode::Register,
            crate::passkey::PasskeyMode::Authenticate => pb::PasskeyMode::Authenticate,
        };
        Response::ok(pb::BeginPasskeyResponse {
            flow_id: Some(flow_id),
            options_json: Some(options_json),
            mode: Some(mode.into()),
            ..Default::default()
        })
    }

    async fn finish_passkey(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, pb::FinishPasskeyRequest>,
    ) -> ServiceResult<pb::FinishPasskeyResponse> {
        let req = request.to_owned_message();
        let (flow_id, credential_json, email) = (
            req.flow_id.clone().unwrap_or_default(),
            req.credential_json.clone().unwrap_or_default(),
            req.email.clone(),
        );
        let (username, mode) = self
            .passkeys
            .finish(&flow_id, &credential_json, email.as_deref())
            .await?;
        let session_token = self.auth.mint_session(&username).await?;
        let action = match mode {
            crate::passkey::PasskeyMode::Register => pb::AuditAction::AccountRegistered,
            crate::passkey::PasskeyMode::Authenticate => pb::AuditAction::SignedIn,
        };
        self.events.sign_in(&username, action, &username).await;
        // AUTHENTICATE only — a fresh registration isn't a "new" sign-in.
        if action == pb::AuditAction::SignedIn {
            notify(
                &self.db,
                &username,
                pb::NotificationKind::NewSignIn,
                "New sign-in",
                "A device just signed in to your account",
                "/account",
            )
            .await;
        }
        // Web reads auth from the httpOnly cookie; the body `session_token`
        // stays for headless/bearer callers.
        let cookie = crate::auth::set_session_cookie(
            &session_token,
            self.cookie_domain.as_deref(),
            self.cookie_secure,
        );
        Ok(Response::new(pb::FinishPasskeyResponse {
            session_token: Some(session_token),
            username: Some(username),
            ..Default::default()
        })
        .with_header(http::header::SET_COOKIE, cookie))
    }

    async fn begin_login(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, pb::BeginLoginRequest>,
    ) -> ServiceResult<pb::BeginLoginResponse> {
        let label = request.to_owned_message().label.unwrap_or_default();
        let begun = self.logins.begin(&label).map_err(|e| match e {
            crate::login::BeginError::TooManyPending => {
                ConnectError::resource_exhausted("too many in-flight sign-ins — try again shortly")
            }
            crate::login::BeginError::Rng(e) => {
                tracing::error!(error = %e, "rng failure opening a sign-in");
                ConnectError::internal("internal error")
            }
        })?;
        Response::ok(pb::BeginLoginResponse {
            device_code: Some(begun.device_code),
            user_code: Some(begun.user_code),
            verification_uri: Some(begun.verification_uri),
            interval_secs: Some(begun.interval_secs),
            expires_in_secs: Some(begun.expires_in_secs),
            ..Default::default()
        })
    }

    async fn watch_login(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, pb::WatchLoginRequest>,
    ) -> ServiceResult<ServiceStream<pb::WatchLoginResponse>> {
        // ANONYMOUS by design: the device_code is the secret, so no auth gate.
        // Emit status now, then only on change — waking on a decision or a ~2s
        // tick so an expiry is still reported with no other activity. Ends once
        // terminal (approved/denied/expired).
        let device_code = request.to_owned_message().device_code.unwrap_or_default();
        let rx = self.logins.subscribe();
        Response::stream_ok(futures::stream::unfold(
            (self.logins.clone(), rx, device_code, None, false),
            |(logins, mut rx, device_code, last, done): (
                _,
                tokio::sync::watch::Receiver<u64>,
                String,
                Option<pb::LoginStatus>,
                bool,
            )| async move {
                if done {
                    return None;
                }
                loop {
                    let first = last.is_none();
                    if !first {
                        tokio::select! {
                            r = rx.changed() => r.ok()?,
                            _ = tokio::time::sleep(std::time::Duration::from_secs(2)) => {}
                        }
                    }
                    let (status, token, username) = poll_login_status(&logins, &device_code);
                    if first || Some(status) != last {
                        let terminal = !matches!(status, pb::LoginStatus::Pending);
                        let resp = pb::WatchLoginResponse {
                            status: Some(status.into()),
                            token,
                            username,
                            ..Default::default()
                        };
                        return Some((Ok(resp), (logins, rx, device_code, Some(status), terminal)));
                    }
                }
            },
        ))
    }

    async fn describe_login(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::DescribeLoginRequest>,
    ) -> ServiceResult<pb::DescribeLoginResponse> {
        require_signed_in(&caller_of(&self.auth, &ctx).await, "approve a sign-in")?;
        let user_code = request.to_owned_message().user_code.unwrap_or_default();
        let resp = match self.logins.describe(&user_code) {
            Some(d) => pb::DescribeLoginResponse {
                found: Some(true),
                label: Some(d.label),
                status: Some(login_status(d.status).into()),
                ..Default::default()
            },
            None => pb::DescribeLoginResponse {
                found: Some(false),
                ..Default::default()
            },
        };
        Response::ok(resp)
    }

    async fn decide_login(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::DecideLoginRequest>,
    ) -> ServiceResult<pb::DecideLoginResponse> {
        let caller = caller_of(&self.auth, &ctx).await;
        require_signed_in(&caller, "approve a sign-in")?;
        let req = request.to_owned_message();
        let user_code = req.user_code.unwrap_or_default();
        let status = if req.approve.unwrap_or(false) {
            let label = self
                .logins
                .describe(&user_code)
                .map(|d| d.label)
                .filter(|l| !l.is_empty())
                .unwrap_or_else(|| "cli token".into());
            // The mint is async now, so it runs before the pending→approved
            // transition; if the code turns out not to be pending, the fresh
            // token is revoked so no orphan session row is left.
            let token = self.auth.mint_api_token(caller.username(), &label).await?;
            let minted = token.clone();
            match self
                .logins
                .approve(&user_code, caller.username().to_string(), move || {
                    Ok::<_, std::convert::Infallible>(minted)
                }) {
                Approve::Approved => {
                    self.events
                        .sign_in(caller.username(), pb::AuditAction::TokenCreated, &label)
                        .await;
                    pb::LoginStatus::Approved
                }
                Approve::MintFailed(e) => match e {},
                Approve::NotPending => {
                    let _ = self.auth.revoke(Some(&format!("Bearer {token}"))).await;
                    return Err(ConnectError::failed_precondition(
                        "no such pending sign-in (it may have expired)",
                    ));
                }
            }
        } else if self.logins.deny(&user_code) {
            pb::LoginStatus::Denied
        } else {
            return Err(ConnectError::failed_precondition(
                "no such pending sign-in (it may have expired)",
            ));
        };
        Response::ok(pb::DecideLoginResponse {
            status: Some(status.into()),
            ..Default::default()
        })
    }

    async fn create_api_token(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::CreateApiTokenRequest>,
    ) -> ServiceResult<pb::CreateApiTokenResponse> {
        let caller = caller_of(&self.auth, &ctx).await;
        require_signed_in(&caller, "create an API token")?;
        // Cap live API tokens: they live a year, so an unbounded mint is a durable-row abuse vector.
        let live_api = self
            .db
            .sessions()
            .list(caller.username())
            .await?
            .into_iter()
            .filter(|(_, r)| r.kind == crate::db::KIND_API)
            .count();
        if live_api >= MAX_API_TOKENS_PER_USER {
            return Err(ConnectError::resource_exhausted(format!(
                "API token limit reached ({MAX_API_TOKENS_PER_USER} per account); revoke one first",
            )));
        }
        let name = request.to_owned_message().name.unwrap_or_default();
        // Trim + cap the client-supplied label (untrusted display name).
        let name = name.trim();
        let label = if name.is_empty() {
            "api token".to_string()
        } else {
            name.chars().take(128).collect()
        };
        let token = self.auth.mint_api_token(caller.username(), &label).await?;
        self.events
            .account(pb::AuditAction::TokenCreated, caller.username(), &label)
            .await;
        Response::ok(pb::CreateApiTokenResponse {
            token: Some(token),
            ..Default::default()
        })
    }

    async fn list_credentials(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, pb::ListCredentialsRequest>,
    ) -> ServiceResult<pb::ListCredentialsResponse> {
        let caller = caller_of(&self.auth, &ctx).await;
        require_signed_in(&caller, "list your passkeys")?;
        let creds = self.passkeys.credentials(caller.username()).await?;
        Response::ok(pb::ListCredentialsResponse {
            credentials: creds
                .into_iter()
                .map(|c| pb::Credential {
                    id: Some(c.id),
                    label: Some(c.label),
                    added_at: ts(c.added_at),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        })
    }

    async fn begin_add_credential(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, pb::BeginAddCredentialRequest>,
    ) -> ServiceResult<pb::BeginAddCredentialResponse> {
        let caller = caller_of(&self.auth, &ctx).await;
        require_signed_in(&caller, "add a passkey")?;
        let (flow_id, options_json) = self.passkeys.begin_add(caller.username()).await?;
        Response::ok(pb::BeginAddCredentialResponse {
            flow_id: Some(flow_id),
            options_json: Some(options_json),
            ..Default::default()
        })
    }

    async fn finish_add_credential(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::FinishAddCredentialRequest>,
    ) -> ServiceResult<pb::FinishAddCredentialResponse> {
        let caller = caller_of(&self.auth, &ctx).await;
        require_signed_in(&caller, "add a passkey")?;
        let req = request.to_owned_message();
        let (flow_id, credential_json, label) = (
            req.flow_id.clone().unwrap_or_default(),
            req.credential_json.clone().unwrap_or_default(),
            req.label.clone().unwrap_or_default(),
        );
        let info = self
            .passkeys
            .finish_add(&flow_id, &credential_json, &label, caller.username())
            .await?;
        self.events
            .account(
                pb::AuditAction::CredentialAdded,
                caller.username(),
                &info.id,
            )
            .await;
        Response::ok(pb::FinishAddCredentialResponse {
            credential: pb::Credential {
                id: Some(info.id),
                label: Some(info.label),
                added_at: ts(info.added_at),
                ..Default::default()
            }
            .into(),
            ..Default::default()
        })
    }

    async fn remove_credential(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::RemoveCredentialRequest>,
    ) -> ServiceResult<pb::RemoveCredentialResponse> {
        let caller = caller_of(&self.auth, &ctx).await;
        require_signed_in(&caller, "remove a passkey")?;
        let id = request.to_owned_message().id.unwrap_or_default();
        self.passkeys.remove(caller.username(), &id).await?;
        self.events
            .account(pb::AuditAction::CredentialRemoved, caller.username(), &id)
            .await;
        Response::ok(pb::RemoveCredentialResponse::default())
    }

    async fn watch_sessions(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, pb::WatchSessionsRequest>,
    ) -> ServiceResult<ServiceStream<pb::WatchSessionsResponse>> {
        let caller = caller_of(&self.auth, &ctx).await;
        require_signed_in(&caller, "list your sessions")?;
        // Token's fixed for the connection — resolve the current-session id once.
        let current = self.auth.current_session_id(request_token(&ctx).as_deref());
        let username = caller.username().to_string();
        let db = self.db.clone();
        resend_stream(self.db.subscribe(Topic::Sessions), move || {
            let db = db.clone();
            let username = username.clone();
            let current = current.clone();
            Box::pin(async move {
                let sessions = db.sessions().list(&username).await.ok()?;
                Some(pb::WatchSessionsResponse {
                    sessions: sessions
                        .into_iter()
                        .map(|(id, rec)| {
                            let is_current = current.as_deref() == Some(id.as_str());
                            let kind = if rec.kind == crate::db::KIND_API {
                                pb::SessionKind::Api
                            } else {
                                pb::SessionKind::Web
                            };
                            pb::Session {
                                id: Some(id),
                                kind: Some(kind.into()),
                                label: Some(rec.label),
                                created_at: ts(rec.created_at),
                                expires_at: ts(rec.expires_at),
                                current: Some(is_current),
                                last_seen: ts(rec.last_seen),
                                ip: Some(rec.ip),
                                device: Some(rec.device),
                                ..Default::default()
                            }
                        })
                        .collect(),
                    ..Default::default()
                })
            })
        })
    }

    async fn revoke_session(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::RevokeSessionRequest>,
    ) -> ServiceResult<pb::RevokeSessionResponse> {
        let caller = caller_of(&self.auth, &ctx).await;
        require_signed_in(&caller, "revoke a session")?;
        let id = request.to_owned_message().id.unwrap_or_default();
        self.db
            .sessions()
            .delete_by_id(caller.username(), &id)
            .await?;
        self.events
            .account(pb::AuditAction::SessionRevoked, caller.username(), &id)
            .await;
        Response::ok(pb::RevokeSessionResponse::default())
    }

    async fn revoke_other_sessions(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, pb::RevokeOtherSessionsRequest>,
    ) -> ServiceResult<pb::RevokeOtherSessionsResponse> {
        let caller = caller_of(&self.auth, &ctx).await;
        require_signed_in(&caller, "revoke sessions")?;
        // Spare the caller's own session; if it can't resolve, keep is empty and
        // every row goes (the honest "sign out everywhere" fallback).
        let keep = self
            .auth
            .current_session_id(request_token(&ctx).as_deref())
            .unwrap_or_default();
        let revoked = self
            .db
            .sessions()
            .delete_others(caller.username(), &keep)
            .await?;
        self.events
            .account(
                pb::AuditAction::SessionRevoked,
                caller.username(),
                "other sessions",
            )
            .await;
        Response::ok(pb::RevokeOtherSessionsResponse {
            revoked: Some(revoked),
            ..Default::default()
        })
    }

    async fn set_email(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::SetEmailRequest>,
    ) -> ServiceResult<pb::SetEmailResponse> {
        let caller = caller_of(&self.auth, &ctx).await;
        require_signed_in(&caller, "set your email")?;
        let email = request.to_owned_message().email.unwrap_or_default();
        self.passkeys
            .set_email(caller.username(), Some(&email))
            .await?;
        // Email is PII — audit target is the account, not the address.
        self.events
            .account(
                pb::AuditAction::EmailChanged,
                caller.username(),
                caller.username(),
            )
            .await;
        Response::ok(pb::SetEmailResponse::default())
    }

    async fn logout(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, pb::LogoutRequest>,
    ) -> ServiceResult<pb::LogoutResponse> {
        let token = request_token(&ctx);
        let _ = self.auth.revoke(token.as_deref()).await;
        let clear =
            crate::auth::clear_session_cookie(self.cookie_domain.as_deref(), self.cookie_secure);
        Ok(Response::new(pb::LogoutResponse::default())
            .with_header(http::header::SET_COOKIE, clear))
    }

    async fn watch_own_activity(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::WatchOwnActivityRequest>,
    ) -> ServiceResult<ServiceStream<pb::WatchOwnActivityResponse>> {
        let caller = caller_of(&self.auth, &ctx).await;
        require_signed_in(&caller, "read your activity")?;
        let limit = match request.to_owned_message().limit.unwrap_or(0) {
            0 => 200,
            n => (n as usize).min(1000),
        };
        let username = caller.username().to_string();
        audit_stream(self.db.clone(), limit, Some(username), None, |entries| {
            pb::WatchOwnActivityResponse {
                entries,
                ..Default::default()
            }
        })
    }

    async fn watch_notifications(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::WatchNotificationsRequest>,
    ) -> ServiceResult<ServiceStream<pb::WatchNotificationsResponse>> {
        let caller = caller_of(&self.auth, &ctx).await;
        require_signed_in(&caller, "read your notifications")?;
        let limit = match request.to_owned_message().limit.unwrap_or(0) {
            0 => 100,
            n => (n as usize).min(500),
        };
        let username = caller.username().to_string();
        let db = self.db.clone();
        resend_stream(self.db.subscribe(Topic::Notifications), move || {
            let db = db.clone();
            let username = username.clone();
            Box::pin(async move {
                let list = db.notifications().list(&username, limit).await.ok()?;
                Some(pb::WatchNotificationsResponse {
                    notifications: list
                        .into_iter()
                        .map(|(id, r)| notification(id, r))
                        .collect(),
                    ..Default::default()
                })
            })
        })
    }

    async fn mark_notification_read(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::MarkNotificationReadRequest>,
    ) -> ServiceResult<pb::MarkNotificationReadResponse> {
        let caller = caller_of(&self.auth, &ctx).await;
        require_signed_in(&caller, "update your notifications")?;
        let id = request.to_owned_message().id.unwrap_or(0);
        // Scoped to the caller so one user can't touch another's inbox.
        self.db
            .notifications()
            .mark_read(caller.username(), id)
            .await?;
        Response::ok(pb::MarkNotificationReadResponse::default())
    }

    async fn mark_all_notifications_read(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, pb::MarkAllNotificationsReadRequest>,
    ) -> ServiceResult<pb::MarkAllNotificationsReadResponse> {
        let caller = caller_of(&self.auth, &ctx).await;
        require_signed_in(&caller, "update your notifications")?;
        self.db
            .notifications()
            .mark_all_read(caller.username())
            .await?;
        Response::ok(pb::MarkAllNotificationsReadResponse::default())
    }
}

//! The HTTP surface. Mounted by each service at `/account`.
//!
//! The invariants these handlers exist to uphold are in DESIGN.md §4; the two
//! that shape almost every function below:
//!
//! * every credential rejection returns [`credential_error`] — one status, one
//!   body, whichever check actually failed;
//! * every endpoint that takes an email address and sends mail answers `200`
//!   with the same body whether or not that address is registered.

use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::http::{header, Method, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::current_user::{CurrentUser, RequestMeta, SESSION_COOKIE};
use crate::{db, email::Templates, password, token, AccountState};

// Rate-limit budgets. Per-IP catches one source hammering many addresses;
// per-email catches many sources hammering one. The DB-side resend cooldown
// in `resend_verify` is a third, narrower guard and not a replacement.
const HOUR: Duration = Duration::from_secs(3600);
const FIVE_MIN: Duration = Duration::from_secs(300);
const REGISTER_PER_IP: usize = 10;
const REGISTER_PER_EMAIL: usize = 3;
const LOGIN_PER_IP: usize = 30;
const LOGIN_PER_EMAIL: usize = 10;
const MAIL_PER_IP: usize = 10;
const MAIL_PER_EMAIL: usize = 3;
const CODE_PER_IP: usize = 20;

pub fn router(state: AccountState) -> Router {
    let public = Router::new()
        .route("/register", post(register))
        .route("/verify", post(verify))
        .route("/verify/{id}/{token}", get(verify_link))
        .route("/verify/code", post(verify_code))
        .route("/verify/resend", post(resend_verify))
        .route("/login", post(login))
        .route("/logout", post(logout))
        .route("/password-reset/request", post(password_reset_request))
        .route("/password-reset/confirm", post(password_reset_confirm));

    let authed = Router::new()
        .route("/me", get(me))
        .route("/password", post(change_password))
        .route("/sessions", get(list_sessions).delete(revoke_other_sessions))
        .route("/sessions/{id}", delete(revoke_session));

    let router = public.merge(authed);

    #[cfg(feature = "oauth")]
    let router = router
        .route("/oauth", get(oauth_providers))
        .route("/oauth/{provider}/start", get(oauth_start))
        .route("/oauth/{provider}/callback", get(oauth_callback));

    router
        .layer(axum::middleware::from_fn_with_state(state.clone(), origin_guard))
        .with_state(state)
}

// ---- shared response shapes ------------------------------------------------

/// The single credential rejection. Login (no account / wrong password /
/// unverified / suspended), verification, and reset-confirm all end here, so
/// the caller cannot tell which check failed.
pub(crate) fn credential_error() -> (StatusCode, Json<Value>) {
    (StatusCode::UNAUTHORIZED, Json(json!({ "error": "invalid credentials" })))
}

pub(crate) fn bad_request(msg: impl Into<String>) -> (StatusCode, Json<Value>) {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": msg.into() })))
}

pub(crate) fn too_many() -> (StatusCode, Json<Value>) {
    (StatusCode::TOO_MANY_REQUESTS, Json(json!({ "error": "too many requests, try again later" })))
}

pub(crate) fn internal_error() -> (StatusCode, Json<Value>) {
    (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "internal error" })))
}

/// The uniform answer when `Mailer::is_healthy` fails. Same status and body
/// for every caller regardless of what email they sent — see the doc on
/// `is_healthy` for why this has to be checked, and answered, before any
/// per-address branching in `register`/`resend_verify`/`password_reset_request`.
pub(crate) fn mail_unavailable() -> (StatusCode, Json<Value>) {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({ "error": "email delivery is currently unavailable, try again shortly" })),
    )
}

pub(crate) fn ok() -> (StatusCode, Json<Value>) {
    (StatusCode::OK, Json(json!({ "status": "ok" })))
}

/// Deliberately loose. Real deliverability is decided by whether the
/// confirmation mail arrives, not by a regex, and every regex strict enough to
/// feel useful rejects addresses that are actually valid.
pub(crate) fn normalize_email(raw: &str) -> Option<String> {
    let email = raw.trim().to_lowercase();
    let valid = !email.is_empty()
        && email.len() <= 256
        && email.contains('@')
        && !email.starts_with('@')
        && !email.ends_with('@')
        && !email.contains(char::is_whitespace);
    valid.then_some(email)
}

// ---- CSRF ------------------------------------------------------------------

/// Rejects state-changing requests from an origin this site does not claim.
///
/// `SameSite=Lax` plus a JSON-only API already blocks the classic cross-site
/// form post (a form cannot set `Content-Type: application/json`). This is the
/// belt to that pair of braces. A request with no `Origin` header at all is
/// allowed: that is a same-origin navigation or a non-browser client, neither
/// of which is the attack.
pub(crate) async fn origin_guard(
    State(state): State<AccountState>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let safe = matches!(*request.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    if !safe && !state.config.allowed_origins.is_empty() {
        if let Some(origin) = request.headers().get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
            let origin = origin.trim_end_matches('/');
            if !state.config.allowed_origins.iter().any(|a| a == origin) {
                tracing::warn!(origin, "rejected state-changing request from foreign origin");
                return (StatusCode::FORBIDDEN, Json(json!({ "error": "forbidden" })))
                    .into_response();
            }
        }
    }
    next.run(request).await
}

// ---- sessions --------------------------------------------------------------

fn session_cookie(state: &AccountState, value: String) -> Cookie<'static> {
    let mut cookie = Cookie::new(SESSION_COOKIE, value);
    cookie.set_http_only(true);
    cookie.set_secure(state.config.secure_cookies);
    cookie.set_same_site(SameSite::Lax);
    cookie.set_path("/");
    cookie.set_max_age(Some(time::Duration::seconds(
        state.config.session_ttl.as_secs() as i64
    )));
    cookie
}

/// Mints a session and returns the jar carrying its cookie. The secret goes to
/// the browser; only its hash reaches the database.
async fn start_session(
    state: &AccountState,
    jar: CookieJar,
    user_id: Uuid,
    meta: &RequestMeta,
) -> anyhow::Result<CookieJar> {
    let secret = token::secret();
    let ttl = chrono::Duration::from_std(state.config.session_ttl)
        .unwrap_or_else(|_| chrono::Duration::days(30));
    db::create_session(
        &state.pool,
        user_id,
        &token::hash(&secret),
        ttl,
        meta.ip.as_deref(),
        meta.user_agent.as_deref(),
    )
    .await?;
    db::mark_login(&state.pool, user_id).await?;
    Ok(jar.add(session_cookie(state, secret)))
}

// ---- register --------------------------------------------------------------

#[derive(Deserialize)]
struct RegisterReq {
    email: String,
    password: String,
    #[serde(default)]
    display_name: Option<String>,
}

async fn register(
    State(state): State<AccountState>,
    meta: RequestMeta,
    Json(req): Json<RegisterReq>,
) -> Response {
    let Some(email) = normalize_email(&req.email) else {
        return bad_request("invalid email").into_response();
    };
    if let Err(e) = password::check_policy(&req.password, &email) {
        return bad_request(e.message()).into_response();
    }
    if !state.limiter.check(&format!("reg:ip:{}", meta.ip_key()), REGISTER_PER_IP, HOUR)
        || !state.limiter.check(&format!("reg:em:{email}"), REGISTER_PER_EMAIL, HOUR)
    {
        return too_many().into_response();
    }
    // Checked before any DB write, and independent of `email`: an account
    // that cannot be verified because mail is down is a dead end, and a
    // response that only fails for the *new-account* branch would tell an
    // attacker which addresses are already registered during an outage.
    if !state.mailer.is_healthy().await {
        return mail_unavailable().into_response();
    }

    let hash = match password::hash(&req.password) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!(%e, "hash password");
            return internal_error().into_response();
        }
    };

    let display_name = req
        .display_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty() && s.len() <= 256);

    match db::create_user(&state.pool, &email, Some(&hash), display_name, false).await {
        // New account: arm the challenge and send the mail. Already taken
        // (`None`, the ON CONFLICT case): do neither — but the response below
        // is identical either way, so registration cannot be used to test
        // whether an address has an account.
        Ok(Some(user_id)) => {
            if let Err(e) = db::grant_roles(&state.pool, user_id, &state.config.default_roles).await
            {
                tracing::error!(%e, "grant default roles");
            }
            send_verification(&state, user_id, &email).await;
            db::log_event(
                &state.pool,
                "register",
                Some(user_id),
                Some(&email),
                meta.ip.as_deref(),
                meta.user_agent.as_deref(),
            )
            .await;
        }
        Ok(None) => {}
        Err(e) => {
            tracing::error!(%e, "create_user");
            return internal_error().into_response();
        }
    }

    (
        StatusCode::CREATED,
        Json(json!({
            "status": "registered",
            "note": "check your email to activate your account",
        })),
    )
        .into_response()
}

/// Arms a fresh link token *and* short code, then mails both. Failures are
/// logged, never surfaced — see `Mailer::send`.
async fn send_verification(state: &AccountState, user_id: Uuid, email: &str) {
    let secret = token::secret();
    let code = token::short_code();
    if let Err(e) =
        db::set_verify_challenge(&state.pool, user_id, &token::hash(&secret), &code).await
    {
        tracing::error!(%e, "set_verify_challenge");
        return;
    }
    let url = state.config.verify_url(&user_id, &secret);
    let (subject, text, html) = Templates::verify(&state.config.product_name, &url, &code);
    state.mailer.send(email, &subject, text, html).await;
}

// ---- verify ----------------------------------------------------------------

#[derive(Deserialize)]
struct VerifyReq {
    id: Uuid,
    token: String,
}

/// Confirming an address proves control of the inbox, which is exactly the
/// evidence a login asks for — so a successful verification signs the user in
/// rather than bouncing them to a login form.
async fn verify(
    State(state): State<AccountState>,
    jar: CookieJar,
    meta: RequestMeta,
    Json(req): Json<VerifyReq>,
) -> Response {
    finish_verify(&state, jar, meta, req.id, &req.token).await
}

async fn verify_link(
    State(state): State<AccountState>,
    jar: CookieJar,
    meta: RequestMeta,
    Path((id, tok)): Path<(Uuid, String)>,
) -> Response {
    finish_verify(&state, jar, meta, id, &tok).await
}

async fn finish_verify(
    state: &AccountState,
    jar: CookieJar,
    meta: RequestMeta,
    id: Uuid,
    raw_token: &str,
) -> Response {
    let ttl = chrono::Duration::from_std(state.config.verify_ttl)
        .unwrap_or_else(|_| chrono::Duration::hours(24));
    match db::consume_verify_token(&state.pool, id, &token::hash(raw_token), ttl).await {
        Ok(true) => {}
        Ok(false) => return credential_error().into_response(),
        Err(e) => {
            tracing::error!(%e, "consume_verify_token");
            return internal_error().into_response();
        }
    }
    verified_response(state, jar, meta, id).await
}

#[derive(Deserialize)]
struct VerifyCodeReq {
    email: String,
    code: String,
}

/// The type-it-in path, for the "we mailed you a 6-digit code" step. Safe only
/// because of the attempt cap enforced in the SQL — six digits is otherwise a
/// 10^6 search.
async fn verify_code(
    State(state): State<AccountState>,
    jar: CookieJar,
    meta: RequestMeta,
    Json(req): Json<VerifyCodeReq>,
) -> Response {
    let Some(email) = normalize_email(&req.email) else {
        return credential_error().into_response();
    };
    if !state.limiter.check(&format!("code:ip:{}", meta.ip_key()), CODE_PER_IP, FIVE_MIN) {
        return too_many().into_response();
    }

    let user = match db::find_user_by_email(&state.pool, &email).await {
        Ok(Some(u)) => u,
        Ok(None) => return credential_error().into_response(),
        Err(e) => {
            tracing::error!(%e, "find_user_by_email");
            return internal_error().into_response();
        }
    };

    let ttl = chrono::Duration::from_std(state.config.verify_ttl)
        .unwrap_or_else(|_| chrono::Duration::hours(24));
    let matched = match db::consume_verify_code(
        &state.pool,
        user.id,
        req.code.trim(),
        ttl,
        state.config.max_verify_attempts,
    )
    .await
    {
        Ok(m) => m,
        Err(e) => {
            tracing::error!(%e, "consume_verify_code");
            return internal_error().into_response();
        }
    };

    if !matched {
        // Charge the attempt only on a miss, so a user who mistypes twice and
        // then gets it right is not locked out by their own success.
        if let Err(e) = db::bump_verify_attempts(&state.pool, user.id).await {
            tracing::error!(%e, "bump_verify_attempts");
        }
        return credential_error().into_response();
    }

    verified_response(&state, jar, meta, user.id).await
}

/// Shared tail of both verification paths: sign in and answer with the account.
async fn verified_response(
    state: &AccountState,
    jar: CookieJar,
    meta: RequestMeta,
    user_id: Uuid,
) -> Response {
    db::log_event(
        &state.pool,
        "verify",
        Some(user_id),
        None,
        meta.ip.as_deref(),
        meta.user_agent.as_deref(),
    )
    .await;

    let jar = match start_session(state, jar, user_id, &meta).await {
        Ok(j) => j,
        Err(e) => {
            tracing::error!(%e, "start_session after verify");
            return internal_error().into_response();
        }
    };

    match account_json(state, user_id).await {
        Ok(Some(body)) => (jar, Json(json!({ "status": "verified", "user": body }))).into_response(),
        Ok(None) => credential_error().into_response(),
        Err(e) => {
            tracing::error!(%e, "load account after verify");
            internal_error().into_response()
        }
    }
}

#[derive(Deserialize)]
struct EmailOnlyReq {
    email: String,
}

/// Always `200`, identical body — existing address or not, already verified or
/// not. The only observable difference is whether a message arrives, which
/// only the address owner can see.
async fn resend_verify(
    State(state): State<AccountState>,
    meta: RequestMeta,
    Json(req): Json<EmailOnlyReq>,
) -> Response {
    let Some(email) = normalize_email(&req.email) else {
        return ok().into_response();
    };
    if !state.limiter.check(&format!("mail:ip:{}", meta.ip_key()), MAIL_PER_IP, HOUR)
        || !state.limiter.check(&format!("mail:em:{email}"), MAIL_PER_EMAIL, HOUR)
    {
        return too_many().into_response();
    }
    // Same reasoning as `register`: checked before the DB lookup, so the
    // answer does not depend on whether this address would actually have
    // triggered a send.
    if !state.mailer.is_healthy().await {
        return mail_unavailable().into_response();
    }

    if let Ok(Some(user)) = db::find_user_by_email(&state.pool, &email).await {
        let cooled = user
            .verify_sent_at
            .map(|sent| {
                chrono::Utc::now() - sent
                    > chrono::Duration::from_std(state.config.resend_cooldown)
                        .unwrap_or_else(|_| chrono::Duration::seconds(60))
            })
            .unwrap_or(true);
        if !user.email_verified && !user.suspended && cooled {
            send_verification(&state, user.id, &email).await;
        }
    }

    ok().into_response()
}

// ---- login / logout ---------------------------------------------------------

#[derive(Deserialize)]
struct LoginReq {
    email: String,
    password: String,
}

async fn login(
    State(state): State<AccountState>,
    jar: CookieJar,
    meta: RequestMeta,
    Json(req): Json<LoginReq>,
) -> Response {
    // Not `normalize_email`s rejection path: an unparseable address is just a
    // failed login, and saying so would be a different answer than a wrong
    // password.
    let email = req.email.trim().to_lowercase();

    if !state.limiter.check(&format!("login:ip:{}", meta.ip_key()), LOGIN_PER_IP, FIVE_MIN)
        || !state.limiter.check(&format!("login:em:{email}"), LOGIN_PER_EMAIL, FIVE_MIN)
    {
        return too_many().into_response();
    }

    let user = match db::find_user_by_email(&state.pool, &email).await {
        Ok(u) => u,
        Err(e) => {
            tracing::error!(%e, "find_user_by_email");
            return internal_error().into_response();
        }
    };

    let authenticated = match &user {
        Some(u) => match &u.password_hash {
            Some(hash) => password::verify(&req.password, hash) && u.email_verified && !u.suspended,
            // An SSO-only account has no local password to be wrong. Still do
            // the argon2 work below so it is not distinguishable by timing.
            None => {
                password::verify(&req.password, password::dummy_hash());
                false
            }
        },
        None => {
            password::verify(&req.password, password::dummy_hash());
            false
        }
    };

    if !authenticated {
        db::log_event(
            &state.pool,
            "login_fail",
            user.as_ref().map(|u| u.id),
            Some(&email),
            meta.ip.as_deref(),
            meta.user_agent.as_deref(),
        )
        .await;
        return credential_error().into_response();
    }

    let user = user.expect("authenticated implies a user row");
    let jar = match start_session(&state, jar, user.id, &meta).await {
        Ok(j) => j,
        Err(e) => {
            tracing::error!(%e, "create_session");
            return internal_error().into_response();
        }
    };
    db::log_event(
        &state.pool,
        "login_ok",
        Some(user.id),
        Some(&email),
        meta.ip.as_deref(),
        meta.user_agent.as_deref(),
    )
    .await;

    match account_json(&state, user.id).await {
        Ok(Some(body)) => (jar, Json(json!({ "status": "ok", "user": body }))).into_response(),
        Ok(None) => credential_error().into_response(),
        Err(e) => {
            tracing::error!(%e, "load account after login");
            internal_error().into_response()
        }
    }
}

async fn logout(State(state): State<AccountState>, jar: CookieJar, meta: RequestMeta) -> Response {
    if let Some(cookie) = jar.get(SESSION_COOKIE) {
        if let Err(e) = db::delete_session_by_token(&state.pool, &token::hash(cookie.value())).await
        {
            tracing::error!(%e, "delete_session");
        }
    }
    db::log_event(&state.pool, "logout", None, None, meta.ip.as_deref(), meta.user_agent.as_deref())
        .await;
    // Same attributes as when it was set, or the browser keeps the old one.
    let mut removal = session_cookie(&state, String::new());
    removal.make_removal();
    (jar.add(removal), Json(json!({ "status": "ok" }))).into_response()
}

// ---- account ----------------------------------------------------------------

#[derive(Serialize)]
struct IdentityJson {
    provider: String,
    email: Option<String>,
    linked_at: chrono::DateTime<chrono::Utc>,
}

async fn account_json(state: &AccountState, user_id: Uuid) -> anyhow::Result<Option<Value>> {
    let Some(user) = db::find_user_by_id(&state.pool, user_id).await? else {
        return Ok(None);
    };
    let roles = db::roles_for_user(&state.pool, user_id).await?;
    let identities: Vec<IdentityJson> = db::identities_for_user(&state.pool, user_id)
        .await?
        .into_iter()
        .map(|i| IdentityJson {
            provider: i.provider,
            email: i.email,
            linked_at: i.created_at,
        })
        .collect();
    Ok(Some(json!({
        "id": user.id,
        "email": user.email,
        "display_name": user.display_name,
        "email_verified": user.email_verified,
        // Whether a local password exists at all, so the UI can offer "set a
        // password" to an SSO-only account instead of "change password".
        "has_password": user.password_hash.is_some(),
        "roles": roles,
        "identities": identities,
    })))
}

async fn me(State(state): State<AccountState>, user: CurrentUser) -> Response {
    match account_json(&state, user.id).await {
        Ok(Some(body)) => Json(body).into_response(),
        Ok(None) => credential_error().into_response(),
        Err(e) => {
            tracing::error!(%e, "load account");
            internal_error().into_response()
        }
    }
}

#[derive(Deserialize)]
struct ChangePasswordReq {
    /// Absent is allowed only for an SSO-only account setting its first
    /// password; an account that has one must prove it knows it.
    #[serde(default)]
    current_password: Option<String>,
    new_password: String,
}

async fn change_password(
    State(state): State<AccountState>,
    user: CurrentUser,
    meta: RequestMeta,
    Json(req): Json<ChangePasswordReq>,
) -> Response {
    if let Err(e) = password::check_policy(&req.new_password, &user.email) {
        return bad_request(e.message()).into_response();
    }

    let row = match db::find_user_by_id(&state.pool, user.id).await {
        Ok(Some(u)) => u,
        Ok(None) => return credential_error().into_response(),
        Err(e) => {
            tracing::error!(%e, "find_user_by_id");
            return internal_error().into_response();
        }
    };

    if let Some(existing) = &row.password_hash {
        let supplied = req.current_password.as_deref().unwrap_or_default();
        if !password::verify(supplied, existing) {
            return credential_error().into_response();
        }
    }

    let hash = match password::hash(&req.new_password) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!(%e, "hash password");
            return internal_error().into_response();
        }
    };
    if let Err(e) = db::update_password_hash(&state.pool, user.id, &hash).await {
        tracing::error!(%e, "update_password_hash");
        return internal_error().into_response();
    }

    // Everything that could have been minted under the old password goes:
    // other sessions, and any reset link still sitting in the inbox.
    if let Err(e) =
        db::delete_sessions_for_user(&state.pool, user.id, Some(user.session_id)).await
    {
        tracing::error!(%e, "revoke other sessions after password change");
    }
    if let Err(e) = db::invalidate_password_resets(&state.pool, user.id).await {
        tracing::error!(%e, "invalidate password resets");
    }
    db::log_event(
        &state.pool,
        "password_change",
        Some(user.id),
        Some(&user.email),
        meta.ip.as_deref(),
        meta.user_agent.as_deref(),
    )
    .await;

    ok().into_response()
}

// ---- password reset ---------------------------------------------------------

async fn password_reset_request(
    State(state): State<AccountState>,
    meta: RequestMeta,
    Json(req): Json<EmailOnlyReq>,
) -> Response {
    let Some(email) = normalize_email(&req.email) else {
        return ok().into_response();
    };
    if !state.limiter.check(&format!("mail:ip:{}", meta.ip_key()), MAIL_PER_IP, HOUR)
        || !state.limiter.check(&format!("mail:em:{email}"), MAIL_PER_EMAIL, HOUR)
    {
        return too_many().into_response();
    }
    // Same reasoning as `register`: checked before the DB lookup, so the
    // answer does not depend on whether this address would actually have
    // triggered a send.
    if !state.mailer.is_healthy().await {
        return mail_unavailable().into_response();
    }

    if let Ok(Some(user)) = db::find_user_by_email(&state.pool, &email).await {
        if !user.suspended {
            let secret = token::secret();
            match db::create_password_reset(&state.pool, user.id, &token::hash(&secret)).await {
                Ok(()) => {
                    let url = state.config.reset_url(&secret);
                    let hours = state.config.reset_ttl.as_secs().div_ceil(3600);
                    let (subject, text, html) =
                        Templates::reset(&state.config.product_name, &url, hours);
                    state.mailer.send(&email, &subject, text, html).await;
                    db::log_event(
                        &state.pool,
                        "reset_request",
                        Some(user.id),
                        Some(&email),
                        meta.ip.as_deref(),
                        meta.user_agent.as_deref(),
                    )
                    .await;
                }
                Err(e) => tracing::error!(%e, "create_password_reset"),
            }
        }
    }

    ok().into_response()
}

#[derive(Deserialize)]
struct ResetConfirmReq {
    token: String,
    new_password: String,
}

async fn password_reset_confirm(
    State(state): State<AccountState>,
    meta: RequestMeta,
    Json(req): Json<ResetConfirmReq>,
) -> Response {
    let ttl = chrono::Duration::from_std(state.config.reset_ttl)
        .unwrap_or_else(|_| chrono::Duration::hours(1));
    let user_id = match db::consume_password_reset(&state.pool, &token::hash(&req.token), ttl).await
    {
        Ok(Some(id)) => id,
        Ok(None) => return credential_error().into_response(),
        Err(e) => {
            tracing::error!(%e, "consume_password_reset");
            return internal_error().into_response();
        }
    };

    // Policy is checked after the token is spent, not before: a rejected
    // password otherwise lets an attacker probe token validity without
    // burning the token.
    let email = match db::find_user_by_id(&state.pool, user_id).await {
        Ok(Some(u)) => u.email,
        Ok(None) => return credential_error().into_response(),
        Err(e) => {
            tracing::error!(%e, "find_user_by_id");
            return internal_error().into_response();
        }
    };
    if let Err(e) = password::check_policy(&req.new_password, &email) {
        return bad_request(e.message()).into_response();
    }

    let hash = match password::hash(&req.new_password) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!(%e, "hash password");
            return internal_error().into_response();
        }
    };
    if let Err(e) = db::update_password_hash(&state.pool, user_id, &hash).await {
        tracing::error!(%e, "update_password_hash");
        return internal_error().into_response();
    }

    // Reaching the inbox is the same proof the verification link asks for, so
    // a reset also confirms an address that was never confirmed.
    if let Err(e) = db::mark_email_verified(&state.pool, user_id).await {
        tracing::error!(%e, "mark_email_verified after reset");
    }
    // A reset that leaves the intruder logged in is not a recovery.
    if let Err(e) = db::delete_sessions_for_user(&state.pool, user_id, None).await {
        tracing::error!(%e, "revoke sessions after reset");
    }
    if let Err(e) = db::invalidate_password_resets(&state.pool, user_id).await {
        tracing::error!(%e, "invalidate password resets");
    }
    db::log_event(
        &state.pool,
        "reset_confirm",
        Some(user_id),
        Some(&email),
        meta.ip.as_deref(),
        meta.user_agent.as_deref(),
    )
    .await;

    ok().into_response()
}

// ---- session management -----------------------------------------------------

#[derive(Serialize)]
struct SessionJson {
    id: Uuid,
    current: bool,
    ip: Option<String>,
    user_agent: Option<String>,
    created_at: chrono::DateTime<chrono::Utc>,
    last_seen_at: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
}

async fn list_sessions(State(state): State<AccountState>, user: CurrentUser) -> Response {
    match db::list_sessions(&state.pool, user.id).await {
        Ok(rows) => {
            let items: Vec<SessionJson> = rows
                .into_iter()
                .map(|s| SessionJson {
                    current: s.id == user.session_id,
                    id: s.id,
                    ip: s.ip,
                    user_agent: s.user_agent,
                    created_at: s.created_at,
                    last_seen_at: s.last_seen_at,
                    expires_at: s.expires_at,
                })
                .collect();
            Json(json!({ "items": items })).into_response()
        }
        Err(e) => {
            tracing::error!(%e, "list_sessions");
            internal_error().into_response()
        }
    }
}

async fn revoke_session(
    State(state): State<AccountState>,
    user: CurrentUser,
    Path(id): Path<Uuid>,
) -> Response {
    match db::delete_session_by_id(&state.pool, user.id, id).await {
        // Scoped to the caller in SQL: a session id is not a secret, so
        // revoking by id alone would let anyone close anyone else`s session.
        Ok(true) => ok().into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, Json(json!({ "error": "not found" }))).into_response(),
        Err(e) => {
            tracing::error!(%e, "delete_session_by_id");
            internal_error().into_response()
        }
    }
}

async fn revoke_other_sessions(State(state): State<AccountState>, user: CurrentUser) -> Response {
    match db::delete_sessions_for_user(&state.pool, user.id, Some(user.session_id)).await {
        Ok(count) => Json(json!({ "status": "ok", "revoked": count })).into_response(),
        Err(e) => {
            tracing::error!(%e, "delete_sessions_for_user");
            internal_error().into_response()
        }
    }
}

// ---- oauth ------------------------------------------------------------------

#[cfg(feature = "oauth")]
async fn oauth_providers(State(state): State<AccountState>) -> Response {
    let items: Vec<Value> = state
        .oauth
        .iter()
        .map(|c| {
            json!({
                "key": c.provider.key,
                "name": c.provider.display_name,
                "start": format!("/account/oauth/{}/start", c.provider.key),
            })
        })
        .collect();
    Json(json!({ "providers": items })).into_response()
}

#[cfg(feature = "oauth")]
#[derive(Deserialize)]
struct OauthStartQuery {
    #[serde(default)]
    redirect_to: Option<String>,
}

/// Site-relative paths only. Without this an `?redirect_to=https://evil` turns
/// the callback into an open redirect, and an open redirect on an endpoint
/// that has just set a session cookie is a credential-leak primitive.
#[cfg(feature = "oauth")]
fn safe_redirect(raw: Option<&str>) -> Option<String> {
    let path = raw?.trim();
    let ok = path.starts_with('/')
        && !path.starts_with("//")
        && !path.starts_with("/\\")
        && path.len() <= 512;
    ok.then(|| path.to_string())
}

#[cfg(feature = "oauth")]
async fn oauth_start(
    State(state): State<AccountState>,
    Path(provider_key): Path<String>,
    Query(q): Query<OauthStartQuery>,
    crate::current_user::OptionalUser(user): crate::current_user::OptionalUser,
) -> Response {
    let Some(configured) = state.oauth.iter().find(|c| c.provider.key == provider_key) else {
        return (StatusCode::NOT_FOUND, Json(json!({ "error": "unknown provider" })))
            .into_response();
    };

    let state_value = token::secret();
    let (verifier, challenge) = crate::oauth::pkce_pair();

    if let Err(e) = db::put_oauth_state(
        &state.pool,
        &token::hash(&state_value),
        configured.provider.key,
        &verifier,
        // Present means "link this provider to the account already signed in",
        // absent means "sign in or sign up with it".
        user.as_ref().map(|u| u.id),
        safe_redirect(q.redirect_to.as_deref()).as_deref(),
    )
    .await
    {
        tracing::error!(%e, "put_oauth_state");
        return internal_error().into_response();
    }

    axum::response::Redirect::to(&configured.authorize_url(&state_value, &challenge)).into_response()
}

#[cfg(feature = "oauth")]
#[derive(Deserialize)]
struct OauthCallbackQuery {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

#[cfg(feature = "oauth")]
async fn oauth_callback(
    State(state): State<AccountState>,
    jar: CookieJar,
    meta: RequestMeta,
    Path(provider_key): Path<String>,
    Query(q): Query<OauthCallbackQuery>,
) -> Response {
    // The browser is here, not an API client, so failures end as a redirect
    // back to the sign-in page with a marker rather than as a JSON body.
    let fail = |reason: &str| -> Response {
        tracing::warn!(provider = %provider_key, reason, "oauth callback rejected");
        axum::response::Redirect::to(&format!(
            "{}/account/sign-in?error=oauth",
            state.config.app_base_url
        ))
        .into_response()
    };

    if q.error.is_some() {
        return fail("provider returned an error");
    }
    let (Some(code), Some(state_value)) = (q.code, q.state) else {
        return fail("missing code or state");
    };

    let flow = match db::take_oauth_state(
        &state.pool,
        &token::hash(&state_value),
        chrono::Duration::minutes(15),
    )
    .await
    {
        Ok(Some(f)) => f,
        Ok(None) => return fail("unknown, expired or replayed state"),
        Err(e) => {
            tracing::error!(%e, "take_oauth_state");
            return fail("state lookup failed");
        }
    };
    if flow.provider != provider_key {
        return fail("state belongs to a different provider");
    }

    let Some(configured) = state.oauth.iter().find(|c| c.provider.key == provider_key) else {
        return fail("provider no longer configured");
    };

    let access_token = match configured.exchange_code(&code, &flow.pkce_verifier).await {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(%e, "oauth code exchange");
            return fail("code exchange failed");
        }
    };
    let profile = match configured.fetch_profile(&access_token).await {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(%e, "oauth profile fetch");
            return fail("profile fetch failed");
        }
    };

    let user_id = match resolve_oauth_user(&state, &provider_key, &profile, flow.link_user_id).await
    {
        Ok(Some(id)) => id,
        Ok(None) => return fail("no verified email from provider"),
        Err(e) => {
            tracing::error!(%e, "resolve oauth user");
            return fail("account resolution failed");
        }
    };

    match db::find_user_by_id(&state.pool, user_id).await {
        Ok(Some(u)) if !u.suspended => {}
        Ok(_) => return fail("account unavailable"),
        Err(e) => {
            tracing::error!(%e, "find_user_by_id");
            return fail("account lookup failed");
        }
    }

    let jar = match start_session(&state, jar, user_id, &meta).await {
        Ok(j) => j,
        Err(e) => {
            tracing::error!(%e, "start_session after oauth");
            return fail("session creation failed");
        }
    };
    db::log_event(
        &state.pool,
        "oauth_login",
        Some(user_id),
        profile.email.as_deref(),
        meta.ip.as_deref(),
        meta.user_agent.as_deref(),
    )
    .await;

    let target = flow.redirect_to.unwrap_or_else(|| "/".to_string());
    (jar, axum::response::Redirect::to(&format!("{}{}", state.config.app_base_url, target)))
        .into_response()
}

/// Turns a provider profile into a local account.
///
/// The order matters: an existing *link* wins outright; otherwise an explicit
/// link request wins; only then do we fall back to matching on the email, and
/// that step demands the provider vouch for the address. Matching an
/// unverified provider email against a local account is account takeover —
/// see the module comment in `oauth.rs`.
#[cfg(feature = "oauth")]
async fn resolve_oauth_user(
    state: &AccountState,
    provider: &str,
    profile: &crate::oauth::Profile,
    link_user_id: Option<Uuid>,
) -> anyhow::Result<Option<Uuid>> {
    if let Some(existing) = db::find_user_by_identity(&state.pool, provider, &profile.subject).await?
    {
        return Ok(Some(existing));
    }

    if let Some(user_id) = link_user_id {
        db::link_identity(&state.pool, user_id, provider, &profile.subject, profile.email.as_deref())
            .await?;
        return Ok(Some(user_id));
    }

    if !profile.email_verified {
        return Ok(None);
    }
    let Some(email) = profile.email.as_deref().and_then(normalize_email) else {
        return Ok(None);
    };

    if let Some(existing) = db::find_user_by_email(&state.pool, &email).await? {
        db::link_identity(&state.pool, existing.id, provider, &profile.subject, Some(&email))
            .await?;
        // The provider just proved control of this address, so an account that
        // registered locally and never confirmed becomes confirmed here.
        if !existing.email_verified {
            db::mark_email_verified(&state.pool, existing.id).await?;
        }
        return Ok(Some(existing.id));
    }

    // New account with no local password — `has_password: false` in
    // `/account/me` is what tells the UI to offer "set a password".
    let display_name = profile.name.as_deref().filter(|s| !s.is_empty());
    let Some(user_id) =
        db::create_user(&state.pool, &email, None, display_name, true).await?
    else {
        // Lost a race against a concurrent registration of the same address;
        // the row now exists, so read it back rather than failing.
        return Ok(db::find_user_by_email(&state.pool, &email).await?.map(|u| u.id));
    };
    db::grant_roles(&state.pool, user_id, &state.config.default_roles).await?;
    db::link_identity(&state.pool, user_id, provider, &profile.subject, Some(&email)).await?;
    Ok(Some(user_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_normalisation() {
        assert_eq!(normalize_email("  Foo@Bar.COM "), Some("foo@bar.com".to_string()));
        assert_eq!(normalize_email("no-at-sign"), None);
        assert_eq!(normalize_email("@leading"), None);
        assert_eq!(normalize_email("trailing@"), None);
        assert_eq!(normalize_email("has space@x.com"), None);
        assert_eq!(normalize_email(""), None);
        assert_eq!(normalize_email(&format!("{}@x.com", "a".repeat(300))), None);
    }

    #[cfg(feature = "oauth")]
    #[test]
    fn redirect_targets_stay_on_this_site() {
        assert_eq!(safe_redirect(Some("/dashboard")), Some("/dashboard".to_string()));
        assert_eq!(safe_redirect(Some("//evil.example")), None);
        assert_eq!(safe_redirect(Some("/\\evil.example")), None);
        assert_eq!(safe_redirect(Some("https://evil.example")), None);
        assert_eq!(safe_redirect(Some("dashboard")), None);
        assert_eq!(safe_redirect(None), None);
    }
}

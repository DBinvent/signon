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

use axum::extract::{Path, State};
#[cfg(feature = "oauth")]
use axum::extract::Query;
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
        .route(
            "/sessions",
            get(list_sessions).delete(revoke_other_sessions),
        )
        .route("/sessions/{id}", delete(revoke_session));

    let router = public.merge(authed).merge(crate::account_mail::routes());

    #[cfg(feature = "oauth")]
    let router = router
        .route("/oauth", get(oauth_providers))
        .route("/oauth/{provider}/start", get(oauth_start))
        // GET for every provider; POST only for Apple, whose `form_post`
        // callback is the origin guard's one exemption below.
        .route(
            "/oauth/{provider}/callback",
            get(oauth_callback).post(oauth_callback_form),
        )
        .route("/oauth/pending", get(pending_status))
        .route("/oauth/pending/email", post(pending_email))
        .route("/oauth/pending/resend", post(pending_resend))
        .route("/oauth/pending/confirm", post(pending_confirm));

    #[cfg(feature = "sso-broker")]
    let router = router.merge(crate::broker::routes());

    router
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            origin_guard,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            forwarded_client_ip,
        ))
        // [i18n] outermost: a refusal of the two above is in the request's language too
        .layer(axum::middleware::from_fn_with_state(state.clone(), request_language))
        .with_state(state)
}

/// The visitor's address, as the site's Worker forwards it — see
/// [`crate::Config::client_ip_key`]. With the right key, `X-Client-IP`
/// replaces `CF-Connecting-IP` for everything downstream (`RequestMeta`:
/// rate limits, sessions, audit events, sign-up and sign-in addresses).
/// Without it the two headers are dropped, so nothing below ever sees a
/// forwarded address that was not vouched for.
pub(crate) async fn forwarded_client_ip(
    State(state): State<AccountState>,
    mut request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let headers = request.headers_mut();
    let forwarded = headers
        .get("x-client-ip")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<std::net::IpAddr>().ok());
    let vouched = match (&state.config.client_ip_key, headers.get("x-client-ip-key")) {
        (Some(key), Some(sent)) => token::constant_time_eq(key.as_bytes(), sent.as_bytes()),
        _ => false,
    };
    if let (true, Some(ip)) = (vouched, forwarded) {
        if let Ok(value) = header::HeaderValue::from_str(&ip.to_string()) {
            headers.insert("cf-connecting-ip", value);
            headers.remove("x-forwarded-for");
        }
    }
    headers.remove("x-client-ip");
    headers.remove("x-client-ip-key");
    next.run(request).await
}

// ---- shared response shapes ------------------------------------------------

/// The single credential rejection. Login (no account / wrong password /
/// unverified / suspended), verification, and reset-confirm all end here, so
/// the caller cannot tell which check failed.
pub(crate) fn credential_error() -> (StatusCode, Json<Value>) {
    (
        StatusCode::UNAUTHORIZED,
        Json(crate::i18n::error_body("err-credentials", &[])),
    )
}

/// A request refused as it was sent: `key` is its message in `locales/*.yml`
pub(crate) fn bad_request(key: &str) -> (StatusCode, Json<Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(crate::i18n::error_body(key, &[])),
    )
}

/// A password the policy refuses: why, with its code
pub(crate) fn policy_rejected(e: password::PolicyError) -> (StatusCode, Json<Value>) {
    (StatusCode::BAD_REQUEST, Json(e.body()))
}

/// [i18n] The language of a request, around every route of this crate: the first language its
/// `Accept-Language` names that there are messages in, else the site's (`Config::lang`). What the
/// handlers answer and mail is in it. A site puts its own routes under the same rule with
/// `axum::middleware::from_fn_with_state(state, signon::request_language)`.
pub async fn request_language(State(state): State<AccountState>, request: Request<axum::body::Body>, next: Next) -> Response {
    let lang = request.headers().get(header::ACCEPT_LANGUAGE).and_then(|v| v.to_str().ok())
        .and_then(crate::i18n::from_accept_language)
        .unwrap_or_else(|| state.config.site_lang());
    crate::i18n::scope(lang, next.run(request)).await
}

pub(crate) fn too_many() -> (StatusCode, Json<Value>) {
    (
        StatusCode::TOO_MANY_REQUESTS,
        Json(crate::i18n::error_body("err-too-many", &[])),
    )
}

pub(crate) fn internal_error() -> (StatusCode, Json<Value>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(crate::i18n::error_body("err-internal", &[])),
    )
}

/// The uniform answer when `Mailer::is_healthy` fails. Same status and body
/// for every caller regardless of what email they sent — see the doc on
/// `is_healthy` for why this has to be checked, and answered, before any
/// per-address branching in `register`/`resend_verify`/`password_reset_request`.
pub(crate) fn mail_unavailable() -> (StatusCode, Json<Value>) {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(crate::i18n::error_body("err-mail-unavailable", &[])),
    )
}

pub(crate) fn ok() -> (StatusCode, Json<Value>) {
    (StatusCode::OK, Json(json!({ "status": "ok" })))
}

// ---- cross-site email verification -----------------------------------------

/// Asks a sibling site (if `cross_verify_url`/`cross_verify_secret` are
/// configured) whether `email` already has a verified account there — see
/// `Config::cross_verify_url`'s doc. `false` on any error, timeout,
/// non-2xx, or when the feature isn't configured: this must fail toward
/// "still requires its own verification," never toward silently marking an
/// unproven address verified, so a network hiccup or a misconfigured
/// secret degrades to the pre-existing behavior rather than a false
/// positive.
///
/// Callers ([`crate::routes::register`], [`crate::routes::resend_verify`])
/// must call this only from a point in the handler that does not change the
/// HTTP response shape based on its result — the account this crate
/// otherwise takes not to reveal via its own public routes (see this
/// module's doc comment) must not become discoverable through response
/// *shape* even though the sibling's own answer is, by construction,
/// gated behind a shared secret at the HTTP layer.
#[cfg(feature = "cross-verify")]
async fn cross_verified(state: &AccountState, email: &str) -> bool {
    let (Some(url), Some(secret)) = (
        &state.config.cross_verify_url,
        &state.config.cross_verify_secret,
    ) else {
        return false;
    };

    #[derive(Deserialize)]
    struct CrossVerifyResp {
        verified: bool,
    }

    let result = state
        .http
        .get(url)
        .bearer_auth(secret)
        .query(&[("email", email)])
        .send()
        .await;
    match result {
        Ok(resp) if resp.status().is_success() => resp
            .json::<CrossVerifyResp>()
            .await
            .map(|b| b.verified)
            .unwrap_or(false),
        Ok(resp) => {
            tracing::warn!(status = %resp.status(), "cross-verify request rejected");
            false
        }
        Err(e) => {
            tracing::warn!(%e, "cross-verify request failed");
            false
        }
    }
}

/// Feature off — always the safe default, no network call. Kept as a
/// same-signature stub so `register`/`resend_verify` never need their own
/// `#[cfg]`.
#[cfg(not(feature = "cross-verify"))]
async fn cross_verified(_state: &AccountState, _email: &str) -> bool {
    false
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
    let safe = matches!(
        *request.method(),
        Method::GET | Method::HEAD | Method::OPTIONS
    );
    if !safe
        && !state.config.allowed_origins.is_empty()
        && !cross_site_post_allowed(request.uri().path())
        && !is_one_click_unsubscribe(request.uri().path())
    {
        if let Some(origin) = request
            .headers()
            .get(header::ORIGIN)
            .and_then(|v| v.to_str().ok())
        {
            let origin = origin.trim_end_matches('/');
            if !state.config.allowed_origins.iter().any(|a| a == origin) {
                tracing::warn!(
                    origin,
                    "rejected state-changing request from foreign origin"
                );
                return (StatusCode::FORBIDDEN, Json(crate::i18n::error_body("err-forbidden", &[])))
                    .into_response();
            }
        }
    }
    next.run(request).await
}

/// The only state-changing requests that legitimately arrive from another
/// site: an IdP posting its answer back — Apple's `form_post` callback or a
/// SAML ACS — and in this crate only Apple's remains: a site federated
/// through a separate SSO service (`broker.rs`) receives no IdP posts at all.
/// Safe without an origin check because the body carries the single-use
/// `state` this site minted, which a forged cross-site post cannot know.
/// Exact shape only; this must never widen to "anything under /oauth".
fn cross_site_post_allowed(path: &str) -> bool {
    path.ends_with("/oauth/apple/callback")
}

/// RFC 8058 one-click unsubscribe: the mail client posts it, from wherever
/// it runs. A forged cross-site post here needs the account's token, and
/// all it could do is turn that account's non-essential mail off.
fn is_one_click_unsubscribe(path: &str) -> bool {
    path.rsplit_once('/')
        .is_some_and(|(prefix, token)| prefix.ends_with("/emails/unsubscribe") && !token.is_empty())
}

// ---- sessions --------------------------------------------------------------

fn session_cookie(state: &AccountState, value: String) -> Cookie<'static> {
    session_cookie_for(state, value, state.config.session_ttl)
}

fn session_cookie_for(state: &AccountState, value: String, ttl: Duration) -> Cookie<'static> {
    let mut cookie = Cookie::new(SESSION_COOKIE, value);
    cookie.set_http_only(true);
    cookie.set_secure(state.config.secure_cookies);
    cookie.set_same_site(SameSite::Lax);
    cookie.set_path("/");
    cookie.set_max_age(Some(time::Duration::seconds(ttl.as_secs() as i64)));
    cookie
}

/// Mints a session and returns the jar carrying its cookie. The secret goes to
/// the browser; only its hash reaches the database.
///
/// `via` records how the user got in (`password`, `oauth:google`,
/// `sso:<connection id>`, …) so the sessions a connection minted can later be
/// revoked as a set. `max_ttl` shortens the session below the site's own TTL
/// — a customer connection's session cap.
pub(crate) async fn start_session(
    state: &AccountState,
    jar: CookieJar,
    user_id: Uuid,
    meta: &RequestMeta,
    via: &str,
    max_ttl: Option<Duration>,
) -> anyhow::Result<CookieJar> {
    let secret = token::secret();
    let ttl = max_ttl
        .map(|cap| cap.min(state.config.session_ttl))
        .unwrap_or(state.config.session_ttl);
    let chrono_ttl = chrono::Duration::from_std(ttl).unwrap_or_else(|_| chrono::Duration::days(30));
    db::create_session(
        &state.pool,
        user_id,
        &token::hash(&secret),
        chrono_ttl,
        meta.ip.as_deref(),
        meta.user_agent.as_deref(),
        via,
    )
    .await?;
    db::mark_login(&state.pool, user_id, meta.ip.as_deref()).await?;
    let (mark, mark_cookie) = browser_mark(state, &jar);
    if let Err(e) = db::remember_browser(&state.pool, &token::hash(&mark), user_id).await {
        tracing::warn!(%e, "remember_browser");
    }
    Ok(jar
        .add(session_cookie_for(state, secret, ttl))
        .add(mark_cookie))
}

// ---- browser marks ------------------------------------------------------------

/// Long-lived, per site (host-only, like the session cookie), random. Says
/// which accounts this browser created or signed in to (`user_browsers`), so
/// a second sign-up from it is asked about first — see [`registered_here`].
pub(crate) const BROWSER_COOKIE: &str = "signon_browser";
/// About as long as browsers keep a cookie at all (Chrome caps at 400 days).
const BROWSER_COOKIE_DAYS: i64 = 400;

/// This browser's mark — the cookie it sent, or a fresh one — with the
/// cookie to send back, re-set every time so its expiry keeps moving.
pub(crate) fn browser_mark(state: &AccountState, jar: &CookieJar) -> (String, Cookie<'static>) {
    let mark = jar
        .get(BROWSER_COOKIE)
        .map(|c| c.value().to_string())
        .filter(|v| (32..=64).contains(&v.len()) && v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
        .unwrap_or_else(token::secret);
    let mut cookie = Cookie::new(BROWSER_COOKIE, mark.clone());
    cookie.set_http_only(true);
    cookie.set_secure(state.config.secure_cookies);
    cookie.set_same_site(SameSite::Lax);
    cookie.set_path("/");
    cookie.set_max_age(Some(time::Duration::days(BROWSER_COOKIE_DAYS)));
    (mark, cookie)
}

/// `Some(409)` when this browser already has an account here and the request
/// did not say "create another anyway". The hint is that account's address,
/// masked — only ever shown to the browser that holds the mark, and decided
/// by the mark alone, never by the address being registered.
pub(crate) async fn registered_here(state: &AccountState, mark: &str, another: bool) -> Option<Response> {
    if another {
        return None;
    }
    match db::browser_account(&state.pool, &token::hash(mark)).await {
        Ok(Some(email)) => Some(
            (
                StatusCode::CONFLICT,
                // `error` is the state a client switches on, the same in every language; its code and
                // its sentence are beside it [review 2026-11-14]
                Json({
                    let (code, message) = crate::i18n::error_in(crate::i18n::current(), "err-registered-here", &[]);
                    json!({
                        "error": "registered_here",
                        "code": code,
                        "message": message,
                        "hint": email.as_deref().map(mask_email),
                    })
                }),
            )
                .into_response(),
        ),
        Ok(None) => None,
        Err(e) => {
            tracing::warn!(%e, "browser_account");
            None
        }
    }
}

/// `vlad@chase.com` → `v•••@chase.com`.
pub(crate) fn mask_email(email: &str) -> String {
    match email.split_once('@') {
        Some((local, domain)) => {
            let first: String = local.chars().take(1).collect();
            format!("{first}•••@{domain}")
        }
        None => "•••".to_string(),
    }
}

// ---- SSO enforcement --------------------------------------------------------

/// `Some(refusal)` when `email`'s domain must sign in through its customer
/// connection — asked of the SSO service (`broker.rs`), decided from the
/// domain alone before any account is looked up, so it reads the same with
/// or without an account. A stub without `sso-broker` so `login` and
/// `register` need no `#[cfg]` of their own.
#[cfg(feature = "sso-broker")]
async fn enforcement_refusal(state: &AccountState, email: &str) -> Option<Response> {
    crate::broker::enforcement_refusal(state, email).await
}

#[cfg(not(feature = "sso-broker"))]
async fn enforcement_refusal(_state: &AccountState, _email: &str) -> Option<Response> {
    None
}

// ---- register --------------------------------------------------------------

#[derive(Deserialize)]
struct RegisterReq {
    email: String,
    password: String,
    #[serde(default)]
    display_name: Option<String>,
    /// The pre-ticked "email me" box. Absent means on — a client that does
    /// not know the field keeps the default.
    #[serde(default = "yes")]
    emails: bool,
    /// "Create another account anyway", after a `registered_here` answer.
    #[serde(default)]
    another: bool,
}

pub(crate) fn yes() -> bool {
    true
}

async fn register(
    State(state): State<AccountState>,
    jar: CookieJar,
    meta: RequestMeta,
    Json(req): Json<RegisterReq>,
) -> Response {
    let Some(email) = normalize_email(&req.email) else {
        return bad_request("err-invalid-email").into_response();
    };
    if let Err(e) = password::check_policy(&req.password, &email) {
        return policy_rejected(e).into_response();
    }
    if !state
        .limiter
        .check(&format!("reg:ip:{}", meta.ip_key()), REGISTER_PER_IP, HOUR)
        || !state
            .limiter
            .check(&format!("reg:em:{email}"), REGISTER_PER_EMAIL, HOUR)
    {
        return too_many().into_response();
    }
    // Before anything about `email` is looked at: the answer depends on the
    // browser's mark only, so it says nothing about the address.
    let (mark, mark_cookie) = browser_mark(&state, &jar);
    if let Some(conflict) = registered_here(&state, &mark, req.another).await {
        return conflict;
    }
    // A domain that enforces SSO gets no local-password accounts at all; its
    // people are created on first sign-in through their connection.
    if let Some(refusal) = enforcement_refusal(&state, &email).await {
        return refusal;
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

    // After every response-affecting gate above, before the one DB write
    // below: `already_verified` only changes internal behavior (the row's
    // initial `email_verified` flag, and whether mail gets sent), never the
    // HTTP response — see `cross_verified`'s doc comment for why that must
    // stay true.
    let already_verified = cross_verified(&state, &email).await;

    match db::create_user(
        &state.pool,
        &email,
        Some(&hash),
        display_name,
        already_verified,
    )
    .await
    {
        // New account: arm the challenge and send the mail — unless a
        // sibling site already vouches for this address, in which case
        // there is nothing to verify. Already taken (`None`, the ON
        // CONFLICT case): do neither — but the response below is identical
        // either way, so registration cannot be used to test whether an
        // address has an account.
        Ok(Some(user_id)) => {
            if let Err(e) = db::grant_roles(&state.pool, user_id, &state.config.default_roles).await
            {
                tracing::error!(%e, "grant default roles");
            }
            if let Err(e) = db::note_signup(&state.pool, user_id, meta.ip.as_deref(), req.emails).await {
                tracing::error!(%e, "note_signup");
            }
            if let Err(e) = db::remember_browser(&state.pool, &token::hash(&mark), user_id).await {
                tracing::warn!(%e, "remember_browser");
            }
            if already_verified {
                tracing::info!(%user_id, "email already verified on a sibling site — skipping verification mail");
                crate::account_mail::send_welcome(&state, user_id).await;
            } else {
                send_verification(&state, user_id, &email).await;
            }
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
        // Already taken. The HTTP response below stays byte-identical to the
        // new-account path either way — that is what actually prevents
        // enumeration — but the response body was never the only thing this
        // address's real owner sees: they see their inbox. Leaving it empty
        // here just meant "I forgot I had an account" and "the mail server
        // is broken" looked the same to them. Tell them instead, and hand
        // them a real way back in — the same reset token
        // `password_reset_request` mints, since whoever reads this message
        // is, by construction, already proven to control the inbox.
        Ok(None) => {
            if let Ok(Some(user)) = db::find_user_by_email(&state.pool, &email).await {
                if !user.suspended {
                    let secret = token::secret();
                    match db::create_password_reset(&state.pool, user.id, &token::hash(&secret)).await
                    {
                        Ok(()) => {
                            let sign_in_url = state.config.sign_in_url();
                            let reset_url = state.config.reset_url(&secret);
                            let hours = state.config.reset_ttl.as_secs().div_ceil(3600);
                            let (subject, text, html) = Templates::already_registered(
                                crate::i18n::current(),
                                &state.config.product_name,
                                &sign_in_url,
                                &reset_url,
                                hours,
                            );
                            state.mailer.send(&email, &subject, text, html).await;
                        }
                        Err(e) => tracing::error!(%e, "create_password_reset (duplicate signup notice)"),
                    }
                }
            }
        }
        Err(e) => {
            tracing::error!(%e, "create_user");
            return internal_error().into_response();
        }
    }

    // The mark cookie goes back on both branches alike — same name, same
    // shape — so it cannot tell a new address from a taken one either.
    (
        StatusCode::CREATED,
        jar.add(mark_cookie),
        Json(json!({
            "status": "registered",
            "note": crate::i18n::text("note-check-email-account", &[]),
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
    let (subject, text, html) = Templates::verify(crate::i18n::current(), &state.config.product_name, &url, &code);
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
    if !state
        .limiter
        .check(&format!("code:ip:{}", meta.ip_key()), CODE_PER_IP, FIVE_MIN)
    {
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

    let jar = match start_session(state, jar, user_id, &meta, "verify", None).await {
        Ok(j) => j,
        Err(e) => {
            tracing::error!(%e, "start_session after verify");
            return internal_error().into_response();
        }
    };
    // The address is confirmed now — the earliest the welcome can go.
    crate::account_mail::send_welcome(state, user_id).await;

    match account_json(state, user_id).await {
        Ok(Some(body)) => {
            (jar, Json(json!({ "status": "verified", "user": body }))).into_response()
        }
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
    if !state
        .limiter
        .check(&format!("mail:ip:{}", meta.ip_key()), MAIL_PER_IP, HOUR)
        || !state
            .limiter
            .check(&format!("mail:em:{email}"), MAIL_PER_EMAIL, HOUR)
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
        if !user.email_verified && !user.suspended {
            // A sibling site vouching for this address settles it outright —
            // no cooldown check, no mail, nothing left to resend. Response
            // stays `ok()` either way (see this fn's doc comment), so this
            // cannot be used to probe cross-site verification status.
            if cross_verified(&state, &email).await {
                if let Err(e) = db::mark_email_verified(&state.pool, user.id).await {
                    tracing::error!(%e, "mark_email_verified via cross-verify");
                }
            } else {
                let cooled = user
                    .verify_sent_at
                    .map(|sent| {
                        chrono::Utc::now() - sent
                            > chrono::Duration::from_std(state.config.resend_cooldown)
                                .unwrap_or_else(|_| chrono::Duration::seconds(60))
                    })
                    .unwrap_or(true);
                if cooled {
                    send_verification(&state, user.id, &email).await;
                }
            }
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

    if !state.limiter.check(
        &format!("login:ip:{}", meta.ip_key()),
        LOGIN_PER_IP,
        FIVE_MIN,
    ) || !state
        .limiter
        .check(&format!("login:em:{email}"), LOGIN_PER_EMAIL, FIVE_MIN)
    {
        return too_many().into_response();
    }

    // Before the account lookup: the answer depends on the domain only.
    if let Some(refusal) = enforcement_refusal(&state, &email).await {
        return refusal;
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
    let jar = match start_session(&state, jar, user.id, &meta, "password", None).await {
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
    db::log_event(
        &state.pool,
        "logout",
        None,
        None,
        meta.ip.as_deref(),
        meta.user_agent.as_deref(),
    )
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

pub(crate) async fn account_json(state: &AccountState, user_id: Uuid) -> anyhow::Result<Option<Value>> {
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
        // The profile page switch for the welcome and news.
        "emails_enabled": db::emails_on(&state.pool, user_id).await?,
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
    // Password sign-in is by address, so on an account with none a password
    // could never be used — refuse it rather than store a dead credential.
    let Some(email) = user.email.as_deref() else {
        return bad_request("err-no-email-no-password")
            .into_response();
    };
    if let Err(e) = password::check_policy(&req.new_password, email) {
        return policy_rejected(e).into_response();
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
    if let Err(e) = db::delete_sessions_for_user(&state.pool, user.id, Some(user.session_id)).await
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
        Some(email),
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
    if !state
        .limiter
        .check(&format!("mail:ip:{}", meta.ip_key()), MAIL_PER_IP, HOUR)
        || !state
            .limiter
            .check(&format!("mail:em:{email}"), MAIL_PER_EMAIL, HOUR)
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
                        Templates::reset(crate::i18n::current(), &state.config.product_name, &url, hours);
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
    // burning the token. A reset is only ever minted for an address, so an
    // account with none cannot hold one; refused alike if it somehow did.
    let email = match db::find_user_by_id(&state.pool, user_id).await {
        Ok(Some(u)) => match u.email {
            Some(e) => e,
            None => return credential_error().into_response(),
        },
        Ok(None) => return credential_error().into_response(),
        Err(e) => {
            tracing::error!(%e, "find_user_by_id");
            return internal_error().into_response();
        }
    };
    if let Err(e) = password::check_policy(&req.new_password, &email) {
        return policy_rejected(e).into_response();
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
        Ok(false) => (StatusCode::NOT_FOUND, Json(crate::i18n::error_body("err-not-found", &[]))).into_response(),
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

/// How long a provider round trip may take, start to callback.
#[cfg(feature = "oauth")]
const OAUTH_STATE_TTL_MIN: i64 = 15;
/// How long a pending identity (Amazon/Facebook code step) stays usable.
#[cfg(feature = "oauth")]
const PENDING_TTL_MIN: i64 = 60;

#[cfg(feature = "oauth")]
async fn oauth_providers(State(state): State<AccountState>) -> Response {
    // Federated: the SSO service's buttons, `href` pointing at this site's
    // `/sso/*` forward.
    #[cfg(feature = "sso-broker")]
    if let Some(broker) = state.broker.as_ref() {
        return Json(crate::broker::providers_json(broker).await).into_response();
    }
    let snapshot = state.sso.current();
    let items: Vec<Value> = snapshot
        .providers
        .iter()
        .map(|c| {
            json!({
                "key": c.provider.key,
                "name": c.provider.display_name,
                // API-relative, for clients that prefix `/api` themselves…
                "start": format!("/account/oauth/{}/start", c.provider.key),
                // …and the site path newer clients navigate to as is.
                "href": format!("/api/account/oauth/{}/start", c.provider.key),
            })
        })
        .collect();
    Json(json!({ "providers": items, "custom_sso": false })).into_response()
}

#[cfg(feature = "oauth")]
#[derive(Deserialize)]
pub(crate) struct OauthStartQuery {
    #[serde(default)]
    pub(crate) redirect_to: Option<String>,
}

/// Site-relative paths only. Without this an `?redirect_to=https://evil` turns
/// the callback into an open redirect, and an open redirect on an endpoint
/// that has just set a session cookie is a credential-leak primitive.
#[cfg(feature = "oauth")]
pub(crate) fn safe_redirect(raw: Option<&str>) -> Option<String> {
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
    let snapshot = state.sso.current();
    let Some(configured) = snapshot.provider(&provider_key) else {
        return (
            StatusCode::NOT_FOUND,
            Json(crate::i18n::error_body("err-unknown-provider", &[])),
        )
            .into_response();
    };

    let state_value = token::secret();
    let nonce = token::secret();
    let (verifier, challenge) = crate::oauth::pkce_pair();

    if let Err(e) = db::put_oauth_state(
        &state.pool,
        db::NewOauthState {
            state_hash: &token::hash(&state_value),
            provider: configured.provider.key,
            pkce_verifier: &verifier,
            // Present means "link this provider to the account already signed
            // in", absent means "sign in or sign up with it".
            link_user_id: user.as_ref().map(|u| u.id),
            redirect_to: safe_redirect(q.redirect_to.as_deref()).as_deref(),
            nonce: Some(&nonce),
        },
    )
    .await
    {
        tracing::error!(%e, "put_oauth_state");
        return internal_error().into_response();
    }

    axum::response::Redirect::to(&configured.authorize_url(&state_value, &challenge, &nonce))
        .into_response()
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

/// Apple's `form_post` body. `user` is present only on the very first
/// authorization and is the one chance to learn the person's name.
#[cfg(feature = "oauth")]
#[derive(Deserialize)]
struct OauthCallbackForm {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    user: Option<String>,
}

#[cfg(feature = "oauth")]
async fn oauth_callback(
    State(state): State<AccountState>,
    jar: CookieJar,
    meta: RequestMeta,
    Path(provider_key): Path<String>,
    Query(q): Query<OauthCallbackQuery>,
) -> Response {
    finish_oauth(&state, jar, meta, &provider_key, q.code, q.state, q.error, None).await
}

/// The `form_post` callback. Only Apple answers this way; any other provider
/// arriving by POST is refused before its body is looked at.
#[cfg(feature = "oauth")]
async fn oauth_callback_form(
    State(state): State<AccountState>,
    jar: CookieJar,
    meta: RequestMeta,
    Path(provider_key): Path<String>,
    axum::Form(f): axum::Form<OauthCallbackForm>,
) -> Response {
    let posts = crate::oauth::provider_by_key(&provider_key)
        .is_some_and(|p| p.response_mode == Some("form_post"));
    if !posts {
        return (StatusCode::METHOD_NOT_ALLOWED, Json(crate::i18n::error_body("err-method", &[])))
            .into_response();
    }
    finish_oauth(&state, jar, meta, &provider_key, f.code, f.state, f.error, f.user).await
}

/// The browser is here, not an API client, so failures end as a redirect
/// back to the sign-in page with a marker rather than as a JSON body.
#[cfg(feature = "oauth")]
pub(crate) fn sign_in_redirect(state: &AccountState, marker: &str) -> Response {
    axum::response::Redirect::to(&format!(
        "{}{}?error={}",
        state.config.app_base_url, state.config.sign_in_path, marker
    ))
    .into_response()
}

#[cfg(feature = "oauth")]
#[allow(clippy::too_many_arguments)]
async fn finish_oauth(
    state: &AccountState,
    jar: CookieJar,
    meta: RequestMeta,
    provider_key: &str,
    code: Option<String>,
    state_value: Option<String>,
    error: Option<String>,
    apple_user: Option<String>,
) -> Response {
    let fail = |reason: &str| -> Response {
        tracing::warn!(provider = %provider_key, reason, "oauth callback rejected");
        let pool = state.pool.clone();
        let via = format!("oauth:{provider_key}");
        let (ip, ua) = (meta.ip.clone(), meta.user_agent.clone());
        // Counted, not awaited inline: the redirect does not wait on it.
        tokio::spawn(async move {
            db::log_event_via(&pool, "oauth_fail", None, None, ip.as_deref(), ua.as_deref(), Some(&via)).await;
        });
        sign_in_redirect(state, "oauth")
    };

    if error.is_some() {
        return fail("provider returned an error");
    }
    let (Some(code), Some(state_value)) = (code, state_value) else {
        return fail("missing code or state");
    };

    let flow = match db::take_oauth_state(
        &state.pool,
        &token::hash(&state_value),
        chrono::Duration::minutes(OAUTH_STATE_TTL_MIN),
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

    let snapshot = state.sso.current();
    let Some(configured) = snapshot.provider(provider_key) else {
        return fail("provider no longer configured");
    };

    let tokens = match configured.exchange_code(&code, &flow.pkce_verifier).await {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(%e, "oauth code exchange");
            return fail("code exchange failed");
        }
    };
    let profile = match configured
        .fetch_profile(&tokens, flow.nonce.as_deref(), apple_user.as_deref())
        .await
    {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(%e, "oauth profile fetch");
            return fail("profile fetch failed");
        }
    };

    let resolved = match resolve_oauth_user(state, provider_key, &profile, flow.link_user_id, meta.ip.as_deref()).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(%e, "resolve oauth user");
            return fail("account resolution failed");
        }
    };
    let user_id = match resolved {
        OauthResolution::User(id) => id,
        OauthResolution::NeedsCode => {
            return start_pending(state, provider_key, &profile, flow.redirect_to.as_deref(), &meta).await;
        }
        OauthResolution::Refused => return fail("no verified email from provider"),
    };

    match db::find_user_by_id(&state.pool, user_id).await {
        Ok(Some(u)) if !u.suspended => {}
        Ok(_) => return fail("account unavailable"),
        Err(e) => {
            tracing::error!(%e, "find_user_by_id");
            return fail("account lookup failed");
        }
    }

    let via = format!("oauth:{provider_key}");
    let jar = match start_session(state, jar, user_id, &meta, &via, None).await {
        Ok(j) => j,
        Err(e) => {
            tracing::error!(%e, "start_session after oauth");
            return fail("session creation failed");
        }
    };
    db::log_event_via(
        &state.pool,
        "oauth_login",
        Some(user_id),
        profile.email.as_deref(),
        meta.ip.as_deref(),
        meta.user_agent.as_deref(),
        Some(&via),
    )
    .await;

    let target = flow.redirect_to.unwrap_or_else(|| "/".to_string());
    (
        jar,
        axum::response::Redirect::to(&format!("{}{}", state.config.app_base_url, target)),
    )
        .into_response()
}

#[cfg(feature = "oauth")]
enum OauthResolution {
    User(Uuid),
    /// The provider does not vouch for the address: prove it with a code.
    NeedsCode,
    /// The provider *does* vouch for addresses but did not for this one.
    Refused,
}

/// Turns a provider profile into a local account.
///
/// The order matters: an existing *link* wins outright; otherwise an explicit
/// link request wins; only then do we fall back to matching on the email, and
/// that step demands the provider vouch for the address. Matching an
/// unverified provider email against a local account is account takeover —
/// see the module comment in `oauth.rs`. A provider that never vouches
/// (Amazon, Facebook) is sent to the code step instead.
#[cfg(feature = "oauth")]
async fn resolve_oauth_user(
    state: &AccountState,
    provider: &str,
    profile: &crate::oauth::Profile,
    link_user_id: Option<Uuid>,
    ip: Option<&str>,
) -> anyhow::Result<OauthResolution> {
    if let Some(existing) =
        db::find_user_by_identity(&state.pool, provider, &profile.subject).await?
    {
        return Ok(OauthResolution::User(existing));
    }

    if let Some(user_id) = link_user_id {
        db::link_identity(
            &state.pool,
            user_id,
            provider,
            &profile.subject,
            profile.email.as_deref(),
            None,
        )
        .await?;
        return Ok(OauthResolution::User(user_id));
    }

    if !profile.email_verified {
        let vouches = crate::oauth::provider_by_key(provider)
            .is_some_and(|p| p.asserts_email_verification());
        return Ok(if vouches {
            OauthResolution::Refused
        } else {
            OauthResolution::NeedsCode
        });
    }
    let Some(email) = profile.email.as_deref().and_then(normalize_email) else {
        return Ok(OauthResolution::Refused);
    };
    let user_id = account_for_proven_email(
        state,
        &email,
        profile.name.as_deref(),
        provider,
        &profile.subject,
        None,
        ip,
    )
    .await?;
    Ok(user_id.map_or(OauthResolution::Refused, OauthResolution::User))
}

/// The account for an address whose control has just been proven — by a
/// provider that vouches for it, a code we mailed, or a customer IdP inside
/// its own verified domain. Links the identity to the existing account at
/// that address, or creates one; either way the address ends up verified.
#[cfg(feature = "oauth")]
pub(crate) async fn account_for_proven_email(
    state: &AccountState,
    email: &str,
    name: Option<&str>,
    provider: &str,
    subject: &str,
    connection_id: Option<Uuid>,
    ip: Option<&str>,
) -> anyhow::Result<Option<Uuid>> {
    if let Some(existing) = db::find_user_by_email(&state.pool, email).await? {
        db::link_identity(&state.pool, existing.id, provider, subject, Some(email), connection_id).await?;
        // Control of this address was just proven, so an account that
        // registered locally and never confirmed becomes confirmed here.
        if !existing.email_verified {
            db::mark_email_verified(&state.pool, existing.id).await?;
            crate::account_mail::send_welcome(state, existing.id).await;
        }
        return Ok(Some(existing.id));
    }

    // New account with no local password — `has_password: false` in
    // `/account/me` is what tells the UI to offer "set a password".
    let display_name = name.map(str::trim).filter(|s| !s.is_empty() && s.len() <= 256);
    let Some(user_id) = db::create_user(&state.pool, email, None, display_name, true).await? else {
        // Lost a race against a concurrent registration of the same address;
        // the row now exists, so read it back rather than failing.
        return Ok(db::find_user_by_email(&state.pool, email).await?.map(|u| u.id));
    };
    db::grant_roles(&state.pool, user_id, &state.config.default_roles).await?;
    db::link_identity(&state.pool, user_id, provider, subject, Some(email), connection_id).await?;
    db::note_signup(&state.pool, user_id, ip, true).await?;
    crate::account_mail::send_welcome(state, user_id).await;
    Ok(Some(user_id))
}

// ---- pending identities (Amazon, Facebook) ---------------------------------

/// Parks a sign-in from a provider that does not vouch for the address and
/// sends the browser to the page that finishes it with a mailed code.
#[cfg(feature = "oauth")]
async fn start_pending(
    state: &AccountState,
    provider_key: &str,
    profile: &crate::oauth::Profile,
    redirect_to: Option<&str>,
    meta: &RequestMeta,
) -> Response {
    let email = profile.email.as_deref().and_then(normalize_email);
    let secret = token::secret();
    let token_hash = token::hash(&secret);
    let via = format!("oauth:{provider_key}");
    let pending = db::NewPending {
        provider: provider_key,
        provider_user_id: &profile.subject,
        email: email.as_deref(),
        display_name: profile.name.as_deref(),
        redirect_to,
        via: Some(&via),
        label: crate::oauth::provider_by_key(provider_key).map(|p| p.display_name),
        ..Default::default()
    };
    if let Err(e) = db::create_pending_identity(&state.pool, &token_hash, &pending).await {
        tracing::error!(%e, "create_pending_identity");
        return sign_in_redirect(state, "oauth");
    }
    if let Some(email) = email.as_deref() {
        mail_pending_code(state, &token_hash, email, provider_key).await;
    }
    db::log_event(
        &state.pool,
        "oauth_pending",
        None,
        email.as_deref(),
        meta.ip.as_deref(),
        meta.user_agent.as_deref(),
    )
    .await;
    axum::response::Redirect::to(&state.config.oauth_confirm_url(&secret)).into_response()
}

#[cfg(feature = "oauth")]
/// Mails the code straight away when the provider gave an address; the
/// confirm page can resend, or take a different address, if it did not
/// arrive. Rate-limited per address and skipped while mail is down.
#[cfg(feature = "oauth")]
pub(crate) async fn mail_pending_code(state: &AccountState, token_hash: &str, email: &str, provider_key: &str) {
    if state
        .limiter
        .check(&format!("mail:em:{email}"), MAIL_PER_EMAIL, HOUR)
        && state.mailer.is_healthy().await
    {
        send_pending_code(state, token_hash, email, provider_key).await;
    }
}

#[cfg(feature = "oauth")]
async fn send_pending_code(state: &AccountState, token_hash: &str, email: &str, provider_key: &str) -> bool {
    let code = token::short_code();
    match db::arm_pending_code(&state.pool, token_hash, email, &code).await {
        Ok(true) => {}
        Ok(false) => return false,
        Err(e) => {
            tracing::error!(%e, "arm_pending_code");
            return false;
        }
    }
    let provider = crate::oauth::provider_by_key(provider_key)
        .map(|p| p.display_name)
        .unwrap_or(provider_key);
    let (subject, text, html) = Templates::sign_in_code(crate::i18n::current(), &state.config.product_name, provider, &code);
    state.mailer.send(email, &subject, text, html).await;
    true
}

#[cfg(feature = "oauth")]
#[allow(clippy::result_large_err)] // Err is an axum Response, returned and consumed at once
async fn load_pending(state: &AccountState, raw: &str) -> Result<db::PendingIdentity, Response> {
    match db::find_pending_identity(
        &state.pool,
        &token::hash(raw),
        chrono::Duration::minutes(PENDING_TTL_MIN),
    )
    .await
    {
        Ok(Some(p)) => Ok(p),
        Ok(None) => Err(credential_error().into_response()),
        Err(e) => {
            tracing::error!(%e, "find_pending_identity");
            Err(internal_error().into_response())
        }
    }
}

#[cfg(feature = "oauth")]
#[derive(Deserialize)]
struct PendingQuery {
    token: String,
}

/// What the confirm page needs to render. The token holder is, by
/// construction, whoever just authenticated at the provider, so showing them
/// the address the provider reported tells them nothing new.
#[cfg(feature = "oauth")]
async fn pending_status(State(state): State<AccountState>, Query(q): Query<PendingQuery>) -> Response {
    let pending = match load_pending(&state, &q.token).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    let provider = crate::oauth::provider_by_key(&pending.provider)
        .map(|p| p.display_name)
        .unwrap_or("provider");
    Json(json!({
        "provider": pending.provider,
        "provider_name": provider,
        "email": pending.email,
        "needs_email": pending.email.is_none(),
        "email_proven": pending.email_proven,
        "code_sent": pending.code_sent_at.is_some(),
    }))
    .into_response()
}

#[cfg(feature = "oauth")]
#[derive(Deserialize)]
struct PendingEmailReq {
    token: String,
    email: String,
}

/// Sets the address to confirm (when the provider gave none, or the user
/// wants another) and mails a code to it.
#[cfg(feature = "oauth")]
async fn pending_email(
    State(state): State<AccountState>,
    meta: RequestMeta,
    Json(req): Json<PendingEmailReq>,
) -> Response {
    let Some(email) = normalize_email(&req.email) else {
        return bad_request("err-invalid-email").into_response();
    };
    if !state
        .limiter
        .check(&format!("mail:ip:{}", meta.ip_key()), MAIL_PER_IP, HOUR)
        || !state
            .limiter
            .check(&format!("mail:em:{email}"), MAIL_PER_EMAIL, HOUR)
    {
        return too_many().into_response();
    }
    let pending = match load_pending(&state, &req.token).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    if let Some(refusal) = enforcement_refusal(&state, &email).await {
        return refusal;
    }
    if !state.mailer.is_healthy().await {
        return mail_unavailable().into_response();
    }
    send_pending_code(&state, &token::hash(&req.token), &email, &pending.provider).await;
    ok().into_response()
}

#[cfg(feature = "oauth")]
async fn pending_resend(
    State(state): State<AccountState>,
    meta: RequestMeta,
    Json(req): Json<PendingQuery>,
) -> Response {
    if !state
        .limiter
        .check(&format!("mail:ip:{}", meta.ip_key()), MAIL_PER_IP, HOUR)
    {
        return too_many().into_response();
    }
    let pending = match load_pending(&state, &req.token).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    let Some(email) = pending.email.as_deref() else {
        return bad_request("err-no-email-yet").into_response();
    };
    if !state
        .limiter
        .check(&format!("mail:em:{email}"), MAIL_PER_EMAIL, HOUR)
    {
        return too_many().into_response();
    }
    let cooled = pending
        .code_sent_at
        .map(|sent| {
            chrono::Utc::now() - sent
                > chrono::Duration::from_std(state.config.resend_cooldown)
                    .unwrap_or_else(|_| chrono::Duration::seconds(60))
        })
        .unwrap_or(true);
    if cooled {
        if !state.mailer.is_healthy().await {
            return mail_unavailable().into_response();
        }
        send_pending_code(&state, &token::hash(&req.token), email, &pending.provider).await;
    }
    ok().into_response()
}

#[cfg(feature = "oauth")]
#[derive(Deserialize)]
struct PendingConfirmReq {
    token: String,
    code: String,
}

/// The code proves the inbox; only now is the identity linked to the
/// account at that address (or one created), and only now is a session
/// started.
#[cfg(feature = "oauth")]
async fn pending_confirm(
    State(state): State<AccountState>,
    jar: CookieJar,
    meta: RequestMeta,
    Json(req): Json<PendingConfirmReq>,
) -> Response {
    if !state
        .limiter
        .check(&format!("code:ip:{}", meta.ip_key()), CODE_PER_IP, FIVE_MIN)
    {
        return too_many().into_response();
    }
    let token_hash = token::hash(&req.token);
    let pending = match db::consume_pending_code(
        &state.pool,
        &token_hash,
        req.code.trim(),
        chrono::Duration::minutes(PENDING_TTL_MIN),
        state.config.max_verify_attempts,
    )
    .await
    {
        Ok(Some(p)) => p,
        Ok(None) => {
            if let Err(e) = db::bump_pending_attempts(&state.pool, &token_hash).await {
                tracing::error!(%e, "bump_pending_attempts");
            }
            return credential_error().into_response();
        }
        Err(e) => {
            tracing::error!(%e, "consume_pending_code");
            return internal_error().into_response();
        }
    };
    let Some(email) = pending.email.as_deref() else {
        return credential_error().into_response();
    };
    if let Some(refusal) = enforcement_refusal(&state, email).await {
        return refusal;
    }

    let linked = match db::find_user_by_identity(&state.pool, &pending.provider, &pending.provider_user_id).await {
        Ok(id) => id,
        Err(e) => {
            tracing::error!(%e, "find_user_by_identity");
            return internal_error().into_response();
        }
    };
    // The address is proven now. A site that asks before creating profiles
    // turns "no account at this address" into the Create-one question.
    if linked.is_none() && state.config.ask_before_creating_profile {
        match db::find_user_by_email(&state.pool, email).await {
            Ok(Some(_)) => {}
            Ok(None) => return ask_to_create(&state, &pending, email).await,
            Err(e) => {
                tracing::error!(%e, "find_user_by_email");
                return internal_error().into_response();
            }
        }
    }

    let user_id = match linked {
        Some(id) => Some(id),
        None => match account_for_proven_email(
            &state,
            email,
            pending.display_name.as_deref(),
            &pending.provider,
            &pending.provider_user_id,
            None,
            meta.ip.as_deref(),
        )
        .await
        {
            Ok(id) => id,
            Err(e) => {
                tracing::error!(%e, "account for pending identity");
                return internal_error().into_response();
            }
        },
    };
    let Some(user_id) = user_id else {
        return credential_error().into_response();
    };
    match db::find_user_by_id(&state.pool, user_id).await {
        Ok(Some(u)) if !u.suspended => {}
        Ok(_) => return credential_error().into_response(),
        Err(e) => {
            tracing::error!(%e, "find_user_by_id");
            return internal_error().into_response();
        }
    }

    let via = pending.via.clone().unwrap_or_else(|| format!("oauth:{}", pending.provider));
    let jar = match start_session(&state, jar, user_id, &meta, &via, None).await {
        Ok(j) => j,
        Err(e) => {
            tracing::error!(%e, "start_session after pending confirm");
            return internal_error().into_response();
        }
    };
    db::log_event_via(
        &state.pool,
        "oauth_login",
        Some(user_id),
        Some(email),
        meta.ip.as_deref(),
        meta.user_agent.as_deref(),
        Some(&via),
    )
    .await;
    match account_json(&state, user_id).await {
        Ok(Some(body)) => (
            jar,
            Json(json!({
                "status": "ok",
                "user": body,
                "redirect_to": pending.redirect_to.unwrap_or_else(|| "/".to_string()),
            })),
        )
            .into_response(),
        Ok(None) => credential_error().into_response(),
        Err(e) => {
            tracing::error!(%e, "load account after pending confirm");
            internal_error().into_response()
        }
    }
}

/// Parks a proven sign-in as a "No profile exists yet. Create one?" question
/// (answered by `POST /account/sso/create-profile`).
#[cfg(feature = "oauth")]
async fn ask_to_create(state: &AccountState, pending: &db::PendingIdentity, email: &str) -> Response {
    let secret = token::secret();
    let label = pending
        .label
        .clone()
        .or_else(|| crate::oauth::provider_by_key(&pending.provider).map(|p| p.display_name.to_string()))
        .unwrap_or_else(|| pending.provider.clone());
    let via = pending.via.clone().unwrap_or_else(|| format!("oauth:{}", pending.provider));
    let row = db::NewPending {
        provider: &pending.provider,
        provider_user_id: &pending.provider_user_id,
        email: Some(email),
        display_name: pending.display_name.as_deref(),
        redirect_to: pending.redirect_to.as_deref(),
        email_proven: true,
        connection_id: pending.connection_id,
        connection_owner: pending.connection_owner,
        via: Some(&via),
        label: Some(&label),
        session_max_hours: pending.session_max_hours,
        ..Default::default()
    };
    if let Err(e) = db::create_pending_identity(&state.pool, &token::hash(&secret), &row).await {
        tracing::error!(%e, "park proven sign-in");
        return internal_error().into_response();
    }
    Json(json!({
        "status": "no_profile",
        "token": secret,
        "email": email,
        "name": pending.display_name,
        "provider_name": label,
        "connection_name": null,
    }))
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_normalisation() {
        assert_eq!(
            normalize_email("  Foo@Bar.COM "),
            Some("foo@bar.com".to_string())
        );
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
        assert_eq!(
            safe_redirect(Some("/dashboard")),
            Some("/dashboard".to_string())
        );
        assert_eq!(safe_redirect(Some("//evil.example")), None);
        assert_eq!(safe_redirect(Some("/\\evil.example")), None);
        assert_eq!(safe_redirect(Some("https://evil.example")), None);
        assert_eq!(safe_redirect(Some("dashboard")), None);
        assert_eq!(safe_redirect(None), None);
    }
}

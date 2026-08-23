//! Every database statement in the crate.
//!
//! Runtime `sqlx::query`/`query_as`, not the `query!` macros — those need a
//! live database or a checked-in `.sqlx` cache at *compile* time, and this
//! crate is built by four repos that do not all have one.
//!
//! Two rules the statements below follow deliberately:
//!
//! * anything that validates a one-time secret also spends it, in the same
//!   statement, so there is no window in which a token is known-good but not
//!   yet consumed;
//! * `create_user` reports "already registered" as `None` rather than an
//!   error, because the caller must not let that difference reach the HTTP
//!   response.

use chrono::{DateTime, Duration, Utc};
use sqlx::PgPool;
use uuid::Uuid;

// ---- users ---------------------------------------------------------------

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub password_hash: Option<String>,
    pub display_name: Option<String>,
    pub email_verified: bool,
    pub verify_sent_at: Option<DateTime<Utc>>,
    pub suspended: bool,
}

// `verify_token_hash`, `verify_code` and `verify_attempts` are deliberately
// absent: nothing outside this module ever compares them in Rust. They are
// only ever matched inside the guarded UPDATEs below, which is what keeps
// check and consume atomic.
const USER_FIELDS: &str = "id, email, password_hash, display_name, email_verified, \
                           verify_sent_at, suspended";

/// Creates the account unless `email` is taken. `None` on conflict — callers
/// must keep that indistinguishable in the response, or registration becomes
/// an account-enumeration oracle.
pub async fn create_user(
    pool: &PgPool,
    email: &str,
    password_hash: Option<&str>,
    display_name: Option<&str>,
    email_verified: bool,
) -> anyhow::Result<Option<Uuid>> {
    let id = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO users (email, password_hash, display_name, email_verified) \
         VALUES ($1, $2, $3, $4) ON CONFLICT (email) DO NOTHING RETURNING id",
    )
    .bind(email)
    .bind(password_hash)
    .bind(display_name)
    .bind(email_verified)
    .fetch_optional(pool)
    .await?;
    Ok(id)
}

pub async fn find_user_by_email(pool: &PgPool, email: &str) -> anyhow::Result<Option<User>> {
    Ok(
        sqlx::query_as::<_, User>(&format!("SELECT {USER_FIELDS} FROM users WHERE email = $1"))
            .bind(email)
            .fetch_optional(pool)
            .await?,
    )
}

pub async fn find_user_by_id(pool: &PgPool, id: Uuid) -> anyhow::Result<Option<User>> {
    Ok(
        sqlx::query_as::<_, User>(&format!("SELECT {USER_FIELDS} FROM users WHERE id = $1"))
            .bind(id)
            .fetch_optional(pool)
            .await?,
    )
}

/// Arms a fresh verification challenge (link token *and* short code) and
/// clears the attempt counter. Register and resend both call this.
pub async fn set_verify_challenge(
    pool: &PgPool,
    user_id: Uuid,
    token_hash: &str,
    code: &str,
) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE users SET verify_token_hash = $2, verify_code = $3, verify_attempts = 0, \
         verify_sent_at = now(), updated_at = now() WHERE id = $1",
    )
    .bind(user_id)
    .bind(token_hash)
    .bind(code)
    .execute(pool)
    .await?;
    Ok(())
}

/// Marks the account verified if `token_hash` is its current, unexpired
/// challenge. Idempotent only in the sense that a second call fails: the
/// challenge is cleared, so a replayed link is rejected.
pub async fn consume_verify_token(
    pool: &PgPool,
    user_id: Uuid,
    token_hash: &str,
    max_age: Duration,
) -> anyhow::Result<bool> {
    let cutoff: DateTime<Utc> = Utc::now() - max_age;
    let rows = sqlx::query(
        "UPDATE users SET email_verified = true, verify_token_hash = NULL, verify_code = NULL, \
         verify_attempts = 0, updated_at = now() \
         WHERE id = $1 AND verify_token_hash = $2 AND verify_sent_at > $3",
    )
    .bind(user_id)
    .bind(token_hash)
    .bind(cutoff)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(rows > 0)
}

/// Same, for the typed-in short code. The `verify_attempts < $4` guard is what
/// makes six digits acceptable; without it the code is a 10^6 search.
pub async fn consume_verify_code(
    pool: &PgPool,
    user_id: Uuid,
    code: &str,
    max_age: Duration,
    max_attempts: i32,
) -> anyhow::Result<bool> {
    let cutoff: DateTime<Utc> = Utc::now() - max_age;
    let rows = sqlx::query(
        "UPDATE users SET email_verified = true, verify_token_hash = NULL, verify_code = NULL, \
         verify_attempts = 0, updated_at = now() \
         WHERE id = $1 AND verify_code = $2 AND verify_sent_at > $3 AND verify_attempts < $4",
    )
    .bind(user_id)
    .bind(code)
    .bind(cutoff)
    .bind(max_attempts)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(rows > 0)
}

pub async fn bump_verify_attempts(pool: &PgPool, user_id: Uuid) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE users SET verify_attempts = verify_attempts + 1, updated_at = now() \
         WHERE id = $1 AND email_verified = false",
    )
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn update_password_hash(pool: &PgPool, user_id: Uuid, hash: &str) -> anyhow::Result<()> {
    sqlx::query("UPDATE users SET password_hash = $2, updated_at = now() WHERE id = $1")
        .bind(user_id)
        .bind(hash)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn mark_login(pool: &PgPool, user_id: Uuid) -> anyhow::Result<()> {
    sqlx::query("UPDATE users SET last_login_at = now() WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Used by the SSO path when the provider vouches for an address that is
/// already registered locally but never confirmed. See `oauth.rs` for why
/// this only ever runs on a provider-verified email.
pub async fn mark_email_verified(pool: &PgPool, user_id: Uuid) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE users SET email_verified = true, verify_token_hash = NULL, verify_code = NULL, \
         updated_at = now() WHERE id = $1",
    )
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(())
}

// ---- password resets ------------------------------------------------------

pub async fn create_password_reset(
    pool: &PgPool,
    user_id: Uuid,
    token_hash: &str,
) -> anyhow::Result<()> {
    sqlx::query("INSERT INTO password_resets (user_id, token_hash) VALUES ($1, $2)")
        .bind(user_id)
        .bind(token_hash)
        .execute(pool)
        .await?;
    Ok(())
}

/// Finds an unused, unexpired reset row and marks it used in one statement.
/// Returns the owning account.
pub async fn consume_password_reset(
    pool: &PgPool,
    token_hash: &str,
    max_age: Duration,
) -> anyhow::Result<Option<Uuid>> {
    let cutoff: DateTime<Utc> = Utc::now() - max_age;
    Ok(sqlx::query_scalar::<_, Uuid>(
        "UPDATE password_resets SET used = true \
         WHERE token_hash = $1 AND used = false AND created_at > $2 RETURNING user_id",
    )
    .bind(token_hash)
    .bind(cutoff)
    .fetch_optional(pool)
    .await?)
}

/// Invalidates every outstanding reset link for an account. Called after a
/// successful reset and after a logged-in password change, so a reset mail
/// still sitting in an inbox cannot be spent later.
pub async fn invalidate_password_resets(pool: &PgPool, user_id: Uuid) -> anyhow::Result<()> {
    sqlx::query("UPDATE password_resets SET used = true WHERE user_id = $1 AND used = false")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

// ---- sessions -------------------------------------------------------------

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SessionRow {
    pub id: Uuid,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

pub async fn create_session(
    pool: &PgPool,
    user_id: Uuid,
    token_hash: &str,
    ttl: Duration,
    ip: Option<&str>,
    user_agent: Option<&str>,
) -> anyhow::Result<Uuid> {
    let expires_at = Utc::now() + ttl;
    Ok(sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO sessions (token_hash, user_id, ip, user_agent, expires_at) \
         VALUES ($1, $2, $3, $4, $5) RETURNING id",
    )
    .bind(token_hash)
    .bind(user_id)
    .bind(ip)
    .bind(user_agent)
    .bind(expires_at)
    .fetch_one(pool)
    .await?)
}

/// Resolves a cookie to `(session id, user id)` and refreshes `last_seen_at`
/// in the same statement. Expired rows simply do not match.
pub async fn touch_session(
    pool: &PgPool,
    token_hash: &str,
) -> anyhow::Result<Option<(Uuid, Uuid)>> {
    Ok(sqlx::query_as::<_, (Uuid, Uuid)>(
        "UPDATE sessions SET last_seen_at = now() \
         WHERE token_hash = $1 AND expires_at > now() RETURNING id, user_id",
    )
    .bind(token_hash)
    .fetch_optional(pool)
    .await?)
}

pub async fn delete_session_by_token(pool: &PgPool, token_hash: &str) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM sessions WHERE token_hash = $1")
        .bind(token_hash)
        .execute(pool)
        .await?;
    Ok(())
}

/// Scoped by `user_id` on purpose: a session id is not a secret, so revoking
/// by id alone would let any logged-in user close anyone`s session.
pub async fn delete_session_by_id(
    pool: &PgPool,
    user_id: Uuid,
    session_id: Uuid,
) -> anyhow::Result<bool> {
    let rows = sqlx::query("DELETE FROM sessions WHERE id = $1 AND user_id = $2")
        .bind(session_id)
        .bind(user_id)
        .execute(pool)
        .await?
        .rows_affected();
    Ok(rows > 0)
}

/// Revokes every session for an account, optionally sparing one (the caller`s
/// own, for "sign out my other devices"). Password changes call this with
/// `except = None` — a reset that leaves the intruder logged in is not a
/// recovery.
pub async fn delete_sessions_for_user(
    pool: &PgPool,
    user_id: Uuid,
    except: Option<Uuid>,
) -> anyhow::Result<u64> {
    let rows = match except {
        Some(keep) => sqlx::query("DELETE FROM sessions WHERE user_id = $1 AND id <> $2")
            .bind(user_id)
            .bind(keep)
            .execute(pool)
            .await?
            .rows_affected(),
        None => sqlx::query("DELETE FROM sessions WHERE user_id = $1")
            .bind(user_id)
            .execute(pool)
            .await?
            .rows_affected(),
    };
    Ok(rows)
}

pub async fn list_sessions(pool: &PgPool, user_id: Uuid) -> anyhow::Result<Vec<SessionRow>> {
    Ok(sqlx::query_as::<_, SessionRow>(
        "SELECT id, ip, user_agent, created_at, last_seen_at, expires_at FROM sessions \
         WHERE user_id = $1 AND expires_at > now() ORDER BY last_seen_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?)
}

/// Housekeeping for expired rows, so `sessions` does not grow without bound.
pub async fn sweep_expired(pool: &PgPool) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM sessions WHERE expires_at < now()")
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM oauth_states WHERE created_at < now() - interval '15 minutes'")
        .execute(pool)
        .await?;
    Ok(())
}

// ---- roles ----------------------------------------------------------------

/// Idempotent — safe on every boot, which is how each site declares the roles
/// it uses without an ordered migration.
pub async fn seed_roles(pool: &PgPool, roles: &[String]) -> anyhow::Result<()> {
    for role in roles {
        sqlx::query("INSERT INTO roles (name) VALUES ($1) ON CONFLICT (name) DO NOTHING")
            .bind(role)
            .execute(pool)
            .await?;
    }
    Ok(())
}

pub async fn grant_roles(pool: &PgPool, user_id: Uuid, roles: &[String]) -> anyhow::Result<()> {
    for role in roles {
        sqlx::query(
            "INSERT INTO user_roles (user_id, role_id) SELECT $1, id FROM roles WHERE name = $2 \
             ON CONFLICT (user_id, role_id) DO NOTHING",
        )
        .bind(user_id)
        .bind(role)
        .execute(pool)
        .await?;
    }
    Ok(())
}

pub async fn roles_for_user(pool: &PgPool, user_id: Uuid) -> anyhow::Result<Vec<String>> {
    Ok(sqlx::query_scalar::<_, String>(
        "SELECT r.name FROM roles r JOIN user_roles ur ON ur.role_id = r.id \
         WHERE ur.user_id = $1 ORDER BY r.name",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?)
}

// ---- federated identities --------------------------------------------------

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Identity {
    pub provider: String,
    pub email: Option<String>,
    pub created_at: DateTime<Utc>,
}

pub async fn find_user_by_identity(
    pool: &PgPool,
    provider: &str,
    provider_user_id: &str,
) -> anyhow::Result<Option<Uuid>> {
    Ok(sqlx::query_scalar::<_, Uuid>(
        "SELECT user_id FROM user_identities WHERE provider = $1 AND provider_user_id = $2",
    )
    .bind(provider)
    .bind(provider_user_id)
    .fetch_optional(pool)
    .await?)
}

pub async fn link_identity(
    pool: &PgPool,
    user_id: Uuid,
    provider: &str,
    provider_user_id: &str,
    email: Option<&str>,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO user_identities (user_id, provider, provider_user_id, email) \
         VALUES ($1, $2, $3, $4) ON CONFLICT (provider, provider_user_id) DO NOTHING",
    )
    .bind(user_id)
    .bind(provider)
    .bind(provider_user_id)
    .bind(email)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn identities_for_user(pool: &PgPool, user_id: Uuid) -> anyhow::Result<Vec<Identity>> {
    Ok(sqlx::query_as::<_, Identity>(
        "SELECT provider, email, created_at FROM user_identities WHERE user_id = $1 \
         ORDER BY created_at",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?)
}

// ---- oauth in-flight state -------------------------------------------------

pub struct OauthState {
    pub provider: String,
    pub pkce_verifier: String,
    pub link_user_id: Option<Uuid>,
    pub redirect_to: Option<String>,
}

pub async fn put_oauth_state(
    pool: &PgPool,
    state_hash: &str,
    provider: &str,
    pkce_verifier: &str,
    link_user_id: Option<Uuid>,
    redirect_to: Option<&str>,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO oauth_states (state_hash, provider, pkce_verifier, link_user_id, redirect_to) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(state_hash)
    .bind(provider)
    .bind(pkce_verifier)
    .bind(link_user_id)
    .bind(redirect_to)
    .execute(pool)
    .await?;
    Ok(())
}

/// Deletes and returns in one statement — a `state` is single use, so a
/// replayed callback finds nothing.
pub async fn take_oauth_state(
    pool: &PgPool,
    state_hash: &str,
    max_age: Duration,
) -> anyhow::Result<Option<OauthState>> {
    let cutoff: DateTime<Utc> = Utc::now() - max_age;
    let row = sqlx::query_as::<_, (String, String, Option<Uuid>, Option<String>)>(
        "DELETE FROM oauth_states WHERE state_hash = $1 AND created_at > $2 \
         RETURNING provider, pkce_verifier, link_user_id, redirect_to",
    )
    .bind(state_hash)
    .bind(cutoff)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(provider, pkce_verifier, link_user_id, redirect_to)| OauthState {
        provider,
        pkce_verifier,
        link_user_id,
        redirect_to,
    }))
}

// ---- audit ----------------------------------------------------------------

/// Best effort: a failure to record an audit row is logged, never propagated
/// into the caller`s response. Losing an audit line is bad; failing a login
/// because the audit insert failed is worse.
pub async fn log_event(
    pool: &PgPool,
    kind: &str,
    user_id: Option<Uuid>,
    email: Option<&str>,
    ip: Option<&str>,
    user_agent: Option<&str>,
) {
    let result = sqlx::query(
        "INSERT INTO auth_events (kind, user_id, email, ip, user_agent) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(kind)
    .bind(user_id)
    .bind(email)
    .bind(ip)
    .bind(user_agent)
    .execute(pool)
    .await;
    if let Err(e) = result {
        tracing::warn!(%e, kind, "could not record auth event");
    }
}

// ---- mailing list ----------------------------------------------------------

/// What `subscribe` needs to know about an address it has just been handed.
/// Deliberately not the whole row: nothing downstream needs the tokens, and a
/// struct that carries them is a struct that can leak them into a log line.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SubscriberStatus {
    pub confirmed: bool,
    pub unsubscribed_at: Option<DateTime<Utc>>,
    pub confirm_sent_at: Option<DateTime<Utc>>,
}

/// Adds the address, or resets an existing row back to "asked, not yet
/// confirmed" — which is also how a previously unsubscribed address comes
/// back, without losing its id or its original `created_at`.
///
/// Returns `(id, was_new, unsubscribe_token)`. The token returned is the
/// *effective* one — on conflict the existing row keeps its own, so links in
/// mail already sent go on working, and the caller must use what comes back
/// here rather than the value it passed in.
///
/// The caller must not let `was_new` reach the HTTP response: whether an
/// address is already on a mailing list is exactly as private as whether it
/// has an account.
pub async fn upsert_subscriber(
    pool: &PgPool,
    email: &str,
    source: Option<&str>,
    confirm_token_hash: &str,
    unsubscribe_token: &str,
    ip: Option<&str>,
    user_agent: Option<&str>,
    referer: Option<&str>,
) -> anyhow::Result<(i64, bool, String)> {
    let row = sqlx::query_as::<_, (i64, bool, String)>(
        "INSERT INTO subscribers \
           (email, source, confirm_token_hash, confirm_sent_at, unsubscribe_token, ip, user_agent, referer) \
         VALUES ($1, $2, $3, now(), $4, $5, $6, $7) \
         ON CONFLICT (email) DO UPDATE SET \
           confirm_token_hash = EXCLUDED.confirm_token_hash, \
           confirm_sent_at = now(), \
           unsubscribed_at = NULL, \
           source = COALESCE(subscribers.source, EXCLUDED.source) \
         RETURNING id, (xmax = 0) AS was_new, unsubscribe_token",
    )
    .bind(email)
    .bind(source)
    .bind(confirm_token_hash)
    .bind(unsubscribe_token)
    .bind(ip)
    .bind(user_agent)
    .bind(referer)
    .fetch_one(pool)
    .await?;
    Ok(row)
}

pub async fn find_subscriber(pool: &PgPool, email: &str) -> anyhow::Result<Option<SubscriberStatus>> {
    Ok(sqlx::query_as::<_, SubscriberStatus>(
        "SELECT confirmed, unsubscribed_at, confirm_sent_at FROM subscribers WHERE email = $1",
    )
    .bind(email)
    .fetch_optional(pool)
    .await?)
}

/// Marks confirmed and spends the confirmation token in one statement, like
/// every other one-time secret in this crate. Returns `(email,
/// unsubscribe_token)` so the caller can put a working unsubscribe link in
/// the welcome mail without a second query.
pub async fn confirm_subscriber(
    pool: &PgPool,
    token_hash: &str,
) -> anyhow::Result<Option<(String, String)>> {
    Ok(sqlx::query_as::<_, (String, String)>(
        "UPDATE subscribers SET confirmed = true, confirmed_at = now(), \
         confirm_token_hash = NULL, unsubscribed_at = NULL \
         WHERE confirm_token_hash = $1 RETURNING email, unsubscribe_token",
    )
    .bind(token_hash)
    .fetch_optional(pool)
    .await?)
}

/// Confirmed, still-subscribed addresses with the token each one's
/// unsubscribe link needs. What a newsletter send reads; nothing in this
/// crate calls it, since sending the newsletter is not this crate's job.
pub async fn active_subscribers(pool: &PgPool) -> anyhow::Result<Vec<(String, String)>> {
    Ok(sqlx::query_as::<_, (String, String)>(
        "SELECT email, unsubscribe_token FROM subscribers \
         WHERE confirmed = true AND unsubscribed_at IS NULL ORDER BY id",
    )
    .fetch_all(pool)
    .await?)
}

/// Idempotent on purpose: clicking an unsubscribe link twice must not look
/// like a failure, and the token stays valid afterwards because it has to
/// keep working in mail sent months ago.
pub async fn unsubscribe(pool: &PgPool, token: &str) -> anyhow::Result<bool> {
    let rows = sqlx::query(
        "UPDATE subscribers SET unsubscribed_at = COALESCE(unsubscribed_at, now()) \
         WHERE unsubscribe_token = $1",
    )
    .bind(token)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(rows > 0)
}

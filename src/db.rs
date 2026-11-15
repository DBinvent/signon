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
    /// `None` for an account with no address (`broker.rs`: a provider that
    /// gave none, or one it does not vouch for). Such an account never has a
    /// password and is never found by address.
    pub email: Option<String>,
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

/// An account with no address at all — a brokered sign-in whose provider
/// gave none, or gave one it does not vouch for (`broker.rs`). Never
/// conflicts: `UNIQUE` lets any number of NULLs through. `email_verified` is
/// true because nothing is waiting to be confirmed — the flag is what lets a
/// session resolve (`current_user.rs`), and there is no address that could
/// ever become verified later.
#[cfg_attr(not(feature = "sso-broker"), allow(dead_code))]
pub async fn create_user_without_email(pool: &PgPool, display_name: Option<&str>) -> anyhow::Result<Uuid> {
    Ok(sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO users (email, password_hash, display_name, email_verified) \
         VALUES (NULL, NULL, $1, true) RETURNING id",
    )
    .bind(display_name)
    .fetch_one(pool)
    .await?)
}

/// Never matches an account with no address: `email = $1` is not true for a
/// NULL.
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

pub async fn mark_login(pool: &PgPool, user_id: Uuid, ip: Option<&str>) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE users SET last_login_at = now(), last_login_ip = COALESCE($2, last_login_ip) \
         WHERE id = $1",
    )
    .bind(user_id)
    .bind(ip)
    .execute(pool)
    .await?;
    Ok(())
}

// ---- sign-up facts, account mail, browser marks ------------------------------

/// What is only known at sign-up: where from, and whether the owner left
/// non-essential mail on (the pre-ticked "email me" box).
pub async fn note_signup(
    pool: &PgPool,
    user_id: Uuid,
    ip: Option<&str>,
    emails: bool,
) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE users SET signup_ip = $2, \
         emails_off_at = CASE WHEN $3 THEN NULL ELSE now() END WHERE id = $1",
    )
    .bind(user_id)
    .bind(ip)
    .bind(emails)
    .execute(pool)
    .await?;
    Ok(())
}

// ---- the mail log (account_mail.rs) -------------------------------------------

/// The account conditions every non-essential mail needs: a confirmed
/// address, mail left on, not suspended. One string so the claim and the
/// audiences can never drift apart.
const MAIL_TO: &str = "u.emails_off_at IS NULL AND u.email IS NOT NULL AND u.email_verified AND NOT u.suspended";

/// A `mail_log` row that blocks another send of its kind: sent, or being
/// sent right now. A send stuck in `sending` for an hour (a crash between
/// claim and finish) stops blocking, like a failed one.
const ALREADY: &str = "(m.status = 'sent' OR (m.status = 'sending' AND m.updated_at > now() - interval '1 hour'))";

/// A claimed send: the log row to finish, and where it goes.
pub struct MailClaim {
    pub log_id: i64,
    pub email: String,
    pub unsubscribe_token: String,
}

/// Claims `kind` for `user_id` in the statement that checks it is owed —
/// the account qualifies and no row of this kind is sent or in flight. A
/// failed row is claimed again (one more attempt); a sent one never. Mints
/// the account's unsubscribe token on its first such mail. `None`: nothing
/// to send — not owed, or another caller got there first.
pub async fn claim_mail(
    pool: &PgPool,
    user_id: Uuid,
    kind: &str,
    new_token: &str,
) -> anyhow::Result<Option<MailClaim>> {
    let row = sqlx::query_as::<_, (i64, String, String)>(&format!(
        "WITH u AS ( \
           UPDATE users u SET unsubscribe_token = COALESCE(u.unsubscribe_token, $3) \
           WHERE u.id = $1 AND {MAIL_TO} \
           RETURNING u.id, u.email, u.unsubscribe_token \
         ), claimed AS ( \
           INSERT INTO mail_log (user_id, kind, status, email) \
           SELECT id, $2, 'sending', email FROM u \
           ON CONFLICT (user_id, kind) DO UPDATE \
             SET status = 'sending', attempts = mail_log.attempts + 1, email = EXCLUDED.email, \
                 error = NULL, updated_at = now() \
             WHERE mail_log.status = 'failed' \
                OR (mail_log.status = 'sending' AND mail_log.updated_at <= now() - interval '1 hour') \
           RETURNING id \
         ) \
         SELECT claimed.id, u.email, u.unsubscribe_token FROM claimed CROSS JOIN u"
    ))
    .bind(user_id)
    .bind(kind)
    .bind(new_token)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(log_id, email, unsubscribe_token)| MailClaim {
        log_id,
        email,
        unsubscribe_token,
    }))
}

/// Marks a claimed send done — `sent`, or `failed` with why.
pub async fn finish_mail(
    pool: &PgPool,
    log_id: i64,
    subject: &str,
    result: &Result<(), String>,
) -> anyhow::Result<()> {
    let (status, error) = match result {
        Ok(()) => ("sent", None),
        Err(e) => ("failed", Some(e.chars().take(500).collect::<String>())),
    };
    sqlx::query(
        "UPDATE mail_log SET status = $2, subject = $3, error = $4, updated_at = now() WHERE id = $1",
    )
    .bind(log_id)
    .bind(status)
    .bind(subject.chars().take(250).collect::<String>())
    .bind(error)
    .execute(pool)
    .await?;
    Ok(())
}

/// Whether `kind` would still go to this account — the cheap check before a
/// template is fetched. The claim re-checks all of it.
pub async fn mail_owed(pool: &PgPool, user_id: Uuid, kind: &str) -> anyhow::Result<bool> {
    Ok(sqlx::query_scalar::<_, bool>(&format!(
        "SELECT {MAIL_TO} AND NOT EXISTS (SELECT 1 FROM mail_log m WHERE m.user_id = u.id \
           AND m.kind = $2 AND {ALREADY}) \
         FROM users u WHERE u.id = $1"
    ))
    .bind(user_id)
    .bind(kind)
    .fetch_optional(pool)
    .await?
    .unwrap_or(false))
}

/// Who a manual run of `kind` would reach, oldest account first. With
/// `after = Some((earlier_kind, days))` — a follow-up — only accounts whose
/// `earlier_kind` was sent more than `days` days ago. Parameters: `$1` the
/// kind, then the limit (a list only), then the earlier kind and the days —
/// numbered per query, since Postgres refuses a parameter it never sees.
fn audience_sql(after: bool, count: bool) -> String {
    let (limit, earlier, days) = if count { (None, 2, 3) } else { (Some(2), 3, 4) };
    let join = if after {
        format!(
            "JOIN mail_log w ON w.user_id = u.id AND w.kind = ${earlier} AND w.status = 'sent' \
             AND w.updated_at <= now() - make_interval(days => ${days})"
        )
    } else {
        String::new()
    };
    let select = if count { "SELECT count(*)" } else { "SELECT u.id" };
    let tail = limit.map(|n| format!(" ORDER BY u.created_at LIMIT ${n}")).unwrap_or_default();
    format!(
        "{select} FROM users u {join} WHERE {MAIL_TO} \
         AND NOT EXISTS (SELECT 1 FROM mail_log m WHERE m.user_id = u.id AND m.kind = $1 AND {ALREADY}){tail}"
    )
}

/// How many accounts `kind` is owed to — see [`mail_audience`].
pub async fn mail_audience_count(pool: &PgPool, kind: &str, after: Option<(&str, i32)>) -> anyhow::Result<i64> {
    let sql = audience_sql(after.is_some(), true);
    let mut q = sqlx::query_scalar::<_, i64>(&sql).bind(kind);
    if let Some((earlier, days)) = after {
        q = q.bind(earlier).bind(days);
    }
    Ok(q.fetch_one(pool).await?)
}

/// Up to `limit` accounts `kind` is owed to, oldest first.
pub async fn mail_audience(
    pool: &PgPool,
    kind: &str,
    after: Option<(&str, i32)>,
    limit: i64,
) -> anyhow::Result<Vec<Uuid>> {
    let sql = audience_sql(after.is_some(), false);
    let mut q = sqlx::query_scalar::<_, Uuid>(&sql).bind(kind).bind(limit);
    if let Some((earlier, days)) = after {
        q = q.bind(earlier).bind(days);
    }
    Ok(q.fetch_all(pool).await?)
}

/// Whether non-essential mail is on for this account.
pub async fn emails_on(pool: &PgPool, user_id: Uuid) -> anyhow::Result<bool> {
    Ok(sqlx::query_scalar::<_, bool>("SELECT emails_off_at IS NULL FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(pool)
        .await?
        .unwrap_or(false))
}

/// The profile page switch.
pub async fn set_emails(pool: &PgPool, user_id: Uuid, on: bool) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE users SET emails_off_at = \
         CASE WHEN $2 THEN NULL ELSE COALESCE(emails_off_at, now()) END WHERE id = $1",
    )
    .bind(user_id)
    .bind(on)
    .execute(pool)
    .await?;
    Ok(())
}

/// A mailed unsubscribe link (or its undo). `false` when the token names no
/// account. The token stays valid — it has to keep working in old mail.
pub async fn set_emails_by_token(pool: &PgPool, token: &str, on: bool) -> anyhow::Result<bool> {
    let rows = sqlx::query(
        "UPDATE users SET emails_off_at = \
         CASE WHEN $2 THEN NULL ELSE COALESCE(emails_off_at, now()) END \
         WHERE unsubscribe_token = $1",
    )
    .bind(token)
    .bind(on)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(rows > 0)
}

/// Records that this browser (the hash of its `signon_browser` cookie) created
/// or signed in to `user_id`.
pub async fn remember_browser(pool: &PgPool, mark_hash: &str, user_id: Uuid) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO user_browsers (mark_hash, user_id) VALUES ($1, $2) \
         ON CONFLICT (mark_hash, user_id) DO UPDATE SET last_seen_at = now()",
    )
    .bind(mark_hash)
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// The account this browser was last seen with, if any — `Some(None)` for
/// one with no address.
pub async fn browser_account(pool: &PgPool, mark_hash: &str) -> anyhow::Result<Option<Option<String>>> {
    Ok(sqlx::query_scalar::<_, Option<String>>(
        "SELECT u.email FROM user_browsers b JOIN users u ON u.id = b.user_id \
         WHERE b.mark_hash = $1 ORDER BY b.last_seen_at DESC LIMIT 1",
    )
    .bind(mark_hash)
    .fetch_optional(pool)
    .await?)
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
    via: &str,
) -> anyhow::Result<Uuid> {
    let expires_at = Utc::now() + ttl;
    Ok(sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO sessions (token_hash, user_id, ip, user_agent, expires_at, via) \
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
    )
    .bind(token_hash)
    .bind(user_id)
    .bind(ip)
    .bind(user_agent)
    .bind(expires_at)
    .bind(via)
    .fetch_one(pool)
    .await?)
}

/// Every session minted through one route in — `sso:<connection id>` when a
/// connection is suspended. Returns how many went.
pub async fn delete_sessions_via(pool: &PgPool, via: &str) -> anyhow::Result<u64> {
    Ok(sqlx::query("DELETE FROM sessions WHERE via = $1")
        .bind(via)
        .execute(pool)
        .await?
        .rows_affected())
}

/// Sessions of every account at `domain` that were *not* minted through
/// `keep_via` — what turning on SSO enforcement for a domain revokes.
/// Compared as a suffix rather than with `LIKE`, where `_` in a domain would
/// be a wildcard.
pub async fn delete_sessions_for_domain_except_via(
    pool: &PgPool,
    domain: &str,
    keep_via: &str,
) -> anyhow::Result<u64> {
    Ok(sqlx::query(
        "DELETE FROM sessions s USING users u \
         WHERE s.user_id = u.id AND right(u.email, length($1) + 1) = '@' || $1 \
         AND s.via IS DISTINCT FROM $2",
    )
    .bind(domain)
    .bind(keep_via)
    .execute(pool)
    .await?
    .rows_affected())
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
    sqlx::query("DELETE FROM pending_identities WHERE created_at < now() - interval '1 hour'")
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

#[cfg(feature = "oauth")]
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

#[cfg(feature = "oauth")]
pub async fn link_identity(
    pool: &PgPool,
    user_id: Uuid,
    provider: &str,
    provider_user_id: &str,
    email: Option<&str>,
    connection_id: Option<Uuid>,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO user_identities (user_id, provider, provider_user_id, email, connection_id) \
         VALUES ($1, $2, $3, $4, $5) ON CONFLICT (provider, provider_user_id) DO NOTHING",
    )
    .bind(user_id)
    .bind(provider)
    .bind(provider_user_id)
    .bind(email)
    .bind(connection_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// One person who has signed in through a customer connection.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct ConnectionUser {
    pub user_id: Uuid,
    /// `None` for an account with no address — the IdP reported none.
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub suspended: bool,
    pub linked_at: DateTime<Utc>,
    pub last_login_at: Option<DateTime<Utc>>,
}

/// Accounts linked through `connection_id` — the customer's People view.
/// Only identities the connection itself created, never "everyone at the
/// domain".
pub async fn users_for_connection(
    pool: &PgPool,
    connection_id: Uuid,
) -> anyhow::Result<Vec<ConnectionUser>> {
    Ok(sqlx::query_as::<_, ConnectionUser>(
        "SELECT u.id AS user_id, u.email, u.display_name, u.suspended, \
                min(i.created_at) AS linked_at, u.last_login_at \
         FROM user_identities i JOIN users u ON u.id = i.user_id \
         WHERE i.connection_id = $1 \
         GROUP BY u.id, u.email, u.display_name, u.suspended, u.last_login_at \
         ORDER BY u.email",
    )
    .bind(connection_id)
    .fetch_all(pool)
    .await?)
}

/// Whether `user_id` holds an identity from `connection_id` — the guard
/// on every People-view action, so a customer can act only on people their
/// own IdP vouched for.
pub async fn user_linked_to_connection(
    pool: &PgPool,
    user_id: Uuid,
    connection_id: Uuid,
) -> anyhow::Result<bool> {
    Ok(sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM user_identities WHERE user_id = $1 AND connection_id = $2)",
    )
    .bind(user_id)
    .bind(connection_id)
    .fetch_one(pool)
    .await?)
}

/// Users linked through `connection_id` whose address is `email` — SCIM
/// deprovisioning resolves the IdP's `userName` to accounts this way.
pub async fn user_ids_for_connection_email(
    pool: &PgPool,
    connection_id: Uuid,
    email: &str,
) -> anyhow::Result<Vec<Uuid>> {
    Ok(sqlx::query_scalar::<_, Uuid>(
        "SELECT DISTINCT u.id FROM user_identities i JOIN users u ON u.id = i.user_id \
         WHERE i.connection_id = $1 AND u.email = $2",
    )
    .bind(connection_id)
    .bind(email)
    .fetch_all(pool)
    .await?)
}

/// Removes every identity a connection created — what deleting a
/// connection does. The accounts stay.
pub async fn unlink_connection(pool: &PgPool, connection_id: Uuid) -> anyhow::Result<u64> {
    Ok(
        sqlx::query("DELETE FROM user_identities WHERE connection_id = $1")
            .bind(connection_id)
            .execute(pool)
            .await?
            .rows_affected(),
    )
}

pub async fn set_suspended(pool: &PgPool, user_id: Uuid, suspended: bool) -> anyhow::Result<()> {
    sqlx::query("UPDATE users SET suspended = $2, updated_at = now() WHERE id = $1")
        .bind(user_id)
        .bind(suspended)
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

#[cfg(feature = "oauth")]
pub struct OauthState {
    pub provider: String,
    pub pkce_verifier: String,
    pub link_user_id: Option<Uuid>,
    pub redirect_to: Option<String>,
    pub nonce: Option<String>,
}

/// What `put_oauth_state` stores for one attempt.
#[cfg(feature = "oauth")]
pub struct NewOauthState<'a> {
    pub state_hash: &'a str,
    pub provider: &'a str,
    pub pkce_verifier: &'a str,
    pub link_user_id: Option<Uuid>,
    pub redirect_to: Option<&'a str>,
    pub nonce: Option<&'a str>,
}

#[cfg(feature = "oauth")]
pub async fn put_oauth_state(pool: &PgPool, row: NewOauthState<'_>) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO oauth_states \
         (state_hash, provider, pkce_verifier, link_user_id, redirect_to, nonce) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(row.state_hash)
    .bind(row.provider)
    .bind(row.pkce_verifier)
    .bind(row.link_user_id)
    .bind(row.redirect_to)
    .bind(row.nonce)
    .execute(pool)
    .await?;
    Ok(())
}

/// Reads *and deletes* the state row in one statement — a replayed callback
/// finds nothing.
#[cfg(feature = "oauth")]
pub async fn take_oauth_state(
    pool: &PgPool,
    state_hash: &str,
    max_age: Duration,
) -> anyhow::Result<Option<OauthState>> {
    let cutoff: DateTime<Utc> = Utc::now() - max_age;
    #[allow(clippy::type_complexity)]
    let row = sqlx::query_as::<
        _,
        (
            String,
            String,
            Option<Uuid>,
            Option<String>,
            Option<String>,
        ),
    >(
        "DELETE FROM oauth_states WHERE state_hash = $1 AND created_at > $2 \
         RETURNING provider, pkce_verifier, link_user_id, redirect_to, nonce",
    )
    .bind(state_hash)
    .bind(cutoff)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(
        |(provider, pkce_verifier, link_user_id, redirect_to, nonce)| OauthState {
            provider,
            pkce_verifier,
            link_user_id,
            redirect_to,
            nonce,
        },
    ))
}

// ---- pending identities ----------------------------------------------------

#[cfg(feature = "oauth")]
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PendingIdentity {
    pub provider: String,
    pub provider_user_id: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub code_sent_at: Option<DateTime<Utc>>,
    pub redirect_to: Option<String>,
    pub email_proven: bool,
    pub connection_id: Option<Uuid>,
    pub connection_owner: Option<Uuid>,
    pub via: Option<String>,
    pub label: Option<String>,
    pub session_max_hours: Option<i32>,
    // Only a brokered "Create one?" question (`broker.rs`) sets or reads these.
    #[cfg_attr(not(feature = "sso-broker"), allow(dead_code))]
    pub email_typed: bool,
    #[cfg_attr(not(feature = "sso-broker"), allow(dead_code))]
    pub identity_email: Option<String>,
}

#[cfg(feature = "oauth")]
const PENDING_FIELDS: &str = "provider, provider_user_id, email, display_name, code_sent_at, redirect_to, \
     email_proven, connection_id, connection_owner, via, label, session_max_hours, email_typed, identity_email";

/// Everything a pending sign-in remembers.
#[cfg(feature = "oauth")]
#[derive(Debug, Clone, Default)]
pub struct NewPending<'a> {
    pub provider: &'a str,
    pub provider_user_id: &'a str,
    pub email: Option<&'a str>,
    pub display_name: Option<&'a str>,
    pub redirect_to: Option<&'a str>,
    pub email_proven: bool,
    pub connection_id: Option<Uuid>,
    pub connection_owner: Option<Uuid>,
    pub via: Option<&'a str>,
    pub label: Option<&'a str>,
    pub session_max_hours: Option<i32>,
    /// `email` is an address typed on a customer connection's button, not
    /// one the IdP reported: it may create a profile, never enter one.
    pub email_typed: bool,
    /// An address the provider reported without vouching for it — kept on
    /// the identity for display, never on the account.
    pub identity_email: Option<&'a str>,
}

#[cfg(feature = "oauth")]
pub async fn create_pending_identity(pool: &PgPool, token_hash: &str, p: &NewPending<'_>) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO pending_identities \
         (token_hash, provider, provider_user_id, email, display_name, redirect_to, email_proven, \
          connection_id, connection_owner, via, label, session_max_hours, email_typed, identity_email) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
    )
    .bind(token_hash)
    .bind(p.provider)
    .bind(p.provider_user_id)
    .bind(p.email)
    .bind(p.display_name)
    .bind(p.redirect_to)
    .bind(p.email_proven)
    .bind(p.connection_id)
    .bind(p.connection_owner)
    .bind(p.via)
    .bind(p.label)
    .bind(p.session_max_hours)
    .bind(p.email_typed)
    .bind(p.identity_email)
    .execute(pool)
    .await?;
    Ok(())
}

#[cfg(feature = "oauth")]
pub async fn find_pending_identity(
    pool: &PgPool,
    token_hash: &str,
    max_age: Duration,
) -> anyhow::Result<Option<PendingIdentity>> {
    let cutoff: DateTime<Utc> = Utc::now() - max_age;
    Ok(sqlx::query_as::<_, PendingIdentity>(&format!(
        "SELECT {PENDING_FIELDS} FROM pending_identities \
         WHERE token_hash = $1 AND created_at > $2"
    ))
    .bind(token_hash)
    .bind(cutoff)
    .fetch_optional(pool)
    .await?)
}

/// Spends a "Create profile?" row (`email_proven`) — never a code step.
/// Its `email`, when set, is proven; NULL means the profile gets no address.
#[cfg(feature = "oauth")]
#[cfg_attr(not(feature = "sso-broker"), allow(dead_code))]
pub async fn take_proven_pending(
    pool: &PgPool,
    token_hash: &str,
    max_age: Duration,
) -> anyhow::Result<Option<PendingIdentity>> {
    let cutoff: DateTime<Utc> = Utc::now() - max_age;
    Ok(sqlx::query_as::<_, PendingIdentity>(&format!(
        "DELETE FROM pending_identities \
         WHERE token_hash = $1 AND created_at > $2 AND email_proven \
         RETURNING {PENDING_FIELDS}"
    ))
    .bind(token_hash)
    .bind(cutoff)
    .fetch_optional(pool)
    .await?)
}

/// Sets (or replaces) the address and arms a fresh code. Resets the attempt
/// counter: a new code is a new six-digit search.
#[cfg(feature = "oauth")]
pub async fn arm_pending_code(
    pool: &PgPool,
    token_hash: &str,
    email: &str,
    code: &str,
) -> anyhow::Result<bool> {
    Ok(sqlx::query(
        "UPDATE pending_identities SET email = $2, code = $3, code_sent_at = now(), attempts = 0 \
         WHERE token_hash = $1 AND NOT email_proven",
    )
    .bind(token_hash)
    .bind(email)
    .bind(code)
    .execute(pool)
    .await?
    .rows_affected()
        > 0)
}

/// Check-and-spend in one statement, same as `consume_verify_code`: a match
/// deletes the row and returns it, a miss changes nothing (the caller bumps
/// the attempt count separately, so a correct code after typos still works).
#[cfg(feature = "oauth")]
pub async fn consume_pending_code(
    pool: &PgPool,
    token_hash: &str,
    code: &str,
    max_age: Duration,
    max_attempts: i32,
) -> anyhow::Result<Option<PendingIdentity>> {
    let cutoff: DateTime<Utc> = Utc::now() - max_age;
    Ok(sqlx::query_as::<_, PendingIdentity>(&format!(
        "DELETE FROM pending_identities \
         WHERE token_hash = $1 AND code = $2 AND code_sent_at > $3 AND attempts < $4 \
         AND email IS NOT NULL AND NOT email_proven RETURNING {PENDING_FIELDS}"
    ))
    .bind(token_hash)
    .bind(code)
    .bind(cutoff)
    .bind(max_attempts)
    .fetch_optional(pool)
    .await?)
}

#[cfg(feature = "oauth")]
pub async fn bump_pending_attempts(pool: &PgPool, token_hash: &str) -> anyhow::Result<()> {
    sqlx::query("UPDATE pending_identities SET attempts = attempts + 1 WHERE token_hash = $1")
        .bind(token_hash)
        .execute(pool)
        .await?;
    Ok(())
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
    log_event_via(pool, kind, user_id, email, ip, user_agent, None).await
}

/// `log_event` plus the route in (`oauth:google`, `sso:<id>`), for the
/// sign-in events an admin counts per provider.
pub async fn log_event_via(
    pool: &PgPool,
    kind: &str,
    user_id: Option<Uuid>,
    email: Option<&str>,
    ip: Option<&str>,
    user_agent: Option<&str>,
    via: Option<&str>,
) {
    let result = sqlx::query(
        "INSERT INTO auth_events (kind, user_id, email, ip, user_agent, via) VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(kind)
    .bind(user_id)
    .bind(email)
    .bind(ip)
    .bind(user_agent)
    .bind(via)
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

pub async fn find_subscriber(
    pool: &PgPool,
    email: &str,
) -> anyhow::Result<Option<SubscriberStatus>> {
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

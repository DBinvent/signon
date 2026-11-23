//! [api] Sign-in and the session check for a caller that is not a browser - an etcd
//! server, a gRPC API. The same accounts, the same rules as
//! `/account/login` - the rate limits, SSO enforcement, the argon2 check, an unverified
//! or suspended account refused with the one answer a wrong password gets - and the same
//! sessions: a token here is a session row's secret, revoked as any session is.
//!
//! ```no_run
//! # async fn wire(state: signon::AccountState) -> anyhow::Result<()> {
//! let s = signon::api::sign_in(&state, "ops@example.com", "secret", "10.0.0.7", "etcd").await;
//! if let Ok(s) = s {
//!     let who = signon::api::identity(&state.pool, &s.token).await?;   // per call
//! }
//! # Ok(())
//! # }
//! ```

use std::time::Duration;

use axum::response::Response;
use sqlx::PgPool;
use uuid::Uuid;

use crate::{db, password, token, AccountState};

/// A session's `last_seen_at` is written at most once a minute by [`identity`]: a
/// caller that checks the token on every request - an etcd server, on every key read -
/// would otherwise write a row per request, and a replicated database carries each one
pub const TOUCH_EVERY: Duration = Duration::from_secs(60);

/// Why [`sign_in`] refused. A wrong password, an unknown address and an unverified or
/// suspended account are one answer, as at `/account/login`.
#[derive(Debug)]
pub enum SignInRefusal {
    Credentials,
    /// the address's or the client's sign-ins in the last five minutes are over the
    /// limit `/account/login` keeps (shared with it: one count per address)
    TooMany,
    /// the address's domain signs in through its SSO connection only
    SsoRequired,
    Internal(anyhow::Error),
}

impl std::fmt::Display for SignInRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignInRefusal::Credentials => f.write_str("wrong address or password"),
            SignInRefusal::TooMany => f.write_str("too many sign-in attempts"),
            SignInRefusal::SsoRequired => f.write_str("this address signs in through its SSO connection"),
            SignInRefusal::Internal(e) => write!(f, "internal error: {e}"),
        }
    }
}

/// A session made by [`sign_in`]: `token` is its secret, what the caller hands back on
/// each request - only its hash is stored
#[derive(Debug, Clone)]
pub struct SignedIn {
    pub token: String,
    pub user_id: Uuid,
    pub expires_in: Duration,
}

/// The account behind a live session, with its roles as they are now
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub user_id: Uuid,
    pub email: Option<String>,
    pub roles: Vec<String>,
}

/// What the password check of a sign-in came to: `routes::login`'s and [`sign_in`]'s
pub(crate) enum Checked {
    Ok(db::User),
    TooMany,
    /// the refusal `/account/login` answers with (the connection to sign in through)
    Sso(Response),
    Wrong,
    Internal(anyhow::Error),
}

/// The password sign-in's checks, in `/account/login`'s order: the limits, SSO
/// enforcement (before the account is looked up: the answer depends on the domain
/// only), the account and its password - the argon2 work done for a missing account or
/// one with no password too, so the answer's time tells nothing. A refusal is logged
/// as `login_fail`. `email` lowercased and trimmed by the caller.
pub(crate) async fn check_password(
    state: &AccountState,
    email: &str,
    password_in: &str,
    client: &str,
    ip: Option<&str>,
    user_agent: Option<&str>,
) -> Checked {
    if !state.limiter.check(&format!("login:ip:{client}"), crate::routes::LOGIN_PER_IP, crate::routes::FIVE_MIN)
        || !state.limiter.check(&format!("login:em:{email}"), crate::routes::LOGIN_PER_EMAIL, crate::routes::FIVE_MIN)
    {
        return Checked::TooMany;
    }
    if let Some(refusal) = crate::routes::enforcement_refusal(state, email).await {
        return Checked::Sso(refusal);
    }
    let user = match db::find_user_by_email(&state.pool, email).await {
        Ok(u) => u,
        Err(e) => return Checked::Internal(e),
    };
    let ok = match &user {
        Some(u) => match &u.password_hash {
            Some(hash) => password::verify(password_in, hash) && u.email_verified && !u.suspended,
            // an SSO-only account has no local password to be wrong: the work is done anyway
            None => {
                password::verify(password_in, password::dummy_hash());
                false
            }
        },
        None => {
            password::verify(password_in, password::dummy_hash());
            false
        }
    };
    if !ok {
        db::log_event(&state.pool, "login_fail", user.as_ref().map(|u| u.id), Some(email), ip, user_agent).await;
        return Checked::Wrong;
    }
    match user {
        Some(u) => Checked::Ok(u),
        None => Checked::Wrong,
    }
}

/// Signs `email` in with its password, as `/account/login` does, and makes a session
/// for a caller that is not a browser: no cookie, the token returned. `client` is the
/// caller's address, for the per-client limit and the event log - each caller's own:
/// one value for every caller puts them all in one limit, and one caller's wrong
/// passwords then lock the rest out ([review 2026-11-21]); `via` names the route
/// in on the session row (`etcd`), so [`crate::revoke_sessions_via`] can end every
/// session made through it. The session lives `Config::session_ttl`.
pub async fn sign_in(
    state: &AccountState,
    email: &str,
    password_in: &str,
    client: &str,
    via: &str,
) -> Result<SignedIn, SignInRefusal> {
    let email = email.trim().to_lowercase();
    let user = match check_password(state, &email, password_in, client, Some(client), None).await {
        Checked::Ok(u) => u,
        Checked::TooMany => return Err(SignInRefusal::TooMany),
        Checked::Sso(_) => return Err(SignInRefusal::SsoRequired),
        Checked::Wrong => return Err(SignInRefusal::Credentials),
        Checked::Internal(e) => return Err(SignInRefusal::Internal(e)),
    };
    let secret = token::secret();
    let ttl = state.config.session_ttl;
    let chrono_ttl = chrono::Duration::from_std(ttl).unwrap_or_else(|_| chrono::Duration::days(30));
    db::create_session(&state.pool, user.id, &token::hash(&secret), chrono_ttl, Some(client), None, via)
        .await
        .map_err(SignInRefusal::Internal)?;
    db::mark_login(&state.pool, user.id, Some(client)).await.map_err(SignInRefusal::Internal)?;
    db::log_event_via(&state.pool, "login_ok", Some(user.id), Some(&email), Some(client), None, Some(via)).await;
    Ok(SignedIn { token: secret, user_id: user.id, expires_in: ttl })
}

/// The account behind `token`, with its roles - `None` for an unknown or expired
/// session, or an account unverified or suspended since. Its `last_seen_at` is written
/// at most once per [`TOUCH_EVERY`].
pub async fn identity(pool: &PgPool, token_in: &str) -> anyhow::Result<Option<Identity>> {
    let Some(user_id) = db::session_user_throttled(pool, &token::hash(token_in), TOUCH_EVERY).await? else {
        return Ok(None);
    };
    let Some(u) = db::find_user_by_id(pool, user_id).await?.filter(|u| u.email_verified && !u.suspended) else {
        return Ok(None);
    };
    Ok(Some(Identity { user_id: u.id, email: u.email, roles: db::roles_for_user(pool, u.id).await? }))
}

/// Ends the session of `token`: what a caller's sign-out does. `false`: there was none.
pub async fn sign_out(pool: &PgPool, token_in: &str) -> anyhow::Result<bool> {
    db::delete_session_by_token_counted(pool, &token::hash(token_in)).await
}

/// An account by address, with its roles: `None` for no such account
pub async fn account(pool: &PgPool, email: &str) -> anyhow::Result<Option<Identity>> {
    let Some(u) = db::find_user_by_email(pool, &email.trim().to_lowercase()).await? else {
        return Ok(None);
    };
    Ok(Some(Identity { user_id: u.id, email: u.email, roles: db::roles_for_user(pool, u.id).await? }))
}

/// Every account's address, in order - the ones with none left out
pub async fn accounts(pool: &PgPool) -> anyhow::Result<Vec<String>> {
    db::user_emails(pool).await
}

/// Makes a verified account with a password, for a tool that is not the sign-up page:
/// the first `root` of an etcd server, an operator's script. The password must pass
/// the policy `/register` holds to. `Ok(None)`: the address is taken.
pub async fn add_account(pool: &PgPool, email: &str, password_in: &str) -> anyhow::Result<Option<Uuid>> {
    let email = email.trim().to_lowercase();
    password::check_policy(password_in, &email).map_err(|e| anyhow::anyhow!("password: {e:?}"))?;
    let hash = password::hash(password_in)?;
    db::add_verified_account(pool, &email, &hash).await
}

/// Every role name this deployment has, in order
pub async fn roles(pool: &PgPool) -> anyhow::Result<Vec<String>> {
    db::role_names(pool).await
}

/// Adds a role; `false`: it was there already
pub async fn add_role(pool: &PgPool, role: &str) -> anyhow::Result<bool> {
    db::add_role(pool, role).await
}

/// Deletes a role with its grants (and, with the `permissions` feature, its
/// permissions); `false`: there was none
pub async fn delete_role(pool: &PgPool, role: &str) -> anyhow::Result<bool> {
    db::delete_role(pool, role).await
}

/// Takes `role` from an account; `false`: it did not have it
pub async fn revoke_role(pool: &PgPool, user_id: Uuid, role: &str) -> anyhow::Result<bool> {
    db::revoke_role(pool, user_id, role).await
}

#[cfg(test)]
#[path = "api_test.rs"]
mod tests;

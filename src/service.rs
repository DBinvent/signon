//! [service] Service accounts (feature `service-accounts`, the table in
//! `schema_service.yaml`): a program's account, not a person's, mapped to the PostgreSQL role
//! it uses - ytproxy connects as that role, and labac applies to it as to a person
//! ([`ServiceAccount::subject`]). Three ways in, each switched on by signon's configuration
//! ([`ServiceConfig`]):
//!
//! - **OAuth2 client credentials:** the account's name is the client id, a secret signon
//!   makes (shown once, kept hashed, rotated by making another) the client secret; `POST
//!   /token` (`grant_type=client_credentials`) answers a short JWT ([`issue`]);
//! - **an API key:** made by signon, shown once, kept hashed ([`by_api_key`]);
//! - **a PostgreSQL password:** an admin's, kept as an argon2 hash, checked by ytproxy when the
//!   program signs in to PostgreSQL through it ([`by_pg_password`]).

use std::time::Duration;

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Form, Json, Router};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::AccountState;

/// [service] Which ways in are on, and the token's key: everything off unless set
#[derive(Debug, Clone, Default)]
pub struct ServiceConfig {
    pub client_credentials: bool,
    pub api_keys: bool,
    pub pg_passwords: bool,
    /// the HS256 key the client-credentials token is signed with
    pub token_key: Option<Vec<u8>>,
    /// how long that token lasts (an hour unless set)
    pub token_ttl: Option<Duration>,
}

/// [service] A service account
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::FromRow)]
pub struct ServiceAccount {
    pub id: Uuid,
    /// its name, and its OAuth2 client id
    pub name: String,
    /// the PostgreSQL role it uses
    pub pg_role: String,
    /// its ABAC groups, for labac, as a JSON array
    pub groups: String,
    pub enabled: bool,
}

impl ServiceAccount {
    /// the groups it is in
    pub fn group_list(&self) -> Vec<String> {
        serde_json::from_str(&self.groups).unwrap_or_default()
    }

    /// [service] labac's subject of it: its groups, its PostgreSQL role, no labels, version 1
    #[cfg(feature = "labac")]
    pub fn subject(&self) -> crate::labac::Subject {
        crate::labac::Subject { user_id: self.id, groups: self.group_list().into_iter().collect(), version: 1,
            pg_roles: vec![self.pg_role.clone()], ..Default::default() }
    }
}

const COLUMNS: &str = "id, name, pg_role, groups, enabled";

/// [service] A service account made: enabled, with no way in until one is set
pub async fn create(pool: &PgPool, name: &str, pg_role: &str, groups: &[String]) -> anyhow::Result<ServiceAccount> {
    anyhow::ensure!(!name.trim().is_empty() && !name.contains(':'), "a service account name, with no ':' in it");
    anyhow::ensure!(!pg_role.trim().is_empty(), "the PostgreSQL role the account uses");
    Ok(sqlx::query_as::<_, ServiceAccount>(sqlx::AssertSqlSafe(format!(
        "INSERT INTO service_accounts (name, pg_role, groups) VALUES ($1, $2, $3) RETURNING {COLUMNS}")))
        .bind(name).bind(pg_role).bind(serde_json::to_string(groups)?).fetch_one(pool).await?)
}

/// [service] An account by its name
pub async fn by_name(pool: &PgPool, name: &str) -> anyhow::Result<Option<ServiceAccount>> {
    Ok(sqlx::query_as::<_, ServiceAccount>(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM service_accounts WHERE name = $1"))).bind(name).fetch_optional(pool).await?)
}

/// [service] Every enabled account, by name: what ytproxy's labac reads its subjects from
pub async fn all_enabled(pool: &PgPool) -> anyhow::Result<Vec<ServiceAccount>> {
    Ok(sqlx::query_as::<_, ServiceAccount>(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM service_accounts WHERE enabled ORDER BY name"))).fetch_all(pool).await?)
}

/// [service] An account switched on or off: off, no way in answers for it - [review 2026-11-21]
/// and no token issued before it either ([`current`])
pub async fn set_enabled(pool: &PgPool, id: Uuid, enabled: bool) -> anyhow::Result<bool> {
    Ok(sqlx::query("UPDATE service_accounts SET enabled = $2, rotated_at = now() WHERE id = $1").bind(id).bind(enabled)
        .execute(pool).await?.rows_affected() == 1)
}

/// [service] A new client secret for `id`, the one before no more: shown here once
pub async fn rotate_client_secret(pool: &PgPool, id: Uuid) -> anyhow::Result<String> {
    let secret = crate::token::secret();
    let n = sqlx::query("UPDATE service_accounts SET secret_hash = $2, rotated_at = now() WHERE id = $1")
        .bind(id).bind(crate::token::hash(&secret)).execute(pool).await?.rows_affected();
    anyhow::ensure!(n == 1, "no such service account");
    Ok(secret)
}

/// [service] A new API key for `id`, the one before no more: shown here once
pub async fn rotate_api_key(pool: &PgPool, id: Uuid) -> anyhow::Result<String> {
    let key = format!("sk_{}", crate::token::secret());
    let n = sqlx::query("UPDATE service_accounts SET api_key_hash = $2, rotated_at = now() WHERE id = $1")
        .bind(id).bind(crate::token::hash(&key)).execute(pool).await?.rows_affected();
    anyhow::ensure!(n == 1, "no such service account");
    Ok(key)
}

/// [service] The PostgreSQL password `id` signs in with through ytproxy
pub async fn set_pg_password(pool: &PgPool, id: Uuid, password: &str) -> anyhow::Result<()> {
    anyhow::ensure!(password.len() >= 12, "a service account password of at least 12 characters");
    let n = sqlx::query("UPDATE service_accounts SET pg_password_hash = $2, rotated_at = now() WHERE id = $1")
        .bind(id).bind(crate::password::hash(password)?).execute(pool).await?.rows_affected();
    anyhow::ensure!(n == 1, "no such service account");
    Ok(())
}

/// [service] The enabled account whose client id and secret these are
pub async fn by_client_credentials(pool: &PgPool, client_id: &str, secret: &str) -> anyhow::Result<Option<ServiceAccount>> {
    Ok(sqlx::query_as::<_, ServiceAccount>(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM service_accounts WHERE name = $1 AND secret_hash = $2 AND enabled")))
        .bind(client_id).bind(crate::token::hash(secret)).fetch_optional(pool).await?)
}

/// [service] The enabled account an API key is
pub async fn by_api_key(pool: &PgPool, key: &str) -> anyhow::Result<Option<ServiceAccount>> {
    if !key.starts_with("sk_") {
        return Ok(None);
    }
    Ok(sqlx::query_as::<_, ServiceAccount>(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM service_accounts WHERE api_key_hash = $1 AND enabled")))
        .bind(crate::token::hash(key)).fetch_optional(pool).await?)
}

/// [service] The enabled account `name` signing in to PostgreSQL with `password`: ytproxy's
/// check; a wrong name costs the same time as a wrong password
pub async fn by_pg_password(pool: &PgPool, name: &str, password: &str) -> anyhow::Result<Option<ServiceAccount>> {
    let row: Option<(Uuid, Option<String>)> = sqlx::query_as("SELECT id, pg_password_hash FROM service_accounts WHERE name = $1 AND enabled")
        .bind(name).fetch_optional(pool).await?;
    let hash = row.as_ref().and_then(|(_, h)| h.clone());
    let ok = crate::password::verify(password, hash.as_deref().unwrap_or(crate::password::dummy_hash()));
    if !ok || hash.is_none() {
        return Ok(None);
    }
    by_name(pool, name).await
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TokenClaims {
    sub: String,
    name: String,
    role: String,
    groups: Vec<String>,
    iat: i64,
    exp: i64,
}

/// [service] The client-credentials token of `a`, valid `ttl`
pub fn issue(key: &[u8], a: &ServiceAccount, ttl: Duration) -> anyhow::Result<String> {
    crate::jwt_backend();
    let now = chrono::Utc::now().timestamp();
    let c = TokenClaims { sub: a.id.to_string(), name: a.name.clone(), role: a.pg_role.clone(), groups: a.group_list(),
        iat: now, exp: now + ttl.as_secs().max(1) as i64 };
    let key = jsonwebtoken::EncodingKey::from_secret(key).map_err(|e| anyhow::anyhow!("service token key: {e}"))?;
    jsonwebtoken::encode(&jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256), &c, &key)
        .map_err(|e| anyhow::anyhow!("service token: {e}"))
}

/// [service] What a client-credentials token says: the account's id, name, role and groups
pub fn verify(key: &[u8], token: &str) -> anyhow::Result<ServiceAccount> {
    crate::jwt_backend();
    Ok(claims(key, token)?.0)
}

/// the token's account as it says it, and when it was issued
fn claims(key: &[u8], token: &str) -> anyhow::Result<(ServiceAccount, i64)> {
    let mut v = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
    v.required_spec_claims = ["exp", "sub"].iter().map(|s| s.to_string()).collect();
    // [review 2026-11-21] a few seconds of clock skew, not jsonwebtoken's minute
    v.leeway = 5;
    let key = jsonwebtoken::DecodingKey::from_secret(key).map_err(|e| anyhow::anyhow!("service token key: {e}"))?;
    let c = jsonwebtoken::decode::<TokenClaims>(token, &key, &v).map_err(|e| anyhow::anyhow!("service token: {e}"))?.claims;
    Ok((ServiceAccount { id: Uuid::parse_str(&c.sub)?, name: c.name, pg_role: c.role, groups: serde_json::to_string(&c.groups)?,
        enabled: true }, c.iat))
}

/// [service] [review 2026-11-21] What a token's account is now: the token signed and not
/// expired, its account enabled, the token issued after the account's last rotation or switch -
/// and the role and groups as they are now, not as the token says them. `None` else.
pub async fn current(pool: &PgPool, key: &[u8], token: &str) -> anyhow::Result<Option<ServiceAccount>> {
    let Ok((said, iat)) = claims(key, token) else { return Ok(None) };
    // the rotation's whole second: a token of that second stands (JWT times are seconds)
    let row: Option<(Option<i64>,)> = sqlx::query_as("SELECT floor(extract(epoch from rotated_at))::bigint FROM service_accounts \
        WHERE id = $1 AND enabled").bind(said.id).fetch_optional(pool).await?;
    match row {
        Some((rotated,)) if rotated.is_none_or(|r| iat >= r) => Ok(sqlx::query_as::<_, ServiceAccount>(sqlx::AssertSqlSafe(format!(
            "SELECT {COLUMNS} FROM service_accounts WHERE id = $1"))).bind(said.id).fetch_optional(pool).await?),
        _ => Ok(None),
    }
}

/// [service] the tokens a client id may ask for in five minutes
const TOKEN_PER_CLIENT: usize = 60;

/// [service] `/token`, when client credentials are on
pub(crate) fn routes() -> Router<AccountState> {
    Router::new().route("/token", post(token))
}

#[derive(Debug, Deserialize)]
pub(crate) struct TokenForm {
    grant_type: String,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    client_secret: Option<String>,
}

/// the client id and secret of HTTP Basic, the way RFC 6749 sends them
fn basic(headers: &HeaderMap) -> Option<(String, String)> {
    use base64::Engine;
    let v = headers.get(header::AUTHORIZATION)?.to_str().ok()?.strip_prefix("Basic ")?;
    let raw = base64::engine::general_purpose::STANDARD.decode(v.trim()).ok()?;
    let (id, secret) = std::str::from_utf8(&raw).ok()?.split_once(':')?;
    Some((id.to_string(), secret.to_string()))
}

fn oauth_error(status: StatusCode, error: &str) -> Response {
    (status, Json(serde_json::json!({ "error": error }))).into_response()
}

/// [service] RFC 6749 4.4: client credentials in, a bearer token out
async fn token(State(state): State<AccountState>, headers: HeaderMap, Form(f): Form<TokenForm>) -> Response {
    let cfg = &state.config.service;
    let Some(key) = cfg.token_key.as_deref().filter(|_| cfg.client_credentials) else {
        return oauth_error(StatusCode::NOT_FOUND, "unsupported_grant_type");
    };
    if f.grant_type != "client_credentials" {
        return oauth_error(StatusCode::BAD_REQUEST, "unsupported_grant_type");
    }
    let Some((id, secret)) = basic(&headers).or_else(|| f.client_id.clone().zip(f.client_secret.clone())) else {
        return oauth_error(StatusCode::UNAUTHORIZED, "invalid_client");
    };
    // [review 2026-11-21] as a sign-in is: a client id asking too often is turned away
    if !state.limiter.check(&format!("token:id:{id}"), TOKEN_PER_CLIENT, Duration::from_secs(300)) {
        return oauth_error(StatusCode::TOO_MANY_REQUESTS, "slow_down");
    }
    let a = match by_client_credentials(&state.pool, &id, &secret).await {
        Ok(Some(a)) => a,
        Ok(None) => return oauth_error(StatusCode::UNAUTHORIZED, "invalid_client"),
        Err(e) => {
            tracing::error!(%e, "service token");
            return oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
        }
    };
    let ttl = cfg.token_ttl.unwrap_or(Duration::from_secs(3600));
    match issue(key, &a, ttl) {
        Ok(t) => (StatusCode::OK, [(header::CACHE_CONTROL, "no-store")],
            Json(serde_json::json!({ "access_token": t, "token_type": "Bearer", "expires_in": ttl.as_secs() }))).into_response(),
        Err(e) => {
            tracing::error!(%e, "service token");
            oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error")
        }
    }
}

#[cfg(test)]
#[path = "service_test.rs"]
mod tests;

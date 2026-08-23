//! Request-scoped identity.
//!
//! `CurrentUser` re-reads the account and its roles from the database on every
//! request. That is deliberate and is the main reason this crate does not use
//! JWTs: a suspension, a role revocation, or a "sign out everywhere" takes
//! effect on the next request rather than whenever a signed blob happens to
//! expire.

use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use axum_extra::extract::cookie::CookieJar;
use serde_json::json;
use uuid::Uuid;

use crate::{db, token, AccountState};

/// Cookie carrying the session token. Not the session id — the id is a stable
/// handle for revocation, the token is the secret (see `token.rs`).
pub const SESSION_COOKIE: &str = "um_session";

#[derive(Debug, Clone)]
pub struct CurrentUser {
    pub id: Uuid,
    pub email: String,
    pub display_name: Option<String>,
    pub email_verified: bool,
    pub roles: Vec<String>,
    /// The session this request arrived on — needed to spare it when the user
    /// signs out their other devices.
    pub session_id: Uuid,
}

impl CurrentUser {
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }

    /// `Err` is already a `403` response, so a handler can `user.require_role("admin")?`.
    pub fn require_role(&self, role: &str) -> Result<(), Response> {
        if self.has_role(role) {
            Ok(())
        } else {
            Err((StatusCode::FORBIDDEN, Json(json!({ "error": "forbidden" }))).into_response())
        }
    }
}

/// Rejection for a missing, expired, unverified or suspended session. One
/// shape, like every other credential failure in the crate.
pub struct AuthRejection;

impl IntoResponse for AuthRejection {
    fn into_response(self) -> Response {
        (StatusCode::UNAUTHORIZED, Json(json!({ "error": "invalid credentials" }))).into_response()
    }
}

async fn resolve<S>(parts: &mut Parts, state: &S) -> Option<CurrentUser>
where
    AccountState: FromRef<S>,
    S: Send + Sync,
{
    let state = AccountState::from_ref(state);
    let jar = CookieJar::from_headers(&parts.headers);
    let raw = jar.get(SESSION_COOKIE)?.value().to_string();

    let (session_id, user_id) = match db::touch_session(&state.pool, &token::hash(&raw)).await {
        Ok(Some(pair)) => pair,
        Ok(None) => return None,
        Err(e) => {
            tracing::error!(%e, "touch_session");
            return None;
        }
    };

    let user = match db::find_user_by_id(&state.pool, user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => return None,
        Err(e) => {
            tracing::error!(%e, "find_user_by_id");
            return None;
        }
    };

    // A session that outlived its account`s good standing is not a session.
    if user.suspended || !user.email_verified {
        return None;
    }

    let roles = match db::roles_for_user(&state.pool, user.id).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(%e, "roles_for_user");
            return None;
        }
    };

    Some(CurrentUser {
        id: user.id,
        email: user.email,
        display_name: user.display_name,
        email_verified: user.email_verified,
        roles,
        session_id,
    })
}

impl<S> FromRequestParts<S> for CurrentUser
where
    AccountState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AuthRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        resolve(parts, state).await.ok_or(AuthRejection)
    }
}

/// For routes that behave differently when signed in but do not require it —
/// the OAuth start route uses it to tell "link a provider to my account" from
/// "sign in with this provider".
pub struct OptionalUser(pub Option<CurrentUser>);

impl<S> FromRequestParts<S> for OptionalUser
where
    AccountState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Ok(OptionalUser(resolve(parts, state).await))
    }
}

/// Client address and user agent, for the session list and the audit trail.
///
/// `CF-Connecting-IP` and `X-Forwarded-For` are attacker-controlled in
/// general. They are trusted here only because every one of these services
/// binds loopback and the sole path in is the Cloudflare tunnel, which
/// rewrites both. If one of them is ever exposed directly, this has to become
/// a `ConnectInfo<SocketAddr>` read instead.
pub struct RequestMeta {
    pub ip: Option<String>,
    pub user_agent: Option<String>,
}

impl RequestMeta {
    pub(crate) fn from_parts(parts: &Parts) -> Self {
        let header = |name: &str| {
            parts
                .headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        };
        let ip = header("cf-connecting-ip").or_else(|| {
            header("x-forwarded-for")
                .and_then(|v| v.split(',').next().map(|s| s.trim().to_string()))
                .filter(|s| !s.is_empty())
        });
        Self {
            ip: ip.map(|s| truncate(s, 64)),
            user_agent: header("user-agent").map(|s| truncate(s, 256)),
        }
    }

    pub(crate) fn ip_key(&self) -> String {
        self.ip.clone().unwrap_or_else(|| "unknown".to_string())
    }
}

impl<S: Send + Sync> FromRequestParts<S> for RequestMeta {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(RequestMeta::from_parts(parts))
    }
}

/// Cuts to a byte budget without splitting a UTF-8 character — the columns
/// these land in are `varchar`, and a client controls the value.
fn truncate(mut s: String, max: usize) -> String {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s.truncate(end);
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_respects_char_boundaries() {
        // 'é' is two bytes, so a cut at 5 must fall back to 4.
        assert_eq!(truncate("aaaaé".to_string(), 5), "aaaa");
        assert_eq!(truncate("abc".to_string(), 5), "abc");
    }

    #[test]
    fn meta_prefers_cf_header_and_takes_first_forwarded_hop() {
        let (parts, _) = axum::http::Request::builder()
            .header("x-forwarded-for", "203.0.113.7, 10.0.0.1")
            .header("user-agent", "curl/8")
            .body(())
            .unwrap()
            .into_parts();
        let meta = RequestMeta::from_parts(&parts);
        assert_eq!(meta.ip.as_deref(), Some("203.0.113.7"));
        assert_eq!(meta.user_agent.as_deref(), Some("curl/8"));

        let (parts, _) = axum::http::Request::builder()
            .header("cf-connecting-ip", "198.51.100.9")
            .header("x-forwarded-for", "203.0.113.7")
            .body(())
            .unwrap()
            .into_parts();
        assert_eq!(RequestMeta::from_parts(&parts).ip.as_deref(), Some("198.51.100.9"));
    }
}

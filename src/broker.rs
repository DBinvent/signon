//! Sign-in federated through a separate SSO service (feature `sso-broker`).
//!
//! A site federated this way does not run any sign-in protocol
//! itself: its `/sso/*` paths are forwarded to the SSO service, which
//! talks to Google, Apple, a customer's Entra ID, … and ends every sign-in by
//! sending the browser back here with a one-time **ticket**.
//! This module is this site's half:
//!
//! * `POST /account/sso/finish {ticket}` redeems the ticket over the internal
//!   API — with this site's own key, and the browser-binding cookie the SSO
//!   service set when the sign-in started, so a ticket minted for another
//!   site or another browser is worthless here;
//! * the identity is matched to a profile — a linked identity, or an address
//!   the provider (or the customer's verified domain) vouches for — and when
//!   there is **no profile** the person is asked before one is created. An
//!   address nobody vouches for (Amazon, Facebook) or one the person typed
//!   on a customer connection's button never enters an existing profile; a
//!   profile created from a sign-in that has no vouched address has none
//!   (`users.email` NULL). There is no mailed-code step here: that is the
//!   in-process flow's (`routes.rs`);
//! * the provider list, home-realm discovery and SSO enforcement are asked
//!   of the SSO service (cached; a stale answer is kept while it is away).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::current_user::{OptionalUser, RequestMeta};
use crate::routes::{
    account_json, bad_request, browser_mark, credential_error, internal_error, normalize_email, registered_here,
    start_session, too_many, yes,
};
use crate::{db, token, AccountState, BoxFut};

/// The cookie the SSO service sets when a sign-in starts (through this
/// site's `/sso/*` forward, so it is this site's cookie) and this site hands
/// back when redeeming the ticket. Cleared once used.
pub const BIND_COOKIE: &str = "ta_sso_bind";

const CACHE_TTL: Duration = Duration::from_secs(60);
/// How long a cached answer is still used while the SSO service is away.
const STALE_TTL: Duration = Duration::from_secs(3600);
/// How long a "Create profile?" question stays answerable.
const CREATE_TTL_MIN: i64 = 15;
const FINISH_PER_IP: usize = 30;

/// What the SSO service vouches for after a verified sign-in.
#[derive(Debug, Clone, Deserialize)]
pub struct BrokerIdentity {
    /// `oauth` (a social provider) or `sso` (a customer connection).
    pub kind: String,
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub provider_name: Option<String>,
    #[serde(default)]
    pub connection_id: Option<Uuid>,
    #[serde(default)]
    pub connection_name: Option<String>,
    /// The connection owner in dash's database — for dash's JIT team
    /// membership. A plain uuid: it lives in another service.
    #[serde(default)]
    pub connection_owner: Option<Uuid>,
    pub subject: String,
    #[serde(default)]
    pub email: Option<String>,
    /// For `sso` with an address the IdP reported, always true — the SSO
    /// service only issues a ticket for an address inside one of the
    /// connection's verified domains.
    pub email_verified: bool,
    /// `sso` only: the IdP reported no address, so `email` is the one the
    /// person typed on the custom-SSO button — inside one of the
    /// connection's verified domains, but typed, not asserted by the IdP. It
    /// may create a profile at that address, never enter an existing one.
    #[serde(default)]
    pub email_typed: bool,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub redirect_to: Option<String>,
    #[serde(default)]
    pub session_max_hours: Option<u32>,
}

/// A domain that must sign in through its customer connection.
#[derive(Debug, Clone, Deserialize)]
pub struct Enforced {
    pub connection: String,
    pub href: String,
}

/// What a site's hook learns about a brokered sign-in.
#[derive(Debug, Clone)]
pub struct SignIn {
    pub user_id: Uuid,
    /// The account's address — `None` for an account that has none.
    pub email: Option<String>,
    /// `oauth:<provider>` or `sso:<connection id>`.
    pub via: String,
    pub connection_id: Option<Uuid>,
    pub connection_owner: Option<Uuid>,
    /// The profile was created by this sign-in.
    pub created: bool,
}

/// A site's own policy around a brokered sign-in — dash uses it for JIT team
/// membership. Errors are logged and never undo the sign-in.
pub trait BrokerHooks: Send + Sync + 'static {
    fn after_sso_sign_in<'a>(&'a self, _sign_in: &'a SignIn) -> BoxFut<'a, anyhow::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

pub(crate) struct NoHooks;
impl BrokerHooks for NoHooks {}

type Cached<T> = Mutex<Option<(Instant, T)>>;

/// The SSO service, as this site reaches it: loopback URL plus this site's
/// own key (the key is how the service knows which site is calling).
pub struct BrokerClient {
    base_url: String,
    key: String,
    http: reqwest::Client,
    providers: Cached<Value>,
    enforced: Mutex<HashMap<String, (Instant, Option<Enforced>)>>,
}

impl BrokerClient {
    pub fn new(base_url: impl Into<String>, key: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            key: key.into(),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            providers: Mutex::new(None),
            enforced: Mutex::new(HashMap::new()),
        }
    }

    /// `SSO_BROKER_URL` + `SSO_BROKER_KEY`, or `None` when either is unset.
    pub fn from_env() -> Option<Self> {
        let url = std::env::var("SSO_BROKER_URL").ok().filter(|s| !s.is_empty())?;
        let key = std::env::var("SSO_BROKER_KEY").ok().filter(|s| !s.is_empty())?;
        Some(Self::new(url, key))
    }

    async fn get(&self, path: &str, query: &[(&str, &str)]) -> anyhow::Result<reqwest::Response> {
        Ok(self
            .http
            .get(format!("{}{path}", self.base_url))
            .query(query)
            .bearer_auth(&self.key)
            .send()
            .await?)
    }

    async fn post(&self, path: &str, body: &Value) -> anyhow::Result<reqwest::Response> {
        Ok(self
            .http
            .post(format!("{}{path}", self.base_url))
            .bearer_auth(&self.key)
            .json(body)
            .send()
            .await?)
    }

    /// `{providers: [{key, name, href}], custom_sso, global_sso}`, cached a
    /// minute and kept for an hour while the SSO service cannot be reached.
    /// `custom_sso`: show the custom SSO button on this site; `global_sso`:
    /// some provider is on for any site, so customer SSO may be set up.
    pub async fn providers(&self) -> anyhow::Result<Value> {
        if let Some((at, v)) = self.providers.lock().unwrap_or_else(|p| p.into_inner()).as_ref() {
            if at.elapsed() < CACHE_TTL {
                return Ok(v.clone());
            }
        }
        let fresh = async {
            let r = self.get("/internal/providers", &[]).await?.error_for_status()?;
            anyhow::Ok(r.json::<Value>().await?)
        }
        .await;
        let mut cache = self.providers.lock().unwrap_or_else(|p| p.into_inner());
        match fresh {
            Ok(v) => {
                *cache = Some((Instant::now(), v.clone()));
                Ok(v)
            }
            Err(e) => match cache.as_ref() {
                Some((at, v)) if at.elapsed() < STALE_TTL => {
                    tracing::warn!(%e, "SSO service unreachable; serving the cached provider list");
                    Ok(v.clone())
                }
                _ => Err(e),
            },
        }
    }

    pub async fn discover(&self, email: &str, redirect_to: Option<&str>) -> anyhow::Result<Value> {
        let r = self
            .post("/internal/discover", &json!({ "email": email, "redirect_to": redirect_to }))
            .await?
            .error_for_status()?;
        Ok(r.json().await?)
    }

    /// Whether `email`'s domain enforces SSO — the domain only, never an
    /// account. Cached per domain for a minute; while the SSO service is
    /// away the last answer is kept for an hour, and a domain never asked
    /// about before is treated as not enforced (logged).
    pub async fn enforced(&self, email: &str) -> Option<Enforced> {
        let domain = crate::sso::domain_of(email)?.to_string();
        if let Some((at, v)) = self.enforced.lock().unwrap_or_else(|p| p.into_inner()).get(&domain) {
            if at.elapsed() < CACHE_TTL {
                return v.clone();
            }
        }
        #[derive(Deserialize)]
        struct Answer {
            enforced: bool,
            #[serde(default)]
            connection: Option<String>,
            #[serde(default)]
            href: Option<String>,
        }
        let fresh = async {
            let r = self.get("/internal/enforced", &[("email", email)]).await?.error_for_status()?;
            anyhow::Ok(r.json::<Answer>().await?)
        }
        .await;
        let mut cache = self.enforced.lock().unwrap_or_else(|p| p.into_inner());
        match fresh {
            Ok(a) => {
                let v = a.enforced.then(|| Enforced {
                    connection: a.connection.unwrap_or_default(),
                    href: a.href.unwrap_or_default(),
                });
                cache.insert(domain, (Instant::now(), v.clone()));
                v
            }
            Err(e) => match cache.get(&domain) {
                Some((at, v)) if at.elapsed() < STALE_TTL => v.clone(),
                _ => {
                    tracing::warn!(%e, %domain, "SSO service unreachable; enforcement unknown for this domain");
                    None
                }
            },
        }
    }

    /// Spends a ticket. `Ok(None)` for every refusal (unknown, spent,
    /// expired, another site's, another browser's) — one shape.
    pub async fn redeem(&self, ticket: &str, binding: &str) -> anyhow::Result<Option<BrokerIdentity>> {
        let r = self
            .post("/internal/tickets/redeem", &json!({ "ticket": ticket, "binding": binding }))
            .await?;
        if r.status() == reqwest::StatusCode::UNAUTHORIZED || r.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        Ok(Some(r.error_for_status()?.json().await?))
    }
}

/// The 403 for an address whose domain must use its connection. Decided
/// from the domain alone, so it reads the same with or without an account.
pub(crate) fn sso_required(e: &Enforced) -> Response {
    (
        StatusCode::FORBIDDEN,
        // `error` is the state a client switches on; its code and its sentence are beside it
        Json({
            let (code, message) = crate::i18n::error_in(crate::i18n::current(), "err-sso-required", &[]);
            json!({ "error": "sso required", "code": code, "message": message, "connection": e.connection, "href": e.href })
        }),
    )
        .into_response()
}

pub(crate) async fn enforcement_refusal(state: &AccountState, email: &str) -> Option<Response> {
    let broker = state.broker.as_ref()?;
    broker.enforced(email).await.map(|e| sso_required(&e))
}

pub(crate) fn routes() -> Router<AccountState> {
    Router::new()
        .route("/sso/discover", post(discover))
        .route("/sso/finish", post(finish))
        .route("/sso/create-profile", post(create_profile))
}

fn not_federated() -> Response {
    (StatusCode::NOT_FOUND, Json(crate::i18n::error_body("err-not-found", &[]))).into_response()
}

#[derive(Deserialize)]
struct DiscoverReq {
    email: String,
    #[serde(default)]
    redirect_to: Option<String>,
}

async fn discover(State(state): State<AccountState>, meta: RequestMeta, Json(req): Json<DiscoverReq>) -> Response {
    let Some(broker) = state.broker.as_ref() else { return not_federated() };
    if !state
        .limiter
        .check(&format!("sso:ip:{}", meta.ip_key()), 30, Duration::from_secs(300))
    {
        return too_many().into_response();
    }
    let Some(email) = normalize_email(&req.email) else {
        return bad_request("err-invalid-email").into_response();
    };
    match broker.discover(&email, req.redirect_to.as_deref()).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => {
            tracing::warn!(%e, "SSO discovery");
            (StatusCode::BAD_GATEWAY, Json(crate::i18n::error_body("err-sso-unavailable", &[]))).into_response()
        }
    }
}

#[derive(Deserialize)]
struct TicketReq {
    ticket: String,
}

/// `<connection id>:<subject>`; a subject too long for the column becomes
/// its hash — stable, still unique per connection. The same key the
/// in-process flow used, so identities carry over.
pub(crate) fn connection_identity_key(connection: Uuid, subject: &str) -> String {
    if subject.len() <= 150 {
        format!("{connection}:{subject}")
    } else {
        let hex: String = Sha256::digest(subject.as_bytes()).iter().map(|b| format!("{b:02x}")).collect();
        format!("{connection}:h:{hex}")
    }
}

/// How a brokered identity is stored and labelled here.
struct Shape {
    provider: String,
    subject: String,
    via: String,
    label: String,
    oauth: bool,
}

fn shape(i: &BrokerIdentity) -> Option<Shape> {
    match (i.kind.as_str(), i.connection_id, i.provider.as_deref()) {
        ("sso", Some(conn), _) => Some(Shape {
            provider: "sso".into(),
            subject: connection_identity_key(conn, &i.subject),
            via: format!("sso:{conn}"),
            label: i.connection_name.clone().unwrap_or_else(|| "single sign-on".into()),
            oauth: false,
        }),
        ("oauth", _, Some(p)) if crate::oauth::provider_by_key(p).is_some() => Some(Shape {
            provider: p.to_string(),
            subject: i.subject.clone(),
            via: format!("oauth:{p}"),
            label: i.provider_name.clone().unwrap_or_else(|| p.to_string()),
            oauth: true,
        }),
        _ => None,
    }
}

fn remove_bind_cookie(state: &AccountState, jar: CookieJar) -> CookieJar {
    let mut c = Cookie::new(BIND_COOKIE, "");
    c.set_path("/");
    c.set_http_only(true);
    c.set_secure(state.config.secure_cookies);
    c.set_same_site(SameSite::Lax);
    c.make_removal();
    jar.add(c)
}

async fn finish(
    State(state): State<AccountState>,
    jar: CookieJar,
    meta: RequestMeta,
    OptionalUser(current): OptionalUser,
    Json(req): Json<TicketReq>,
) -> Response {
    let Some(broker) = state.broker.clone() else { return not_federated() };
    if !state
        .limiter
        .check(&format!("finish:ip:{}", meta.ip_key()), FINISH_PER_IP, Duration::from_secs(300))
    {
        return too_many().into_response();
    }
    let binding = jar.get(BIND_COOKIE).map(|c| c.value().to_string()).unwrap_or_default();
    let jar = remove_bind_cookie(&state, jar);
    let identity = match broker.redeem(req.ticket.trim(), &binding).await {
        Ok(Some(i)) => i,
        Ok(None) => return (jar, credential_error()).into_response(),
        Err(e) => {
            tracing::error!(%e, "redeem SSO ticket");
            return (jar, (StatusCode::BAD_GATEWAY, Json(crate::i18n::error_body("err-sso-unavailable", &[])))).into_response();
        }
    };
    let Some(sh) = shape(&identity) else {
        tracing::warn!(kind = %identity.kind, "SSO ticket with an unusable identity");
        return (jar, credential_error()).into_response();
    };
    let redirect_to = crate::routes::safe_redirect(identity.redirect_to.as_deref());
    let cap = identity.session_max_hours.map(|h| Duration::from_secs(u64::from(h) * 3600));

    // 1. Already linked: sign in.
    match db::find_user_by_identity(&state.pool, &sh.provider, &sh.subject).await {
        Ok(Some(user_id)) => {
            let user = match db::find_user_by_id(&state.pool, user_id).await {
                Ok(Some(u)) if !u.suspended => u,
                Ok(_) => return (jar, credential_error()).into_response(),
                Err(e) => {
                    tracing::error!(%e, "find_user_by_id");
                    return (jar, internal_error()).into_response();
                }
            };
            // A provider identity linked long ago must not become the way
            // around a domain that now enforces its connection. An account
            // with no address belongs to no domain.
            if sh.oauth {
                if let Some(r) = enforcement_for(&state, user.email.as_deref()).await {
                    return (jar, r).into_response();
                }
            }
            return signed_in(&state, jar, &meta, &sh, &identity, user_id, user.email.as_deref(), cap, redirect_to, false).await;
        }
        Ok(None) => {}
        Err(e) => {
            tracing::error!(%e, "find_user_by_identity");
            return (jar, internal_error()).into_response();
        }
    }

    // 2. Already signed in here — the account page's "Connect": a provider
    // identity joins this account, whatever address it asserts, as the
    // in-process flow's link does. The SSO service cannot know who is
    // signed in on this site; this browser can, and the ticket is bound to
    // it. Provider identities only: a customer connection's identity is
    // placed by its verified domain, never by whoever is signed in.
    if sh.oauth {
        if let Some(me) = current {
            if let Some(r) = enforcement_for(&state, me.email.as_deref()).await {
                return (jar, r).into_response();
            }
            if let Err(e) = db::link_identity(&state.pool, me.id, &sh.provider, &sh.subject, identity.email.as_deref(), None).await {
                tracing::error!(%e, "link provider to the signed-in account");
                return (jar, internal_error()).into_response();
            }
            return signed_in(&state, jar, &meta, &sh, &identity, me.id, me.email.as_deref(), cap, redirect_to, false).await;
        }
    }

    let email = identity.email.as_deref().and_then(normalize_email);
    // Asked of any address a provider reports, vouched for or not — the
    // answer depends on the domain alone, as it always has.
    if sh.oauth {
        if let Some(r) = enforcement_for(&state, email.as_deref()).await {
            return (jar, r).into_response();
        }
    }

    // 3./4. Which address, if any, this sign-in may enter or create a
    // profile by.
    let address = if sh.oauth {
        match email {
            Some(e) if identity.email_verified => Address::Proven(e),
            // Amazon and Facebook report an address they do not vouch for;
            // GitHub-style providers may report none. No mailed code here:
            // the profile is created with no address, and a reported one is
            // kept on the identity row for display only. Putting an
            // unvouched address on users.email would let a later *vouched*
            // sign-in at that address (Google, a customer connection) merge
            // into an account someone else created.
            reported => Address::None { reported },
        }
    } else if identity.email_typed {
        match email {
            Some(e) => Address::Typed(e),
            None => Address::None { reported: None },
        }
    } else {
        match email {
            Some(e) if identity.email_verified => Address::Proven(e),
            // The SSO service never asserts an address it does not vouch for.
            Some(_) => return (jar, credential_error()).into_response(),
            None => Address::None { reported: None },
        }
    };

    match &address {
        // A profile at that (proven) address: link and sign in.
        Address::Proven(email) => match db::find_user_by_email(&state.pool, email).await {
            Ok(Some(user)) => {
                if user.suspended {
                    return (jar, credential_error()).into_response();
                }
                if let Err(e) = link(&state, user.id, &sh, Some(email), identity.connection_id, !user.email_verified).await {
                    tracing::error!(%e, "link brokered identity");
                    return (jar, internal_error()).into_response();
                }
                return signed_in(&state, jar, &meta, &sh, &identity, user.id, Some(email), cap, redirect_to, false).await;
            }
            Ok(None) => {}
            Err(e) => {
                tracing::error!(%e, "find_user_by_email");
                return (jar, internal_error()).into_response();
            }
        },
        // Typed, not asserted: never a way into an account that exists — this
        // identity is not linked to it (step 1), and an address someone typed
        // proves nothing about who holds that account.
        Address::Typed(email) => match db::find_user_by_email(&state.pool, email).await {
            Ok(Some(_)) => return (jar, address_taken()).into_response(),
            Ok(None) => {}
            Err(e) => {
                tracing::error!(%e, "find_user_by_email");
                return (jar, internal_error()).into_response();
            }
        },
        Address::None { .. } => {}
    }

    // 5. No profile: ask.
    let secret = token::secret();
    let pending = db::NewPending {
        provider: &sh.provider,
        provider_user_id: &sh.subject,
        email: address.profile_email(),
        display_name: identity.name.as_deref(),
        redirect_to: redirect_to.as_deref(),
        email_proven: true,
        connection_id: identity.connection_id,
        connection_owner: identity.connection_owner,
        via: Some(&sh.via),
        label: Some(&sh.label),
        session_max_hours: identity.session_max_hours.map(|h| h as i32),
        email_typed: matches!(address, Address::Typed(_)),
        identity_email: match &address {
            Address::None { reported } => reported.as_deref(),
            _ => None,
        },
    };
    if let Err(e) = db::create_pending_identity(&state.pool, &token::hash(&secret), &pending).await {
        tracing::error!(%e, "create pending profile");
        return (jar, internal_error()).into_response();
    }
    (jar, Json(no_profile_body(&secret, address.profile_email(), identity.name.as_deref(), &sh.label, sh.oauth))).into_response()
}

/// What a brokered sign-in's address amounts to on this site.
enum Address {
    /// Vouched for by the provider, or asserted by a customer IdP inside a
    /// verified domain: enters the account at that address, or creates one.
    Proven(String),
    /// Typed on a customer connection's button because the IdP reported
    /// none: creates a profile at that address, never enters one.
    Typed(String),
    /// Nothing this site can trust: the profile gets no address. `reported`
    /// is what an `oauth` provider said without vouching, for the identity
    /// row only.
    None { reported: Option<String> },
}

impl Address {
    /// The address the profile is created with.
    fn profile_email(&self) -> Option<&str> {
        match self {
            Address::Proven(e) | Address::Typed(e) => Some(e),
            Address::None { .. } => None,
        }
    }
}

/// An address typed on a customer connection's button that already has an
/// account here. No session, no link: the person signs in to that account
/// some other way (and can connect the IdP from there).
fn address_taken() -> Response {
    (
        StatusCode::CONFLICT,
        Json(crate::i18n::error_body("err-account-exists", &[])),
    )
        .into_response()
}

/// Enforcement needs an address: one with none belongs to no domain.
async fn enforcement_for(state: &AccountState, email: Option<&str>) -> Option<Response> {
    enforcement_refusal(state, email?).await
}

pub(crate) fn no_profile_body(token: &str, email: Option<&str>, name: Option<&str>, label: &str, oauth: bool) -> Value {
    json!({
        "status": "no_profile",
        "token": token,
        // Null when the profile will have no address.
        "email": email,
        "name": name,
        "provider_name": oauth.then_some(label),
        "connection_name": (!oauth).then_some(label),
    })
}

async fn link(state: &AccountState, user_id: Uuid, sh: &Shape, email: Option<&str>, connection: Option<Uuid>, verify: bool) -> anyhow::Result<()> {
    db::link_identity(&state.pool, user_id, &sh.provider, &sh.subject, email, connection).await?;
    if verify {
        // The provider (or the customer's verified domain) just proved the
        // address, so an unconfirmed local account becomes confirmed.
        db::mark_email_verified(&state.pool, user_id).await?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn signed_in(
    state: &AccountState,
    jar: CookieJar,
    meta: &RequestMeta,
    sh: &Shape,
    identity: &BrokerIdentity,
    user_id: Uuid,
    email: Option<&str>,
    cap: Option<Duration>,
    redirect_to: Option<String>,
    created: bool,
) -> Response {
    let jar = match start_session(state, jar, user_id, meta, &sh.via, cap).await {
        Ok(j) => j,
        Err(e) => {
            tracing::error!(%e, "start_session after SSO");
            return internal_error().into_response();
        }
    };
    let sign_in = SignIn {
        user_id,
        email: email.map(str::to_string),
        via: sh.via.clone(),
        connection_id: identity.connection_id,
        connection_owner: identity.connection_owner,
        created,
    };
    if let Err(e) = state.broker_hooks.after_sso_sign_in(&sign_in).await {
        tracing::error!(%e, "after_sso_sign_in hook");
    }
    db::log_event_via(
        &state.pool,
        if sh.oauth { "oauth_login" } else { "sso_login" },
        Some(user_id),
        email,
        meta.ip.as_deref(),
        meta.user_agent.as_deref(),
        Some(&sh.via),
    )
    .await;
    ok_body(state, jar, user_id, redirect_to).await
}

pub(crate) async fn ok_body(state: &AccountState, jar: CookieJar, user_id: Uuid, redirect_to: Option<String>) -> Response {
    match account_json(state, user_id).await {
        Ok(Some(user)) => (
            jar,
            Json(json!({ "status": "ok", "user": user, "redirect_to": redirect_to.unwrap_or_else(|| "/".into()) })),
        )
            .into_response(),
        Ok(None) => credential_error().into_response(),
        Err(e) => {
            tracing::error!(%e, "load account after SSO");
            internal_error().into_response()
        }
    }
}

#[derive(Deserialize)]
struct CreateReq {
    token: String,
    /// The pre-ticked "email me" box on the "Create one?" prompt.
    #[serde(default = "yes")]
    emails: bool,
    /// "Create another account anyway", after a `registered_here` answer.
    #[serde(default)]
    another: bool,
}

/// "Create one?" → yes. Whatever address the question carries was settled
/// before it was asked (proven, typed, or none); this creates the profile,
/// links the identity and signs in.
async fn create_profile(State(state): State<AccountState>, jar: CookieJar, meta: RequestMeta, Json(req): Json<CreateReq>) -> Response {
    if !state
        .limiter
        .check(&format!("finish:ip:{}", meta.ip_key()), FINISH_PER_IP, Duration::from_secs(300))
    {
        return too_many().into_response();
    }
    // Before the pending row is spent: "create another anyway" has to be able
    // to come back with the same token.
    let (mark, _) = browser_mark(&state, &jar);
    if let Some(conflict) = registered_here(&state, &mark, req.another).await {
        return conflict;
    }
    let row = match db::take_proven_pending(&state.pool, &token::hash(req.token.trim()), chrono::Duration::minutes(CREATE_TTL_MIN)).await {
        Ok(Some(r)) => r,
        Ok(None) => return credential_error().into_response(),
        Err(e) => {
            tracing::error!(%e, "take_proven_pending");
            return internal_error().into_response();
        }
    };
    let via = row.via.clone().unwrap_or_else(|| format!("oauth:{}", row.provider));
    let oauth = !via.starts_with("sso:");
    // The same address `finish` asked about: the profile's, or the one a
    // provider reported without vouching.
    if oauth {
        if let Some(r) = enforcement_for(&state, row.email.as_deref().or(row.identity_email.as_deref())).await {
            return r;
        }
    }
    let sh = Shape {
        provider: row.provider.clone(),
        subject: row.provider_user_id.clone(),
        via,
        label: row.label.clone().unwrap_or_default(),
        oauth,
    };
    let name = row.display_name.as_deref().map(str::trim).filter(|s| !s.is_empty() && s.len() <= 256);

    // The same sign-in answered twice (two tabs) finds its identity linked
    // by the first answer: sign in to that account rather than make another.
    let linked = match db::find_user_by_identity(&state.pool, &sh.provider, &sh.subject).await {
        Ok(Some(id)) => match db::find_user_by_id(&state.pool, id).await {
            Ok(Some(u)) if !u.suspended => Some(u),
            Ok(_) => return credential_error().into_response(),
            Err(e) => {
                tracing::error!(%e, "find_user_by_id");
                return internal_error().into_response();
            }
        },
        Ok(None) => None,
        Err(e) => {
            tracing::error!(%e, "find_user_by_identity");
            return internal_error().into_response();
        }
    };

    let (user_id, account_email, created) = if let Some(u) = linked {
        (u.id, u.email, false)
    } else if let Some(email) = row.email.clone() {
        // Someone may have created the account another way in the meantime —
        // then a proven address links rather than creates. A typed one never
        // enters an account that exists.
        let (user_id, created) = match db::find_user_by_email(&state.pool, &email).await {
            Ok(Some(_)) if row.email_typed => return address_taken(),
            Ok(Some(u)) if u.suspended => return credential_error().into_response(),
            Ok(Some(u)) => (u.id, false),
            Ok(None) => match db::create_user(&state.pool, &email, None, name, true).await {
                Ok(Some(id)) => (id, true),
                Ok(None) if row.email_typed => return address_taken(),
                Ok(None) => match db::find_user_by_email(&state.pool, &email).await {
                    Ok(Some(u)) => (u.id, false),
                    _ => return internal_error().into_response(),
                },
                Err(e) => {
                    tracing::error!(%e, "create_user from SSO");
                    return internal_error().into_response();
                }
            },
            Err(e) => {
                tracing::error!(%e, "find_user_by_email");
                return internal_error().into_response();
            }
        };
        if let Err(e) = link(&state, user_id, &sh, Some(&email), row.connection_id, !created).await {
            tracing::error!(%e, "link created profile");
            return internal_error().into_response();
        }
        (user_id, Some(email), created)
    } else {
        // No address this site can trust: a profile with none. A provider's
        // unvouched address stays on the identity row only (see `finish`).
        let id = match db::create_user_without_email(&state.pool, name).await {
            Ok(id) => id,
            Err(e) => {
                tracing::error!(%e, "create_user_without_email from SSO");
                return internal_error().into_response();
            }
        };
        if let Err(e) = link(&state, id, &sh, row.identity_email.as_deref(), row.connection_id, false).await {
            tracing::error!(%e, "link created profile");
            return internal_error().into_response();
        }
        (id, None, true)
    };
    if created {
        if let Err(e) = db::grant_roles(&state.pool, user_id, &state.config.default_roles).await {
            tracing::error!(%e, "grant default roles");
        }
        db::log_event_via(&state.pool, "profile_created", Some(user_id), account_email.as_deref(), meta.ip.as_deref(), meta.user_agent.as_deref(), Some(&sh.via)).await;
        if let Err(e) = db::note_signup(&state.pool, user_id, meta.ip.as_deref(), req.emails).await {
            tracing::error!(%e, "note_signup");
        }
        // No verification step follows an SSO sign-in: the address (if any)
        // is as confirmed now as it will ever be.
        crate::account_mail::send_welcome(&state, user_id).await;
    }
    let identity = BrokerIdentity {
        kind: if oauth { "oauth".into() } else { "sso".into() },
        provider: oauth.then(|| row.provider.clone()),
        provider_name: None,
        connection_id: row.connection_id,
        connection_name: None,
        connection_owner: row.connection_owner,
        subject: row.provider_user_id.clone(),
        email: account_email.clone(),
        email_verified: account_email.is_some(),
        email_typed: row.email_typed,
        name: row.display_name.clone(),
        redirect_to: row.redirect_to.clone(),
        session_max_hours: row.session_max_hours.map(|h| h.max(1) as u32),
    };
    let cap = identity.session_max_hours.map(|h| Duration::from_secs(u64::from(h) * 3600));
    signed_in(&state, jar, &meta, &sh, &identity, user_id, account_email.as_deref(), cap, row.redirect_to, created).await
}

/// For `GET /account/oauth` when federated: the SSO service's buttons, with
/// `start` kept equal to `href` for clients that only know `start`.
pub(crate) async fn providers_json(broker: &BrokerClient) -> Value {
    match broker.providers().await {
        Ok(mut v) => {
            if let Some(list) = v["providers"].as_array_mut() {
                for p in list {
                    if p.get("start").is_none() {
                        p["start"] = p["href"].clone();
                    }
                }
            }
            v
        }
        Err(e) => {
            tracing::warn!(%e, "SSO provider list unavailable");
            json!({ "providers": [], "custom_sso": false })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_subjects_are_hashed_into_the_identity_key() {
        let c = Uuid::nil();
        assert_eq!(connection_identity_key(c, "abc"), format!("{c}:abc"));
        let long = "x".repeat(200);
        let k = connection_identity_key(c, &long);
        assert!(k.starts_with(&format!("{c}:h:")) && k.len() <= 190, "{k}");
    }

    #[test]
    fn unknown_identity_shapes_are_refused() {
        let base = BrokerIdentity {
            kind: "oauth".into(),
            provider: Some("myspace".into()),
            provider_name: None,
            connection_id: None,
            connection_name: None,
            connection_owner: None,
            subject: "s".into(),
            email: None,
            email_verified: true,
            email_typed: false,
            name: None,
            redirect_to: None,
            session_max_hours: None,
        };
        assert!(shape(&base).is_none(), "unknown provider");
        let sso_without_connection = BrokerIdentity { kind: "sso".into(), ..base.clone() };
        assert!(shape(&sso_without_connection).is_none());
        let google = BrokerIdentity { provider: Some("google".into()), ..base };
        assert_eq!(shape(&google).unwrap().via, "oauth:google");
    }
}

//! Shared user management for web back offices.
//!
//! Each site owns its own database and mounts the same router:
//!
//! ```no_run
//! # async fn wire() -> anyhow::Result<()> {
//! let db_url = "postgres:///mysite?host=/var/run/postgresql&user=mysite";
//! signon::migrate(db_url).await?;
//!
//! let pool = sqlx::postgres::PgPoolOptions::new()
//!     .max_connections(5)
//!     .connect(db_url)
//!     .await?;
//!
//! let config = signon::Config::new("Acme", "https://dash.example.com").with_env();
//! let state = signon::AccountState::from_env(pool, config).await?;
//!
//! let app = axum::Router::new().nest("/account", signon::router(state));
//! # Ok(())
//! # }
//! ```
//!
//! The reasoning behind every choice here — and what was taken from, or
//! deliberately not taken from, the three implementations that came before —
//! is in `DESIGN.md`.

// The crypto backend of jsonwebtoken: one, named by a feature (Cargo.toml). With neither, a token operation
// would panic at run time - said here, at build time, instead.
#[cfg(all(feature = "oauth", not(any(feature = "jwt-rust-crypto", feature = "jwt-aws-lc"))))]
compile_error!("signon: feature `oauth` needs a jsonwebtoken backend: `jwt-rust-crypto` (the default) or `jwt-aws-lc`");

// [i18n] the messages of locales/*.yml, compiled in; a language without one is English
rust_i18n::i18n!("locales", fallback = "en");

mod account_mail;
mod config;
mod current_user;
mod db;
mod email;
mod password;
mod ratelimit;
mod routes;
mod subscribe;
pub mod i18n;
pub mod token;

#[cfg(feature = "oauth")]
pub mod jwt;
#[cfg(feature = "oauth")]
pub mod oauth;
#[cfg(feature = "oauth")]
pub mod sso;
#[cfg(feature = "sso")]
pub mod oidc;
#[cfg(feature = "saml")]
mod c14n;
#[cfg(feature = "saml")]
pub mod saml;
#[cfg(feature = "sso-broker")]
pub mod broker;
#[cfg(feature = "notify")]
pub mod notify;
#[cfg(all(test, feature = "oauth"))]
mod flow_tests;
#[cfg(feature = "test-support")]
pub mod testing;
// the private keys the tests sign with: made on first use, never in the repository
#[cfg(all(feature = "oauth", any(test, feature = "test-support")))]
mod fixture_keys;

/// `Pin<Box<dyn Future>>`, spelled out so this crate needs no `async-trait`
/// for its hook traits.
pub type BoxFut<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

use std::sync::Arc;

use axum::Router;
use sqlx::PgPool;

pub use account_mail::mail_admin_router;
pub use config::{Config, FooterNote, Welcome};
pub use current_user::{AuthRejection, CurrentUser, OptionalUser, RequestMeta, SESSION_COOKIE};
pub use email::Mailer;
pub use password::{
    check_policy, PolicyError, MAX_LEN as PASSWORD_MAX_LEN, MIN_LEN as PASSWORD_MIN_LEN,
};
pub use ratelimit::RateLimiter;
pub use routes::request_language;

/// State shared by every `/account/*` handler.
///
/// Clone is cheap — everything expensive is behind an `Arc` or is already a
/// pool handle.
#[derive(Clone)]
pub struct AccountState {
    pub pool: PgPool,
    pub mailer: Arc<Mailer>,
    pub config: Arc<Config>,
    pub limiter: Arc<RateLimiter>,
    /// Social providers this site signs in with *in-process*. Starts from
    /// the environment; replaceable at runtime ([`sso::SsoRegistry`]).
    #[cfg(feature = "oauth")]
    pub sso: Arc<sso::SsoRegistry>,
    /// Set when sign-in is federated through a separate SSO service
    /// (`broker.rs`). It then answers the provider list, discovery and
    /// enforcement, and hands this site verified identities as tickets.
    #[cfg(feature = "sso-broker")]
    pub broker: Option<Arc<broker::BrokerClient>>,
    #[cfg(feature = "sso-broker")]
    pub broker_hooks: Arc<dyn broker::BrokerHooks>,
    /// For `routes::cross_verified`'s call to the sibling site — a short
    /// timeout so a slow or hung sibling cannot stall registration/resend.
    #[cfg(feature = "cross-verify")]
    pub http: reqwest::Client,
}

impl AccountState {
    /// Wires the mailer and any configured SSO providers from the process
    /// environment, and seeds the roles named in `config`.
    ///
    /// Seeding on every boot rather than in a migration is what lets four
    /// repos share one `schema.yaml` while each declaring its own role names.
    ///
    /// Fails — refusing to start the service — if `EMAIL_HOST`/`PORT`/`LOGIN`/
    /// `KEY` are not all set (see `Mailer::from_env`). A service that cannot
    /// send the verify/reset mail its own endpoints promise should not come
    /// up at all; use `from_env_with_mailer` to opt out (tests, local dev).
    pub async fn from_env(pool: PgPool, config: Config) -> anyhow::Result<Self> {
        let mailer = Mailer::from_env()?;
        Self::build(pool, config, mailer).await
    }

    /// Same as `from_env`, but with a caller-supplied mailer instead of
    /// requiring `EMAIL_HOST`/`PORT`/`LOGIN`/`KEY` — the escape hatch for
    /// tests and a local run with no relay. Pass `Mailer::disabled()` for
    /// either.
    pub async fn from_env_with_mailer(
        pool: PgPool,
        config: Config,
        mailer: Mailer,
    ) -> anyhow::Result<Self> {
        Self::build(pool, config, mailer).await
    }

    async fn build(pool: PgPool, config: Config, mailer: Mailer) -> anyhow::Result<Self> {
        db::seed_roles(&pool, &config.roles).await?;

        #[cfg(feature = "oauth")]
        let sso = {
            // Providers register their redirect URI against the public API
            // prefix, which is what the Worker forwards from — see
            // Config::api_base_url.
            let configured = oauth::from_env(&config.api_base_url());
            if configured.is_empty() {
                tracing::info!("no OAuth providers configured in the environment");
            }
            Arc::new(sso::SsoRegistry::new(sso::SsoSnapshot {
                providers: configured,
                version: "env".to_string(),
            }))
        };

        Ok(Self {
            pool,
            mailer: Arc::new(mailer),
            config: Arc::new(config),
            limiter: Arc::new(RateLimiter::new()),
            #[cfg(feature = "oauth")]
            sso,
            #[cfg(feature = "sso-broker")]
            broker: None,
            #[cfg(feature = "sso-broker")]
            broker_hooks: Arc::new(broker::NoHooks),
            #[cfg(feature = "cross-verify")]
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(3))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
        })
    }

    /// For tests and for a service that wants to swap in a different mailer
    /// after a successful `from_env`/`from_env_with_mailer`.
    pub fn with_mailer(mut self, mailer: Mailer) -> Self {
        self.mailer = Arc::new(mailer);
        self
    }

    /// Federates sign-in through a separate SSO service. Also turns on
    /// "ask before creating a profile" — nobody gets an account from a
    /// sign-in they did not confirm — and drops any providers this process
    /// loaded itself (`OAUTH_*`), so the in-process `/oauth/{p}/start` path
    /// cannot run beside the service and around its switches.
    #[cfg(feature = "sso-broker")]
    pub fn with_broker(mut self, client: broker::BrokerClient) -> Self {
        let local = self.sso.current().providers.len();
        if local > 0 {
            tracing::warn!(providers = local, "OAUTH_* credentials ignored: sign-in is federated through the SSO service");
            self.sso.replace(sso::SsoSnapshot::default());
        }
        self.broker = Some(Arc::new(client));
        let mut config = (*self.config).clone();
        config.ask_before_creating_profile = true;
        self.config = Arc::new(config);
        self
    }

    /// Plugs a service's own policy into a brokered SSO sign-in — dash's JIT
    /// team membership. See [`broker::BrokerHooks`].
    #[cfg(feature = "sso-broker")]
    pub fn with_broker_hooks(mut self, hooks: Arc<dyn broker::BrokerHooks>) -> Self {
        self.broker_hooks = hooks;
        self
    }

    /// The environment's providers, as read at startup — what a service
    /// that manages providers itself falls back to for any provider it has
    /// no row for.
    #[cfg(feature = "oauth")]
    pub fn env_providers(&self) -> Vec<oauth::Configured> {
        oauth::from_env(&self.config.api_base_url())
    }
}

/// Mount at `/news` in the service`s own router: the updates-and-news
/// mailing list, ported from a landing site's D1 waitlist onto the site's
/// own Postgres. Optional - a site that does not want a list simply does not
/// mount it, and the `subscribers` table stays empty.
pub fn subscribe_router(state: AccountState) -> Router {
    subscribe::router(state)
}

/// Confirmed, still-subscribed addresses, each with the token its unsubscribe
/// link needs. For whatever eventually sends the newsletter — this crate
/// collects subscribers, it does not send to them.
pub async fn active_subscribers(pool: &PgPool) -> anyhow::Result<Vec<(String, String)>> {
    db::active_subscribers(pool).await
}

/// Mount at `/account` in the service`s own router. Every path inside
/// (`/register`, `/login`, `/oauth/...`) is relative to that, and the frontend
/// reaches them through its Worker as `/api/account/...`.
pub fn router(state: AccountState) -> Router {
    routes::router(state)
}

const SCHEMA: &str = include_str!("../schema.yaml");

/// Applies `schema.yaml` to `db_url`. Call once at startup, before building
/// the pool.
///
/// Safe to run on every boot — `schema_guard` diffs against what is already
/// there and only ever appends. It stands in place of an ordered migration
/// chain that several repos would have to keep in step.
pub async fn migrate(db_url: &str) -> anyhow::Result<()> {
    let schema = schema_guard_tokio::load_schema_from_src(SCHEMA.to_string())
        .map_err(|e| anyhow::anyhow!("parse signon schema.yaml: {e}"))?;
    schema_guard_tokio::migrate_opt(
        schema,
        db_url,
        &schema_guard_tokio::MigrationOptions::default(),
    )
    .await
    .map_err(|e| anyhow::anyhow!("apply signon schema.yaml: {e}"))?;
    Ok(())
}

/// Deletes expired sessions and abandoned OAuth state rows.
pub async fn sweep(pool: &PgPool) -> anyhow::Result<()> {
    db::sweep_expired(pool).await
}

/// Runs [`sweep`] hourly for the life of the process. Optional — a service
/// that never calls it just accumulates dead rows.
pub fn spawn_housekeeping(pool: PgPool) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            ticker.tick().await;
            if let Err(e) = db::sweep_expired(&pool).await {
                tracing::warn!(%e, "session sweep failed");
            }
        }
    });
}

/// Grants a role to an account. For the bootstrap case every deployment hits
/// once — promoting the first administrator — and for admin screens later.
pub async fn grant_role(pool: &PgPool, user_id: uuid::Uuid, role: &str) -> anyhow::Result<()> {
    db::grant_roles(pool, user_id, std::slice::from_ref(&role.to_string())).await
}

/// Looks an account up by address, so a service can promote or inspect one
/// without depending on this crate`s private query layer.
pub async fn user_id_by_email(pool: &PgPool, email: &str) -> anyhow::Result<Option<uuid::Uuid>> {
    Ok(db::find_user_by_email(pool, &email.trim().to_lowercase())
        .await?
        .map(|u| u.id))
}

/// The account behind a session cookie value, for a sibling service that
/// was handed the cookie (an SSO service reads a site's session
/// this way, over the internal API). `None` for an unknown, expired,
/// unverified or suspended session — one answer. The address is `None` for
/// an account that has none.
pub async fn user_for_session_token(
    pool: &PgPool,
    session_token: &str,
) -> anyhow::Result<Option<(uuid::Uuid, Option<String>, Option<String>)>> {
    let Some((_session, user_id)) = db::touch_session(pool, &token::hash(session_token)).await? else {
        return Ok(None);
    };
    Ok(db::find_user_by_id(pool, user_id)
        .await?
        .filter(|u| u.email_verified && !u.suspended)
        .map(|u| (u.id, u.email, u.display_name)))
}

/// Deletes every session minted through `via` (`sso:<connection id>`, or
/// `oauth:<provider>`). What suspending a connection or disabling a provider
/// does to the people already signed in through it.
pub async fn revoke_sessions_via(pool: &PgPool, via: &str) -> anyhow::Result<u64> {
    db::delete_sessions_via(pool, via).await
}

/// Deletes the sessions of every account at `domain` except those minted
/// through `keep_via` — what turning on SSO enforcement does.
pub async fn revoke_sessions_for_domain_except(
    pool: &PgPool,
    domain: &str,
    keep_via: &str,
) -> anyhow::Result<u64> {
    db::delete_sessions_for_domain_except_via(pool, domain, keep_via).await
}

/// Deletes every session of one account.
pub async fn revoke_user_sessions(pool: &PgPool, user_id: uuid::Uuid) -> anyhow::Result<u64> {
    db::delete_sessions_for_user(pool, user_id, None).await
}

/// Suspends or reinstates an account. A suspended account cannot sign in by
/// any route, and its existing sessions stop resolving immediately.
pub async fn set_user_suspended(
    pool: &PgPool,
    user_id: uuid::Uuid,
    suspended: bool,
) -> anyhow::Result<()> {
    db::set_suspended(pool, user_id, suspended).await
}

pub use db::ConnectionUser;

/// Accounts that have signed in through a customer connection.
pub async fn users_for_connection(
    pool: &PgPool,
    connection_id: uuid::Uuid,
) -> anyhow::Result<Vec<ConnectionUser>> {
    db::users_for_connection(pool, connection_id).await
}

/// Whether an account holds an identity from this connection.
pub async fn user_linked_to_connection(
    pool: &PgPool,
    user_id: uuid::Uuid,
    connection_id: uuid::Uuid,
) -> anyhow::Result<bool> {
    db::user_linked_to_connection(pool, user_id, connection_id).await
}

/// Accounts linked through `connection_id` with this address.
pub async fn user_ids_for_connection_email(
    pool: &PgPool,
    connection_id: uuid::Uuid,
    email: &str,
) -> anyhow::Result<Vec<uuid::Uuid>> {
    db::user_ids_for_connection_email(pool, connection_id, &email.trim().to_lowercase()).await
}

/// Removes every identity a deleted connection created. The accounts stay.
pub async fn unlink_connection(pool: &PgPool, connection_id: uuid::Uuid) -> anyhow::Result<u64> {
    db::unlink_connection(pool, connection_id).await
}

/// Whether `email` has a verified account in *this* service's own database.
/// `false` for both "no such account" and "account exists but unverified" —
/// deliberately not distinguishable, same reasoning as everywhere else in
/// this crate that touches an email address (see `routes.rs`'s module doc).
///
/// For a service's own `/internal/email-verified` endpoint, answering the
/// sibling site's `routes::cross_verified` call — see that function's doc
/// for why this must sit behind a shared secret rather than being left open
/// the way `/internal/crl`/`/internal/report` are elsewhere in this
/// ecosystem: this specific boolean is exactly the kind of thing this crate
/// otherwise goes out of its way never to reveal to an anonymous caller.
pub async fn is_email_verified(pool: &PgPool, email: &str) -> anyhow::Result<bool> {
    Ok(db::find_user_by_email(pool, &email.trim().to_lowercase())
        .await?
        .map(|u| u.email_verified)
        .unwrap_or(false))
}

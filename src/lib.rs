//! Shared user management for the four backoffice sites (dash-ta, register-ta,
//! dash-qw, dash-db).
//!
//! Each site owns its own database and mounts the same router:
//!
//! ```no_run
//! # async fn wire() -> anyhow::Result<()> {
//! let db_url = "postgres:///qwbo?host=/var/run/postgresql&user=qwbo";
//! user_mgmt::migrate(db_url).await?;
//!
//! let pool = sqlx::postgres::PgPoolOptions::new()
//!     .max_connections(5)
//!     .connect(db_url)
//!     .await?;
//!
//! let config = user_mgmt::Config::new("QW", "https://dash.knownby.work").with_env();
//! let state = user_mgmt::AccountState::from_env(pool, config).await?;
//!
//! let app = axum::Router::new().nest("/account", user_mgmt::router(state));
//! # Ok(())
//! # }
//! ```
//!
//! The reasoning behind every choice here — and what was taken from, or
//! deliberately not taken from, the three implementations that came before —
//! is in `DESIGN.md`.

mod config;
mod current_user;
mod db;
mod email;
mod password;
mod ratelimit;
mod routes;
mod subscribe;
mod token;

#[cfg(feature = "oauth")]
pub mod oauth;

use std::sync::Arc;

use axum::Router;
use sqlx::PgPool;

pub use config::Config;
pub use current_user::{AuthRejection, CurrentUser, OptionalUser, RequestMeta, SESSION_COOKIE};
pub use email::Mailer;
pub use password::{check_policy, PolicyError, MAX_LEN as PASSWORD_MAX_LEN, MIN_LEN as PASSWORD_MIN_LEN};
pub use ratelimit::RateLimiter;

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
    #[cfg(feature = "oauth")]
    pub oauth: Arc<Vec<oauth::Configured>>,
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
        let oauth = {
            // Providers register their redirect URI against the public API
            // prefix, which is what the Worker forwards from — see
            // Config::api_base_url.
            let configured = oauth::from_env(&config.api_base_url());
            if configured.is_empty() {
                tracing::info!("no OAuth providers configured — SSO buttons will not be offered");
            }
            Arc::new(configured)
        };

        Ok(Self {
            pool,
            mailer: Arc::new(mailer),
            config: Arc::new(config),
            limiter: Arc::new(RateLimiter::new()),
            #[cfg(feature = "oauth")]
            oauth,
        })
    }

    /// For tests and for a service that wants to swap in a different mailer
    /// after a successful `from_env`/`from_env_with_mailer`.
    pub fn with_mailer(mut self, mailer: Mailer) -> Self {
        self.mailer = Arc::new(mailer);
        self
    }
}

/// Mount at `/news` in the service`s own router: the updates-and-news
/// mailing list, ported from `trust-atria-landing`'s D1 waitlist onto the
/// home Postgres. Optional — a site that does not want a list simply does not
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
/// there and only ever appends. Same mechanism `xpc_backend` and
/// `trust-atria-bo` already use, in place of an ordered migration chain that
/// four separate repos would have to keep in step.
pub async fn migrate(db_url: &str) -> anyhow::Result<()> {
    let schema = schema_guard_tokio::load_schema_from_src(SCHEMA.to_string())
        .map_err(|e| anyhow::anyhow!("parse user_mgmt schema.yaml: {e}"))?;
    schema_guard_tokio::migrate_opt(
        schema,
        db_url,
        &schema_guard_tokio::MigrationOptions::default(),
    )
    .await
    .map_err(|e| anyhow::anyhow!("apply user_mgmt schema.yaml: {e}"))?;
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

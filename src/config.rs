//! Per-site configuration. Everything a deployment needs to differ on lives
//! here; the handlers themselves are identical across the four sites.

use std::time::Duration;

/// Where the four sites differ: branding in the emails, the public origins
/// links are built against, and the policy knobs.
#[derive(Clone, Debug)]
pub struct Config {
    /// Appears in email subjects and bodies — "Atria Dash", "DBinvent", "QW".
    pub product_name: String,

    /// Public origin of the *site the user is looking at*, no trailing slash
    /// (`https://dash.ta.com`). Verification and reset links point at
    /// frontend routes under this, not at the JSON API — a user who clicks a
    /// mail link should land on a page, not on a `{"status":"verified"}`
    /// response body.
    pub app_base_url: String,

    /// Frontend route that handles a verification link. `{id}` and `{token}`
    /// are substituted.
    pub verify_path: String,

    /// Frontend route that handles a reset link. `{token}` is substituted.
    pub reset_path: String,

    /// Frontend route that handles a mailing-list confirmation link.
    /// `{token}` is substituted.
    pub subscribe_confirm_path: String,

    /// Frontend route that handles an unsubscribe link. `{token}` is
    /// substituted. This one has to keep working in mail sent months ago, so
    /// changing it breaks every link already in the wild — leave it alone
    /// unless the page moves.
    pub unsubscribe_path: String,

    /// Where "someone joined the mailing list" alerts go, from `NOTIFY_TO`.
    /// Empty means nobody is told, which is the safe default for a site that
    /// has not decided who owns the list. Mirrors the same variable in
    /// `trust-atria-landing`'s Worker.
    pub notify_to: Vec<String>,

    /// Public prefix that reaches *this service*, when it differs from
    /// `app_base_url` — `https://dash.ta.com/api`, because the `/api`
    /// segment exists only on the public side and the Worker strips it before
    /// forwarding. `None` means `<app_base_url>/api`, which is what all four
    /// Workers are configured to do.
    ///
    /// Only OAuth needs it: the redirect URI registered with each provider has
    /// to be an address the provider can actually send a browser to.
    pub api_base_url_override: Option<String>,

    /// Origins allowed to make state-changing requests. Defaults to
    /// `[app_base_url]` — secure by default; a dev run on
    /// `http://localhost:3000` has to say so through `ALLOWED_ORIGINS`. Empty
    /// disables the check entirely. A request carrying no `Origin` header at
    /// all is allowed either way — that is a same-origin navigation or a
    /// non-browser client, neither of which is the CSRF case.
    pub allowed_origins: Vec<String>,

    /// `Secure` on the session cookie. Only turn this off to test over plain
    /// HTTP on localhost; a non-secure session cookie on a real deployment is
    /// a network-readable credential.
    pub secure_cookies: bool,

    pub session_ttl: Duration,
    pub reset_ttl: Duration,
    pub verify_ttl: Duration,
    /// Minimum gap between two verification sends to the same account.
    pub resend_cooldown: Duration,
    /// Wrong short-code submissions tolerated before the code is dead and a
    /// resend is required. A six-digit code needs this; a 32-byte token does
    /// not.
    pub max_verify_attempts: i32,

    /// Roles this deployment recognises, seeded into `roles` at startup.
    pub roles: Vec<String>,
    /// Roles granted to every newly registered account.
    pub default_roles: Vec<String>,

    /// Loopback URL of a sibling site's `GET /internal/email-verified` —
    /// see `routes::cross_verified`. `None` (the default) disables the
    /// feature entirely: a deployment that never sets `CROSS_VERIFY_URL`
    /// behaves exactly as if this crate had no such thing.
    #[cfg(feature = "cross-verify")]
    pub cross_verify_url: Option<String>,
    /// Shared secret presented to (and required from) the sibling's
    /// endpoint — required whenever `cross_verify_url` is set, or every
    /// call answers unauthorized and the feature is silently a no-op.
    #[cfg(feature = "cross-verify")]
    pub cross_verify_secret: Option<String>,
}

impl Config {
    /// Defaults chosen to be safe rather than convenient: secure cookies on,
    /// one-hour reset links, one-day verification links.
    pub fn new(product_name: impl Into<String>, app_base_url: impl Into<String>) -> Self {
        let app_base_url = app_base_url.into().trim_end_matches('/').to_string();
        Self {
            product_name: product_name.into(),
            verify_path: "/account/verify?id={id}&token={token}".to_string(),
            reset_path: "/account/reset?token={token}".to_string(),
            subscribe_confirm_path: "/news/confirm?token={token}".to_string(),
            unsubscribe_path: "/news/unsubscribe?token={token}".to_string(),
            notify_to: Vec::new(),
            api_base_url_override: None,
            allowed_origins: vec![app_base_url.clone()],
            app_base_url,
            secure_cookies: true,
            session_ttl: Duration::from_secs(30 * 24 * 3600),
            reset_ttl: Duration::from_secs(3600),
            verify_ttl: Duration::from_secs(24 * 3600),
            resend_cooldown: Duration::from_secs(60),
            max_verify_attempts: 5,
            roles: vec!["admin".to_string(), "user".to_string()],
            default_roles: vec!["user".to_string()],
            #[cfg(feature = "cross-verify")]
            cross_verify_url: None,
            #[cfg(feature = "cross-verify")]
            cross_verify_secret: None,
        }
    }

    /// Reads the environment overrides every deployment shares:
    ///
    /// - `APP_BASE_URL` — public site origin (also settable via [`Config::new`])
    /// - `PUBLIC_BASE_URL` — public prefix reaching this service, if not
    ///   `<APP_BASE_URL>/api`. The name matches what the two trust-atria
    ///   services already set in their unit files.
    /// - `ALLOWED_ORIGINS` — comma separated
    /// - `INSECURE_COOKIES=1` — local plain-HTTP dev only
    /// - `CROSS_VERIFY_URL` / `CROSS_VERIFY_SECRET` — see `cross_verify_url`'s
    ///   own doc comment (only with the `cross-verify` feature)
    pub fn with_env(mut self) -> Self {
        if let Ok(url) = std::env::var("APP_BASE_URL") {
            let url = url.trim_end_matches('/').to_string();
            // Keep the default origin allow-list in step with the base URL.
            // An allow-list the caller has already customised is left alone.
            if self.allowed_origins == [self.app_base_url.clone()] {
                self.allowed_origins = vec![url.clone()];
            }
            self.app_base_url = url;
        }
        if let Ok(url) = std::env::var("PUBLIC_BASE_URL") {
            self.api_base_url_override = Some(url.trim_end_matches('/').to_string());
        }
        if let Ok(origins) = std::env::var("ALLOWED_ORIGINS") {
            self.allowed_origins = origins
                .split(',')
                .map(|o| o.trim().trim_end_matches('/').to_string())
                .filter(|o| !o.is_empty())
                .collect();
        }
        if let Ok(to) = std::env::var("NOTIFY_TO") {
            self.notify_to = to
                .split(',')
                .map(|a| a.trim().to_string())
                .filter(|a| !a.is_empty())
                .collect();
        }
        if std::env::var("INSECURE_COOKIES").is_ok_and(|v| v == "1" || v == "true") {
            tracing::warn!(
                "INSECURE_COOKIES set — session cookie will be sent over plain HTTP. \
                 Local development only."
            );
            self.secure_cookies = false;
        }
        #[cfg(feature = "cross-verify")]
        {
            if let Ok(url) = std::env::var("CROSS_VERIFY_URL") {
                self.cross_verify_url = Some(url);
            }
            if let Ok(secret) = std::env::var("CROSS_VERIFY_SECRET") {
                self.cross_verify_secret = Some(secret);
            }
        }
        self
    }

    /// Public address of this service, for the OAuth redirect URIs.
    pub fn api_base_url(&self) -> String {
        self.api_base_url_override
            .clone()
            .unwrap_or_else(|| format!("{}/api", self.app_base_url))
    }

    pub(crate) fn verify_url(&self, id: &uuid::Uuid, token: &str) -> String {
        format!(
            "{}{}",
            self.app_base_url,
            self.verify_path
                .replace("{id}", &id.to_string())
                .replace("{token}", token)
        )
    }

    pub(crate) fn reset_url(&self, token: &str) -> String {
        format!("{}{}", self.app_base_url, self.reset_path.replace("{token}", token))
    }

    pub(crate) fn subscribe_confirm_url(&self, token: &str) -> String {
        format!(
            "{}{}",
            self.app_base_url,
            self.subscribe_confirm_path.replace("{token}", token)
        )
    }

    pub(crate) fn unsubscribe_url(&self, token: &str) -> String {
        format!(
            "{}{}",
            self.app_base_url,
            self.unsubscribe_path.replace("{token}", token)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_are_built_against_the_site_not_the_api() {
        let cfg = Config::new("QW", "https://dash.knownby.work/");
        let id = uuid::Uuid::nil();
        assert_eq!(
            cfg.verify_url(&id, "tok"),
            "https://dash.knownby.work/account/verify?id=00000000-0000-0000-0000-000000000000&token=tok"
        );
        assert_eq!(cfg.reset_url("tok"), "https://dash.knownby.work/account/reset?token=tok");
    }

    #[test]
    fn trailing_slash_is_not_doubled() {
        assert_eq!(Config::new("x", "https://a.b///").app_base_url, "https://a.b");
    }

    #[test]
    fn mailing_list_urls_point_at_frontend_pages() {
        let cfg = Config::new("QW", "https://dash.knownby.work");
        assert_eq!(
            cfg.subscribe_confirm_url("tok"),
            "https://dash.knownby.work/news/confirm?token=tok"
        );
        assert_eq!(
            cfg.unsubscribe_url("tok"),
            "https://dash.knownby.work/news/unsubscribe?token=tok"
        );
    }

    #[test]
    fn origin_allow_list_defaults_to_the_site_itself() {
        let cfg = Config::new("x", "https://a.b");
        assert_eq!(cfg.allowed_origins, vec!["https://a.b".to_string()]);
    }

    #[test]
    fn api_base_url_defaults_to_the_worker_api_prefix() {
        assert_eq!(Config::new("x", "https://a.b").api_base_url(), "https://a.b/api");
        let mut cfg = Config::new("x", "https://a.b");
        cfg.api_base_url_override = Some("https://a.b/backend".to_string());
        assert_eq!(cfg.api_base_url(), "https://a.b/backend");
    }
}

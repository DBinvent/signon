//! Per-site configuration. Everything a deployment needs to differ on lives
//! here; the handlers themselves are identical across sites.

use std::time::Duration;

/// Where sites differ: branding in the emails, the public origins
/// links are built against, and the policy knobs.
#[derive(Clone, Debug)]
pub struct Config {
    /// Appears in email subjects and bodies - "Acme Dash", "Demo".
    pub product_name: String,

    /// [i18n] The site's own language (`APP_LANG`; English when not set): what a request that asks for
    /// none of this crate's languages is answered in, and the language of mail nobody's request causes -
    /// the owner's alert, an admin's run. One of `i18n::LANGS`, or a locale of one (`de_DE.UTF-8`).
    pub lang: String,

    /// Public origin of the *site the user is looking at*, no trailing slash
    /// (`https://dash.example.com`). Verification and reset links point at
    /// frontend routes under this, not at the JSON API — a user who clicks a
    /// mail link should land on a page, not on a `{"status":"verified"}`
    /// response body.
    pub app_base_url: String,

    /// Frontend route that handles a verification link. `{id}` and `{token}`
    /// are substituted.
    pub verify_path: String,

    /// Frontend route that handles a reset link. `{token}` is substituted.
    pub reset_path: String,

    /// Frontend route for signing in with an existing account — no
    /// substitution, just a landing page. Used only by the
    /// already-registered notice `routes::register` sends when someone
    /// tries to sign up with an address that already has one.
    pub sign_in_path: String,

    /// Frontend page that finishes a sign-in needing an emailed code
    /// (Amazon, Facebook). `{token}` is the pending-identity token.
    pub oauth_confirm_path: String,

    /// Frontend route that handles a mailing-list confirmation link.
    /// `{token}` is substituted.
    pub subscribe_confirm_path: String,

    /// Frontend route that handles an unsubscribe link. `{token}` is
    /// substituted. This one has to keep working in mail sent months ago, so
    /// changing it breaks every link already in the wild — leave it alone
    /// unless the page moves.
    pub unsubscribe_path: String,

    /// Frontend page behind the unsubscribe link in mail to an *account*
    /// (the welcome, news) — not the mailing list's. `{token}` is
    /// substituted. Old mail links here too, so it should not move.
    pub account_unsubscribe_path: String,

    /// The welcome a new account gets once its address is confirmed — or at
    /// creation, when a provider or a sibling site already vouches for it —
    /// unless its owner unticked "email me" at sign-up. `None`, the default,
    /// sends none: a site opts in with [`Config::with_welcome`], so the other
    /// deployments of this crate do not start mailing anyone unasked.
    pub welcome: Option<Welcome>,

    /// A line on top of the footer of the welcome and the follow-up, ending
    /// in a link - one that asks for feedback, say. `None`, the default, adds
    /// nothing: see [`Config::with_footer_note`].
    pub footer_note: Option<FooterNote>,

    /// [signed-in] The page the redirect after a sign-in carries, for a browser where the
    /// redirect does not go through: HTML, `{url}` the address to go on
    /// to (filled in escaped). `None`, the default: signon's own page - the sign-in worked,
    /// the link, and a meta refresh. See [`Config::with_signed_in_page`].
    pub signed_in_page: Option<String>,

    /// [service] Which ways in the service accounts have, and the token's key - all off
    /// unless set: see [`Config::with_service_accounts`]
    #[cfg(feature = "service-accounts")]
    pub service: crate::service::ServiceConfig,

    /// [labac] A person's token for the database (the `/labac/token` page) and OPA's levels -
    /// off unless set: see [`Config::with_labac`]
    #[cfg(feature = "labac")]
    pub labac: crate::labac::LabacConfig,

    /// Where the welcome's text is read when one goes out
    /// (`WELCOME_TEMPLATE_URL`; empty turns it off): `GET` answering
    /// `{subject, body, action_label, action_url}` - a template source of the
    /// site's, where the text is edited and approved. When set, it
    /// alone decides: a 404 (not approved, or switched off there), an error,
    /// a timeout or a malformed answer all mean no welcome — the built-in
    /// [`Config::welcome`] is then never sent in its place.
    #[cfg(feature = "welcome-remote")]
    pub welcome_url: Option<String>,

    /// Where the follow-up's text is read (`FOLLOWUP_TEMPLATE_URL`; empty
    /// turns it off) — same answer shape and the same rule as
    /// [`Config::welcome_url`], except there is no built-in follow-up: with
    /// no answer there is nothing to send. Sent only by a manual run.
    #[cfg(feature = "welcome-remote")]
    pub followup_url: Option<String>,

    /// The key a site's template admin presents to start a catch-up or
    /// follow-up run (`MAIL_ADMIN_KEY`, at least 16 characters):
    /// `account_mail::mail_admin_router`. `None`: those routes answer 404.
    pub mail_admin_key: Option<String>,

    /// Shared secret the site's Worker sends beside the visitor's address
    /// (`X-Client-IP` + `X-Client-IP-Key`, `CLIENT_IP_KEY`). A Worker that
    /// forwards to another zone's hostname makes Cloudflare report the
    /// Worker's own address as `CF-Connecting-IP` — the same for every
    /// visitor, so per-address rate limits become one global bucket and the
    /// recorded addresses mean nothing. The forwarded address is used
    /// instead, but only when the key matches: the tunnel hostname is
    /// reachable by anyone, who can send any header. `None`: the forwarded
    /// headers are ignored (and stripped).
    pub client_ip_key: Option<String>,

    /// Where "someone joined the mailing list" alerts go, from `NOTIFY_TO`.
    /// Empty means nobody is told, which is the safe default for a site that
    /// has not decided who owns the list.
    pub notify_to: Vec<String>,

    /// Public prefix that reaches *this service*, when it differs from
    /// `app_base_url` - `https://dash.example.com/api`, because the `/api`
    /// segment exists only on the public side and the Worker strips it before
    /// forwarding. `None` means `<app_base_url>/api`, the usual arrangement.
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

    /// A sign-in through a provider that finds no account here asks
    /// "No profile exists yet. Create one?" instead of creating it silently.
    /// Off by default (a site with in-process providers keeps creating on the first sign-in); turned on
    /// by `AccountState::with_broker`.
    pub ask_before_creating_profile: bool,

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
    /// [i18n] The site's language as one of `i18n::LANGS`
    pub fn site_lang(&self) -> &'static str {
        crate::i18n::language(&self.lang)
    }

    /// Defaults chosen to be safe rather than convenient: secure cookies on,
    /// one-hour reset links, one-day verification links.
    pub fn new(product_name: impl Into<String>, app_base_url: impl Into<String>) -> Self {
        let app_base_url = app_base_url.into().trim_end_matches('/').to_string();
        Self {
            product_name: product_name.into(),
            lang: crate::i18n::DEFAULT_LANG.to_string(),
            verify_path: "/account/verify?id={id}&token={token}".to_string(),
            reset_path: "/account/reset?token={token}".to_string(),
            sign_in_path: "/account/sign-in".to_string(),
            oauth_confirm_path: "/account/oauth/confirm?token={token}".to_string(),
            subscribe_confirm_path: "/news/confirm?token={token}".to_string(),
            unsubscribe_path: "/news/unsubscribe?token={token}".to_string(),
            account_unsubscribe_path: "/account/unsubscribe?token={token}".to_string(),
            welcome: None,
            footer_note: None,
            signed_in_page: None,
            #[cfg(feature = "service-accounts")]
            service: Default::default(),
            #[cfg(feature = "labac")]
            labac: Default::default(),
            #[cfg(feature = "welcome-remote")]
            welcome_url: None,
            #[cfg(feature = "welcome-remote")]
            followup_url: None,
            mail_admin_key: None,
            client_ip_key: None,
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
            ask_before_creating_profile: false,
            #[cfg(feature = "cross-verify")]
            cross_verify_url: None,
            #[cfg(feature = "cross-verify")]
            cross_verify_secret: None,
        }
    }

    /// Reads the environment overrides every deployment shares:
    ///
    /// - `APP_BASE_URL` — public site origin (also settable via [`Config::new`])
    /// - `APP_LANG` - the site's language, see `lang`
    /// - `PUBLIC_BASE_URL` — public prefix reaching this service, if not
    ///   `<APP_BASE_URL>/api`.
    /// - `ALLOWED_ORIGINS` — comma separated
    /// - `INSECURE_COOKIES=1` — local plain-HTTP dev only
    /// - `CLIENT_IP_KEY` — see `client_ip_key`'s own doc comment
    /// - `WELCOME_TEMPLATE_URL` / `FOLLOWUP_TEMPLATE_URL` — see `welcome_url`
    ///   and `followup_url` (feature `welcome-remote`)
    /// - `MAIL_ADMIN_KEY` — see `mail_admin_key`
    /// - `CROSS_VERIFY_URL` / `CROSS_VERIFY_SECRET` — see `cross_verify_url`'s
    ///   own doc comment (only with the `cross-verify` feature)
    pub fn with_env(mut self) -> Self {
        if let Ok(lang) = std::env::var("APP_LANG") {
            if !lang.trim().is_empty() {
                self.lang = lang;
            }
        }
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
        #[cfg(feature = "welcome-remote")]
        if let Ok(url) = std::env::var("WELCOME_TEMPLATE_URL") {
            let url = url.trim();
            self.welcome_url = (!url.is_empty()).then(|| url.to_string());
        }
        #[cfg(feature = "welcome-remote")]
        if let Ok(url) = std::env::var("FOLLOWUP_TEMPLATE_URL") {
            let url = url.trim();
            self.followup_url = (!url.is_empty()).then(|| url.to_string());
        }
        if let Ok(key) = std::env::var("MAIL_ADMIN_KEY") {
            let key = key.trim().to_string();
            if key.len() >= 16 {
                self.mail_admin_key = Some(key);
            } else if !key.is_empty() {
                tracing::warn!("MAIL_ADMIN_KEY is shorter than 16 characters — ignored");
            }
        }
        if let Ok(key) = std::env::var("CLIENT_IP_KEY") {
            let key = key.trim().to_string();
            // Short keys are refused rather than trusted: this one decides
            // which address every rate limit and audit line is keyed on.
            if key.len() >= 16 {
                self.client_ip_key = Some(key);
            } else if !key.is_empty() {
                tracing::warn!("CLIENT_IP_KEY is shorter than 16 characters — ignored");
            }
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
        format!(
            "{}{}",
            self.app_base_url,
            self.reset_path.replace("{token}", token)
        )
    }

    pub(crate) fn sign_in_url(&self) -> String {
        format!("{}{}", self.app_base_url, self.sign_in_path)
    }

    #[cfg(feature = "oauth")]
    pub(crate) fn oauth_confirm_url(&self, token: &str) -> String {
        format!(
            "{}{}",
            self.app_base_url,
            self.oauth_confirm_path
                .replace("{token}", &urlencoding_lite(token))
        )
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

    /// Opts this site into the welcome mail — see [`Config::welcome`].
    pub fn with_welcome(mut self, welcome: Welcome) -> Self {
        self.welcome = Some(welcome);
        self
    }

    /// Adds a line to the footer of the welcome and the follow-up — see
    /// [`Config::footer_note`].
    pub fn with_footer_note(mut self, note: FooterNote) -> Self {
        self.footer_note = Some(note);
        self
    }

    /// [signed-in] A page of the site's own for the redirect after a sign-in - see
    /// [`Config::signed_in_page`]
    pub fn with_signed_in_page(mut self, html: impl Into<String>) -> Self {
        self.signed_in_page = Some(html.into());
        self
    }

    /// [service] The service accounts' ways in: `POST /token` answers with client credentials on
    #[cfg(feature = "service-accounts")]
    pub fn with_service_accounts(mut self, service: crate::service::ServiceConfig) -> Self {
        self.service = service;
        self
    }

    /// [labac] A person's database token and OPA: `GET /labac/token` answers when it has a key
    #[cfg(feature = "labac")]
    pub fn with_labac(mut self, labac: crate::labac::LabacConfig) -> Self {
        self.labac = labac;
        self
    }

    /// Where the welcome's text is read from, unless `WELCOME_TEMPLATE_URL`
    /// already said — see [`Config::welcome_url`]. Call after `with_env`.
    #[cfg(feature = "welcome-remote")]
    pub fn with_default_welcome_url(mut self, url: impl Into<String>) -> Self {
        if std::env::var_os("WELCOME_TEMPLATE_URL").is_none() {
            self.welcome_url = Some(url.into());
        }
        self
    }

    /// Where the follow-up's text is read from, unless `FOLLOWUP_TEMPLATE_URL`
    /// already said — see [`Config::followup_url`]. Call after `with_env`.
    #[cfg(feature = "welcome-remote")]
    pub fn with_default_followup_url(mut self, url: impl Into<String>) -> Self {
        if std::env::var_os("FOLLOWUP_TEMPLATE_URL").is_none() {
            self.followup_url = Some(url.into());
        }
        self
    }

    /// The page an account's unsubscribe link opens.
    pub(crate) fn account_unsubscribe_url(&self, token: &str) -> String {
        format!(
            "{}{}",
            self.app_base_url,
            self.account_unsubscribe_path.replace("{token}", token)
        )
    }

    /// RFC 8058 one-click target, for the `List-Unsubscribe` header. The mail
    /// client POSTs here itself, without a browser, so it is the API rather
    /// than a page.
    pub(crate) fn one_click_unsubscribe_url(&self, token: &str) -> String {
        format!("{}/account/emails/unsubscribe/{token}", self.api_base_url())
    }
}

/// A site's welcome mail. The paragraphs are plain text — escaped into the
/// HTML part, so a site cannot inject markup by accident — followed by an
/// optional button, then the unsubscribe footer this crate adds itself.
#[derive(Clone, Debug)]
pub struct Welcome {
    pub subject: String,
    pub paragraphs: Vec<String>,
    /// `(label, absolute URL)`.
    pub action: Option<(String, String)>,
    /// The footer line, when the text's source sends one with a template -
    /// and then it wins over [`Config::footer_note`]:
    /// `Some(None)` is "no line". `None`: the site's own.
    pub footer_note: Option<Option<FooterNote>>,
}

/// A line on top of the footer of a welcome or follow-up, above why the mail
/// came. Plain text like the welcome's paragraphs, escaped into the HTML part,
/// then the link if it has one.
#[derive(Clone, Debug)]
pub struct FooterNote {
    pub text: String,
    /// `(label, absolute URL)`.
    pub link: Option<(String, String)>,
}

/// Tokens from `token::secret` are already URL-safe; this only guards a
/// caller that passes something else.
#[cfg(feature = "oauth")]
fn urlencoding_lite(raw: &str) -> String {
    raw.chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~'))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_are_built_against_the_site_not_the_api() {
        let cfg = Config::new("Demo", "https://dash.example.com/");
        let id = uuid::Uuid::nil();
        assert_eq!(
            cfg.verify_url(&id, "tok"),
            "https://dash.example.com/account/verify?id=00000000-0000-0000-0000-000000000000&token=tok"
        );
        assert_eq!(
            cfg.reset_url("tok"),
            "https://dash.example.com/account/reset?token=tok"
        );
        assert_eq!(
            cfg.sign_in_url(),
            "https://dash.example.com/account/sign-in"
        );
    }

    #[test]
    fn trailing_slash_is_not_doubled() {
        assert_eq!(
            Config::new("x", "https://a.b///").app_base_url,
            "https://a.b"
        );
    }

    #[test]
    fn mailing_list_urls_point_at_frontend_pages() {
        let cfg = Config::new("Demo", "https://dash.example.com");
        assert_eq!(
            cfg.subscribe_confirm_url("tok"),
            "https://dash.example.com/news/confirm?token=tok"
        );
        assert_eq!(
            cfg.unsubscribe_url("tok"),
            "https://dash.example.com/news/unsubscribe?token=tok"
        );
    }

    #[test]
    fn origin_allow_list_defaults_to_the_site_itself() {
        let cfg = Config::new("x", "https://a.b");
        assert_eq!(cfg.allowed_origins, vec!["https://a.b".to_string()]);
    }

    #[test]
    fn api_base_url_defaults_to_the_worker_api_prefix() {
        assert_eq!(
            Config::new("x", "https://a.b").api_base_url(),
            "https://a.b/api"
        );
        let mut cfg = Config::new("x", "https://a.b");
        cfg.api_base_url_override = Some("https://a.b/backend".to_string());
        assert_eq!(cfg.api_base_url(), "https://a.b/backend");
    }
}

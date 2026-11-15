//! OAuth2 / OIDC sign-in with the social providers.
//!
//! One authorization-code flow, described per provider by a table entry rather
//! than a module — adding a provider is a `Provider` literal plus, at most, a
//! profile shape.
//!
//! Two rules that are the whole security story of this file:
//!
//! * **`state` is single-use and server-side.** It is generated per attempt,
//!   only its hash is stored, and the callback deletes the row in the same
//!   statement that reads it. A replayed callback finds nothing.
//! * **An account is only ever matched to an existing local account on a
//!   provider-*verified* email.** Skipping that check is a complete account
//!   takeover: register at the provider with the victim`s address, sign in,
//!   and get handed their account. Older account code matched on the bare
//!   address.
//!   Providers that do not vouch for the address at all (Amazon, Facebook,
//!   Microsoft) go through the pending-identity code step in `routes.rs`
//!   instead.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

use crate::{jwt, token};

/// How a provider tells us who signed in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfileShape {
    /// OIDC `userinfo`: `sub`, `name`, `email`, `email_verified`.
    Oidc,
    /// GitHub is not OIDC: `GET /user` has no reliable email (it is `null`
    /// unless the user made one public — which the 2021 implementation did
    /// not account for), so the verified address comes from `/user/emails`.
    GitHub,
    /// Apple has no userinfo endpoint. Everything comes from the `id_token`
    /// returned by the token endpoint, verified against Apple's JWKS. The
    /// name arrives exactly once, in the `user` form field of the very first
    /// authorization, and never again.
    AppleIdToken,
    /// Login with Amazon: `GET /user/profile` → `user_id`, `name`, `email`.
    /// No verification claim of any kind.
    Amazon,
    /// Graph API `GET /me?fields=id,name,email`. No verification claim, and
    /// the email is absent for accounts registered with a phone number.
    Facebook,
    /// Microsoft identity platform (Entra ID work/school accounts and
    /// personal Microsoft accounts, the `common` endpoint): OIDC userinfo at
    /// Graph — `sub`, `name`, `email`. Shaped like [`ProfileShape::Oidc`]
    /// but never vouching: the `email` claim is whatever a tenant
    /// administrator typed into that user's mail attribute, unverified and
    /// mutable, so trusting it lets any tenant sign in as any address (the
    /// "nOAuth" takeover). There is no `email_verified`.
    Microsoft,
}

#[derive(Clone, Copy, Debug)]
pub struct Provider {
    pub key: &'static str,
    pub display_name: &'static str,
    pub authorize_url: &'static str,
    pub token_url: &'static str,
    /// Userinfo / profile endpoint. Empty for [`ProfileShape::AppleIdToken`].
    pub profile_url: &'static str,
    /// Only meaningful for [`ProfileShape::GitHub`].
    pub emails_url: &'static str,
    /// For `id_token` verification. Empty where the shape does not use one.
    pub issuer: &'static str,
    pub jwks_url: &'static str,
    pub scope: &'static str,
    pub shape: ProfileShape,
    /// Send PKCE. Off only where the provider is not documented to accept
    /// it — an unknown `code_verifier` on the token request is a failed
    /// sign-in at some providers, and the client secret already binds the
    /// code to us there.
    pub pkce: bool,
    /// Send a `nonce` and require it back in the `id_token`.
    pub nonce: bool,
    /// `form_post` makes the callback a cross-site `POST` — Apple requires it
    /// whenever `name` or `email` is in the scope.
    pub response_mode: Option<&'static str>,
}

impl Provider {
    /// Whether this provider ever vouches for an email address. The ones
    /// that do not are never trusted to link to an existing account on the
    /// address alone — see the module doc.
    pub fn asserts_email_verification(&self) -> bool {
        !matches!(
            self.shape,
            ProfileShape::Amazon | ProfileShape::Facebook | ProfileShape::Microsoft
        )
    }
}

/// Graph API version for Facebook. Versions are retired about two years after
/// release; bump this before that happens or sign-in stops working.
pub const FACEBOOK_GRAPH_VERSION: &str = "v23.0";

/// The registry. Everything provider-specific is here.
pub const PROVIDERS: &[Provider] = &[
    Provider {
        key: "github",
        display_name: "GitHub",
        authorize_url: "https://github.com/login/oauth/authorize",
        token_url: "https://github.com/login/oauth/access_token",
        profile_url: "https://api.github.com/user",
        emails_url: "https://api.github.com/user/emails",
        issuer: "",
        jwks_url: "",
        scope: "read:user user:email",
        shape: ProfileShape::GitHub,
        pkce: true,
        nonce: false,
        response_mode: None,
    },
    Provider {
        key: "linkedin",
        display_name: "LinkedIn",
        authorize_url: "https://www.linkedin.com/oauth/v2/authorization",
        token_url: "https://www.linkedin.com/oauth/v2/accessToken",
        // OIDC. The `r_liteprofile` + `r_emailaddress` pair and the
        // /v2/me + /v2/clientAwareMemberHandles calls are LinkedIn`s
        // retired flow - one userinfo call replaces both.
        profile_url: "https://api.linkedin.com/v2/userinfo",
        emails_url: "",
        issuer: "",
        jwks_url: "",
        scope: "openid profile email",
        shape: ProfileShape::Oidc,
        pkce: true,
        nonce: false,
        response_mode: None,
    },
    Provider {
        key: "google",
        display_name: "Google",
        authorize_url: "https://accounts.google.com/o/oauth2/v2/auth",
        token_url: "https://oauth2.googleapis.com/token",
        profile_url: "https://openidconnect.googleapis.com/v1/userinfo",
        emails_url: "",
        issuer: "",
        jwks_url: "",
        scope: "openid email profile",
        shape: ProfileShape::Oidc,
        pkce: true,
        nonce: false,
        response_mode: None,
    },
    Provider {
        key: "apple",
        display_name: "Apple",
        authorize_url: "https://appleid.apple.com/auth/authorize",
        token_url: "https://appleid.apple.com/auth/token",
        profile_url: "",
        emails_url: "",
        issuer: "https://appleid.apple.com",
        jwks_url: "https://appleid.apple.com/auth/keys",
        scope: "name email",
        shape: ProfileShape::AppleIdToken,
        pkce: false,
        nonce: true,
        response_mode: Some("form_post"),
    },
    Provider {
        key: "amazon",
        display_name: "Amazon",
        authorize_url: "https://www.amazon.com/ap/oa",
        token_url: "https://api.amazon.com/auth/o2/token",
        profile_url: "https://api.amazon.com/user/profile",
        emails_url: "",
        issuer: "",
        jwks_url: "",
        scope: "profile",
        shape: ProfileShape::Amazon,
        pkce: false,
        nonce: false,
        response_mode: None,
    },
    Provider {
        key: "facebook",
        display_name: "Facebook",
        authorize_url: "https://www.facebook.com/v23.0/dialog/oauth",
        token_url: "https://graph.facebook.com/v23.0/oauth/access_token",
        profile_url: "https://graph.facebook.com/v23.0/me?fields=id,name,email",
        emails_url: "",
        issuer: "",
        jwks_url: "",
        scope: "email public_profile",
        shape: ProfileShape::Facebook,
        pkce: false,
        nonce: false,
        response_mode: None,
    },
    Provider {
        key: "microsoft",
        display_name: "Microsoft",
        // `common`: work/school (Entra ID) and personal accounts alike. The
        // app registration must allow both ("Accounts in any organizational
        // directory and personal Microsoft accounts").
        authorize_url: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        token_url: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        profile_url: "https://graph.microsoft.com/oidc/userinfo",
        emails_url: "",
        // No id_token verification: with `common` the issuer is per tenant,
        // and userinfo over the access token says the same.
        issuer: "",
        jwks_url: "",
        scope: "openid email profile",
        shape: ProfileShape::Microsoft,
        pkce: true,
        nonce: false,
        response_mode: None,
    },
];

pub fn provider_by_key(key: &str) -> Option<&'static Provider> {
    PROVIDERS.iter().find(|p| p.key == key)
}

/// How this site proves itself to a provider's token endpoint.
#[derive(Clone)]
pub enum ClientSecret {
    Static(String),
    /// Apple's client secret is not a stored string but an ES256 JWT signed
    /// with a `.p8` key, valid for at most six months. Holding the key and
    /// minting per exchange means it never expires underneath us.
    Apple(AppleKey),
}

#[derive(Clone)]
pub struct AppleKey {
    pub team_id: String,
    pub key_id: String,
    /// PKCS#8 PEM, exactly as downloaded from Apple (`AuthKey_<id>.p8`).
    pub private_key_pem: String,
}

impl ClientSecret {
    fn resolve(&self, client_id: &str) -> anyhow::Result<String> {
        match self {
            ClientSecret::Static(s) => Ok(s.clone()),
            ClientSecret::Apple(key) => jwt::apple_client_secret(key, client_id),
        }
    }

    /// Checks the secret is usable before it is stored — for Apple, that the
    /// key actually signs an ES256 client secret for `client_id`.
    pub fn validate(&self, client_id: &str) -> anyhow::Result<()> {
        if self.is_empty() {
            anyhow::bail!("empty credentials");
        }
        self.resolve(client_id).map(|_| ())
    }

    pub fn is_empty(&self) -> bool {
        match self {
            ClientSecret::Static(s) => s.trim().is_empty(),
            ClientSecret::Apple(k) => {
                k.team_id.trim().is_empty()
                    || k.key_id.trim().is_empty()
                    || k.private_key_pem.trim().is_empty()
            }
        }
    }
}

/// Where a provider's endpoints are. Copied from the [`PROVIDERS`] table by
/// default; replaceable with [`Configured::with_endpoints`] for a provider
/// reached somewhere else (the test suite's mock, a regional endpoint).
#[derive(Clone, Debug)]
pub struct Endpoints {
    pub authorize: String,
    pub token: String,
    pub profile: String,
    pub emails: String,
    pub issuer: String,
    pub jwks: String,
}

impl Endpoints {
    pub fn of(provider: &Provider) -> Self {
        Self {
            authorize: provider.authorize_url.to_string(),
            token: provider.token_url.to_string(),
            profile: provider.profile_url.to_string(),
            emails: provider.emails_url.to_string(),
            issuer: provider.issuer.to_string(),
            jwks: provider.jwks_url.to_string(),
        }
    }
}

/// A provider that this deployment actually has credentials for.
#[derive(Clone)]
pub struct Configured {
    pub provider: &'static Provider,
    pub client_id: String,
    secret: ClientSecret,
    pub redirect_uri: String,
    pub endpoints: Endpoints,
}

/// Hand-written so neither a client secret nor an Apple key can reach a log
/// line through `{:?}`.
impl std::fmt::Debug for Configured {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Configured")
            .field("provider", &self.provider.key)
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri)
            .finish_non_exhaustive()
    }
}

impl Configured {
    /// For a service that keeps provider credentials somewhere other than the
    /// environment (dash's `/admin` console). `None` for an unknown provider
    /// key or empty credentials — the same "simply absent" rule as
    /// [`from_env`].
    pub fn new(
        provider_key: &str,
        client_id: impl Into<String>,
        secret: ClientSecret,
        redirect_uri: impl Into<String>,
    ) -> Option<Self> {
        let provider = provider_by_key(provider_key)?;
        let client_id = client_id.into();
        if client_id.trim().is_empty() || secret.is_empty() {
            return None;
        }
        if matches!(secret, ClientSecret::Apple(_)) != (provider.shape == ProfileShape::AppleIdToken) {
            return None;
        }
        Some(Self {
            provider,
            client_id,
            secret,
            redirect_uri: redirect_uri.into(),
            endpoints: Endpoints::of(provider),
        })
    }

    pub fn with_endpoints(mut self, endpoints: Endpoints) -> Self {
        self.endpoints = endpoints;
        self
    }

    /// One credential set, several callback URLs - an SSO service that
    /// registers one app per provider and calls back per site.
    pub fn with_redirect_uri(mut self, redirect_uri: impl Into<String>) -> Self {
        self.redirect_uri = redirect_uri.into();
        self
    }
}

/// The redirect URI registered with each provider:
/// `<api_base_url>/account/oauth/<key>/callback`.
pub fn redirect_uri_for(api_base_url: &str, provider_key: &str) -> String {
    format!(
        "{}/account/oauth/{}/callback",
        api_base_url.trim_end_matches('/'),
        provider_key
    )
}

/// Reads `OAUTH_<KEY>_CLIENT_ID` / `OAUTH_<KEY>_CLIENT_SECRET` for each known
/// provider. A provider with no credentials is simply absent, so a site that
/// does not want SSO configures nothing and the frontend renders no buttons.
///
/// Apple takes `OAUTH_APPLE_CLIENT_ID` (the Services ID) plus
/// `OAUTH_APPLE_TEAM_ID`, `OAUTH_APPLE_KEY_ID` and the `.p8` key — inline as
/// `OAUTH_APPLE_PRIVATE_KEY` (`\n` escapes accepted) or as a file at
/// `OAUTH_APPLE_PRIVATE_KEY_PATH` — instead of a client secret.
///
/// `api_base_url` is the public prefix that reaches this service — the
/// redirect URI registered with each provider must be
/// `<api_base_url>/account/oauth/<key>/callback`.
pub fn from_env(api_base_url: &str) -> Vec<Configured> {
    let mut out = Vec::new();
    for provider in PROVIDERS {
        let upper = provider.key.to_uppercase();
        let var = |name: &str| std::env::var(format!("OAUTH_{upper}_{name}")).ok();
        let Some(client_id) = var("CLIENT_ID") else {
            continue;
        };
        let secret = if provider.shape == ProfileShape::AppleIdToken {
            let pem = var("PRIVATE_KEY")
                .map(|inline| inline.replace("\\n", "\n"))
                .or_else(|| {
                    var("PRIVATE_KEY_PATH").and_then(|path| match std::fs::read_to_string(&path) {
                        Ok(pem) => Some(pem),
                        Err(e) => {
                            tracing::error!(%e, path, "cannot read OAUTH_APPLE_PRIVATE_KEY_PATH");
                            None
                        }
                    })
                });
            let (Some(team_id), Some(key_id), Some(private_key_pem)) =
                (var("TEAM_ID"), var("KEY_ID"), pem)
            else {
                continue;
            };
            ClientSecret::Apple(AppleKey {
                team_id,
                key_id,
                private_key_pem,
            })
        } else {
            let Some(secret) = var("CLIENT_SECRET") else {
                continue;
            };
            ClientSecret::Static(secret)
        };
        let redirect_uri =
            var("REDIRECT_URI").unwrap_or_else(|| redirect_uri_for(api_base_url, provider.key));
        let Some(configured) = Configured::new(provider.key, client_id, secret, redirect_uri) else {
            continue;
        };
        tracing::info!(provider = provider.key, redirect_uri = %configured.redirect_uri, "oauth provider configured");
        out.push(configured);
    }
    out
}

// ---- PKCE -----------------------------------------------------------------

/// `(verifier, challenge)` for PKCE S256.
///
/// For the OIDC providers it is what stops a stolen authorization code from
/// being redeemed by anyone but the browser that started the flow. Generated
/// for every flow, sent only where [`Provider::pkce`] says the provider takes
/// it.
pub fn pkce_pair() -> (String, String) {
    let verifier = token::secret();
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

/// What a token endpoint hands back that this crate uses.
#[derive(Debug, Default)]
pub struct TokenSet {
    pub access_token: Option<String>,
    pub id_token: Option<String>,
}

impl Configured {
    pub fn authorize_url(&self, state: &str, challenge: &str, nonce: &str) -> String {
        let enc = urlencoding::encode;
        let mut url = format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}",
            self.endpoints.authorize,
            enc(&self.client_id),
            enc(&self.redirect_uri),
            enc(self.provider.scope),
            enc(state),
        );
        if self.provider.pkce {
            url.push_str(&format!(
                "&code_challenge={}&code_challenge_method=S256",
                enc(challenge)
            ));
        }
        if self.provider.nonce {
            url.push_str(&format!("&nonce={}", enc(nonce)));
        }
        if let Some(mode) = self.provider.response_mode {
            url.push_str(&format!("&response_mode={}", enc(mode)));
        }
        url
    }

    /// Authorization code -> tokens.
    pub async fn exchange_code(&self, code: &str, verifier: &str) -> anyhow::Result<TokenSet> {
        let secret = self.secret.resolve(&self.client_id)?;
        let mut params = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", self.redirect_uri.as_str()),
            ("client_id", self.client_id.as_str()),
            ("client_secret", secret.as_str()),
        ];
        if self.provider.pkce {
            params.push(("code_verifier", verifier));
        }
        let tokens = post_token_form(&self.endpoints.token, &params, None).await?;
        if tokens.access_token.is_none() && tokens.id_token.is_none() {
            anyhow::bail!("token endpoint returned neither an access token nor an id_token");
        }
        Ok(tokens)
    }

    /// Tokens -> the facts this crate needs about the user.
    ///
    /// `nonce` is the value sent on the authorize request; `apple_user` is
    /// the raw `user` form field Apple posts on a first authorization.
    pub async fn fetch_profile(
        &self,
        tokens: &TokenSet,
        nonce: Option<&str>,
        apple_user: Option<&str>,
    ) -> anyhow::Result<Profile> {
        let access = || {
            tokens
                .access_token
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("no access token"))
        };
        match self.provider.shape {
            ProfileShape::Oidc => {
                #[derive(Deserialize)]
                struct Oidc {
                    sub: String,
                    name: Option<String>,
                    email: Option<String>,
                    // Some providers send this as a JSON bool, some as the
                    // string "true"; absent means "not asserted".
                    #[serde(default)]
                    email_verified: Option<serde_json::Value>,
                }
                let profile: Oidc = get_json(&self.endpoints.profile, access()?).await?;
                Ok(Profile {
                    subject: profile.sub,
                    name: profile.name,
                    email_verified: truthy(profile.email_verified.as_ref()),
                    email: profile.email,
                })
            }
            ProfileShape::GitHub => {
                #[derive(Deserialize)]
                struct GhUser {
                    id: i64,
                    login: String,
                    name: Option<String>,
                }
                #[derive(Deserialize)]
                struct GhEmail {
                    email: String,
                    primary: bool,
                    verified: bool,
                }
                let user: GhUser = get_json(&self.endpoints.profile, access()?).await?;
                let emails: Vec<GhEmail> = get_json(&self.endpoints.emails, access()?)
                    .await
                    .unwrap_or_default();
                let chosen = emails
                    .iter()
                    .find(|e| e.primary && e.verified)
                    .or_else(|| emails.iter().find(|e| e.verified));
                Ok(Profile {
                    subject: user.id.to_string(),
                    name: user.name.or(Some(user.login)),
                    email_verified: chosen.is_some(),
                    email: chosen.map(|e| e.email.clone()),
                })
            }
            ProfileShape::AppleIdToken => {
                let id_token = tokens
                    .id_token
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("apple returned no id_token"))?;
                let nonce = nonce.ok_or_else(|| anyhow::anyhow!("apple flow without a nonce"))?;
                let claims = jwt::verify_id_token(
                    id_token,
                    &self.endpoints.jwks,
                    &self.endpoints.issuer,
                    &self.client_id,
                    Some(nonce),
                )
                .await?;
                Ok(Profile {
                    subject: claims.sub,
                    email_verified: truthy(claims.email_verified.as_ref()),
                    email: claims.email,
                    name: claims.name.or_else(|| apple_user.and_then(apple_name)),
                })
            }
            ProfileShape::Amazon => {
                #[derive(Deserialize)]
                struct AmazonProfile {
                    user_id: String,
                    name: Option<String>,
                    email: Option<String>,
                }
                let p: AmazonProfile = get_json(&self.endpoints.profile, access()?).await?;
                Ok(Profile {
                    subject: p.user_id,
                    name: p.name,
                    email: p.email,
                    email_verified: false,
                })
            }
            ProfileShape::Microsoft => {
                #[derive(Deserialize)]
                struct MicrosoftUserinfo {
                    sub: String,
                    name: Option<String>,
                    email: Option<String>,
                }
                let p: MicrosoftUserinfo = get_json(&self.endpoints.profile, access()?).await?;
                Ok(Profile {
                    subject: p.sub,
                    name: p.name,
                    email: p.email,
                    // Never — see ProfileShape::Microsoft.
                    email_verified: false,
                })
            }
            ProfileShape::Facebook => {
                #[derive(Deserialize)]
                struct FacebookProfile {
                    id: String,
                    name: Option<String>,
                    email: Option<String>,
                }
                let p: FacebookProfile = get_json(&self.endpoints.profile, access()?).await?;
                Ok(Profile {
                    subject: p.id,
                    name: p.name,
                    email: p.email,
                    email_verified: false,
                })
            }
        }
    }
}

/// `"Jane Appleseed"` out of Apple's first-authorization `user` field:
/// `{"name":{"firstName":"Jane","lastName":"Appleseed"},"email":"…"}`.
fn apple_name(raw: &str) -> Option<String> {
    #[derive(Deserialize)]
    struct Name {
        #[serde(rename = "firstName")]
        first: Option<String>,
        #[serde(rename = "lastName")]
        last: Option<String>,
    }
    #[derive(Deserialize)]
    struct User {
        name: Option<Name>,
    }
    let user: User = serde_json::from_str(raw).ok()?;
    let name = user.name?;
    let full = [name.first, name.last]
        .into_iter()
        .flatten()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    (!full.is_empty() && full.len() <= 256).then_some(full)
}

/// What a provider tells us about the person who just signed in.
#[derive(Debug, Clone)]
pub struct Profile {
    /// Stable subject id at the provider. Never the email — that can change.
    pub subject: String,
    pub email: Option<String>,
    /// Whether the *provider* vouches for the address. Everything downstream
    /// hinges on this; see the module comment.
    pub email_verified: bool,
    pub name: Option<String>,
}

pub(crate) fn truthy(value: Option<&serde_json::Value>) -> bool {
    match value {
        Some(serde_json::Value::Bool(b)) => *b,
        Some(serde_json::Value::String(s)) => s.eq_ignore_ascii_case("true"),
        _ => false,
    }
}

/// POSTs a token request and reads the parts of the answer this crate uses.
/// `basic_auth` sends the client credentials as HTTP Basic instead of in the
/// form — what some custom IdPs require.
pub(crate) async fn post_token_form(
    url: &str,
    params: &[(&str, &str)],
    basic_auth: Option<(&str, &str)>,
) -> anyhow::Result<TokenSet> {
    #[derive(Deserialize)]
    struct TokenResponse {
        access_token: Option<String>,
        id_token: Option<String>,
        error: Option<String>,
        error_description: Option<String>,
    }

    let mut request = http()
        .post(url)
        // GitHub answers form-encoded unless asked for JSON; the OIDC
        // providers answer JSON either way.
        .header(reqwest::header::ACCEPT, "application/json")
        .form(params);
    if let Some((user, pass)) = basic_auth {
        request = request.basic_auth(user, Some(pass));
    }
    let response = request.send().await?;

    let status = response.status();
    let body = response.text().await?;
    let parsed: TokenResponse = serde_json::from_str(&body).map_err(|e| {
        // The body can carry the client secret back in an echo of the
        // request on some providers, so it is never logged or returned.
        anyhow::anyhow!("token endpoint returned unparseable body (status {status}): {e}")
    })?;

    if parsed.access_token.is_some() || parsed.id_token.is_some() {
        return Ok(TokenSet {
            access_token: parsed.access_token,
            id_token: parsed.id_token,
        });
    }
    let err = parsed.error.unwrap_or_else(|| status.to_string());
    let detail = parsed.error_description.unwrap_or_default();
    Err(anyhow::anyhow!("token endpoint refused: {err} {detail}"))
}

pub(crate) async fn get_json<T: serde::de::DeserializeOwned>(
    url: &str,
    access_token: &str,
) -> anyhow::Result<T> {
    let response = http()
        .get(url)
        .header(reqwest::header::ACCEPT, "application/json")
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {access_token}"),
        )
        // GitHub rejects requests without one.
        .header(reqwest::header::USER_AGENT, "signon")
        .send()
        .await?;
    let status = response.status();
    if !status.is_success() {
        return Err(anyhow::anyhow!("{url} returned {status}"));
    }
    Ok(response.json::<T>().await?)
}

pub(crate) fn http() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            // A provider endpoint never needs to redirect us, and following
            // one would let a misconfigured custom IdP point our token
            // request somewhere else.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("build reqwest client")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_keys_are_unique_and_lowercase() {
        let mut seen = std::collections::HashSet::new();
        for p in PROVIDERS {
            assert!(seen.insert(p.key), "duplicate provider key {}", p.key);
            assert_eq!(p.key, p.key.to_lowercase());
        }
    }

    #[test]
    fn all_seven_providers_are_registered() {
        for key in ["apple", "amazon", "google", "facebook", "linkedin", "github", "microsoft"] {
            assert!(provider_by_key(key).is_some(), "{key} missing");
        }
    }

    #[test]
    fn facebook_urls_use_the_pinned_graph_version() {
        let fb = provider_by_key("facebook").unwrap();
        for url in [fb.authorize_url, fb.token_url, fb.profile_url] {
            assert!(url.contains(FACEBOOK_GRAPH_VERSION), "{url}");
        }
    }

    #[test]
    fn only_amazon_facebook_and_microsoft_lack_email_verification() {
        let unverified: Vec<_> = PROVIDERS
            .iter()
            .filter(|p| !p.asserts_email_verification())
            .map(|p| p.key)
            .collect();
        assert_eq!(unverified, ["amazon", "facebook", "microsoft"]);
    }

    #[test]
    fn pkce_challenge_is_s256_of_the_verifier() {
        let (verifier, challenge) = pkce_pair();
        assert_eq!(
            challenge,
            URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
        );
        assert_ne!(verifier, challenge);
    }

    fn configured(key: &str) -> Configured {
        let secret = if key == "apple" {
            ClientSecret::Apple(AppleKey {
                team_id: "T".into(),
                key_id: "K".into(),
                private_key_pem: "pem".into(),
            })
        } else {
            ClientSecret::Static("secret".to_string())
        };
        Configured::new(
            key,
            "id with space",
            secret,
            format!("https://a.b/api/account/oauth/{key}/callback"),
        )
        .unwrap()
    }

    #[test]
    fn authorize_url_encodes_every_parameter() {
        let url = configured("github").authorize_url("st/ate", "chal+lenge", "n");
        assert!(url.contains("client_id=id%20with%20space"));
        assert!(url.contains(
            "redirect_uri=https%3A%2F%2Fa.b%2Fapi%2Faccount%2Foauth%2Fgithub%2Fcallback"
        ));
        assert!(url.contains("state=st%2Fate"));
        assert!(url.contains("code_challenge=chal%2Blenge"));
        assert!(url.contains("code_challenge_method=S256"));
        // The secret is never a query parameter.
        assert!(!url.contains("secret"));
        // GitHub takes neither a nonce nor a response mode.
        assert!(!url.contains("nonce="));
        assert!(!url.contains("response_mode="));
    }

    #[test]
    fn apple_authorize_url_asks_for_form_post_and_a_nonce_without_pkce() {
        let url = configured("apple").authorize_url("s", "c", "the-nonce");
        assert!(url.contains("response_mode=form_post"));
        assert!(url.contains("nonce=the-nonce"));
        assert!(url.contains("scope=name%20email"));
        assert!(!url.contains("code_challenge"));
    }

    #[test]
    fn configured_refuses_empty_or_mismatched_credentials() {
        assert!(Configured::new("google", "", ClientSecret::Static("s".into()), "r").is_none());
        assert!(Configured::new("google", "id", ClientSecret::Static(" ".into()), "r").is_none());
        assert!(Configured::new("nope", "id", ClientSecret::Static("s".into()), "r").is_none());
        // Apple needs a key, everyone else a static secret.
        assert!(Configured::new("apple", "id", ClientSecret::Static("s".into()), "r").is_none());
        let key = ClientSecret::Apple(AppleKey {
            team_id: "T".into(),
            key_id: "K".into(),
            private_key_pem: "p".into(),
        });
        assert!(Configured::new("google", "id", key, "r").is_none());
    }

    #[test]
    fn configured_debug_hides_secrets() {
        let c = Configured::new("google", "id", ClientSecret::Static("hunter2".into()), "r").unwrap();
        assert!(!format!("{c:?}").contains("hunter2"));
    }

    #[test]
    fn apple_name_is_read_from_the_first_authorization_user_field() {
        assert_eq!(
            apple_name(r#"{"name":{"firstName":"Jane","lastName":"Appleseed"},"email":"x@y.z"}"#),
            Some("Jane Appleseed".to_string())
        );
        assert_eq!(apple_name(r#"{"name":{"firstName":"Jane"}}"#), Some("Jane".to_string()));
        assert_eq!(apple_name(r#"{"email":"x@y.z"}"#), None);
        assert_eq!(apple_name("not json"), None);
    }

    #[test]
    fn email_verified_accepts_bool_and_string() {
        assert!(truthy(Some(&serde_json::json!(true))));
        assert!(truthy(Some(&serde_json::json!("true"))));
        assert!(!truthy(Some(&serde_json::json!(false))));
        assert!(!truthy(Some(&serde_json::json!("no"))));
        assert!(!truthy(None));
    }
}

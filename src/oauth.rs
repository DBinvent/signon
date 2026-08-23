//! OAuth2 / OIDC sign-in.
//!
//! One authorization-code flow with PKCE, described per provider by a table
//! entry rather than a module — adding a fourth provider is a `Provider`
//! literal plus, at most, a profile shape.
//!
//! Two rules that are the whole security story of this file:
//!
//! * **`state` is single-use and server-side.** It is generated per attempt,
//!   only its hash is stored, and the callback deletes the row in the same
//!   statement that reads it. A replayed callback finds nothing.
//! * **An account is only ever matched to an existing local account on a
//!   provider-*verified* email.** Skipping that check is a complete account
//!   takeover: register at the provider with the victim`s address, sign in,
//!   and get handed their account. The 2021 user-cabinet
//!   (`dbinvent-bo/backend/src/model/oauth.rs`) matched on the bare address.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

use crate::token;

/// How a provider`s profile endpoint answers.
#[derive(Clone, Copy, Debug)]
pub enum ProfileShape {
    /// OIDC `userinfo`: `sub`, `name`, `email`, `email_verified`.
    Oidc,
    /// GitHub is not OIDC: `GET /user` has no reliable email (it is `null`
    /// unless the user made one public — which the 2021 implementation did
    /// not account for), so the verified address comes from `/user/emails`.
    GitHub,
}

#[derive(Clone, Copy, Debug)]
pub struct Provider {
    pub key: &'static str,
    pub display_name: &'static str,
    pub authorize_url: &'static str,
    pub token_url: &'static str,
    pub profile_url: &'static str,
    /// Only meaningful for [`ProfileShape::GitHub`].
    pub emails_url: &'static str,
    pub scope: &'static str,
    pub shape: ProfileShape,
}

/// The registry. Everything provider-specific is here.
pub const PROVIDERS: &[Provider] = &[
    Provider {
        key: "github",
        display_name: "GitHub",
        authorize_url: "https://github.com/login/oauth/authorize",
        token_url: "https://github.com/login/oauth/access_token",
        profile_url: "https://api.github.com/user",
        emails_url: "https://api.github.com/user/emails",
        scope: "read:user user:email",
        shape: ProfileShape::GitHub,
    },
    Provider {
        key: "linkedin",
        display_name: "LinkedIn",
        authorize_url: "https://www.linkedin.com/oauth/v2/authorization",
        token_url: "https://www.linkedin.com/oauth/v2/accessToken",
        // OIDC. The `r_liteprofile` + `r_emailaddress` pair and the
        // /v2/me + /v2/clientAwareMemberHandles calls in
        // dbinvent-bo/backend/auth.md are LinkedIn`s retired flow — one
        // userinfo call replaces both.
        profile_url: "https://api.linkedin.com/v2/userinfo",
        emails_url: "",
        scope: "openid profile email",
        shape: ProfileShape::Oidc,
    },
    Provider {
        key: "google",
        display_name: "Google",
        authorize_url: "https://accounts.google.com/o/oauth2/v2/auth",
        token_url: "https://oauth2.googleapis.com/token",
        profile_url: "https://openidconnect.googleapis.com/v1/userinfo",
        emails_url: "",
        scope: "openid email profile",
        shape: ProfileShape::Oidc,
    },
];

pub fn provider_by_key(key: &str) -> Option<&'static Provider> {
    PROVIDERS.iter().find(|p| p.key == key)
}

/// A provider that this deployment actually has credentials for.
#[derive(Clone, Debug)]
pub struct Configured {
    pub provider: &'static Provider,
    pub client_id: String,
    client_secret: String,
    pub redirect_uri: String,
}

/// Reads `OAUTH_<KEY>_CLIENT_ID` / `OAUTH_<KEY>_CLIENT_SECRET` for each known
/// provider. A provider with no credentials is simply absent, so a site that
/// does not want SSO configures nothing and the frontend renders no buttons.
///
/// `api_base_url` is the public prefix that reaches this service — the
/// redirect URI registered with each provider must be
/// `<api_base_url>/account/oauth/<key>/callback`.
pub fn from_env(api_base_url: &str) -> Vec<Configured> {
    let mut out = Vec::new();
    for provider in PROVIDERS {
        let upper = provider.key.to_uppercase();
        let (Ok(client_id), Ok(client_secret)) = (
            std::env::var(format!("OAUTH_{upper}_CLIENT_ID")),
            std::env::var(format!("OAUTH_{upper}_CLIENT_SECRET")),
        ) else {
            continue;
        };
        if client_id.trim().is_empty() || client_secret.trim().is_empty() {
            continue;
        }
        let redirect_uri = std::env::var(format!("OAUTH_{upper}_REDIRECT_URI")).unwrap_or_else(|_| {
            format!("{}/account/oauth/{}/callback", api_base_url.trim_end_matches('/'), provider.key)
        });
        tracing::info!(provider = provider.key, %redirect_uri, "oauth provider configured");
        out.push(Configured { provider, client_id, client_secret, redirect_uri });
    }
    out
}

// ---- PKCE -----------------------------------------------------------------

/// `(verifier, challenge)` for PKCE S256.
///
/// GitHub`s OAuth Apps ignore PKCE; sending it anyway costs nothing and means
/// the flow does not branch per provider. For the OIDC providers it is what
/// stops a stolen authorization code from being redeemed by anyone but the
/// browser that started the flow.
pub fn pkce_pair() -> (String, String) {
    let verifier = token::secret();
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

impl Configured {
    pub fn authorize_url(&self, state: &str, challenge: &str) -> String {
        let enc = urlencoding::encode;
        format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}\
             &code_challenge={}&code_challenge_method=S256",
            self.provider.authorize_url,
            enc(&self.client_id),
            enc(&self.redirect_uri),
            enc(self.provider.scope),
            enc(state),
            enc(challenge),
        )
    }

    /// Authorization code -> access token.
    pub async fn exchange_code(&self, code: &str, verifier: &str) -> anyhow::Result<String> {
        #[derive(Deserialize)]
        struct TokenResponse {
            access_token: Option<String>,
            error: Option<String>,
            error_description: Option<String>,
        }

        let params = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", self.redirect_uri.as_str()),
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.as_str()),
            ("code_verifier", verifier),
        ];

        let response = http()
            .post(self.provider.token_url)
            // GitHub answers form-encoded unless asked for JSON; the OIDC
            // providers answer JSON either way.
            .header(reqwest::header::ACCEPT, "application/json")
            .form(&params)
            .send()
            .await?;

        let status = response.status();
        let body = response.text().await?;
        let parsed: TokenResponse = serde_json::from_str(&body).map_err(|e| {
            // The body can carry the client secret back in an echo of the
            // request on some providers, so it is never logged or returned.
            anyhow::anyhow!("token endpoint returned unparseable body (status {status}): {e}")
        })?;

        if let Some(token) = parsed.access_token {
            return Ok(token);
        }
        let err = parsed.error.unwrap_or_else(|| status.to_string());
        let detail = parsed.error_description.unwrap_or_default();
        Err(anyhow::anyhow!("token endpoint refused: {err} {detail}"))
    }

    /// Access token -> the three facts this crate needs about the user.
    pub async fn fetch_profile(&self, access_token: &str) -> anyhow::Result<Profile> {
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
                let profile: Oidc = get_json(self.provider.profile_url, access_token).await?;
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
                let user: GhUser = get_json(self.provider.profile_url, access_token).await?;
                let emails: Vec<GhEmail> = get_json(self.provider.emails_url, access_token)
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
        }
    }
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

fn truthy(value: Option<&serde_json::Value>) -> bool {
    match value {
        Some(serde_json::Value::Bool(b)) => *b,
        Some(serde_json::Value::String(s)) => s.eq_ignore_ascii_case("true"),
        _ => false,
    }
}

async fn get_json<T: serde::de::DeserializeOwned>(
    url: &str,
    access_token: &str,
) -> anyhow::Result<T> {
    let response = http()
        .get(url)
        .header(reqwest::header::ACCEPT, "application/json")
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {access_token}"))
        // GitHub rejects requests without one.
        .header(reqwest::header::USER_AGENT, "user_mgmt")
        .send()
        .await?;
    let status = response.status();
    if !status.is_success() {
        return Err(anyhow::anyhow!("{url} returned {status}"));
    }
    Ok(response.json::<T>().await?)
}

fn http() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
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
    fn pkce_challenge_is_s256_of_the_verifier() {
        let (verifier, challenge) = pkce_pair();
        assert_eq!(challenge, URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())));
        assert_ne!(verifier, challenge);
    }

    #[test]
    fn authorize_url_encodes_every_parameter() {
        let cfg = Configured {
            provider: provider_by_key("github").unwrap(),
            client_id: "id with space".to_string(),
            client_secret: "secret".to_string(),
            redirect_uri: "https://a.b/api/account/oauth/github/callback".to_string(),
        };
        let url = cfg.authorize_url("st/ate", "chal+lenge");
        assert!(url.contains("client_id=id%20with%20space"));
        assert!(url.contains("redirect_uri=https%3A%2F%2Fa.b%2Fapi%2Faccount%2Foauth%2Fgithub%2Fcallback"));
        assert!(url.contains("state=st%2Fate"));
        assert!(url.contains("code_challenge=chal%2Blenge"));
        assert!(url.contains("code_challenge_method=S256"));
        // The secret is never a query parameter.
        assert!(!url.contains("secret"));
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

//! A generic OpenID Connect relying party, for customer-configured IdPs —
//! a library: an SSO service drives it (feature `sso`).
//!
//! The social providers in `oauth.rs` are a fixed table we wrote by hand. A
//! customer IdP is whatever the customer pointed us at, so everything here is
//! learned from its discovery document — and checked against what the
//! customer *said* the issuer was, because a discovery document that names a
//! different issuer is either a misconfiguration or an attempt to borrow
//! someone else's.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde::Deserialize;

use crate::jwt::{self, IdClaims};
use crate::oauth::{self, TokenSet};

/// One customer IdP, as the relying party needs it.
#[derive(Clone)]
pub struct OidcSettings {
    /// Exactly as the customer entered it and as discovery confirmed it —
    /// compared byte for byte with `iss`.
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    /// `openid email profile` when `None`.
    pub scopes: Option<String>,
}

/// Hand-written so the client secret can never reach a log line through
/// `{:?}` — DESIGN.md §4.
impl std::fmt::Debug for OidcSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcSettings")
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field("client_secret", &"<redacted>")
            .field("scopes", &self.scopes)
            .finish()
    }
}

const DISCOVERY_TTL: Duration = Duration::from_secs(3600);

/// The parts of `/.well-known/openid-configuration` this crate uses.
#[derive(Debug, Clone, Deserialize)]
pub struct Discovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    #[serde(default)]
    pub userinfo_endpoint: Option<String>,
    #[serde(default)]
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    /// RFC 9207. When advertised, the callback must carry `iss` and it must
    /// match — the cheap, standard half of the mix-up defence.
    #[serde(default)]
    pub authorization_response_iss_parameter_supported: Option<bool>,
}

fn cache() -> &'static Mutex<HashMap<String, (Instant, Discovery)>> {
    static CACHE: OnceLock<Mutex<HashMap<String, (Instant, Discovery)>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The discovery URL for an issuer, per OIDC Discovery §4.
pub fn discovery_url(issuer: &str) -> String {
    format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    )
}

/// Fetches and validates an issuer's discovery document, bypassing the
/// cache. For the "check" button where a customer configures a connection:
/// an issuer that fails here can never sign anyone in.
pub async fn discover_fresh(issuer: &str) -> anyhow::Result<Discovery> {
    let url = discovery_url(issuer);
    let response = oauth::http()
        .get(&url)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await?;
    let status = response.status();
    if !status.is_success() {
        anyhow::bail!("{url} returned {status}");
    }
    let doc: Discovery = response.json().await?;
    // OIDC Discovery §4.3: the issuer in the document MUST be identical to
    // the one used to fetch it.
    if doc.issuer != issuer {
        anyhow::bail!(
            "discovery document names issuer {:?}, not the configured {:?}",
            doc.issuer,
            issuer
        );
    }
    for (name, url) in [
        ("authorization_endpoint", &doc.authorization_endpoint),
        ("token_endpoint", &doc.token_endpoint),
        ("jwks_uri", &doc.jwks_uri),
    ] {
        if !secure_url(url) {
            anyhow::bail!("{name} is not an https URL");
        }
    }
    cache()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(issuer.to_string(), (Instant::now(), doc.clone()));
    Ok(doc)
}

pub async fn discover(issuer: &str) -> anyhow::Result<Discovery> {
    {
        let cache = cache().lock().unwrap_or_else(|p| p.into_inner());
        if let Some((at, doc)) = cache.get(issuer) {
            if at.elapsed() < DISCOVERY_TTL {
                return Ok(doc.clone());
            }
        }
    }
    discover_fresh(issuer).await
}

/// `https://` always. Plain `http://` only to a loopback address, which is
/// what the test suite's mock IdP listens on — never reachable from outside
/// the host, so never something a customer can configure for real.
fn secure_url(url: &str) -> bool {
    url.starts_with("https://")
        || url.starts_with("http://127.0.0.1:")
        || url.starts_with("http://localhost:")
}

impl Discovery {
    /// Builds the authorization request.
    pub fn authorize_url(
        &self,
        settings: &OidcSettings,
        redirect_uri: &str,
        state: &str,
        nonce: &str,
        challenge: &str,
        login_hint: Option<&str>,
    ) -> String {
        let enc = urlencoding::encode;
        let scope = settings.scopes.as_deref().unwrap_or("openid email profile");
        let sep = if self.authorization_endpoint.contains('?') { '&' } else { '?' };
        let mut url = format!(
            "{}{sep}response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&nonce={}\
             &code_challenge={}&code_challenge_method=S256",
            self.authorization_endpoint,
            enc(&settings.client_id),
            enc(redirect_uri),
            enc(scope),
            enc(state),
            enc(nonce),
            enc(challenge),
        );
        if let Some(hint) = login_hint {
            url.push_str(&format!("&login_hint={}", enc(hint)));
        }
        url
    }

    /// Code -> tokens, authenticating the way the IdP says it accepts:
    /// `client_secret_basic` unless only `client_secret_post` is offered.
    pub async fn exchange_code(
        &self,
        settings: &OidcSettings,
        redirect_uri: &str,
        code: &str,
        verifier: &str,
    ) -> anyhow::Result<TokenSet> {
        let methods = self.token_endpoint_auth_methods_supported.as_deref();
        // Absent means `client_secret_basic` (OIDC Discovery §3).
        let basic = methods.is_none_or(|m| m.iter().any(|x| x == "client_secret_basic"));
        let mut params = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("code_verifier", verifier),
        ];
        if !basic {
            params.push(("client_id", settings.client_id.as_str()));
            params.push(("client_secret", settings.client_secret.as_str()));
        }
        // RFC 6749 §2.3.1: Basic credentials are form-urlencoded first.
        let user = urlencoding::encode(&settings.client_id).into_owned();
        let pass = urlencoding::encode(&settings.client_secret).into_owned();
        let auth = basic.then_some((user.as_str(), pass.as_str()));
        oauth::post_token_form(&self.token_endpoint, &params, auth).await
    }

    /// Verifies the `id_token` and, when it carries no email, asks userinfo
    /// for one. The subject must agree between the two (OIDC Core §5.3.2) —
    /// otherwise userinfo could graft another person's address onto this
    /// sign-in.
    pub async fn identify(
        &self,
        settings: &OidcSettings,
        tokens: &TokenSet,
        nonce: &str,
    ) -> anyhow::Result<IdClaims> {
        let id_token = tokens
            .id_token
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("IdP returned no id_token"))?;
        let mut claims = jwt::verify_id_token(
            id_token,
            &self.jwks_uri,
            &settings.issuer,
            &settings.client_id,
            Some(nonce),
        )
        .await?;
        if claims.email.is_none() {
            if let (Some(url), Some(access)) = (&self.userinfo_endpoint, &tokens.access_token) {
                #[derive(Deserialize)]
                struct UserInfo {
                    sub: String,
                    email: Option<String>,
                    name: Option<String>,
                }
                let info: UserInfo = oauth::get_json(url, access).await?;
                if info.sub != claims.sub {
                    anyhow::bail!("userinfo subject does not match the id_token");
                }
                claims.email = info.email;
                claims.name = claims.name.or(info.name);
            }
        }
        Ok(claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oidc_settings_debug_hides_the_secret() {
        let s = OidcSettings {
            issuer: "i".into(),
            client_id: "c".into(),
            client_secret: "hunter2".into(),
            scopes: None,
        };
        assert!(!format!("{s:?}").contains("hunter2"));
    }

    #[test]
    fn discovery_url_handles_a_trailing_slash() {
        assert_eq!(
            discovery_url("https://idp.acme.com/"),
            "https://idp.acme.com/.well-known/openid-configuration"
        );
        assert_eq!(
            discovery_url("https://login.microsoftonline.com/tid/v2.0"),
            "https://login.microsoftonline.com/tid/v2.0/.well-known/openid-configuration"
        );
    }

    #[test]
    fn only_https_or_loopback_endpoints_are_accepted() {
        assert!(secure_url("https://idp.acme.com/token"));
        assert!(secure_url("http://127.0.0.1:8080/token"));
        assert!(!secure_url("http://idp.acme.com/token"));
        assert!(!secure_url("http://127.0.0.1.evil.com/token"));
        assert!(!secure_url("javascript:alert(1)"));
    }

    #[test]
    fn authorize_url_carries_nonce_pkce_and_login_hint() {
        let d = Discovery {
            issuer: "https://idp".into(),
            authorization_endpoint: "https://idp/authorize?tenant=1".into(),
            token_endpoint: "https://idp/token".into(),
            jwks_uri: "https://idp/jwks".into(),
            userinfo_endpoint: None,
            token_endpoint_auth_methods_supported: None,
            authorization_response_iss_parameter_supported: None,
        };
        let s = OidcSettings {
            issuer: "https://idp".into(),
            client_id: "cid".into(),
            client_secret: "sec".into(),
            scopes: None,
        };
        let url = d.authorize_url(&s, "https://r/cb", "st", "no", "ch", Some("bob@acme.com"));
        assert!(url.starts_with("https://idp/authorize?tenant=1&response_type=code"));
        assert!(url.contains("nonce=no"));
        assert!(url.contains("code_challenge=ch"));
        assert!(url.contains("login_hint=bob%40acme.com"));
        assert!(url.contains("scope=openid%20email%20profile"));
        assert!(!url.contains("sec"));
    }
}

//! `id_token` verification and Apple's client-secret JWT.
//!
//! Used by Apple sign-in and by every customer OIDC connection, so it is the
//! one place where "is this assertion really from the IdP, for us, for this
//! attempt" is decided:
//!
//! * the signing key comes from the IdP's JWKS, fetched by us over TLS from a
//!   URL we were configured with — never from the token itself;
//! * the algorithm must be an asymmetric one we accept *and* match the key the
//!   `kid` names; `none` and every HMAC algorithm are refused, which is what
//!   closes the "sign with the public key as an HMAC secret" confusion;
//! * `iss`, `aud`, `exp` and `nonce` are all required and all checked.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;

use crate::oauth::AppleKey;

/// Asymmetric algorithms only. An `id_token` is verified with a *public* key;
/// accepting anything symmetric would let anyone holding that public key mint
/// tokens.
const ACCEPTED: &[Algorithm] = &[
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
    Algorithm::ES256,
    Algorithm::ES384,
];

/// Clock skew allowed on `exp`/`nbf`/`iat`.
const LEEWAY_SECS: u64 = 60;
/// How long a fetched JWKS is trusted before it is fetched again.
const JWKS_TTL: Duration = Duration::from_secs(3600);
/// A `kid` we have not seen triggers a refetch (the IdP rotated keys), but at
/// most this often — otherwise a stream of tokens with made-up `kid`s turns
/// into a stream of requests to the IdP.
const JWKS_MIN_REFETCH: Duration = Duration::from_secs(60);

/// The claims this crate reads out of a verified `id_token`.
#[derive(Debug, Clone, Deserialize)]
pub struct IdClaims {
    pub sub: String,
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: Option<serde_json::Value>,
    pub name: Option<String>,
    pub nonce: Option<String>,
    pub azp: Option<String>,
}

struct CachedJwks {
    fetched_at: Instant,
    keys: JwkSet,
}

/// The crypto backend of jsonwebtoken, where it would pick none: a build with both `jwt-rust-crypto` and
/// `jwt-aws-lc` (`--all-features`, or a host whose own jsonwebtoken has the other one). The pure-Rust one
/// is named then, once - unless the host named its own first, which stands. With one backend built in,
/// jsonwebtoken takes it by itself and this does nothing.
pub(crate) fn backend() {
    #[cfg(all(feature = "jwt-rust-crypto", feature = "jwt-aws-lc"))]
    {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            let _ = jsonwebtoken::crypto::rust_crypto::DEFAULT_PROVIDER.install_default();
        });
    }
}

fn jwks_cache() -> &'static Mutex<HashMap<String, CachedJwks>> {
    static CACHE: OnceLock<Mutex<HashMap<String, CachedJwks>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

async fn fetch_jwks(url: &str) -> anyhow::Result<JwkSet> {
    let response = crate::oauth::http()
        .get(url)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await?;
    let status = response.status();
    if !status.is_success() {
        anyhow::bail!("jwks {url} returned {status}");
    }
    Ok(response.json::<JwkSet>().await?)
}

/// The JWK named by `kid`, from cache or freshly fetched.
async fn key_for(jwks_url: &str, kid: Option<&str>) -> anyhow::Result<jsonwebtoken::jwk::Jwk> {
    let pick = |set: &JwkSet| -> Option<jsonwebtoken::jwk::Jwk> {
        match kid {
            Some(kid) => set.find(kid).cloned(),
            // No `kid` is legal only when there is exactly one key to mean.
            None if set.keys.len() == 1 => set.keys.first().cloned(),
            None => None,
        }
    };

    let refetch = {
        let cache = jwks_cache().lock().unwrap_or_else(|p| p.into_inner());
        match cache.get(jwks_url) {
            Some(cached) if cached.fetched_at.elapsed() < JWKS_TTL => {
                if let Some(key) = pick(&cached.keys) {
                    return Ok(key);
                }
                cached.fetched_at.elapsed() >= JWKS_MIN_REFETCH
            }
            _ => true,
        }
    };
    if !refetch {
        anyhow::bail!("id_token names a key the IdP does not publish");
    }

    let fresh = fetch_jwks(jwks_url).await?;
    let key = pick(&fresh);
    jwks_cache()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(
            jwks_url.to_string(),
            CachedJwks {
                fetched_at: Instant::now(),
                keys: fresh,
            },
        );
    key.ok_or_else(|| anyhow::anyhow!("id_token names a key the IdP does not publish"))
}

/// Verifies an `id_token` and returns its claims.
///
/// `expected_nonce` is required whenever the flow sent one — which every flow
/// in this crate that reaches here does.
pub async fn verify_id_token(
    token: &str,
    jwks_url: &str,
    issuer: &str,
    audience: &str,
    expected_nonce: Option<&str>,
) -> anyhow::Result<IdClaims> {
    backend();
    let header = jsonwebtoken::decode_header(token)?;
    if !ACCEPTED.contains(&header.alg) {
        anyhow::bail!("id_token algorithm {:?} is not accepted", header.alg);
    }
    let jwk = key_for(jwks_url, header.kid.as_deref()).await?;
    // A JWK that pins its own algorithm must agree with the header — the
    // other half of refusing an attacker's choice of algorithm.
    if let Some(pinned) = jwk.common.key_algorithm {
        if format!("{pinned:?}") != format!("{:?}", header.alg) {
            anyhow::bail!("id_token algorithm does not match the key's");
        }
    }
    let key = DecodingKey::from_jwk(&jwk)?;

    let mut validation = Validation::new(header.alg);
    validation.algorithms = vec![header.alg];
    validation.leeway = LEEWAY_SECS;
    validation.validate_nbf = true;
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[audience]);
    validation.required_spec_claims = ["exp", "iss", "aud", "sub"]
        .into_iter()
        .map(String::from)
        .collect();

    let data = jsonwebtoken::decode::<IdClaims>(token, &key, &validation)?;
    let claims = data.claims;

    // `azp`, when present, names the party the token was issued to; with
    // several audiences it is the one that matters.
    if let Some(azp) = &claims.azp {
        if azp != audience {
            anyhow::bail!("id_token was issued to another party");
        }
    }
    if let Some(expected) = expected_nonce {
        if claims.nonce.as_deref() != Some(expected) {
            anyhow::bail!("id_token nonce does not match this attempt");
        }
    }
    Ok(claims)
}

/// Apple's client secret: an ES256 JWT signed with the `.p8` key.
///
/// One day of validity — Apple accepts up to six months, but a secret minted
/// per exchange has no reason to outlive the exchange by much, and a short one
/// is worthless to anyone who captures it from a log.
pub fn apple_client_secret(key: &AppleKey, client_id: &str) -> anyhow::Result<String> {
    backend();
    #[derive(serde::Serialize)]
    struct Claims<'a> {
        iss: &'a str,
        iat: u64,
        exp: u64,
        aud: &'a str,
        sub: &'a str,
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let mut header = jsonwebtoken::Header::new(Algorithm::ES256);
    header.kid = Some(key.key_id.clone());
    let encoding = jsonwebtoken::EncodingKey::from_ec_pem(key.private_key_pem.as_bytes())
        .map_err(|e| anyhow::anyhow!("apple private key is not a usable ES256 PEM: {e}"))?;
    Ok(jsonwebtoken::encode(
        &header,
        &Claims {
            iss: &key.team_id,
            iat: now,
            exp: now + 24 * 3600,
            aud: "https://appleid.apple.com",
            sub: client_id,
        },
        &encoding,
    )?)
}

#[cfg(any(test, feature = "test-support"))]
pub mod test_keys {
    //! The P-256 key of the tests' identity provider: the PKCS#8 PEM and its public JWK.
    //! It is not in the repository: `openssl` makes it the first time a test asks
    //! (`crate::fixture_keys`), and it is never used for anything but these tests.
    use crate::fixture_keys::ec;

    pub fn ec_private_pem() -> &'static str {
        &ec().pem
    }

    pub fn ec_jwk_x() -> &'static str {
        &ec().x
    }

    pub fn ec_jwk_y() -> &'static str {
        &ec().y
    }

    pub fn jwks(kid: &str) -> serde_json::Value {
        serde_json::json!({
            "keys": [{
                "kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256", "kid": kid,
                "x": ec_jwk_x(), "y": ec_jwk_y(),
            }]
        })
    }

    pub fn sign(kid: &str, claims: &serde_json::Value) -> String {
        super::backend();
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        header.kid = Some(kid.to_string());
        let key = jsonwebtoken::EncodingKey::from_ec_pem(ec_private_pem().as_bytes()).unwrap();
        jsonwebtoken::encode(&header, claims, &key).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_keys::*;

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Serves `jwks` at `/jwks` on an ephemeral port; returns its URL.
    async fn serve_jwks(jwks: serde_json::Value) -> String {
        let app = axum::Router::new().route(
            "/jwks",
            axum::routing::get(move || {
                let jwks = jwks.clone();
                async move { axum::Json(jwks) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}/jwks")
    }

    fn claims(overrides: serde_json::Value) -> serde_json::Value {
        let mut base = serde_json::json!({
            "iss": "https://idp.test", "aud": "client-1", "sub": "user-1",
            "exp": now() + 300, "iat": now(), "nonce": "n-1",
            "email": "bob@acme.com", "email_verified": true,
        });
        for (k, v) in overrides.as_object().unwrap() {
            if v.is_null() {
                base.as_object_mut().unwrap().remove(k);
            } else {
                base[k] = v.clone();
            }
        }
        base
    }

    async fn verify(token: &str, url: &str) -> anyhow::Result<IdClaims> {
        verify_id_token(token, url, "https://idp.test", "client-1", Some("n-1")).await
    }

    #[tokio::test]
    async fn a_good_token_verifies() {
        let url = serve_jwks(jwks("k1")).await;
        let c = verify(&sign("k1", &claims(serde_json::json!({}))), &url)
            .await
            .unwrap();
        assert_eq!(c.sub, "user-1");
        assert_eq!(c.email.as_deref(), Some("bob@acme.com"));
    }

    #[tokio::test]
    async fn sso03_every_bad_claim_is_refused() {
        let url = serve_jwks(jwks("k2")).await;
        for (case, overrides) in [
            ("wrong iss", serde_json::json!({"iss": "https://evil.test"})),
            ("wrong aud", serde_json::json!({"aud": "client-2"})),
            ("expired", serde_json::json!({"exp": now() - 3600})),
            ("not yet valid", serde_json::json!({"nbf": now() + 3600})),
            ("wrong nonce", serde_json::json!({"nonce": "n-2"})),
            ("no nonce", serde_json::json!({"nonce": null})),
            ("no exp", serde_json::json!({"exp": null})),
            ("azp for another party", serde_json::json!({"azp": "client-2"})),
        ] {
            let token = sign("k2", &claims(overrides));
            assert!(verify(&token, &url).await.is_err(), "{case} was accepted");
        }
    }

    #[tokio::test]
    async fn sso03_a_tampered_signature_is_refused() {
        let url = serve_jwks(jwks("k3")).await;
        let token = sign("k3", &claims(serde_json::json!({})));
        let mut parts: Vec<String> = token.split('.').map(String::from).collect();
        // Swap the payload for one claiming another subject; keep the old
        // signature.
        let forged = sign("k3", &claims(serde_json::json!({"sub": "admin"})));
        parts[1] = forged.split('.').nth(1).unwrap().to_string();
        assert!(verify(&parts.join("."), &url).await.is_err());
    }

    #[tokio::test]
    async fn sso03_hmac_and_none_are_refused_whatever_the_key() {
        let url = serve_jwks(jwks("k4")).await;
        // HS256 "signed" with the public key's x coordinate — the classic
        // algorithm-confusion attempt.
        backend();
        let mut header = jsonwebtoken::Header::new(Algorithm::HS256);
        header.kid = Some("k4".into());
        let hs = jsonwebtoken::encode(
            &header,
            &claims(serde_json::json!({})),
            &jsonwebtoken::EncodingKey::from_secret(ec_jwk_x().as_bytes()).unwrap(),
        )
        .unwrap();
        assert!(verify(&hs, &url).await.is_err());

        let none = format!(
            "{}.{}.",
            base64_url(r#"{"alg":"none","kid":"k4"}"#),
            base64_url(&claims(serde_json::json!({})).to_string())
        );
        assert!(verify(&none, &url).await.is_err());
    }

    #[tokio::test]
    async fn an_unknown_kid_is_refused() {
        let url = serve_jwks(jwks("k5")).await;
        let token = sign("someone-elses-key", &claims(serde_json::json!({})));
        assert!(verify(&token, &url).await.is_err());
    }

    #[test]
    fn apple_client_secret_is_an_es256_jwt_for_apple() {
        let key = AppleKey {
            team_id: "TEAM123".into(),
            key_id: "KEY123".into(),
            private_key_pem: ec_private_pem().into(),
        };
        let secret = apple_client_secret(&key, "com.example.web").unwrap();
        let header = jsonwebtoken::decode_header(&secret).unwrap();
        assert_eq!(header.alg, Algorithm::ES256);
        assert_eq!(header.kid.as_deref(), Some("KEY123"));
        let jwk: jsonwebtoken::jwk::Jwk =
            serde_json::from_value(jwks("x")["keys"][0].clone()).unwrap();
        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_audience(&["https://appleid.apple.com"]);
        validation.set_issuer(&["TEAM123"]);
        let data = jsonwebtoken::decode::<serde_json::Value>(
            &secret,
            &DecodingKey::from_jwk(&jwk).unwrap(),
            &validation,
        )
        .unwrap();
        assert_eq!(data.claims["sub"], "com.example.web");
    }

    fn base64_url(s: &str) -> String {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s)
    }
}

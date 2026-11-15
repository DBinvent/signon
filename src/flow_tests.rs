//! End-to-end sign-in flows: the real router, a real Postgres, and an
//! in-process mock IdP / provider on a loopback port. Case ids are
//! `SSO.md`'s.
//!
//! Needs a scratch database — `SIGNON_TEST_DB`, or by default
//! `postgres:///signon_test` over the local socket. Without one every
//! test here prints a note and passes, so the crate still tests clean on a
//! machine with no Postgres. Rows are never cleaned up; every test uses
//! addresses and slugs of its own.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{header, HeaderMap, Request, StatusCode};
use axum::routing::{get, post};
use axum::Router;
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

use crate::jwt::test_keys;
use crate::oauth::{AppleKey, ClientSecret, Configured, Endpoints};
use crate::sso::SsoSnapshot;
use crate::{AccountState, Config, Mailer};

const SITE: &str = "https://register.test";

// ---- harness -------------------------------------------------------------------

static MIGRATED: tokio::sync::OnceCell<bool> = tokio::sync::OnceCell::const_new();

async fn pool() -> Option<sqlx::PgPool> {
    let url = std::env::var("SIGNON_TEST_DB")
        .unwrap_or_else(|_| "postgres:///signon_test?host=/var/run/postgresql".to_string());
    let ok = *MIGRATED
        .get_or_init(|| async {
            // Skip only when there is no database to talk to. Once one
            // answers, a migration failure is a real failure — a broken
            // schema.yaml must not pass as "skipped".
            if let Err(e) = sqlx::postgres::PgPoolOptions::new()
                .max_connections(1)
                .connect(&url)
                .await
            {
                eprintln!("flow tests skipped: no test database ({e})");
                return false;
            }
            crate::migrate(&url).await.expect("apply schema.yaml to the test database");
            true
        })
        .await;
    if !ok {
        return None;
    }
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .ok()
}

struct Harness {
    state: AccountState,
    app: Router,
    idp: MockIdp,
}

async fn harness() -> Option<Harness> {
    let pool = pool().await?;
    let config = Config::new("TEST", SITE);
    let state = AccountState::from_env_with_mailer(pool, config, Mailer::disabled())
        .await
        .unwrap();
    // Nothing from this process's environment leaks into a test.
    state.sso.replace(SsoSnapshot::default());
    let app = Router::new().nest("/account", crate::router(state.clone()));
    Some(Harness {
        state,
        app,
        idp: MockIdp::start().await,
    })
}

macro_rules! harness_or_skip {
    () => {
        match harness().await {
            Some(h) => h,
            None => return,
        }
    };
}

fn unique(prefix: &str) -> String {
    format!("{prefix}{}", &Uuid::new_v4().simple().to_string()[..10])
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: Value,
}

impl Reply {
    fn location(&self) -> String {
        self.headers
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string()
    }

    /// The `signon_session=…` pair, if this reply set one.
    fn session(&self) -> Option<String> {
        self.headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find(|c| c.starts_with("signon_session=") && !c.starts_with("signon_session=;"))
            .map(|c| c.split(';').next().unwrap().to_string())
    }
}

impl Harness {
    async fn send(&self, request: Request<Body>) -> Reply {
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap();
        let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        Reply { status, headers, body }
    }

    async fn get(&self, path: &str, cookie: Option<&str>) -> Reply {
        let mut req = Request::get(path);
        if let Some(c) = cookie {
            req = req.header(header::COOKIE, c);
        }
        self.send(req.body(Body::empty()).unwrap()).await
    }

    async fn post_json(&self, path: &str, body: Value) -> Reply {
        self.send(
            Request::post(path)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ORIGIN, SITE)
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
    }

    async fn post_form(&self, path: &str, form: &[(&str, &str)], origin: &str) -> Reply {
        let body = form
            .iter()
            .map(|(k, v)| format!("{k}={}", urlencoding::encode(v)))
            .collect::<Vec<_>>()
            .join("&");
        self.send(
            Request::post(path)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::ORIGIN, origin)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
    }

    async fn me(&self, cookie: &str) -> Reply {
        self.get("/account/me", Some(cookie)).await
    }

    fn snapshot(&self, providers: Vec<Configured>) {
        self.state.sso.replace(SsoSnapshot {
            providers,
            version: unique("v"),
        });
    }

    async fn session_via(&self, user_id: Uuid) -> Vec<String> {
        sqlx::query_scalar::<_, Option<String>>("SELECT via FROM sessions WHERE user_id = $1")
            .bind(user_id)
            .fetch_all(&self.state.pool)
            .await
            .unwrap()
            .into_iter()
            .flatten()
            .collect()
    }

    async fn user_id(&self, email: &str) -> Option<Uuid> {
        crate::user_id_by_email(&self.state.pool, email).await.unwrap()
    }
}

/// `name=value` pairs out of a URL's query string.
fn query_of(url: &str) -> HashMap<String, String> {
    url.split_once('?')
        .map(|(_, q)| q)
        .unwrap_or_default()
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.to_string(), urlencoding::decode(v).unwrap().into_owned()))
        .collect()
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// ---- mock IdP / provider -------------------------------------------------------

#[derive(Default)]
struct MockState {
    /// code -> (id_token claims, profile JSON)
    grants: HashMap<String, (Option<Value>, Value)>,
    /// access token -> profile JSON
    profiles: HashMap<String, Value>,
    /// How the last token request authenticated: "basic", "post" or "apple-jwt".
    last_auth: Option<String>,
}

#[derive(Clone)]
struct MockIdp {
    base: String,
    state: Arc<Mutex<MockState>>,
}

const MOCK_KID: &str = "mock-kid";

impl MockIdp {
    async fn start() -> Self {
        let state = Arc::new(Mutex::new(MockState::default()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());

        let discovery = {
            let base = base.clone();
            move || {
                let base = base.clone();
                async move {
                    axum::Json(json!({
                        "issuer": base,
                        "authorization_endpoint": format!("{base}/authorize"),
                        "token_endpoint": format!("{base}/token"),
                        "jwks_uri": format!("{base}/jwks"),
                        "userinfo_endpoint": format!("{base}/profile"),
                        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
                    }))
                }
            }
        };
        let token = {
            let state = state.clone();
            move |headers: HeaderMap, axum::Form(form): axum::Form<HashMap<String, String>>| {
                let state = state.clone();
                async move {
                    let mut s = state.lock().unwrap();
                    s.last_auth = Some(if headers.contains_key(header::AUTHORIZATION) {
                        "basic".into()
                    } else if form.get("client_secret").is_some_and(|c| c.matches('.').count() == 2) {
                        "apple-jwt".into()
                    } else {
                        "post".into()
                    });
                    let Some((claims, profile)) = form.get("code").and_then(|c| s.grants.remove(c)) else {
                        return (StatusCode::BAD_REQUEST, axum::Json(json!({"error": "invalid_grant"})));
                    };
                    let access = Uuid::new_v4().to_string();
                    s.profiles.insert(access.clone(), profile);
                    let mut body = json!({"access_token": access, "token_type": "Bearer"});
                    if let Some(claims) = claims {
                        body["id_token"] = json!(test_keys::sign(MOCK_KID, &claims));
                    }
                    (StatusCode::OK, axum::Json(body))
                }
            }
        };
        let profile = {
            let state = state.clone();
            move |headers: HeaderMap| {
                let state = state.clone();
                async move {
                    let bearer = headers
                        .get(header::AUTHORIZATION)
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.strip_prefix("Bearer "))
                        .unwrap_or_default()
                        .to_string();
                    match state.lock().unwrap().profiles.get(&bearer) {
                        Some(p) => (StatusCode::OK, axum::Json(p.clone())),
                        None => (StatusCode::UNAUTHORIZED, axum::Json(json!({}))),
                    }
                }
            }
        };
        let app = Router::new()
            .route("/.well-known/openid-configuration", get(discovery))
            .route("/jwks", get(|| async { axum::Json(test_keys::jwks(MOCK_KID)) }))
            .route("/token", post(token))
            .route("/profile", get(profile));
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self { base, state }
    }

    /// Registers what the token endpoint answers for a fresh code.
    fn grant(&self, id_token_claims: Option<Value>, profile: Value) -> String {
        let code = Uuid::new_v4().to_string();
        self.state
            .lock()
            .unwrap()
            .grants
            .insert(code.clone(), (id_token_claims, profile));
        code
    }

    fn endpoints(&self, issuer: &str) -> Endpoints {
        Endpoints {
            authorize: format!("{}/authorize", self.base),
            token: format!("{}/token", self.base),
            profile: format!("{}/profile", self.base),
            emails: String::new(),
            issuer: issuer.to_string(),
            jwks: format!("{}/jwks", self.base),
        }
    }

    fn last_auth(&self) -> Option<String> {
        self.state.lock().unwrap().last_auth.clone()
    }
}

fn social(h: &Harness, key: &str, secret: ClientSecret, issuer: &str) -> Configured {
    Configured::new(
        key,
        format!("{key}-client"),
        secret,
        crate::oauth::redirect_uri_for(&format!("{SITE}/api"), key),
    )
    .unwrap()
    .with_endpoints(h.idp.endpoints(issuer))
}

// ---- SSO-01 ----------------------------------------------------------------------

#[tokio::test]
async fn sso01_providers_come_from_the_live_snapshot() {
    let h = harness_or_skip!();
    let r = h.get("/account/oauth", None).await;
    assert_eq!(r.body["providers"], json!([]));
    assert_eq!(r.body["custom_sso"], json!(false));

    let google = social(&h, "google", ClientSecret::Static("s".into()), "");
    h.snapshot(vec![google]);
    let r = h.get("/account/oauth", None).await;
    assert_eq!(r.body["providers"][0]["key"], "google");

    // Disabled (absent from the snapshot) means no start and no callback.
    h.snapshot(vec![]);
    assert_eq!(h.get("/account/oauth/google/start", None).await.status, StatusCode::NOT_FOUND);
    let r = h.get("/account/oauth/google/callback?code=x&state=y", None).await;
    assert!(r.location().ends_with("/account/sign-in?error=oauth"), "{}", r.location());
}

// ---- SSO-02: Apple form_post ------------------------------------------------------

#[tokio::test]
async fn sso02_apple_form_post_callback_signs_in_and_keeps_the_first_name() {
    let h = harness_or_skip!();
    let apple = social(
        &h,
        "apple",
        ClientSecret::Apple(AppleKey {
            team_id: "TEAM".into(),
            key_id: "KEY".into(),
            private_key_pem: test_keys::ec_private_pem().into(),
        }),
        "https://appleid.apple.com",
    );
    h.snapshot(vec![apple]);

    let start = h.get("/account/oauth/apple/start?redirect_to=/keys", None).await;
    assert_eq!(start.status, StatusCode::SEE_OTHER, "{:?}", start.body);
    let q = query_of(&start.location());
    assert_eq!(q["response_mode"], "form_post");
    let email = format!("{}@apple-user.test", unique("a"));
    let code = h.idp.grant(
        Some(json!({
            "iss": "https://appleid.apple.com", "aud": "apple-client", "sub": unique("apple-"),
            "email": email, "email_verified": "true", "nonce": q["nonce"],
            "exp": now_secs() + 300, "iat": now_secs(),
        })),
        json!({}),
    );

    let r = h
        .post_form(
            "/account/oauth/apple/callback",
            &[
                ("code", &code),
                ("state", &q["state"]),
                ("user", r#"{"name":{"firstName":"Jane","lastName":"Doe"}}"#),
            ],
            "https://appleid.apple.com",
        )
        .await;
    assert_eq!(r.location(), format!("{SITE}/keys"));
    assert_eq!(h.idp.last_auth().as_deref(), Some("apple-jwt"));
    let cookie = r.session().expect("session cookie");
    let me = h.me(&cookie).await;
    assert_eq!(me.body["email"], email);
    assert_eq!(me.body["display_name"], "Jane Doe");
    let user = h.user_id(&email).await.unwrap();
    assert_eq!(h.session_via(user).await, ["oauth:apple"]);
}

#[tokio::test]
async fn sso02_the_origin_guard_still_applies_everywhere_else() {
    let h = harness_or_skip!();
    let google = social(&h, "google", ClientSecret::Static("s".into()), "");
    h.snapshot(vec![google]);
    // A foreign-origin POST to the login endpoint is still refused…
    let r = h
        .send(
            Request::post("/account/login")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ORIGIN, "https://appleid.apple.com")
                .body(Body::from(r#"{"email":"a@b.c","password":"x"}"#))
                .unwrap(),
        )
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    // …and a POST callback for a provider that does not use form_post is
    // not one at all.
    let r = h
        .post_form("/account/oauth/google/callback", &[("code", "x"), ("state", "y")], SITE)
        .await;
    assert_eq!(r.status, StatusCode::METHOD_NOT_ALLOWED);
}

// ---- SSO-04 / SSO-05: providers that do not vouch for the email -------------------

async fn amazon_callback(h: &Harness, email: &str, subject: &str) -> Reply {
    let start = h.get("/account/oauth/amazon/start", None).await;
    let q = query_of(&start.location());
    assert!(!q.contains_key("code_challenge"), "amazon gets no PKCE");
    let code = h.idp.grant(
        None,
        json!({"user_id": subject, "name": "Amy Zon", "email": email}),
    );
    h.get(
        &format!("/account/oauth/amazon/callback?code={code}&state={}", urlencoding::encode(&q["state"])),
        None,
    )
    .await
}

async fn pending_code(h: &Harness, token: &str) -> String {
    sqlx::query_scalar::<_, String>("SELECT code FROM pending_identities WHERE token_hash = $1")
        .bind(crate::token::hash(token))
        .fetch_one(&h.state.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn sso04_amazon_links_to_an_existing_account_only_after_the_code() {
    let h = harness_or_skip!();
    let amazon = social(&h, "amazon", ClientSecret::Static("s".into()), "");
    h.snapshot(vec![amazon]);

    // The victim's account already exists, with a password.
    let email = format!("{}@victim.test", unique("v"));
    let victim = crate::db::create_user(&h.state.pool, &email, Some("x"), None, true)
        .await
        .unwrap()
        .unwrap();

    let subject = unique("amzn1.account.");
    let r = amazon_callback(&h, &email, &subject).await;
    assert!(r.session().is_none(), "no session before the code");
    let confirm = r.location();
    assert!(confirm.starts_with(&format!("{SITE}/account/oauth/confirm?token=")), "{confirm}");
    let token = query_of(&confirm)["token"].clone();

    let status = h.get(&format!("/account/oauth/pending?token={token}"), None).await;
    assert_eq!(status.body["email"], email);
    assert_eq!(status.body["code_sent"], true);

    // A wrong code is the ordinary credential failure…
    let wrong = h.post_json("/account/oauth/pending/confirm", json!({"token": token, "code": "000000"})).await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    // …the right one signs in to the *existing* account and links Amazon.
    let code = pending_code(&h, &token).await;
    let ok = h.post_json("/account/oauth/pending/confirm", json!({"token": token, "code": code})).await;
    assert_eq!(ok.status, StatusCode::OK, "{:?}", ok.body);
    assert_eq!(ok.body["user"]["id"], json!(victim));
    assert!(ok.session().is_some());

    // Linked now: the next Amazon sign-in goes straight through.
    let again = amazon_callback(&h, &email, &subject).await;
    assert_eq!(again.location(), format!("{SITE}/"));
    assert!(again.session().is_some());
}

#[tokio::test]
async fn sso04_five_wrong_codes_burn_the_pending_identity() {
    let h = harness_or_skip!();
    let amazon = social(&h, "amazon", ClientSecret::Static("s".into()), "");
    h.snapshot(vec![amazon]);
    let email = format!("{}@burn.test", unique("b"));
    let r = amazon_callback(&h, &email, &unique("amzn1.")).await;
    let token = query_of(&r.location())["token"].clone();
    let code = pending_code(&h, &token).await;
    for _ in 0..5 {
        let wrong = h.post_json("/account/oauth/pending/confirm", json!({"token": token, "code": "999999"})).await;
        assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    }
    let late = h.post_json("/account/oauth/pending/confirm", json!({"token": token, "code": code})).await;
    assert_eq!(late.status, StatusCode::UNAUTHORIZED);
    assert!(h.user_id(&email).await.is_none());
}

#[tokio::test]
async fn sso05_a_replayed_state_is_refused() {
    let h = harness_or_skip!();
    let google = social(&h, "google", ClientSecret::Static("s".into()), "");
    h.snapshot(vec![google]);
    let start = h.get("/account/oauth/google/start", None).await;
    let state = query_of(&start.location())["state"].clone();
    let email = format!("{}@g.test", unique("g"));
    let profile = json!({"sub": unique("g-"), "email": email, "email_verified": true, "name": "G"});
    let first = h.idp.grant(None, profile.clone());
    let path = |code: &str| format!("/account/oauth/google/callback?code={code}&state={}", urlencoding::encode(&state));
    assert!(h.get(&path(&first), None).await.session().is_some());
    let second = h.idp.grant(None, profile);
    let replay = h.get(&path(&second), None).await;
    assert!(replay.session().is_none());
    assert!(replay.location().ends_with("error=oauth"));
}


// ---- federated through an SSO service (feature `sso-broker`) -------------------
//
// A mock SSO service stands in for the real one: it answers the
// provider list, discovery and enforcement, and redeems tickets — each bound
// to a browser value, single use, for this site's key only.

#[cfg(feature = "sso-broker")]
mod brokered {
    use super::*;

    const SITE_KEY: &str = "site-key";

    #[derive(Default)]
    struct Broker {
        /// ticket -> (binding, identity)
        tickets: HashMap<String, (String, Value)>,
    }

    struct Mock {
        base: String,
        state: Arc<Mutex<Broker>>,
    }

    impl Mock {
        async fn start() -> Self {
            let state = Arc::new(Mutex::new(Broker::default()));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let authed = |h: &HeaderMap| {
                h.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) == Some(&format!("Bearer {SITE_KEY}"))
            };
            let redeem = {
                let state = state.clone();
                move |h: HeaderMap, axum::Json(b): axum::Json<Value>| {
                    let state = state.clone();
                    async move {
                        if !authed(&h) {
                            return (StatusCode::UNAUTHORIZED, axum::Json(json!({})));
                        }
                        let mut s = state.lock().unwrap();
                        let ticket = b["ticket"].as_str().unwrap_or_default().to_string();
                        match s.tickets.remove(&ticket) {
                            Some((binding, identity)) if b["binding"].as_str() == Some(binding.as_str()) => {
                                (StatusCode::OK, axum::Json(identity))
                            }
                            _ => (StatusCode::UNAUTHORIZED, axum::Json(json!({ "error": "invalid ticket" }))),
                        }
                    }
                }
            };
            let app = Router::new()
                .route("/internal/tickets/redeem", post(redeem))
                .route(
                    "/internal/providers",
                    get(move |h: HeaderMap| async move {
                        if !authed(&h) {
                            return (StatusCode::UNAUTHORIZED, axum::Json(json!({})));
                        }
                        (StatusCode::OK, axum::Json(json!({
                            "providers": [{"key": "google", "name": "Google", "href": "/sso/start/google"}],
                            "custom_sso": true,
                        })))
                    }),
                )
                .route(
                    "/internal/discover",
                    post(|axum::Json(b): axum::Json<Value>| async move {
                        let email = b["email"].as_str().unwrap_or_default();
                        axum::Json(if email.ends_with("@acme.test") {
                            json!({ "sso": true, "name": "Acme", "href": "/sso/org/acme/start?login_hint=x" })
                        } else {
                            json!({ "sso": false })
                        })
                    }),
                )
                .route(
                    "/internal/enforced",
                    get(|axum::extract::Query(q): axum::extract::Query<HashMap<String, String>>| async move {
                        let email = q.get("email").cloned().unwrap_or_default();
                        axum::Json(if email.ends_with("@enforced.test") {
                            json!({ "enforced": true, "connection": "Enforced Inc", "href": "/sso/org/enforced/start" })
                        } else {
                            json!({ "enforced": false })
                        })
                    }),
                );
            tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            Self { base, state }
        }

        /// Mints a ticket the way the SSO service does at the end of a sign-in.
        fn ticket(&self, binding: &str, identity: Value) -> String {
            let t = Uuid::new_v4().to_string();
            self.state.lock().unwrap().tickets.insert(t.clone(), (binding.to_string(), identity));
            t
        }
    }

    #[derive(Default)]
    struct Seen(Mutex<Vec<crate::broker::SignIn>>);
    impl crate::broker::BrokerHooks for Seen {
        fn after_sso_sign_in<'a>(&'a self, s: &'a crate::broker::SignIn) -> crate::BoxFut<'a, anyhow::Result<()>> {
            self.0.lock().unwrap().push(s.clone());
            Box::pin(async { Ok(()) })
        }
    }

    async fn federated() -> Option<(Harness, Mock, Arc<Seen>)> {
        let mut h = harness().await?;
        let mock = Mock::start().await;
        let seen = Arc::new(Seen::default());
        h.state = h
            .state
            .clone()
            .with_broker(crate::broker::BrokerClient::new(&mock.base, SITE_KEY))
            .with_broker_hooks(seen.clone());
        h.app = Router::new().nest("/account", crate::router(h.state.clone()));
        Some((h, mock, seen))
    }

    fn google(email: &str, sub: &str) -> Value {
        json!({ "kind": "oauth", "provider": "google", "provider_name": "Google", "subject": sub,
                "email": email, "email_verified": true, "name": "Gina", "redirect_to": "/keys" })
    }

    async fn finish(h: &Harness, ticket: &str, binding: Option<&str>) -> Reply {
        let mut req = Request::post("/account/sso/finish")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ORIGIN, SITE);
        if let Some(b) = binding {
            req = req.header(header::COOKIE, format!("{}={b}", crate::broker::BIND_COOKIE));
        }
        h.send(req.body(Body::from(json!({ "ticket": ticket }).to_string())).unwrap()).await
    }

    #[tokio::test]
    async fn providers_this_process_loaded_are_dropped_once_federated() {
        let Some(mut h) = harness().await else { return };
        h.snapshot(vec![social(&h, "google", ClientSecret::Static("s".into()), "")]);
        assert_eq!(h.get("/account/oauth/google/start", None).await.status, StatusCode::SEE_OTHER, "live before");
        let mock = Mock::start().await;
        h.state = h.state.clone().with_broker(crate::broker::BrokerClient::new(&mock.base, SITE_KEY));
        h.app = Router::new().nest("/account", crate::router(h.state.clone()));
        assert_eq!(
            h.get("/account/oauth/google/start", None).await.status,
            StatusCode::NOT_FOUND,
            "no in-process provider path beside the SSO service"
        );
    }

    #[tokio::test]
    async fn the_provider_list_and_discovery_come_from_the_sso_service() {
        let Some((h, _mock, _)) = federated().await else { return };
        let r = h.get("/account/oauth", None).await;
        assert_eq!(r.body["providers"][0]["href"], "/sso/start/google");
        assert_eq!(r.body["custom_sso"], true);
        let d = h.post_json("/account/sso/discover", json!({ "email": "bob@acme.test" })).await;
        assert_eq!(d.body["href"], "/sso/org/acme/start?login_hint=x");
        let d = h.post_json("/account/sso/discover", json!({ "email": "bob@else.test" })).await;
        assert_eq!(d.body, json!({ "sso": false }));
    }

    #[tokio::test]
    async fn no_profile_asks_then_creates_on_confirmation_only() {
        let Some((h, mock, seen)) = federated().await else { return };
        let email = format!("{}@new.test", unique("n"));
        let t = mock.ticket("b1", google(&email, &unique("g")));
        let r = finish(&h, &t, Some("b1")).await;
        assert_eq!(r.body["status"], "no_profile", "{:?}", r.body);
        assert_eq!(r.body["email"], email);
        assert_eq!(r.body["provider_name"], "Google");
        assert!(r.session().is_none(), "nothing signed in yet");
        assert!(h.user_id(&email).await.is_none(), "nothing created yet");

        let token = r.body["token"].as_str().unwrap().to_string();
        let c = h.post_json("/account/sso/create-profile", json!({ "token": token })).await;
        assert_eq!(c.body["status"], "ok", "{:?}", c.body);
        assert_eq!(c.body["redirect_to"], "/keys");
        let cookie = c.session().expect("session");
        assert_eq!(h.me(&cookie).await.body["email"], email);
        let user = h.user_id(&email).await.unwrap();
        assert_eq!(h.session_via(user).await, ["oauth:google"]);
        assert!(seen.0.lock().unwrap().iter().any(|s| s.user_id == user && s.created));

        // The question is answered once.
        let again = h.post_json("/account/sso/create-profile", json!({ "token": token })).await;
        assert_eq!(again.status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn an_existing_profile_at_a_vouched_address_signs_straight_in() {
        let Some((h, mock, _)) = federated().await else { return };
        let email = format!("{}@have.test", unique("e"));
        let existing = crate::db::create_user(&h.state.pool, &email, Some("x"), None, true).await.unwrap().unwrap();
        let t = mock.ticket("b2", google(&email, &unique("g")));
        let r = finish(&h, &t, Some("b2")).await;
        assert_eq!(r.body["status"], "ok", "{:?}", r.body);
        assert_eq!(r.body["user"]["id"], json!(existing));
        assert!(r.session().is_some());
    }

    #[tokio::test]
    async fn a_ticket_is_worthless_in_another_browser_or_twice() {
        let Some((h, mock, _)) = federated().await else { return };
        let identity = google(&format!("{}@x.test", unique("w")), &unique("g"));
        let t = mock.ticket("right", identity.clone());
        assert_eq!(finish(&h, &t, Some("wrong")).await.status, StatusCode::UNAUTHORIZED);
        assert_eq!(finish(&h, &t, None).await.status, StatusCode::UNAUTHORIZED);
        let t = mock.ticket("right", identity);
        assert_eq!(finish(&h, &t, Some("right")).await.status, StatusCode::OK);
        assert_eq!(finish(&h, &t, Some("right")).await.status, StatusCode::UNAUTHORIZED, "spent");
    }

    #[tokio::test]
    async fn a_customer_connection_sign_in_carries_its_cap_and_reaches_the_hook() {
        let Some((h, mock, seen)) = federated().await else { return };
        let conn = Uuid::new_v4();
        let owner = Uuid::new_v4();
        let email = format!("{}@acme.test", unique("c"));
        let t = mock.ticket("b3", json!({
            "kind": "sso", "connection_id": conn, "connection_name": "Acme SSO", "connection_owner": owner,
            "subject": "okta-1", "email": email, "email_verified": true, "session_max_hours": 2,
        }));
        let r = finish(&h, &t, Some("b3")).await;
        assert_eq!(r.body["status"], "no_profile");
        assert_eq!(r.body["connection_name"], "Acme SSO");
        let c = h.post_json("/account/sso/create-profile", json!({ "token": r.body["token"] })).await;
        assert_eq!(c.body["status"], "ok", "{:?}", c.body);
        let set_cookie = c
            .headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find(|v| v.starts_with(crate::SESSION_COOKIE))
            .unwrap();
        assert!(set_cookie.contains("Max-Age=7200"), "{set_cookie}");
        let user = h.user_id(&email).await.unwrap();
        assert_eq!(h.session_via(user).await, [format!("sso:{conn}")]);
        let linked = crate::users_for_connection(&h.state.pool, conn).await.unwrap();
        assert_eq!(linked.len(), 1);
        let s = seen.0.lock().unwrap().iter().find(|s| s.user_id == user).cloned().unwrap();
        assert_eq!((s.connection_id, s.connection_owner, s.created), (Some(conn), Some(owner), true));
    }

    fn user_of(r: &Reply) -> Uuid {
        r.body["user"]["id"].as_str().and_then(|s| s.parse().ok()).expect("user id in the reply")
    }

    async fn identity_email(h: &Harness, provider: &str, subject: &str) -> Option<String> {
        sqlx::query_scalar::<_, Option<String>>(
            "SELECT email FROM user_identities WHERE provider = $1 AND provider_user_id = $2",
        )
        .bind(provider)
        .bind(subject)
        .fetch_one(&h.state.pool)
        .await
        .unwrap()
    }

    fn amazon(email: &str, sub: &str) -> Value {
        json!({ "kind": "oauth", "provider": "amazon", "provider_name": "Amazon", "subject": sub,
                "email": email, "email_verified": false, "name": "Amy Zon" })
    }

    #[tokio::test]
    async fn amazon_asks_without_a_code_and_creates_a_profile_with_no_email() {
        let Some((h, mock, seen)) = federated().await else { return };
        let email = format!("{}@amzn.test", unique("a"));
        let subject = unique("amzn1.");
        let t = mock.ticket("b4", amazon(&email, &subject));
        let r = finish(&h, &t, Some("b4")).await;
        assert_eq!(r.body["status"], "no_profile", "no mailed-code step: {:?}", r.body);
        assert_eq!(r.body["email"], Value::Null, "the profile will have no address");
        assert_eq!(r.body["name"], "Amy Zon");
        assert_eq!(r.body["provider_name"], "Amazon");
        assert!(r.session().is_none());
        let code: Option<String> = sqlx::query_scalar("SELECT code FROM pending_identities WHERE token_hash = $1")
            .bind(crate::token::hash(r.body["token"].as_str().unwrap()))
            .fetch_one(&h.state.pool)
            .await
            .unwrap();
        assert!(code.is_none(), "nothing mailed");

        let c = h.post_json("/account/sso/create-profile", json!({ "token": r.body["token"] })).await;
        assert_eq!(c.body["status"], "ok", "{:?}", c.body);
        assert_eq!(c.body["user"]["email"], Value::Null);
        let user = user_of(&c);
        let cookie = c.session().expect("session");
        let me = h.me(&cookie).await;
        assert_eq!(me.body["email"], Value::Null);
        assert_eq!(me.body["display_name"], "Amy Zon");
        assert_eq!(me.body["identities"][0]["email"], email, "the reported address, for display only");
        assert!(h.user_id(&email).await.is_none(), "users.email stays NULL");
        assert_eq!(identity_email(&h, "amazon", &subject).await.as_deref(), Some(email.as_str()));
        assert_eq!(h.session_via(user).await, ["oauth:amazon"]);
        assert!(seen.0.lock().unwrap().iter().any(|s| s.user_id == user && s.created && s.email.is_none()));

        // Linked now: the next Amazon sign-in goes straight in.
        let t = mock.ticket("b4b", amazon(&email, &subject));
        let again = finish(&h, &t, Some("b4b")).await;
        assert_eq!(again.body["status"], "ok", "{:?}", again.body);
        assert_eq!(user_of(&again), user);
    }

    #[tokio::test]
    async fn an_unvouched_address_never_enters_the_account_at_that_address() {
        let Some((h, mock, _)) = federated().await else { return };
        let email = format!("{}@victim.test", unique("v"));
        let victim = crate::db::create_user(&h.state.pool, &email, Some("x"), None, true).await.unwrap().unwrap();
        let subject = unique("amzn1.");
        let t = mock.ticket("b20", amazon(&email, &subject));
        let r = finish(&h, &t, Some("b20")).await;
        assert_eq!(r.body["status"], "no_profile", "{:?}", r.body);
        assert_eq!(r.body["email"], Value::Null);
        assert!(r.session().is_none(), "not signed in to the account at that address");

        let c = h.post_json("/account/sso/create-profile", json!({ "token": r.body["token"] })).await;
        assert_eq!(c.body["status"], "ok", "{:?}", c.body);
        let created = user_of(&c);
        assert_ne!(created, victim, "a new profile, never the victim's");
        assert_eq!(c.body["user"]["email"], Value::Null);
        assert_eq!(crate::db::find_user_by_identity(&h.state.pool, "amazon", &subject).await.unwrap(), Some(created));
        assert_eq!(h.user_id(&email).await, Some(victim), "the address still belongs to the victim alone");
    }

    #[tokio::test]
    async fn a_github_like_identity_with_no_email_creates_a_profile_with_none() {
        let Some((h, mock, _)) = federated().await else { return };
        // Vouching provider, but no address at all (a private GitHub email):
        // asked, never refused, whatever `email_verified` says.
        for (binding, verified) in [("b21", true), ("b22", false)] {
            let subject = unique("gh-");
            let t = mock.ticket(binding, json!({ "kind": "oauth", "provider": "github", "provider_name": "GitHub",
                "subject": subject, "email": null, "email_verified": verified, "name": "Octo Cat" }));
            let r = finish(&h, &t, Some(binding)).await;
            assert_eq!(r.body["status"], "no_profile", "{:?}", r.body);
            assert_eq!(r.body["email"], Value::Null);
            assert_eq!(r.body["name"], "Octo Cat");
            assert_eq!(r.body["provider_name"], "GitHub");

            let c = h.post_json("/account/sso/create-profile", json!({ "token": r.body["token"] })).await;
            assert_eq!(c.body["status"], "ok", "{:?}", c.body);
            let user = user_of(&c);
            let cookie = c.session().expect("session");
            let me = h.me(&cookie).await;
            assert_eq!((me.body["email"].clone(), me.body["has_password"].clone()), (Value::Null, json!(false)));
            assert_eq!(identity_email(&h, "github", &subject).await, None);

            // What a sibling service handed the cookie learns: no address.
            let raw = cookie.trim_start_matches("signon_session=");
            let who = crate::user_for_session_token(&h.state.pool, raw).await.unwrap();
            assert_eq!(who, Some((user, None, Some("Octo Cat".to_string()))));

            // A password would have no address to sign in with.
            let pw = h
                .send(
                    Request::post("/account/password")
                        .header(header::CONTENT_TYPE, "application/json")
                        .header(header::ORIGIN, SITE)
                        .header(header::COOKIE, &cookie)
                        .body(Body::from(json!({ "new_password": "a-long-password-1" }).to_string()))
                        .unwrap(),
                )
                .await;
            assert_eq!(pw.status, StatusCode::BAD_REQUEST, "{:?}", pw.body);
        }
    }

    fn typed(email: &str, conn: Uuid, sub: &str) -> Value {
        json!({ "kind": "sso", "connection_id": conn, "connection_name": "Acme SSO", "connection_owner": Uuid::new_v4(),
                "subject": sub, "email": email, "email_verified": true, "email_typed": true, "name": "Tia Typed" })
    }

    #[tokio::test]
    async fn a_typed_address_that_has_an_account_is_refused() {
        let Some((h, mock, seen)) = federated().await else { return };
        let email = format!("{}@acme.test", unique("t"));
        let existing = crate::db::create_user(&h.state.pool, &email, Some("x"), None, true).await.unwrap().unwrap();
        let conn = Uuid::new_v4();
        let subject = unique("okta-");
        let t = mock.ticket("b23", typed(&email, conn, &subject));
        let r = finish(&h, &t, Some("b23")).await;
        assert_eq!(r.status, StatusCode::CONFLICT, "{:?}", r.body);
        assert_eq!(
            r.body,
            json!({ "error": "an account with this address already exists - sign in to it another way", "code": "SO-E021" })
        );
        assert!(r.session().is_none());
        let key = crate::broker::connection_identity_key(conn, &subject);
        assert_eq!(crate::db::find_user_by_identity(&h.state.pool, "sso", &key).await.unwrap(), None, "no link");
        assert!(crate::users_for_connection(&h.state.pool, conn).await.unwrap().is_empty());
        assert!(!seen.0.lock().unwrap().iter().any(|s| s.user_id == existing));
    }

    #[tokio::test]
    async fn a_typed_address_creates_a_profile_at_that_address() {
        let Some((h, mock, seen)) = federated().await else { return };
        let email = format!("{}@acme.test", unique("t"));
        let conn = Uuid::new_v4();
        let subject = unique("okta-");
        let t = mock.ticket("b24", typed(&email, conn, &subject));
        let r = finish(&h, &t, Some("b24")).await;
        assert_eq!(r.body["status"], "no_profile", "{:?}", r.body);
        assert_eq!(r.body["email"], email);
        assert_eq!(r.body["connection_name"], "Acme SSO");

        // Someone registers the address while the question is open: the
        // answer is the same refusal, not a way into their account.
        let other = format!("{}@acme.test", unique("t"));
        let t2 = mock.ticket("b25", typed(&other, conn, &unique("okta-")));
        let r2 = finish(&h, &t2, Some("b25")).await;
        assert_eq!(r2.body["status"], "no_profile");
        crate::db::create_user(&h.state.pool, &other, Some("x"), None, false).await.unwrap().unwrap();
        let late = h.post_json("/account/sso/create-profile", json!({ "token": r2.body["token"] })).await;
        assert_eq!(late.status, StatusCode::CONFLICT, "{:?}", late.body);
        assert!(late.session().is_none());

        let c = h.post_json("/account/sso/create-profile", json!({ "token": r.body["token"] })).await;
        assert_eq!(c.body["status"], "ok", "{:?}", c.body);
        let user = user_of(&c);
        assert_eq!(c.body["user"]["email"], email);
        assert_eq!(c.body["user"]["email_verified"], true, "custom-SSO users are trusted");
        assert_eq!(h.user_id(&email).await, Some(user));
        assert_eq!(h.session_via(user).await, [format!("sso:{conn}")]);
        let s = seen.0.lock().unwrap().iter().find(|s| s.user_id == user).cloned().unwrap();
        assert_eq!((s.email.as_deref(), s.created), (Some(email.as_str()), true));

        // The identity is linked now, so the next sign-in through it goes
        // straight in — the refusal is only for accounts it is not linked to.
        let t = mock.ticket("b26", typed(&email, conn, &subject));
        let again = finish(&h, &t, Some("b26")).await;
        assert_eq!(again.body["status"], "ok", "{:?}", again.body);
        assert_eq!(user_of(&again), user);
    }

    #[tokio::test]
    async fn an_sso_identity_with_no_email_creates_a_profile_with_none() {
        let Some((h, mock, seen)) = federated().await else { return };
        let conn = Uuid::new_v4();
        let owner = Uuid::new_v4();
        let t = mock.ticket("b27", json!({ "kind": "sso", "connection_id": conn, "connection_name": "Acme SSO",
            "connection_owner": owner, "subject": unique("okta-"), "email": null, "email_verified": false,
            "name": "Nora None" }));
        let r = finish(&h, &t, Some("b27")).await;
        assert_eq!(r.body["status"], "no_profile", "{:?}", r.body);
        assert_eq!(r.body["email"], Value::Null);
        assert_eq!(r.body["name"], "Nora None");
        assert_eq!(r.body["connection_name"], "Acme SSO");

        let c = h.post_json("/account/sso/create-profile", json!({ "token": r.body["token"] })).await;
        assert_eq!(c.body["status"], "ok", "{:?}", c.body);
        let user = user_of(&c);
        assert_eq!(c.body["user"]["email"], Value::Null);
        assert_eq!(h.session_via(user).await, [format!("sso:{conn}")]);
        let people = crate::users_for_connection(&h.state.pool, conn).await.unwrap();
        assert_eq!(people.len(), 1);
        assert_eq!((people[0].user_id, people[0].email.as_deref()), (user, None));
        let s = seen.0.lock().unwrap().iter().find(|s| s.user_id == user).cloned().unwrap();
        assert_eq!((s.email, s.connection_owner, s.created), (None, Some(owner), true));
    }

    #[tokio::test]
    async fn sso13_enforcement_is_asked_of_the_sso_service_by_domain() {
        let Some((h, mock, _)) = federated().await else { return };
        let existing = format!("{}@enforced.test", unique("x"));
        crate::db::create_user(&h.state.pool, &existing, Some("x"), None, true).await.unwrap();
        let a = h.post_json("/account/login", json!({ "email": existing, "password": "whatever-123" })).await;
        let b = h.post_json("/account/login", json!({ "email": "nobody@enforced.test", "password": "whatever-123" })).await;
        assert_eq!(a.status, StatusCode::FORBIDDEN);
        assert_eq!((a.status, &a.body), (b.status, &b.body), "identical with or without an account");
        assert_eq!(a.body["href"], "/sso/org/enforced/start");
        // A social provider is no way around it.
        let t = mock.ticket("b5", google(&existing, &unique("g")));
        assert_eq!(finish(&h, &t, Some("b5")).await.status, StatusCode::FORBIDDEN);
        let other = h.post_json("/account/login", json!({ "email": "x@free.test", "password": "whatever-123" })).await;
        assert_eq!(other.status, StatusCode::UNAUTHORIZED);
    }

    /// The finish page's POST from a browser that is also signed in.
    async fn finish_signed_in(h: &Harness, ticket: &str, binding: &str, session: &str) -> Reply {
        h.send(
            Request::post("/account/sso/finish")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ORIGIN, SITE)
                .header(header::COOKIE, format!("{}={binding}; {session}", crate::broker::BIND_COOKIE))
                .body(Body::from(json!({ "ticket": ticket }).to_string()))
                .unwrap(),
        )
        .await
    }

    fn connection_identity(email: &str) -> Value {
        json!({ "kind": "sso", "connection_id": Uuid::new_v4(), "connection_name": "Acme SSO",
                "connection_owner": Uuid::new_v4(), "subject": unique("okta-"), "email": email, "email_verified": true })
    }

    #[tokio::test]
    async fn connect_links_a_provider_to_the_signed_in_account_whatever_its_address() {
        let Some((h, mock, _)) = federated().await else { return };
        let email = format!("{}@work.test", unique("alice"));
        let alice = crate::db::create_user(&h.state.pool, &email, Some("x"), None, true).await.unwrap().unwrap();
        let t = mock.ticket("b6", google(&email, &unique("g")));
        let session = finish(&h, &t, Some("b6")).await.session().expect("signed in");

        // "Connect Google" with a personal address no account has.
        let personal = unique("g-personal");
        let t = mock.ticket("b7", google(&format!("{}@gmail.test", unique("alice")), &personal));
        let r = finish_signed_in(&h, &t, "b7", &session).await;
        assert_eq!(r.body["status"], "ok", "{:?}", r.body);
        assert_eq!(r.body["user"]["id"], json!(alice), "the signed-in account, not a new one");
        assert_eq!(crate::db::find_user_by_identity(&h.state.pool, "google", &personal).await.unwrap(), Some(alice));

        // The same kind of identity in a browser signed in to nothing asks instead.
        let t = mock.ticket("b8", google(&format!("{}@gmail.test", unique("bob")), &unique("g")));
        assert_eq!(finish(&h, &t, Some("b8")).await.body["status"], "no_profile");
    }

    #[tokio::test]
    async fn a_connection_identity_is_never_linked_to_whoever_is_signed_in() {
        let Some((h, mock, seen)) = federated().await else { return };
        let email = format!("{}@work.test", unique("alice"));
        let alice = crate::db::create_user(&h.state.pool, &email, Some("x"), None, true).await.unwrap().unwrap();
        let t = mock.ticket("b9", google(&email, &unique("g")));
        let session = finish(&h, &t, Some("b9")).await.session().expect("signed in");

        let carol = format!("{}@acme.test", unique("carol"));
        let t = mock.ticket("b10", connection_identity(&carol));
        let r = finish_signed_in(&h, &t, "b10", &session).await;
        assert_eq!(r.body["status"], "no_profile", "placed by its own address: {:?}", r.body);
        assert!(!seen.0.lock().unwrap().iter().any(|s| s.user_id == alice && s.connection_id.is_some()));
    }

    #[tokio::test]
    async fn connect_is_no_way_around_enforcement() {
        let Some((h, mock, _)) = federated().await else { return };
        let email = format!("{}@enforced.test", unique("e"));
        crate::db::create_user(&h.state.pool, &email, Some("x"), None, true).await.unwrap();
        // Signed in the enforced way: through the domain's connection.
        let t = mock.ticket("b11", connection_identity(&email));
        let session = finish(&h, &t, Some("b11")).await.session().expect("signed in through the connection");
        let t = mock.ticket("b12", google(&format!("{}@gmail.test", unique("e")), &unique("g")));
        let r = finish_signed_in(&h, &t, "b12", &session).await;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{:?}", r.body);
        assert!(r.session().is_none(), "no provider session for an enforced domain");
    }

    // ---- the welcome and the browser mark on a created profile -----------------

    #[tokio::test]
    async fn a_created_profile_is_welcomed_and_a_second_one_from_the_browser_is_asked_first() {
        let Some(mut h) = super::account_mail::welcoming().await else { return };
        let mock = Mock::start().await;
        h.state = h
            .state
            .clone()
            .with_broker(crate::broker::BrokerClient::new(&mock.base, SITE_KEY))
            .with_broker_hooks(Arc::new(Seen::default()));
        h.app = Router::new().nest("/account", crate::router(h.state.clone()));

        let create = |body: Value, cookie: Option<String>| {
            let mut req = Request::post("/account/sso/create-profile")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ORIGIN, SITE);
            if let Some(c) = cookie {
                req = req.header(header::COOKIE, c);
            }
            h.send(req.body(Body::from(body.to_string())).unwrap())
        };

        // A vouched address: the profile is created and welcomed at once —
        // no verification step follows an SSO sign-in.
        let first = format!("{}@acme.test", unique("p"));
        let t = mock.ticket("bw1", google(&first, &unique("sub")));
        let r = finish(&h, &t, Some("bw1")).await;
        assert_eq!(r.body["status"], "no_profile", "{:?}", r.body);
        let c = create(json!({ "token": r.body["token"] }), None).await;
        assert_eq!(c.body["status"], "ok", "{:?}", c.body);
        let welcomes = super::account_mail::welcomes(&first);
        assert_eq!(welcomes.len(), 1);
        let mark = super::account_mail::mark_cookie(&c).expect("the sign-in marks the browser");

        // Another identity in the same browser: asked first, and the refusal
        // does not spend the token — "create another" retries with it.
        let second = format!("{}@acme.test", unique("q"));
        let t = mock.ticket("bw2", google(&second, &unique("sub")));
        let r = finish(&h, &t, Some("bw2")).await;
        let token = r.body["token"].clone();
        let asked = create(json!({ "token": token }), Some(mark.clone())).await;
        assert_eq!(asked.status, StatusCode::CONFLICT, "{:?}", asked.body);
        assert_eq!(asked.body["error"], "registered_here");
        assert_eq!(asked.body["hint"], super::account_mail::masked(&first));
        let again = create(json!({ "token": token, "another": true, "emails": false }), Some(mark)).await;
        assert_eq!(again.body["status"], "ok", "{:?}", again.body);
        // ...and unticking "email me" on the prompt means no welcome.
        assert!(super::account_mail::welcomes(&second).is_empty());
    }
}

// ---- the welcome, opting out, the browser mark, the forwarded address -----------

mod account_mail {
    use super::*;
    use crate::email::outbox;

    const KEY: &str = "test-client-ip-key-0123456789";

    /// A site that sends a welcome and trusts its Worker's forwarded address.
    pub(super) async fn welcoming() -> Option<Harness> {
        let pool = pool().await?;
        let mut config = Config::new("TEST", SITE).with_welcome(crate::Welcome {
            subject: "Welcome to TEST".into(),
            paragraphs: vec!["Hello & welcome <b>.".into()],
            action: Some(("Open TEST".into(), format!("{SITE}/start"))),
            footer_note: None,
        });
        config.client_ip_key = Some(KEY.into());
        let state = AccountState::from_env_with_mailer(pool, config, Mailer::disabled())
            .await
            .unwrap();
        state.sso.replace(SsoSnapshot::default());
        let app = Router::new().nest("/account", crate::router(state.clone()));
        Some(Harness {
            state,
            app,
            idp: MockIdp::start().await,
        })
    }

    pub(super) fn welcomes(address: &str) -> Vec<outbox::Sent> {
        outbox::to(address)
            .into_iter()
            .filter(|m| m.subject == "Welcome to TEST")
            .collect()
    }

    pub(super) fn masked(email: &str) -> String {
        format!("{}•••@{}", &email[..1], email.split_once('@').unwrap().1)
    }

    /// `signon_browser=…` out of a reply's cookies.
    pub(super) fn mark_cookie(reply: &Reply) -> Option<String> {
        reply
            .headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find(|c| c.starts_with("signon_browser="))
            .map(|c| c.split(';').next().unwrap().to_string())
    }

    async fn post(h: &Harness, path: &str, body: Value, cookie: Option<&str>, headers: &[(&str, &str)]) -> Reply {
        let mut req = Request::post(path)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ORIGIN, SITE);
        if let Some(c) = cookie {
            req = req.header(header::COOKIE, c);
        }
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        h.send(req.body(Body::from(body.to_string())).unwrap()).await
    }

    async fn register(h: &Harness, email: &str, cookie: Option<&str>, extra: Value) -> Reply {
        let mut body = json!({ "email": email, "password": "correct horse battery staple" });
        for (k, v) in extra.as_object().unwrap() {
            body[k] = v.clone();
        }
        post(h, "/account/register", body, cookie, &[]).await
    }

    /// Confirms with the code from the latest verification mail; the reply
    /// carries the first session.
    async fn verify(h: &Harness, email: &str) -> Reply {
        let mail = outbox::to(email)
            .into_iter()
            .rev()
            .find(|m| m.subject.starts_with("Confirm your"))
            .expect("a verification mail");
        let code = mail
            .text
            .split("confirmation page: ")
            .nth(1)
            .unwrap()
            .chars()
            .take(6)
            .collect::<String>();
        post(h, "/account/verify/code", json!({ "email": email, "code": code }), None, &[]).await
    }

    fn header_of<'a>(mail: &'a outbox::Sent, name: &str) -> &'a str {
        &mail.headers.iter().find(|(k, _)| k == name).unwrap().1
    }

    /// The token out of a welcome's `List-Unsubscribe: <…/unsubscribe/TOKEN>`.
    fn unsubscribe_token(mail: &outbox::Sent) -> String {
        header_of(mail, "List-Unsubscribe")
            .trim_matches(|c| c == '<' || c == '>')
            .rsplit('/')
            .next()
            .unwrap()
            .to_string()
    }

    async fn emails_enabled(h: &Harness, session: &str) -> Value {
        h.me(session).await.body["emails_enabled"].clone()
    }

    /// Signs `email` up and confirms it — for the other modules' tests.
    #[cfg_attr(not(feature = "welcome-remote"), allow(dead_code))]
    pub(super) async fn sign_up_and_verify(h: &Harness, email: &str) {
        assert_eq!(register(h, email, None, json!({})).await.status, StatusCode::CREATED);
        assert_eq!(verify(h, email).await.status, StatusCode::OK);
    }

    #[tokio::test]
    async fn the_welcome_goes_once_after_the_address_is_confirmed() {
        let Some(h) = welcoming().await else { return };
        let email = format!("{}@example.test", unique("w"));
        assert_eq!(register(&h, &email, None, json!({})).await.status, StatusCode::CREATED);
        assert!(welcomes(&email).is_empty(), "not before the address is confirmed");

        let v = verify(&h, &email).await;
        assert_eq!(v.status, StatusCode::OK, "{:?}", v.body);
        let sent = welcomes(&email);
        assert_eq!(sent.len(), 1);
        let w = &sent[0];
        assert!(w.text.starts_with("Hello & welcome <b>."), "{}", w.text);
        assert!(w.text.contains(&format!("Open TEST: {SITE}/start")), "{}", w.text);
        let token = unsubscribe_token(w);
        assert_eq!(
            header_of(w, "List-Unsubscribe"),
            format!("<{SITE}/api/account/emails/unsubscribe/{token}>")
        );
        assert_eq!(header_of(w, "List-Unsubscribe-Post"), "List-Unsubscribe=One-Click");
        assert!(w.text.contains(&format!("{SITE}/account/unsubscribe?token={token}")), "{}", w.text);

        // Every other way an account can become usable calls this too; the
        // claim keeps it to one.
        let user = h.user_id(&email).await.unwrap();
        crate::account_mail::send_welcome(&h.state, user).await;
        assert_eq!(welcomes(&email).len(), 1);
        assert_eq!(emails_enabled(&h, &v.session().unwrap()).await, true);
    }

    #[tokio::test]
    async fn unticking_email_me_at_sign_up_sends_no_welcome() {
        let Some(h) = welcoming().await else { return };
        let email = format!("{}@example.test", unique("n"));
        register(&h, &email, None, json!({ "emails": false })).await;
        let v = verify(&h, &email).await;
        assert!(welcomes(&email).is_empty());
        assert_eq!(emails_enabled(&h, &v.session().unwrap()).await, false);
    }

    #[tokio::test]
    async fn no_welcome_unless_the_site_has_one() {
        let h = harness_or_skip!();
        let email = format!("{}@example.test", unique("d"));
        register(&h, &email, None, json!({})).await;
        assert_eq!(verify(&h, &email).await.status, StatusCode::OK);
        assert!(outbox::to(&email).iter().all(|m| m.subject.starts_with("Confirm your")));
    }

    #[tokio::test]
    async fn the_mailed_links_turn_mail_off_and_back_on() {
        let Some(h) = welcoming().await else { return };
        let email = format!("{}@example.test", unique("u"));
        register(&h, &email, None, json!({})).await;
        let session = verify(&h, &email).await.session().unwrap();
        let token = unsubscribe_token(&welcomes(&email)[0]);

        // The page behind the link (it asks before it posts).
        let r = post(&h, "/account/emails/unsubscribe", json!({ "token": token }), None, &[]).await;
        assert_eq!(r.body["emails_enabled"], false, "{:?}", r.body);
        assert_eq!(emails_enabled(&h, &session).await, false);
        // Its undo.
        let r = post(&h, "/account/emails/unsubscribe", json!({ "token": token, "enabled": true }), None, &[]).await;
        assert_eq!(r.body["emails_enabled"], true);
        assert_eq!(emails_enabled(&h, &session).await, true);

        // One-click: the mail client posts from wherever it runs.
        let r = h
            .send(
                Request::post(format!("/account/emails/unsubscribe/{token}"))
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .header(header::ORIGIN, "https://mail.example")
                    .body(Body::from("List-Unsubscribe=One-Click"))
                    .unwrap(),
            )
            .await;
        assert_eq!(r.status, StatusCode::OK);
        assert_eq!(emails_enabled(&h, &session).await, false);

        // A made-up token: the page says so, one-click answers the same 200.
        let r = post(&h, "/account/emails/unsubscribe", json!({ "token": "nope" }), None, &[]).await;
        assert_eq!(r.status, StatusCode::NOT_FOUND);
        let r = h
            .send(Request::post("/account/emails/unsubscribe/nope").body(Body::empty()).unwrap())
            .await;
        assert_eq!(r.status, StatusCode::OK);
    }

    #[tokio::test]
    async fn the_profile_switch_needs_a_session() {
        let Some(h) = welcoming().await else { return };
        let email = format!("{}@example.test", unique("s"));
        register(&h, &email, None, json!({})).await;
        let session = verify(&h, &email).await.session().unwrap();
        let r = post(&h, "/account/emails", json!({ "enabled": false }), Some(&session), &[]).await;
        assert_eq!(r.body["emails_enabled"], false);
        assert_eq!(emails_enabled(&h, &session).await, false);
        post(&h, "/account/emails", json!({ "enabled": true }), Some(&session), &[]).await;
        assert_eq!(emails_enabled(&h, &session).await, true);
        let r = post(&h, "/account/emails", json!({ "enabled": false }), None, &[]).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_second_sign_up_from_the_same_browser_is_asked_about_first() {
        let Some(h) = welcoming().await else { return };
        let first = format!("{}@example.test", unique("a"));
        let r = register(&h, &first, None, json!({})).await;
        assert_eq!(r.status, StatusCode::CREATED);
        let mark = mark_cookie(&r).expect("sign-up marks the browser");

        let second = format!("{}@example.test", unique("b"));
        let asked = register(&h, &second, Some(&mark), json!({})).await;
        assert_eq!(asked.status, StatusCode::CONFLICT, "{:?}", asked.body);
        assert_eq!(asked.body["error"], "registered_here");
        assert_eq!(asked.body["hint"], masked(&first));
        assert!(h.user_id(&second).await.is_none(), "nothing created on the question");

        let r = register(&h, &second, Some(&mark), json!({ "another": true })).await;
        assert_eq!(r.status, StatusCode::CREATED);
        assert!(h.user_id(&second).await.is_some());

        // Another browser is not asked.
        let third = format!("{}@example.test", unique("c"));
        assert_eq!(register(&h, &third, None, json!({})).await.status, StatusCode::CREATED);

        // A taken address answers exactly like a new one, mark cookie included.
        let taken = register(&h, &first, None, json!({})).await;
        assert_eq!(taken.status, StatusCode::CREATED);
        assert!(mark_cookie(&taken).is_some());
    }

    #[tokio::test]
    async fn signing_in_marks_the_browser_too() {
        let Some(h) = welcoming().await else { return };
        let email = format!("{}@example.test", unique("l"));
        register(&h, &email, None, json!({})).await;
        verify(&h, &email).await;
        let login = post(
            &h,
            "/account/login",
            json!({ "email": email, "password": "correct horse battery staple" }),
            None,
            &[],
        )
        .await;
        assert_eq!(login.status, StatusCode::OK, "{:?}", login.body);
        let mark = mark_cookie(&login).unwrap();
        let other = format!("{}@example.test", unique("m"));
        let asked = register(&h, &other, Some(&mark), json!({})).await;
        assert_eq!(asked.status, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn the_forwarded_client_address_counts_only_with_the_key() {
        let Some(h) = welcoming().await else { return };
        let email = format!("{}@example.test", unique("ip"));
        let r = post(
            &h,
            "/account/register",
            json!({ "email": email, "password": "correct horse battery staple" }),
            None,
            &[("x-client-ip", "203.0.113.7"), ("x-client-ip-key", KEY), ("cf-connecting-ip", "2a06:98c0:3600::103")],
        )
        .await;
        assert_eq!(r.status, StatusCode::CREATED);
        verify(&h, &email).await;
        let user = h.user_id(&email).await.unwrap();
        let signup: Option<String> = sqlx::query_scalar("SELECT signup_ip FROM users WHERE id = $1")
            .bind(user)
            .fetch_one(&h.state.pool)
            .await
            .unwrap();
        assert_eq!(signup.as_deref(), Some("203.0.113.7"));

        let login = |headers: Vec<(&'static str, &'static str)>| {
            let email = email.clone();
            let h = &h;
            async move {
                post(h, "/account/login", json!({ "email": email, "password": "correct horse battery staple" }), None, &headers).await
            }
        };
        let last_ip = || async {
            sqlx::query_scalar::<_, Option<String>>("SELECT last_login_ip FROM users WHERE id = $1")
                .bind(user)
                .fetch_one(&h.state.pool)
                .await
                .unwrap()
        };

        // With the key: the forwarded address.
        login(vec![("x-client-ip", "198.51.100.4"), ("x-client-ip-key", KEY), ("cf-connecting-ip", "2a06:98c0:3600::103")]).await;
        assert_eq!(last_ip().await.as_deref(), Some("198.51.100.4"));
        // A wrong key, or none: ignored, and the tunnel's address stands.
        login(vec![("x-client-ip", "198.51.100.5"), ("x-client-ip-key", "guess-guess-guess-guess"), ("cf-connecting-ip", "192.0.2.10")]).await;
        assert_eq!(last_ip().await.as_deref(), Some("192.0.2.10"));
        login(vec![("x-client-ip", "198.51.100.6"), ("cf-connecting-ip", "192.0.2.11")]).await;
        assert_eq!(last_ip().await.as_deref(), Some("192.0.2.11"));
        // Not an address at all: ignored.
        login(vec![("x-client-ip", "not-an-ip"), ("x-client-ip-key", KEY), ("cf-connecting-ip", "192.0.2.12")]).await;
        assert_eq!(last_ip().await.as_deref(), Some("192.0.2.12"));
    }
}

// ---- the welcome's text from a URL (feature welcome-remote) -----------------------

#[cfg(feature = "welcome-remote")]
mod welcome_remote {
    use super::*;
    use crate::email::outbox;

    /// Answers the way the landing Worker does: a template, or 404.
    pub(super) async fn template_server() -> String {
        let app = Router::new()
            .route(
                "/email-templates/good",
                get(|| async {
                    axum::Json(json!({
                        "subject": "Edited welcome to {product}",
                        "body": "Edited first.\n\nSee {site}/docs.",
                        "action_label": "Start",
                        "action_url": "{site}/start",
                    }))
                }),
            )
            .route(
                "/email-templates/followup",
                get(|| async {
                    axum::Json(json!({
                        "subject": "Following up on {product}",
                        "body": "How is it going?",
                        "action_label": null,
                        "action_url": null,
                    }))
                }),
            )
            .route(
                "/email-templates/scripted",
                get(|| async {
                    axum::Json(json!({
                        "subject": "Hi", "body": "Text.", "action_label": "Go", "action_url": "javascript:alert(1)",
                    }))
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        base
    }

    async fn harness_reading(url: String) -> Option<Harness> {
        let mut h = super::account_mail::welcoming().await?;
        let mut config = (*h.state.config).clone();
        config.welcome_url = Some(url);
        h.state.config = Arc::new(config);
        h.app = Router::new().nest("/account", crate::router(h.state.clone()));
        Some(h)
    }

    /// Registers and confirms `email`; the welcomes it then received.
    async fn welcomed(h: &Harness, email: &str) -> Vec<outbox::Sent> {
        super::account_mail::sign_up_and_verify(h, email).await;
        outbox::to(email)
            .into_iter()
            .filter(|m| !m.subject.starts_with("Confirm your"))
            .collect()
    }

    #[tokio::test]
    async fn the_edited_template_is_what_goes_out() {
        let base = template_server().await;
        let Some(h) = harness_reading(format!("{base}/email-templates/good")).await else { return };
        let email = format!("{}@example.test", unique("r"));
        let sent = welcomed(&h, &email).await;
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].subject, "Edited welcome to TEST");
        assert!(sent[0].text.starts_with(&format!("Edited first.\n\nSee {SITE}/docs.")), "{}", sent[0].text);
        assert!(sent[0].text.contains(&format!("Start: {SITE}/start")), "{}", sent[0].text);
        // The unsubscribe footer and headers are the sender's, whatever the template says.
        assert!(sent[0].headers.iter().any(|(k, _)| k == "List-Unsubscribe"));
        assert!(sent[0].text.contains("/account/unsubscribe?token="));
    }

    #[tokio::test]
    async fn not_approved_switched_off_or_no_answer_sends_nothing() {
        let base = template_server().await;
        for url in [
            // The landing Worker's answer for a template not approved or switched off.
            format!("{base}/email-templates/missing"),
            // Nothing listens on port 1.
            "http://127.0.0.1:1/email-templates/good".to_string(),
        ] {
            let Some(h) = harness_reading(url.clone()).await else { return };
            let email = format!("{}@example.test", unique("f"));
            let sent = welcomed(&h, &email).await;
            assert!(sent.is_empty(), "{url}: the built-in text must not stand in — {sent:?}");
            // Not marked as welcomed either: nothing went.
            let user = h.user_id(&email).await.unwrap();
            let logged: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM mail_log WHERE user_id = $1 AND kind = 'welcome')",
            )
            .bind(user)
            .fetch_one(&h.state.pool)
            .await
            .unwrap();
            assert!(!logged, "{url}: no row — the catch-up run can still reach it");
        }
    }

    #[tokio::test]
    async fn a_button_that_is_not_a_web_address_is_dropped() {
        let base = template_server().await;
        let Some(h) = harness_reading(format!("{base}/email-templates/scripted")).await else { return };
        let email = format!("{}@example.test", unique("j"));
        let sent = welcomed(&h, &email).await;
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].subject, "Hi");
        assert!(!sent[0].text.contains("javascript:"), "{}", sent[0].text);
    }
}

// ---- the send log and the manual runs (catch-up welcome, follow-up) -----------------

#[cfg(feature = "welcome-remote")]
mod mail_runs {
    use super::*;
    use crate::email::outbox;

    const KEY: &str = "test-mail-admin-key-0123456789";

    /// A database of this test's own: a run reaches every account owed a mail,
    /// so counts in the shared test database would include other tests'
    /// accounts — and a run would mail them mid-test. Dropped and recreated
    /// on every run.
    async fn fresh_pool(name: &str) -> Option<sqlx::PgPool> {
        let shared = pool().await?;
        let db = format!("signon_test_{name}");
        sqlx::query(&format!("DROP DATABASE IF EXISTS {db} WITH (FORCE)")).execute(&shared).await.ok()?;
        sqlx::query(&format!("CREATE DATABASE {db}")).execute(&shared).await.ok()?;
        let url = std::env::var("SIGNON_TEST_DB")
            .unwrap_or_else(|_| "postgres:///signon_test?host=/var/run/postgresql".to_string())
            .replacen("signon_test", &db, 1);
        crate::migrate(&url).await.expect("migrate the fresh database");
        sqlx::postgres::PgPoolOptions::new().max_connections(4).connect(&url).await.ok()
    }

    /// A site on `pool`: a built-in welcome only when `welcome`, the follow-up
    /// read from `followup_url`, runs behind `KEY`.
    async fn site(pool: sqlx::PgPool, welcome: bool, followup_url: Option<String>) -> Harness {
        let mut config = Config::new("TEST", SITE);
        if welcome {
            config = config.with_welcome(crate::Welcome {
                subject: "Welcome to TEST".into(),
                paragraphs: vec!["Hello.".into()],
                action: None,
                footer_note: None,
            });
        }
        config.followup_url = followup_url;
        config.mail_admin_key = Some(KEY.into());
        let state = AccountState::from_env_with_mailer(pool, config, Mailer::disabled())
            .await
            .unwrap();
        state.sso.replace(SsoSnapshot::default());
        let app = Router::new()
            .nest("/account", crate::router(state.clone()))
            .nest("/internal/mail", crate::mail_admin_router(state.clone()));
        Harness { state, app, idp: MockIdp::start().await }
    }

    async fn admin(h: &Harness, method: &str, path: &str, body: Option<Value>, key: Option<&str>) -> Reply {
        let mut req = Request::builder().method(method).uri(path);
        if let Some(k) = key {
            req = req.header(header::AUTHORIZATION, format!("Bearer {k}"));
        }
        let body = match body {
            Some(b) => {
                req = req.header(header::CONTENT_TYPE, "application/json");
                Body::from(b.to_string())
            }
            None => Body::empty(),
        };
        h.send(req.body(body).unwrap()).await
    }

    async fn sign_up(h: &Harness, email: &str, emails: bool) {
        let r = h
            .post_json(
                "/account/register",
                json!({ "email": email, "password": "correct horse battery staple", "emails": emails }),
            )
            .await;
        assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
        let mail = outbox::to(email)
            .into_iter()
            .rev()
            .find(|m| m.subject.starts_with("Confirm your"))
            .expect("a verification mail");
        let code: String = mail.text.split("confirmation page: ").nth(1).unwrap().chars().take(6).collect();
        let v = h.post_json("/account/verify/code", json!({ "email": email, "code": code })).await;
        assert_eq!(v.status, StatusCode::OK, "{:?}", v.body);
    }

    async fn log_of(h: &Harness, email: &str, kind: &str) -> Option<(String, Option<String>, i32, Option<String>)> {
        sqlx::query_as::<_, (String, Option<String>, i32, Option<String>)>(
            "SELECT m.status, m.subject, m.attempts, m.error FROM mail_log m JOIN users u ON u.id = m.user_id \
             WHERE u.email = $1 AND m.kind = $2",
        )
        .bind(email)
        .bind(kind)
        .fetch_optional(&h.state.pool)
        .await
        .unwrap()
    }

    fn mails(email: &str, subject: &str) -> usize {
        outbox::to(email).iter().filter(|m| m.subject == subject).count()
    }

    #[tokio::test]
    async fn every_send_is_logged_and_runs_reach_only_who_is_owed() {
        let Some(pool) = fresh_pool("mail_runs").await else { return };
        let base = super::welcome_remote::template_server().await;
        let welcoming = site(pool.clone(), true, Some(format!("{base}/email-templates/followup"))).await;
        let plain = site(pool.clone(), false, None).await;
        let at = |who: &str| format!("{who}-{}@example.test", unique(""));
        let (a, b, c) = (at("welcomed"), at("never"), at("optedout"));
        let d = format!("fail-delivery-{}@example.test", unique(""));

        // A: welcomed at sign-up, and the send is logged.
        sign_up(&welcoming, &a, true).await;
        assert_eq!(mails(&a, "Welcome to TEST"), 1);
        let (status, subject, attempts, error) = log_of(&welcoming, &a, "welcome").await.expect("logged");
        assert_eq!((status.as_str(), subject.as_deref(), attempts, error), ("sent", Some("Welcome to TEST"), 1, None));
        // B: signed up while the site had no welcome — nothing sent, nothing logged.
        sign_up(&plain, &b, true).await;
        assert!(log_of(&plain, &b, "welcome").await.is_none());
        // C: unticked "email me".
        sign_up(&welcoming, &c, false).await;
        // D: the relay refuses it — logged as failed, with why.
        sign_up(&welcoming, &d, true).await;
        let (status, _, _, error) = log_of(&welcoming, &d, "welcome").await.unwrap();
        assert_eq!(status, "failed");
        assert_eq!(error.as_deref(), Some("test: the relay refused it"));

        // Only with the key.
        let q = "/internal/mail/audience?kind=welcome";
        assert_eq!(admin(&welcoming, "GET", q, None, None).await.status, StatusCode::NOT_FOUND);
        assert_eq!(admin(&welcoming, "GET", q, None, Some("wrong-key-wrong-key")).await.status, StatusCode::NOT_FOUND);

        // Catch-up: B (never sent) and D (failed) — not A (sent), not C (opted out).
        let r = admin(&welcoming, "GET", q, None, Some(KEY)).await;
        assert_eq!((r.body["count"].as_i64(), r.body["ready"].as_bool()), (Some(2), Some(true)), "{:?}", r.body);
        let r = admin(&welcoming, "POST", "/internal/mail/send", Some(json!({ "kind": "welcome" })), Some(KEY)).await;
        assert_eq!(r.body["sent"], 1, "{:?}", r.body);
        assert_eq!(r.body["failed"], 1, "D fails again");
        assert_eq!(r.body["remaining"], 1, "and stays owed — the next run tries it again");
        assert_eq!(mails(&b, "Welcome to TEST"), 1);
        assert_eq!(mails(&a, "Welcome to TEST"), 1, "never twice");
        assert_eq!(mails(&c, "Welcome to TEST"), 0, "never to an opted-out account");
        assert_eq!(log_of(&welcoming, &d, "welcome").await.unwrap().2, 2, "a second attempt, counted");

        // Follow-up: welcomed more than N days ago. None are, three days on…
        let f = |days: i32| format!("/internal/mail/audience?kind=followup&days={days}");
        assert_eq!(admin(&welcoming, "GET", &f(3), None, Some(KEY)).await.body["count"], 0);
        // …all welcomed ones are with no delay: A and B.
        assert_eq!(admin(&welcoming, "GET", &f(0), None, Some(KEY)).await.body["count"], 2);
        let r = admin(&welcoming, "POST", "/internal/mail/send", Some(json!({ "kind": "followup", "days": 0 })), Some(KEY)).await;
        assert_eq!((r.body["sent"].as_i64(), r.body["remaining"].as_i64()), (Some(2), Some(0)), "{:?}", r.body);
        assert_eq!(mails(&a, "Following up on TEST"), 1);
        assert_eq!(mails(&b, "Following up on TEST"), 1);
        assert_eq!(mails(&d, "Following up on TEST"), 0, "never welcomed, so no follow-up");
        // A second run finds nobody.
        let r = admin(&welcoming, "POST", "/internal/mail/send", Some(json!({ "kind": "followup", "days": 0 })), Some(KEY)).await;
        assert_eq!(r.body["sent"], 0);
        assert_eq!(mails(&a, "Following up on TEST"), 1);

        // Opting out after the fact takes an account out of every run.
        sqlx::query("UPDATE users SET emails_off_at = now() WHERE email = $1").bind(&d).execute(&pool).await.unwrap();
        assert_eq!(admin(&welcoming, "GET", q, None, Some(KEY)).await.body["count"], 0);
    }

    #[tokio::test]
    async fn a_follow_up_with_no_approved_template_is_refused() {
        let Some(pool) = fresh_pool("mail_runs_off").await else { return };
        let base = super::welcome_remote::template_server().await;
        // The landing Worker answers 404 for a template not approved or switched off.
        let h = site(pool, true, Some(format!("{base}/email-templates/missing"))).await;
        let r = admin(&h, "GET", "/internal/mail/audience?kind=followup", None, Some(KEY)).await;
        assert_eq!(r.body["ready"], false, "{:?}", r.body);
        let r = admin(&h, "POST", "/internal/mail/send", Some(json!({ "kind": "followup" })), Some(KEY)).await;
        assert_eq!(r.status, StatusCode::CONFLICT, "{:?}", r.body);
        let r = admin(&h, "POST", "/internal/mail/send", Some(json!({ "kind": "newsletter" })), Some(KEY)).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST);
    }
}

// ---- [i18n] the language of a request: its errors, and the mail it causes ------------------------

mod languages {
    use super::*;
    use crate::email::outbox;

    async fn post(h: &Harness, path: &str, body: Value, lang: Option<&str>) -> Reply {
        let mut req = Request::post(path)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ORIGIN, SITE);
        if let Some(lang) = lang {
            req = req.header(header::ACCEPT_LANGUAGE, lang);
        }
        h.send(req.body(Body::from(body.to_string())).unwrap()).await
    }

    /// An error is answered with its code and its text: English with no `Accept-Language`, the request's
    /// language with one, English again for a language there are no messages in. The code is the same in all.
    #[tokio::test]
    async fn an_error_is_in_the_language_of_the_request_with_the_same_code() {
        let h = harness_or_skip!();
        let login = json!({ "email": format!("{}@example.test", unique("nobody")), "password": "wrong password" });
        let plain = post(&h, "/account/login", login.clone(), None).await;
        assert_eq!(plain.status, StatusCode::UNAUTHORIZED);
        assert_eq!(plain.body, json!({ "error": "invalid credentials", "code": "SO-E001" }));

        let mut texts = vec![plain.body["error"].as_str().unwrap().to_string()];
        for lang in ["de-DE,de;q=0.9,en;q=0.8", "ru", "fr-FR", "zh-CN", "ja"] {
            let r = post(&h, "/account/login", login.clone(), Some(lang)).await;
            assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{lang}");
            assert_eq!(r.body["code"], "SO-E001", "{lang}: the same code");
            let text = r.body["error"].as_str().unwrap().to_string();
            assert!(!texts.contains(&text), "{lang}: its own text, not {text}");
            texts.push(text);
        }
        let other = post(&h, "/account/login", login.clone(), Some("es-ES, pt;q=0.8")).await;
        assert_eq!(other.body, json!({ "error": "invalid credentials", "code": "SO-E001" }), "no messages in Spanish: English");

        // a password the policy refuses: the number is in the text, the code beside it
        let short = json!({ "email": format!("{}@example.test", unique("short")), "password": "short" });
        let en = post(&h, "/account/register", short.clone(), None).await;
        assert_eq!((en.status, &en.body), (StatusCode::BAD_REQUEST, &json!({ "error": "password must be at least 8 characters", "code": "SO-E022" })));
        let de = post(&h, "/account/register", short, Some("de")).await;
        assert_eq!(de.body["code"], "SO-E022");
        assert!(de.body["error"].as_str().unwrap().contains(" 8 ") && de.body["error"] != en.body["error"], "{:?}", de.body);

        // a refusal of the origin guard, ahead of every handler, is in the language too
        let foreign = Request::post("/account/login")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ORIGIN, "https://evil.test")
            .header(header::ACCEPT_LANGUAGE, "fr")
            .body(Body::from(login.to_string())).unwrap();
        let refused = h.send(foreign).await;
        assert_eq!(refused.status, StatusCode::FORBIDDEN);
        assert_eq!(refused.body["code"], "SO-E005");
        assert_ne!(refused.body["error"], "forbidden", "{:?}", refused.body);
    }

    /// The mail a request causes is in that request's language: a confirmation asked for in Russian is
    /// Russian, with the link and the code as in any language; one asked for with no language is English
    #[tokio::test]
    async fn a_mail_is_in_the_language_of_the_request_that_caused_it() {
        let h = harness_or_skip!();
        let english = crate::i18n::text_in("en", "mail-verify-subject", &[("product", "TEST")]);
        let russian = crate::i18n::text_in("ru", "mail-verify-subject", &[("product", "TEST")]);
        assert_ne!(english, russian);

        let ru = format!("{}@example.test", unique("ru"));
        let r = post(&h, "/account/register", json!({ "email": ru, "password": "correct horse battery staple" }), Some("ru-RU, ru;q=0.9")).await;
        assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
        let mail = outbox::to(&ru);
        assert_eq!(mail.len(), 1);
        assert_eq!(mail[0].subject, russian);
        assert!(mail[0].text.contains(&format!("{SITE}/account/verify?id=")), "the link: {}", mail[0].text);
        assert!(!mail[0].text.contains("Confirm your email address"), "no English sentence in it: {}", mail[0].text);

        let en = format!("{}@example.test", unique("en"));
        let r = post(&h, "/account/register", json!({ "email": en, "password": "correct horse battery staple" }), None).await;
        assert_eq!(r.status, StatusCode::CREATED);
        assert_eq!(outbox::to(&en)[0].subject, english);
    }

    /// A request that names none of the languages is answered in the site's own (`Config::lang`)
    #[tokio::test]
    async fn the_sites_language_answers_a_request_that_names_none() {
        let Some(pool) = pool().await else { return };
        let mut config = Config::new("TEST", SITE);
        config.lang = "de_DE.UTF-8".to_string();
        assert_eq!(config.site_lang(), "de");
        let state = AccountState::from_env_with_mailer(pool, config, Mailer::disabled()).await.unwrap();
        state.sso.replace(SsoSnapshot::default());
        let h = Harness { app: Router::new().nest("/account", crate::router(state.clone())), state, idp: MockIdp::start().await };
        let login = json!({ "email": format!("{}@example.test", unique("nobody")), "password": "wrong password" });
        let german = crate::i18n::error_in("de", "err-credentials", &[]).1;
        assert_eq!(post(&h, "/account/login", login.clone(), None).await.body, json!({ "error": german, "code": "SO-E001" }));
        assert_eq!(post(&h, "/account/login", login.clone(), Some("es")).await.body["error"], german, "Spanish: the site's");
        assert_eq!(post(&h, "/account/login", login, Some("en-US")).await.body["error"], "invalid credentials", "English asked for");
    }
}

// ---- [i18n] [review 2026-11-14] the list's mail, the owner's alert, the notes and the two states --------

mod languages_of_the_list {
    use super::*;
    use crate::email::outbox;

    /// A signup asked for in French: its note and its confirmation are French; the owner's alert of it is in
    /// the site's language (German here), not the visitor's
    #[tokio::test]
    async fn a_signup_is_in_the_visitors_language_and_its_alert_in_the_sites() {
        let Some(pool) = pool().await else { return };
        let owner = format!("{}@example.test", unique("owner"));
        let mut config = Config::new("TEST", SITE);
        config.lang = "de".to_string();
        config.notify_to = vec![owner.clone()];
        let state = AccountState::from_env_with_mailer(pool, config, Mailer::disabled()).await.unwrap();
        let app = Router::new().nest("/news", crate::subscribe_router(state.clone()));
        let visitor = format!("{}@example.test", unique("lecteur"));
        let request = Request::post("/news/subscribe")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ORIGIN, SITE)
            .header(header::ACCEPT_LANGUAGE, "fr-FR, fr;q=0.9")
            .body(Body::from(json!({ "email": visitor }).to_string()))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value = serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap()).unwrap();
        assert_eq!(body["note"], crate::i18n::text_in("fr", "note-check-email-subscription", &[]));
        assert_ne!(body["note"], "check your email to confirm the subscription");

        let confirmation = outbox::to(&visitor);
        assert_eq!(confirmation.len(), 1);
        assert_eq!(confirmation[0].subject, crate::i18n::text_in("fr", "mail-sub-confirm-subject", &[("product", "TEST")]));
        // the alert is sent after the answer: it is there shortly
        let german = crate::i18n::text_in("de", "mail-signup-subject", &[("product", "TEST"), ("email", &visitor)]);
        let mut alert = Vec::new();
        for _ in 0..50 {
            alert = outbox::to(&owner);
            if !alert.is_empty() { break; }
            tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        }
        assert_eq!(alert.len(), 1, "the owner is told");
        assert_eq!(alert[0].subject, german, "in the site's language, not the visitor's");
        assert!(alert[0].text.contains(&crate::i18n::text_in("de", "mail-signup-unconfirmed", &[])), "{}", alert[0].text);
    }

    /// A registration's note is in the request's language; English when none is asked for
    #[tokio::test]
    async fn the_note_of_a_registration_is_in_the_requests_language() {
        let h = harness_or_skip!();
        for (lang, key_lang) in [(None, "en"), (Some("ja"), "ja")] {
            let mut req = Request::post("/account/register")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ORIGIN, SITE);
            if let Some(lang) = lang {
                req = req.header(header::ACCEPT_LANGUAGE, lang);
            }
            let body = json!({ "email": format!("{}@example.test", unique("note")), "password": "correct horse battery staple" });
            let r = h.send(req.body(Body::from(body.to_string())).unwrap()).await;
            assert_eq!(r.status, StatusCode::CREATED);
            assert_eq!(r.body["status"], "registered", "the state is the same in every language");
            assert_eq!(r.body["note"], crate::i18n::text_in(key_lang, "note-check-email-account", &[]));
        }
        assert_eq!(crate::i18n::text_in("en", "note-check-email-account", &[]), "check your email to activate your account");
    }

    /// The two states a client switches on keep their word, and have a code and a sentence beside it
    #[test]
    fn a_state_has_its_code_beside_it() {
        for (key, code) in [("err-registered-here", "SO-E025"), ("err-sso-required", "SO-E026")] {
            for lang in crate::i18n::LANGS {
                let (c, text) = crate::i18n::error_in(lang, key, &[]);
                assert_eq!(c, code, "{lang} {key}");
                assert!(!text.is_empty());
            }
        }
    }
}

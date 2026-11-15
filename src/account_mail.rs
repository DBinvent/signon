//! Mail to an account that is not about the account itself — the welcome
//! and its follow-up — the internal send log behind them, and the owner's
//! way to turn them off.
//!
//! Opt-out, per site: the sign-up form's "email me" box is pre-ticked
//! (`note_signup`), and every such mail carries an unsubscribe link plus the
//! RFC 8058 one-click headers. Account mail (verification, password reset,
//! sign-in codes) is not affected by any of it — those are the account
//! working, not marketing.
//!
//! Every send is logged in `mail_log`, one row per account per kind: claimed
//! before it goes, then marked sent or failed with the relay's reason. That
//! row is what makes a kind reach an account at most once, and what the two
//! manual runs work from ([`mail_admin_router`]): the catch-up welcome (to
//! accounts that never got one) and the follow-up (to accounts welcomed more
//! than N days ago). The log is internal — shown to nobody.
//!
//! The mailing list in `subscribe.rs` is a different thing: bare addresses,
//! double opt-in, no account. The two never share a token or a table.
//!
//! Routes, under `/account`:
//!
//! | Method | Path | |
//! |---|---|---|
//! | POST | `/emails` | signed in: `{enabled}` — the profile page switch |
//! | POST | `/emails/unsubscribe` | `{token, enabled?}` — the unsubscribe page (and its undo) |
//! | POST | `/emails/unsubscribe/{token}` | one-click, POSTed by the mail client itself |

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::current_user::CurrentUser;
use crate::routes::{bad_request, internal_error};
use crate::{db, email::Templates, subscribe::list_headers, token, AccountState, Welcome};

/// The kinds of non-essential mail, as `mail_log.kind` spells them.
pub(crate) const WELCOME: &str = "welcome";
pub(crate) const FOLLOWUP: &str = "followup";

pub(crate) fn routes() -> Router<AccountState> {
    Router::new()
        .route("/emails", post(set_emails))
        .route("/emails/unsubscribe", post(unsubscribe))
        .route("/emails/unsubscribe/{token}", post(one_click))
}

/// Sends the site's welcome to `user_id` if the site has one and the account
/// qualifies — a confirmed address, mail left on, not sent before. Safe to
/// call from every place an account can become usable: the claim in
/// `db::claim_mail` makes all but the first send a no-op.
///
/// Where the text comes from decides whether there is one: with
/// [`crate::Config::welcome_url`] it is that URL's answer and nothing else —
/// a template not approved or switched off (404), or no answer at all, means
/// no welcome, and nothing is logged as sent (the catch-up run can reach the
/// account later). Without it, the built-in [`crate::Config::welcome`].
pub(crate) async fn send_welcome(state: &AccountState, user_id: Uuid) {
    if !welcome_configured(state) {
        return;
    }
    // Cheap first: most calls are for accounts already welcomed or opted out,
    // and those must not cost a fetch.
    match db::mail_owed(&state.pool, user_id, WELCOME).await {
        Ok(true) => {}
        Ok(false) => return,
        Err(e) => {
            tracing::error!(%e, %user_id, "mail_owed");
            return;
        }
    }
    let Some(welcome) = resolve(state, WELCOME).await else {
        return;
    };
    send_one(state, user_id, WELCOME, &welcome).await;
}

/// What one send came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Sent {
    Sent,
    Failed,
    /// Not owed after all (opted out meanwhile, another run got there first).
    Skipped,
}

/// Claims, sends and logs one mail of `kind` with `text`.
pub(crate) async fn send_one(state: &AccountState, user_id: Uuid, kind: &str, text: &Welcome) -> Sent {
    let claim = match db::claim_mail(&state.pool, user_id, kind, &token::secret()).await {
        Ok(Some(claim)) => claim,
        Ok(None) => return Sent::Skipped,
        Err(e) => {
            tracing::error!(%e, %user_id, kind, "claim_mail");
            return Sent::Failed;
        }
    };
    let page = state.config.account_unsubscribe_url(&claim.unsubscribe_token);
    // The footer line the text's source sent with it, else the site's own.
    let note = match &text.footer_note {
        Some(sent) => sent.as_ref(),
        None => state.config.footer_note.as_ref(),
    };
    let (subject, body, html) = Templates::welcome(crate::i18n::current(), &state.config.product_name, text, note, &page);
    let headers = list_headers(&state.config.one_click_unsubscribe_url(&claim.unsubscribe_token));
    let result = state
        .mailer
        .deliver(&claim.email, &subject, body, html, &headers)
        .await;
    if let Err(e) = db::finish_mail(&state.pool, claim.log_id, &subject, &result).await {
        tracing::error!(%e, %user_id, kind, "finish_mail");
    }
    match result {
        Ok(()) => {
            tracing::info!(%user_id, kind, "account mail sent");
            Sent::Sent
        }
        Err(_) => Sent::Failed,
    }
}

fn welcome_configured(state: &AccountState) -> bool {
    #[cfg(feature = "welcome-remote")]
    if state.config.welcome_url.is_some() {
        return true;
    }
    state.config.welcome.is_some()
}

/// The text for `kind`, if there is one to send right now. The welcome:
/// `Config::welcome_url`'s answer when that is configured — approved and
/// switched on there, or nothing — else the built-in `Config::welcome`. The
/// follow-up: only ever `Config::followup_url`'s answer; it has no built-in
/// text.
async fn resolve(state: &AccountState, kind: &str) -> Option<Welcome> {
    #[cfg(feature = "welcome-remote")]
    {
        let url = if kind == WELCOME {
            state.config.welcome_url.as_deref()
        } else {
            state.config.followup_url.as_deref()
        };
        if let Some(url) = url {
            return match remote_template(&state.config, url).await {
                Ok(Some(w)) => Some(w),
                Ok(None) => {
                    tracing::info!(url, kind, "template not approved or switched off — not sent");
                    None
                }
                Err(e) => {
                    tracing::warn!(%e, url, kind, "template unavailable — not sent");
                    None
                }
            };
        }
    }
    if kind == WELCOME {
        state.config.welcome.clone()
    } else {
        None
    }
}

/// `GET url` → a [`Welcome`]. `Ok(None)` for a 404 — the template is not
/// approved, or is switched off — or one that is no use (no subject, no
/// text). Short timeout: a verification answer waits on it. A `footer` in the
/// answer (`{text, label, url}`) is the footer line to send with it.
#[cfg(feature = "welcome-remote")]
async fn remote_template(config: &crate::Config, url: &str) -> anyhow::Result<Option<Welcome>> {
    #[derive(Deserialize)]
    struct Footer {
        #[serde(default)]
        text: String,
        #[serde(default)]
        label: Option<String>,
        #[serde(default)]
        url: Option<String>,
    }
    #[derive(Deserialize)]
    struct Remote {
        subject: String,
        body: String,
        #[serde(default)]
        action_label: Option<String>,
        #[serde(default)]
        action_url: Option<String>,
        #[serde(default)]
        footer: Option<Footer>,
    }
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(1500))
        .build()?;
    let response = client.get(url).send().await?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    let r: Remote = response.error_for_status()?.json().await?;
    let welcome = welcome_from_template(
        config,
        &r.subject,
        &r.body,
        r.action_label.as_deref(),
        r.action_url.as_deref(),
    );
    Ok(welcome.map(|mut w| {
        w.footer_note = r
            .footer
            .map(|f| footer_from_template(&f.text, f.label.as_deref(), f.url.as_deref()));
        w
    }))
}

/// The footer line a template's source sent → a [`crate::FooterNote`];
/// `None` for an empty line, which is no line. One line, at most 300
/// characters; the link stays only with both parts and an http(s) URL.
#[cfg(feature = "welcome-remote")]
pub(crate) fn footer_from_template(
    text: &str,
    label: Option<&str>,
    url: Option<&str>,
) -> Option<crate::FooterNote> {
    let text: String = text.split_whitespace().collect::<Vec<_>>().join(" ").chars().take(300).collect();
    if text.is_empty() {
        return None;
    }
    let link = match (label.map(str::trim), url.map(str::trim)) {
        (Some(label), Some(url))
            if !label.is_empty() && (url.starts_with("https://") || url.starts_with("http://")) =>
        {
            Some((label.chars().take(60).collect(), url.to_string()))
        }
        _ => None,
    };
    Some(crate::FooterNote { text, link })
}

/// Template text → a [`Welcome`]: one paragraph per blank-line-separated
/// block, `{site}` (this site's origin) and `{product}` substituted. The
/// subject is cut to its first line — it becomes a header. The button stays
/// only with both parts and an http(s) URL once substituted; a template that
/// has no subject or no text at all is no mail.
#[cfg(feature = "welcome-remote")]
pub(crate) fn welcome_from_template(
    config: &crate::Config,
    subject: &str,
    body: &str,
    action_label: Option<&str>,
    action_url: Option<&str>,
) -> Option<Welcome> {
    let fill = |s: &str| {
        s.replace("{site}", &config.app_base_url)
            .replace("{product}", &config.product_name)
    };
    let subject: String = fill(subject.lines().next().unwrap_or_default().trim()).chars().take(200).collect();
    let body: String = body.replace("\r\n", "\n").replace('\r', "\n").chars().take(5000).collect();
    let paragraphs: Vec<String> = body
        .split("\n\n")
        .map(|p| fill(p.trim()))
        .filter(|p| !p.is_empty())
        .collect();
    if subject.is_empty() || paragraphs.is_empty() {
        return None;
    }
    let action = match (action_label.map(str::trim), action_url.map(str::trim)) {
        (Some(label), Some(url)) if !label.is_empty() && !url.is_empty() => {
            let url = fill(url);
            (url.starts_with("https://") || url.starts_with("http://"))
                .then(|| (fill(label).chars().take(60).collect(), url))
        }
        _ => None,
    };
    Some(Welcome {
        subject,
        paragraphs,
        action,
        footer_note: None,
    })
}

// ---- manual runs: the catch-up welcome and the follow-up --------------------------

/// Accounts one run sends to at most; the answer says how many remain, and
/// the next run takes those. Keeps one request well inside any timeout.
const RUN_LIMIT: i64 = 200;

/// The admin side of the mail log, for a host app to nest (for example at
/// `/internal/mail`) and the site's template admin to call:
///
/// | Method | Path | |
/// |---|---|---|
/// | GET | `/audience?kind=welcome\|followup&days=N` | `{count, ready}` — how many it would reach, and whether the template is approved and switched on |
/// | POST | `/send` | `{kind, days}` → `{sent, failed, skipped, remaining}` — up to 200 accounts per call |
///
/// `welcome` reaches accounts that never got one; `followup` accounts whose
/// welcome went more than `days` days ago (default 3) and that have not had
/// the follow-up. Opted-out, unconfirmed and suspended accounts never.
/// Behind `Authorization: Bearer <MAIL_ADMIN_KEY>` (`Config::mail_admin_key`);
/// without that key configured, both answer 404.
pub fn mail_admin_router(state: AccountState) -> Router {
    Router::new()
        .route("/audience", get(audience))
        .route("/send", post(run))
        .layer(axum::middleware::from_fn_with_state(state.clone(), crate::routes::request_language)) // [i18n]
        .with_state(state)
}

fn admin_authorized(state: &AccountState, headers: &HeaderMap) -> bool {
    let Some(key) = state.config.mail_admin_key.as_deref() else {
        return false;
    };
    let presented = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default();
    !presented.is_empty() && token::constant_time_eq(presented.as_bytes(), key.as_bytes())
}

#[derive(Deserialize)]
struct RunReq {
    kind: String,
    #[serde(default = "default_days")]
    days: i32,
}

fn default_days() -> i32 {
    3
}

/// `(kind, the earlier kind and delay a follow-up waits on)`, or a 400.
#[allow(clippy::result_large_err)] // the Err is a response, returned at once
fn parse_run(req: &RunReq) -> Result<(&'static str, Option<(&'static str, i32)>), Response> {
    if !(0..=365).contains(&req.days) {
        return Err(bad_request("err-mail-days").into_response());
    }
    match req.kind.as_str() {
        WELCOME => Ok((WELCOME, None)),
        FOLLOWUP => Ok((FOLLOWUP, Some((WELCOME, req.days)))),
        _ => Err(bad_request("err-mail-kind").into_response()),
    }
}

fn not_found() -> Response {
    (StatusCode::NOT_FOUND, Json(crate::i18n::error_body("err-not-found", &[]))).into_response()
}

async fn audience(State(state): State<AccountState>, headers: HeaderMap, Query(req): Query<RunReq>) -> Response {
    if !admin_authorized(&state, &headers) {
        return not_found();
    }
    let (kind, after) = match parse_run(&req) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let count = match db::mail_audience_count(&state.pool, kind, after).await {
        Ok(n) => n,
        Err(e) => {
            tracing::error!(%e, kind, "mail_audience_count");
            return internal_error().into_response();
        }
    };
    let ready = resolve(&state, kind).await.is_some();
    Json(json!({ "kind": kind, "count": count, "ready": ready })).into_response()
}

async fn run(State(state): State<AccountState>, headers: HeaderMap, Json(req): Json<RunReq>) -> Response {
    if !admin_authorized(&state, &headers) {
        return not_found();
    }
    let (kind, after) = match parse_run(&req) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Some(text) = resolve(&state, kind).await else {
        return (
            StatusCode::CONFLICT,
            Json(crate::i18n::error_body("err-template-off", &[])),
        )
            .into_response();
    };
    let users = match db::mail_audience(&state.pool, kind, after, RUN_LIMIT).await {
        Ok(u) => u,
        Err(e) => {
            tracing::error!(%e, kind, "mail_audience");
            return internal_error().into_response();
        }
    };
    // [i18n] a run is the admin's request, not the readers': its mail is in the site's language
    let (sent, failed, skipped) = crate::i18n::scope(state.config.site_lang(), async {
        let (mut sent, mut failed, mut skipped) = (0, 0, 0);
        for user_id in users {
            match send_one(&state, user_id, kind, &text).await {
                Sent::Sent => sent += 1,
                Sent::Failed => failed += 1,
                Sent::Skipped => skipped += 1,
            }
        }
        (sent, failed, skipped)
    }).await;
    // Failed ones count as remaining: the next run tries them again.
    let remaining = db::mail_audience_count(&state.pool, kind, after).await.unwrap_or(-1);
    tracing::info!(kind, sent, failed, skipped, remaining, "mail run");
    Json(json!({ "kind": kind, "sent": sent, "failed": failed, "skipped": skipped, "remaining": remaining }))
        .into_response()
}

#[derive(Deserialize)]
struct SetEmailsReq {
    enabled: bool,
}

async fn set_emails(
    State(state): State<AccountState>,
    user: CurrentUser,
    Json(req): Json<SetEmailsReq>,
) -> Response {
    if let Err(e) = db::set_emails(&state.pool, user.id, req.enabled).await {
        tracing::error!(%e, "set_emails");
        return internal_error().into_response();
    }
    Json(json!({ "emails_enabled": req.enabled })).into_response()
}

#[derive(Deserialize)]
struct UnsubscribeReq {
    token: String,
    /// `true` is the page's "changed my mind" — the same link turns mail
    /// back on.
    #[serde(default)]
    enabled: bool,
}

/// The page behind the mailed link. It posts on load, like the mailing
/// list's page — and offers the undo (`enabled: true`) right there, since a
/// link scanner that opens every URL in a message can land on it too.
async fn unsubscribe(State(state): State<AccountState>, Json(req): Json<UnsubscribeReq>) -> Response {
    if req.token.is_empty() || req.token.len() > 64 {
        return bad_request("err-invalid-link").into_response();
    }
    match db::set_emails_by_token(&state.pool, &req.token, req.enabled).await {
        Ok(true) => Json(json!({ "emails_enabled": req.enabled })).into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(crate::i18n::error_body("err-account-unsubscribe-link", &[])),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(%e, "set_emails_by_token");
            internal_error().into_response()
        }
    }
}

/// RFC 8058: the mail client POSTs `List-Unsubscribe=One-Click` here on the
/// user's behalf. Always 200 — a client has nothing useful to do with a
/// failure, and the answer must not sort tokens into real and not.
async fn one_click(State(state): State<AccountState>, Path(token): Path<String>) -> Response {
    if !token.is_empty() && token.len() <= 64 {
        if let Err(e) = db::set_emails_by_token(&state.pool, &token, false).await {
            tracing::error!(%e, "one-click unsubscribe");
        }
    }
    Json(json!({ "status": "ok" })).into_response()
}

#[cfg(all(test, feature = "welcome-remote"))]
mod tests {
    use super::*;

    #[test]
    fn a_template_becomes_paragraphs_with_the_site_filled_in() {
        let config = crate::Config::new("Acme Dash", "https://dash.example");
        let w = welcome_from_template(
            &config,
            "Welcome to {product}\r\nBcc: someone@evil.example",
            "First.\r\n\r\nSecond line\nstill second.\n\n\n\nThird at {site}.\n\n   \n",
            Some("Open {product}"),
            Some("{site}/start"),
        )
        .unwrap();
        assert_eq!(w.subject, "Welcome to Acme Dash", "one line — it is a header");
        assert_eq!(
            w.paragraphs,
            ["First.", "Second line\nstill second.", "Third at https://dash.example."]
        );
        assert_eq!(w.action, Some(("Open Acme Dash".into(), "https://dash.example/start".into())));
    }

    #[test]
    fn a_button_needs_both_parts_and_a_web_address() {
        let config = crate::Config::new("X", "https://x.example");
        let action = |label: Option<&str>, url: Option<&str>| {
            welcome_from_template(&config, "S", "B", label, url).unwrap().action
        };
        assert_eq!(action(Some("Go"), Some("javascript:alert(1)")), None);
        assert_eq!(action(Some("Go"), Some("data:text/html,x")), None);
        assert_eq!(action(Some("Go"), None), None);
        assert_eq!(action(Some(" "), Some("https://a.example")), None);
        assert_eq!(action(Some("Go"), Some("https://a.example")), Some(("Go".into(), "https://a.example".into())));
    }

    #[test]
    fn no_subject_or_no_text_is_no_welcome() {
        let config = crate::Config::new("X", "https://x.example");
        assert!(welcome_from_template(&config, "  ", "Body", None, None).is_none());
        assert!(welcome_from_template(&config, "S", "\n\n  \n", None, None).is_none());
    }

    #[test]
    fn a_footer_line_from_the_template_source_is_one_line_and_a_web_link() {
        let n = footer_from_template("  We listen.\nReally. ", Some("Tell us"), Some("https://x/f")).unwrap();
        assert_eq!(n.text, "We listen. Really.", "one line — newlines are spaces");
        assert_eq!(n.link, Some(("Tell us".to_string(), "https://x/f".to_string())));
        let scripted = footer_from_template("We listen.", Some("Tell us"), Some("javascript:alert(1)")).unwrap();
        assert!(scripted.link.is_none(), "only an http(s) link");
        assert!(footer_from_template("We listen.", None, Some("https://x/f")).unwrap().link.is_none());
        assert!(footer_from_template("   ", None, None).is_none(), "an empty line is no line");
    }
}

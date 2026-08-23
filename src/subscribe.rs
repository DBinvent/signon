//! Mailing list for product updates and news.
//!
//! Ported from `trust-atria-landing`'s waitlist (`worker/src/index.ts`
//! `handleWaitlist` + `notify.ts`), which keeps the same data in Cloudflare
//! D1. Here it lives in the home Postgres alongside everything else, so a
//! site that already runs one of these backends needs no second datastore and
//! no second set of SMTP credentials.
//!
//! Three things this adds over the D1 original, and why:
//!
//! * **Double opt-in.** Anyone can type someone else's address into a signup
//!   box. A waitlist you personally contact can live with that; a recurring
//!   "updates and news" list cannot — it is the difference between a mailing
//!   list and a way to send mail to strangers. Nothing but the confirmation
//!   itself is ever sent to an unconfirmed address.
//! * **A working unsubscribe link**, carried in every message from the first
//!   one, with a long-lived token because it has to keep working in mail sent
//!   months ago.
//! * **The same enumeration guard as the account endpoints.** The D1 version
//!   answers `200 {ok:true}` on a duplicate and `201` on a new signup, which
//!   tells a caller whether an address is already on the list. Here both
//!   answer identically.
//!
//! Unsubscribing sets a timestamp rather than deleting the row, so a later
//! resubscribe is a state change and a mis-click is recoverable.

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use std::time::Duration;

use crate::current_user::RequestMeta;
use crate::email::Templates;
use crate::routes::{bad_request, internal_error, mail_unavailable, normalize_email, ok, too_many};
use crate::{db, token, AccountState};

const HOUR: Duration = Duration::from_secs(3600);
const SUBSCRIBE_PER_IP: usize = 10;
const SUBSCRIBE_PER_EMAIL: usize = 3;
/// Minimum gap between two confirmation sends to the same address. Stops the
/// signup box being used to repeatedly mail someone who never asked.
const CONFIRM_RESEND_COOLDOWN: Duration = Duration::from_secs(300);

/// Mount at `/news` in the service's own router — the frontend reaches it as
/// `/api/news/...`, and `Config::subscribe_confirm_path` /
/// `Config::unsubscribe_path` are the matching *page* routes the mail links
/// point at.
pub fn router(state: AccountState) -> Router {
    Router::new()
        .route("/subscribe", post(subscribe))
        .route("/confirm", post(confirm))
        .route("/confirm/{token}", get(confirm_link))
        .route("/unsubscribe", post(unsubscribe))
        .route("/unsubscribe/{token}", get(unsubscribe_link))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::routes::origin_guard,
        ))
        .with_state(state)
}

#[derive(Deserialize)]
struct SubscribeReq {
    email: String,
    /// Which page or site this came from, so one list can serve several entry
    /// points. Free text from the client, so it is length-capped and only ever
    /// stored, never interpreted.
    #[serde(default)]
    source: Option<String>,
}

async fn subscribe(
    State(state): State<AccountState>,
    meta: RequestMeta,
    headers: HeaderMap,
    Json(req): Json<SubscribeReq>,
) -> Response {
    let Some(email) = normalize_email(&req.email) else {
        return bad_request("a valid email is required").into_response();
    };

    if !state.limiter.check(&format!("sub:ip:{}", meta.ip_key()), SUBSCRIBE_PER_IP, HOUR)
        || !state.limiter.check(&format!("sub:em:{email}"), SUBSCRIBE_PER_EMAIL, HOUR)
    {
        return too_many().into_response();
    }

    // Before any lookup, and independent of the address — same reasoning as
    // `routes::register`. A `503` that only appeared for addresses that would
    // actually have been mailed would say which those were.
    if !state.mailer.is_healthy().await {
        return mail_unavailable().into_response();
    }

    let existing = match db::find_subscriber(&state.pool, &email).await {
        Ok(row) => row,
        Err(e) => {
            tracing::error!(%e, "find_subscriber");
            return internal_error().into_response();
        }
    };

    // Already confirmed and still subscribed: nothing to do, and nothing to
    // say about it either.
    let already_active =
        existing.as_ref().is_some_and(|s| s.confirmed && s.unsubscribed_at.is_none());
    let cooling_down = existing.as_ref().is_some_and(|s| {
        s.confirm_sent_at.is_some_and(|sent| {
            chrono::Utc::now() - sent
                < chrono::Duration::from_std(CONFIRM_RESEND_COOLDOWN)
                    .unwrap_or_else(|_| chrono::Duration::seconds(300))
        })
    });

    if !already_active && !cooling_down {
        let confirm_token = token::secret();
        let unsubscribe_token = token::secret();
        let source = req
            .source
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty() && s.len() <= 64);
        let referer = headers
            .get(header::REFERER)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.chars().take(512).collect::<String>());

        match db::upsert_subscriber(
            &state.pool,
            &email,
            source,
            &token::hash(&confirm_token),
            // Stored in the clear — see the column note in schema.yaml: every
            // future newsletter has to rebuild this link, which a hash makes
            // impossible.
            &unsubscribe_token,
            meta.ip.as_deref(),
            meta.user_agent.as_deref(),
            referer.as_deref(),
        )
        .await
        {
            Ok((_id, _was_new, stored_unsubscribe_token)) => {
                // `was_new` deliberately unused in the response — see the
                // module doc on the enumeration guard.
                //
                // The unsubscribe token comes back from the statement rather
                // than being the one generated above: on a resubscribe the
                // existing row keeps its own, so that links in mail already
                // sent keep working, and mailing the freshly generated value
                // would hand out a link that is in no row at all.
                let unsubscribe_url = state.config.unsubscribe_url(&stored_unsubscribe_token);
                let (subject, text, html) = Templates::subscribe_confirm(
                    &state.config.product_name,
                    &state.config.subscribe_confirm_url(&confirm_token),
                    &unsubscribe_url,
                );
                state
                    .mailer
                    .send_with_headers(&email, &subject, text, html, &list_headers(&unsubscribe_url))
                    .await;
                notify_owner(&state, &email, source, &meta, referer.as_deref()).await;
            }
            Err(e) => {
                tracing::error!(%e, "upsert_subscriber");
                return internal_error().into_response();
            }
        }
    }

    // One answer for every path through the above: new address, address that
    // is already on the list, address in its resend cooldown.
    (
        axum::http::StatusCode::OK,
        Json(json!({
            "status": "ok",
            "note": "check your email to confirm the subscription",
        })),
    )
        .into_response()
}

/// Mirrors `trust-atria-landing/worker/src/notify.ts`. Best effort: a failure
/// to tell the owner must not change what the visitor sees.
async fn notify_owner(
    state: &AccountState,
    email: &str,
    source: Option<&str>,
    meta: &RequestMeta,
    referer: Option<&str>,
) {
    if state.config.notify_to.is_empty() {
        return;
    }
    let (subject, text, html) = Templates::signup_notice(
        &state.config.product_name,
        email,
        source,
        meta.ip.as_deref(),
        meta.user_agent.as_deref(),
        referer,
    );
    for to in &state.config.notify_to {
        state.mailer.send(to, &subject, text.clone(), html.clone()).await;
    }
}

/// One-click unsubscribe headers (RFC 8058), on every list message.
///
/// This is what keeps list mail out of spam folders — Gmail and Yahoo require
/// it from bulk senders — and it gives the recipient a way out that does not
/// depend on them finding the link in the body. `List-Unsubscribe-Post` is
/// what makes the mail client's own "unsubscribe" button work without opening
/// a browser, which is why the endpoint accepts POST as well as GET.
fn list_headers(unsubscribe_url: &str) -> Vec<(String, String)> {
    vec![
        ("List-Unsubscribe".to_string(), format!("<{unsubscribe_url}>")),
        ("List-Unsubscribe-Post".to_string(), "List-Unsubscribe=One-Click".to_string()),
    ]
}

#[derive(Deserialize)]
struct TokenReq {
    token: String,
}

async fn confirm(State(state): State<AccountState>, Json(req): Json<TokenReq>) -> Response {
    finish_confirm(&state, &req.token).await
}

async fn confirm_link(State(state): State<AccountState>, Path(tok): Path<String>) -> Response {
    finish_confirm(&state, &tok).await
}

async fn finish_confirm(state: &AccountState, raw_token: &str) -> Response {
    match db::confirm_subscriber(&state.pool, &token::hash(raw_token)).await {
        Ok(Some((email, unsubscribe_token))) => {
            // One welcome message, carrying the unsubscribe link from the very
            // first mail rather than making someone wait for a newsletter to
            // find the way off the list.
            let unsubscribe_url = state.config.unsubscribe_url(&unsubscribe_token);
            let (subject, text, html) =
                Templates::subscribe_welcome(&state.config.product_name, &unsubscribe_url);
            state
                .mailer
                .send_with_headers(&email, &subject, text, html, &list_headers(&unsubscribe_url))
                .await;
            (
                axum::http::StatusCode::OK,
                Json(json!({ "status": "confirmed" })),
            )
                .into_response()
        }
        Ok(None) => {
            // Expired, already used, or never existed — one answer for all
            // three, and a `400` rather than a `401` because there is no
            // credential involved.
            bad_request("that confirmation link is no longer valid").into_response()
        }
        Err(e) => {
            tracing::error!(%e, "confirm_subscriber");
            internal_error().into_response()
        }
    }
}

async fn unsubscribe(State(state): State<AccountState>, Json(req): Json<TokenReq>) -> Response {
    finish_unsubscribe(&state, &req.token).await
}

async fn unsubscribe_link(State(state): State<AccountState>, Path(tok): Path<String>) -> Response {
    finish_unsubscribe(&state, &tok).await
}

async fn finish_unsubscribe(state: &AccountState, raw_token: &str) -> Response {
    // Compared against the column as-is, not hashed: the unsubscribe token is
    // the one secret in this crate stored in the clear, because every future
    // newsletter has to rebuild the link. See the column note in schema.yaml.
    match db::unsubscribe(&state.pool, raw_token).await {
        // Idempotent: a second click is a success, not an error. Someone who
        // wants off a list should never be shown a failure page.
        Ok(true) => ok().into_response(),
        Ok(false) => bad_request("that unsubscribe link is not valid").into_response(),
        Err(e) => {
            tracing::error!(%e, "unsubscribe");
            internal_error().into_response()
        }
    }
}

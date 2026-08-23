//! Outbound mail.
//!
//! Shape borrowed from `xpc_backend/src/xpc/ext/emailer.rs` (lettre 0.11,
//! async, rustls). A service with no working mail relay cannot deliver the
//! verify/reset links its own `/account/register` etc. promise, so — unlike
//! an earlier version of this module — a missing or unreachable relay is not
//! quietly downgraded to "log the message instead": `from_env` refuses to
//! construct at all (see `AccountState::from_env`, which fails startup on
//! this), and `is_healthy` lets a handler refuse a request rather than
//! silently swallowing a send it cannot make. `disabled()` is the deliberate
//! opt-out for tests and local runs that do not want either.

use lettre::message::{header, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

/// How a `Mailer` actually puts a message on the wire.
///
/// Two providers, one interface. SMTP is the original (Brevo relay); the
/// Cloudflare arm exists because `knownby.work` and `dbinvent.com` are already
/// onboarded to Cloudflare Email Sending, and a Rust service is not a Worker,
/// so it uses the REST API rather than the `send_email` binding. The binding
/// needs no credential and is the right choice *inside* a Worker; from here a
/// scoped API token is the only option there is.
enum Provider {
    Smtp(Box<AsyncSmtpTransport<Tokio1Executor>>),
    /// Cloudflare Email Sending REST API.
    Cloudflare {
        account_id: String,
        token: String,
        http: reqwest::Client,
    },
}

pub struct Mailer {
    transport: Option<Provider>,
    from: String,
    /// Optional display name on the envelope sender.
    from_name: Option<String>,
    host: String,
    /// Set only by `disabled()`. Makes `is_healthy` report healthy without a
    /// real relay, so tests and local dev are not forced to fake one — see
    /// the module doc for why an *unset* relay in a real deployment does not
    /// get this treatment.
    disabled: bool,
}

impl Mailer {
    /// Reads `EMAIL_HOST`, `EMAIL_PORT`, `EMAIL_LOGIN`, `EMAIL_KEY`, `EMAIL_FROM`
    /// (the Brevo relay settings already in `trust-atria-bo/crates/env.sample`).
    ///
    /// Fails if any of the five is missing, unparseable, or the relay cannot
    /// even be built — a service that cannot send mail should not come up
    /// believing it can. Use `disabled()` for a deployment that genuinely has
    /// none (tests, local dev without a relay).
    ///
    /// `EMAIL_FROM` is mandatory, not defaulted to `EMAIL_LOGIN`: the login is
    /// typically a relay-internal handle (Brevo's is `<id>@smtp-brevo.com`),
    /// not an address on a domain with SPF/DKIM set up to send as — a relay
    /// can accept the send (`250 OK`, logged as sent) and then silently drop
    /// or hold it downstream for exactly that reason, with nothing on this
    /// end to show for it. Caught in production 2026-08-23: `is_healthy`'s
    /// probe and `send`'s own logging both looked clean while every mail
    /// silently vanished.
    pub fn from_env() -> anyhow::Result<Self> {
        // `EMAIL_PROVIDER=cloudflare` switches to Cloudflare Email Sending;
        // anything else (or unset) keeps the SMTP relay, so nothing already
        // deployed changes behaviour by upgrading this crate.
        if std::env::var("EMAIL_PROVIDER").is_ok_and(|p| p.eq_ignore_ascii_case("cloudflare")) {
            return Self::cloudflare_from_env();
        }
        let host = std::env::var("EMAIL_HOST")
            .map_err(|_| anyhow::anyhow!("EMAIL_HOST is not set"))?;
        let port: u16 = std::env::var("EMAIL_PORT")
            .map_err(|_| anyhow::anyhow!("EMAIL_PORT is not set"))?
            .parse()
            .map_err(|e| anyhow::anyhow!("EMAIL_PORT is not a valid port: {e}"))?;
        let login = std::env::var("EMAIL_LOGIN")
            .map_err(|_| anyhow::anyhow!("EMAIL_LOGIN is not set"))?;
        let key = std::env::var("EMAIL_KEY")
            .map_err(|_| anyhow::anyhow!("EMAIL_KEY is not set"))?;
        let from = std::env::var("EMAIL_FROM")
            .map_err(|_| anyhow::anyhow!("EMAIL_FROM is not set"))?;

        // `relay()` is implicit/wrapper TLS (SMTPS, conventionally port 465);
        // `starttls_relay()` connects in plaintext and upgrades (conventionally
        // port 587, e.g. Brevo). Using the wrong one for the configured port
        // is not a fallback-able mismatch — the two speak different bytes on
        // the wire from the first packet, and lettre surfaces it as an opaque
        // "received corrupt message" TLS error rather than anything naming the
        // real cause.
        let builder = if port == 465 {
            AsyncSmtpTransport::<Tokio1Executor>::relay(&host)
        } else {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&host)
        };
        let transport = builder
            .map_err(|e| anyhow::anyhow!("cannot build SMTP relay for {host}:{port}: {e}"))?
            .port(port)
            .credentials(Credentials::new(login, key))
            .build();

        tracing::info!(host = %host, port, "SMTP relay configured");
        Ok(Self {
            transport: Some(Provider::Smtp(Box::new(transport))),
            from,
            from_name: std::env::var("EMAIL_FROM_NAME").ok(),
            host,
            disabled: false,
        })
    }

    /// Cloudflare Email Sending, via the REST API.
    ///
    /// `CF_ACCOUNT_ID` + `CF_EMAIL_TOKEN` + `EMAIL_FROM`. The token needs the
    /// account-level *Email Sending* send permission; a token that can only
    /// *read* `email/sending/zones` returns `10000 Authentication error` on
    /// the send call, which is not distinguishable from a bad token by the
    /// message alone.
    ///
    /// `EMAIL_FROM` must be on a domain onboarded to Email Sending
    /// (`wrangler email sending enable <domain>`), and — as with SMTP — a
    /// sender the platform will actually vouch for. Unlike SMTP there is no
    /// login/sender split here: the address is the whole identity.
    fn cloudflare_from_env() -> anyhow::Result<Self> {
        let account_id = std::env::var("CF_ACCOUNT_ID")
            .map_err(|_| anyhow::anyhow!("CF_ACCOUNT_ID is not set"))?;
        let token = std::env::var("CF_EMAIL_TOKEN")
            .map_err(|_| anyhow::anyhow!("CF_EMAIL_TOKEN is not set"))?;
        let from = std::env::var("EMAIL_FROM")
            .map_err(|_| anyhow::anyhow!("EMAIL_FROM is not set"))?;
        if account_id.trim().is_empty() || token.trim().is_empty() {
            anyhow::bail!("CF_ACCOUNT_ID and CF_EMAIL_TOKEN must not be empty");
        }

        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(|e| anyhow::anyhow!("build HTTP client for Cloudflare Email: {e}"))?;

        tracing::info!(account = %account_id, %from, "Cloudflare Email Sending configured");
        Ok(Self {
            transport: Some(Provider::Cloudflare { account_id, token, http }),
            from,
            from_name: std::env::var("EMAIL_FROM_NAME").ok(),
            host: "api.cloudflare.com".to_string(),
            disabled: false,
        })
    }

    /// Disabled mailer, for tests and local runs with no relay: every send
    /// goes to the log, and `is_healthy` reports healthy rather than failing
    /// every register/resend/reset-request — that would make the disabled
    /// mailer untestable rather than merely quiet.
    pub fn disabled() -> Self {
        Self {
            transport: None,
            from: "no-reply@localhost".to_string(),
            from_name: None,
            host: "(disabled)".to_string(),
            disabled: true,
        }
    }

    /// The relay hostname, for a handler or caller that wants it in a log
    /// line beyond what `send`/`is_healthy` already emit.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Whether this mailer can actually deliver right now. A real SMTP `NOOP`
    /// round trip against the configured relay, not just "is a transport
    /// configured" — the failure this exists to catch is the relay being
    /// unreachable or rejecting auth, which "configured" alone would not
    /// detect. `disabled()` mailers always report healthy; see its doc.
    ///
    /// Callers that gate a whole endpoint on this (register, resend,
    /// password-reset-request) must call it *before* branching on whether the
    /// requested email exists — otherwise "healthy" vs "unhealthy" becomes
    /// visible only on the request that would have sent mail, which is
    /// exactly the account-existence signal those endpoints exist to hide.
    pub async fn is_healthy(&self) -> bool {
        if self.disabled {
            return true;
        }
        let Some(transport) = &self.transport else {
            // Unreachable in practice — from_env() never returns a mailer
            // with no transport — but a false default here is the safe one.
            return false;
        };
        match transport {
            Provider::Smtp(smtp) => match smtp.test_connection().await {
                Ok(true) => true,
                Ok(false) => {
                    tracing::error!(host = %self.host, "SMTP relay NOOP rejected");
                    false
                }
                Err(e) => {
                    tracing::error!(%e, host = %self.host, "cannot reach SMTP relay");
                    false
                }
            },
            // No NOOP equivalent on a REST API, so the probe is the cheapest
            // authenticated GET there is — but *which* one matters more than
            // it looks.
            //
            // The obvious choice, listing the domains onboarded to Email
            // Sending, is wrong: a token scoped narrowly to *send* is not
            // necessarily allowed to *read* `email/sending/zones`, and a real
            // one on this account is not (403). Probing with it would have
            // refused every send from a perfectly good token — caught
            // 2026-08-23 by a token that failed this probe and then sent
            // successfully on the very next call.
            //
            // So: verify the token itself first, which any live API token can
            // do, and keep the zones read only as a fallback for credentials
            // that cannot verify (an OAuth-style credential, for one). Either
            // answering means the API is reachable and the credential is
            // alive. Neither proves the *sender domain* is onboarded — no
            // more than an SMTP NOOP proves the relay will accept your From
            // address. That failure surfaces on the send, and is logged
            // there.
            Provider::Cloudflare { account_id, token, http } => {
                let verify = "https://api.cloudflare.com/client/v4/user/tokens/verify";
                let zones = format!(
                    "https://api.cloudflare.com/client/v4/accounts/{account_id}/email/sending/zones"
                );

                let mut last_status = None;
                for url in [verify.to_string(), zones] {
                    match http.get(&url).bearer_auth(token).send().await {
                        Ok(response) if response.status().is_success() => return true,
                        Ok(response) => last_status = Some(response.status()),
                        Err(e) => {
                            tracing::error!(%e, "cannot reach the Cloudflare API");
                            return false;
                        }
                    }
                }

                tracing::error!(
                    status = ?last_status,
                    "Cloudflare credential rejected — check CF_EMAIL_TOKEN"
                );
                false
            }
        }
    }

    /// Never returns an error into a handler. A failed send must not change
    /// the HTTP response, or "did the mail go out" becomes an enumeration
    /// signal on endpoints that are otherwise careful not to be one — that is
    /// what `is_healthy` is for instead, checked before any per-address
    /// branching rather than after a specific send fails.
    pub async fn send(&self, to: &str, subject: &str, text: String, html: String) {
        self.send_with_headers(to, subject, text, html, &[]).await
    }

    /// `send`, plus extra RFC 5322 headers.
    ///
    /// Exists for `List-Unsubscribe` / `List-Unsubscribe-Post` on the mailing
    /// list: a one-click unsubscribe header is what keeps bulk-ish mail out of
    /// spam folders, and Gmail requires it above a volume threshold. The
    /// account mails do not use it — they are transactional and have nothing
    /// to unsubscribe from.
    pub async fn send_with_headers(
        &self,
        to: &str,
        subject: &str,
        text: String,
        html: String,
        headers: &[(String, String)],
    ) {
        let Some(transport) = &self.transport else {
            tracing::info!(to, subject, body = %text, host = %self.host, "email not sent (mailer disabled)");
            return;
        };

        if let Provider::Cloudflare { account_id, token, http } = transport {
            self.send_cloudflare(account_id, token, http, to, subject, text, html, headers)
                .await;
            return;
        }
        let Provider::Smtp(transport) = transport else { unreachable!() };

        let from = match self.from.parse() {
            Ok(m) => m,
            Err(e) => {
                tracing::error!(%e, from = %self.from, "invalid EMAIL_FROM/EMAIL_LOGIN address");
                return;
            }
        };
        let to_addr = match to.parse() {
            Ok(m) => m,
            Err(e) => {
                tracing::error!(%e, to, "invalid recipient address");
                return;
            }
        };

        let message = Message::builder()
            .from(from)
            .to(to_addr)
            .subject(subject)
            .multipart(
                MultiPart::alternative()
                    // Plain text first: every message should have a fallback,
                    // and some clients show whichever part comes last.
                    .singlepart(
                        SinglePart::builder()
                            .header(header::ContentType::TEXT_PLAIN)
                            .body(text),
                    )
                    .singlepart(
                        SinglePart::builder()
                            .header(header::ContentType::TEXT_HTML)
                            .body(html),
                    ),
            );

        let message = match message {
            Ok(m) => m,
            Err(e) => {
                tracing::error!(%e, "build email message");
                return;
            }
        };

        match transport.send(message).await {
            Ok(_) => tracing::info!(to, host = %self.host, "email sent"),
            Err(e) => tracing::error!(%e, to, host = %self.host, "send email"),
        }
    }

    /// The REST call. Field names differ from the Workers binding in ways that
    /// are easy to get wrong and fail only at runtime: `from` takes `address`
    /// (not `email`), and reply-to would be `reply_to` (not `replyTo`).
    #[allow(clippy::too_many_arguments)]
    async fn send_cloudflare(
        &self,
        account_id: &str,
        token: &str,
        http: &reqwest::Client,
        to: &str,
        subject: &str,
        text: String,
        html: String,
        headers: &[(String, String)],
    ) {
        let mut body = serde_json::json!({
            "to": to,
            "from": match &self.from_name {
                Some(name) => serde_json::json!({ "address": self.from, "name": name }),
                None => serde_json::json!({ "address": self.from }),
            },
            "subject": subject,
            // Both parts, always: some clients only render text, and a
            // text-less message scores worse with spam filters.
            "text": text,
            "html": html,
        });
        if !headers.is_empty() {
            let map: serde_json::Map<String, serde_json::Value> = headers
                .iter()
                .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
                .collect();
            body["headers"] = serde_json::Value::Object(map);
        }

        let url = format!(
            "https://api.cloudflare.com/client/v4/accounts/{account_id}/email/sending/send"
        );
        let response = match http.post(&url).bearer_auth(token).json(&body).send().await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(%e, to, "Cloudflare Email send request failed");
                return;
            }
        };

        let status = response.status();
        let payload = response.text().await.unwrap_or_default();
        if !status.is_success() {
            // The body carries Cloudflare's numeric error code, which is the
            // only way to tell "domain not onboarded" from "token cannot
            // send". It never echoes the token.
            tracing::error!(%status, to, response = %payload, "Cloudflare Email send rejected");
            return;
        }

        // A 200 is not delivery: the result splits recipients into delivered,
        // queued and permanent_bounces, and a bounce here is a silent failure
        // everywhere else.
        match serde_json::from_str::<serde_json::Value>(&payload) {
            Ok(v) => {
                let bounced = v["result"]["permanent_bounces"].as_array().is_some_and(|a| !a.is_empty());
                if bounced {
                    tracing::error!(to, response = %payload, "Cloudflare Email permanently bounced");
                } else {
                    tracing::info!(to, host = %self.host, "email sent");
                }
            }
            Err(_) => tracing::info!(to, host = %self.host, "email sent"),
        }
    }
}

/// The two templates, kept as plain `format!` rather than a template engine:
/// there are two of them, no site localises them, and a dependency that only
/// renders two strings is not worth its build time.
pub(crate) struct Templates;

impl Templates {
    pub(crate) fn verify(product: &str, url: &str, code: &str) -> (String, String, String) {
        let subject = format!("Confirm your {product} account");
        let text = format!(
            "Confirm your email address to activate your {product} account.\n\n\
             {url}\n\n\
             Or enter this code on the confirmation page: {code}\n\n\
             If you did not create this account, ignore this message.\n"
        );
        let html = format!(
            "<p>Confirm your email address to activate your {product} account.</p>\
             <p><a href=\"{url}\">{url}</a></p>\
             <p>Or enter this code on the confirmation page: <strong>{code}</strong></p>\
             <p>If you did not create this account, ignore this message.</p>"
        );
        (subject, text, html)
    }

    pub(crate) fn reset(product: &str, url: &str, ttl_hours: u64) -> (String, String, String) {
        let subject = format!("Reset your {product} password");
        let text = format!(
            "Use this link to choose a new {product} password:\n\n\
             {url}\n\n\
             The link works once and expires in {ttl_hours} hour(s).\n\
             If you did not ask for this, ignore this message — your password is unchanged.\n"
        );
        let html = format!(
            "<p>Use this link to choose a new {product} password:</p>\
             <p><a href=\"{url}\">{url}</a></p>\
             <p>The link works once and expires in {ttl_hours} hour(s).</p>\
             <p>If you did not ask for this, ignore this message — your password is unchanged.</p>"
        );
        (subject, text, html)
    }

    /// Double opt-in confirmation for the updates-and-news list.
    ///
    /// Someone else can type your address into a signup box, so this message
    /// is the only one that ever reaches an unconfirmed address, and it has to
    /// read as harmless to a person who did not ask for it.
    pub(crate) fn subscribe_confirm(
        product: &str,
        confirm_url: &str,
        unsubscribe_url: &str,
    ) -> (String, String, String) {
        let subject = format!("Confirm your subscription to {product} updates");
        let text = format!(
            "Confirm that you want {product} updates and news at this address:\n\n\
             {confirm_url}\n\n\
             We will not send anything else until you do.\n\
             If you did not ask for this, ignore this message, or remove the address here:\n\
             {unsubscribe_url}\n"
        );
        let html = format!(
            "<p>Confirm that you want {product} updates and news at this address:</p>\
             <p><a href=\"{confirm_url}\">{confirm_url}</a></p>\
             <p>We will not send anything else until you do.</p>\
             <p>If you did not ask for this, ignore this message, or \
             <a href=\"{unsubscribe_url}\">remove the address</a>.</p>"
        );
        (subject, text, html)
    }

    /// Sent once, on confirmation. Carries the unsubscribe link so the
    /// subscriber has one from the very first message rather than having to
    /// wait for a newsletter to arrive.
    pub(crate) fn subscribe_welcome(
        product: &str,
        unsubscribe_url: &str,
    ) -> (String, String, String) {
        let subject = format!("You are subscribed to {product} updates");
        let text = format!(
            "You are on the list — we will send {product} updates and news here.\n\n\
             You can unsubscribe at any time:\n{unsubscribe_url}\n"
        );
        let html = format!(
            "<p>You are on the list — we will send {product} updates and news here.</p>\
             <p>You can <a href=\"{unsubscribe_url}\">unsubscribe</a> at any time.</p>"
        );
        (subject, text, html)
    }

    /// The owner alert, mirroring `trust-atria-landing/worker/src/notify.ts`.
    /// Plain text only — nobody styles their own ops mail.
    pub(crate) fn signup_notice(
        product: &str,
        email: &str,
        source: Option<&str>,
        ip: Option<&str>,
        user_agent: Option<&str>,
        referer: Option<&str>,
    ) -> (String, String, String) {
        let subject = format!("New {product} newsletter signup: {email}");
        let dash = "—";
        let body = format!(
            "{email} asked for {product} updates.\n\n\
             When:     {when}\n\
             Source:   {source}\n\
             Address:  {ip}\n\
             Referer:  {referer}\n\
             Agent:    {agent}\n\n\
             Not yet confirmed — this is the signup, not the double opt-in.\n\n\
             All signups:\n\
             psql -d <site db> -c 'SELECT email, confirmed, created_at FROM subscribers \
             ORDER BY id DESC LIMIT 20'\n",
            when = chrono::Utc::now().to_rfc3339(),
            source = source.unwrap_or(dash),
            ip = ip.unwrap_or(dash),
            referer = referer.unwrap_or(dash),
            agent = user_agent.unwrap_or(dash),
        );
        // Same string for both parts: the HTML alternative exists only so the
        // message is not flagged as text-only by filters that dislike that.
        let html = format!("<pre>{}</pre>", html_escape(&body));
        (subject, body, html)
    }
}

/// Minimal escaping for the one place this crate puts caller-controlled text
/// into HTML. `user_agent` and `referer` are attacker-supplied headers, and
/// they end up in a message a human opens.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscribe_templates_always_offer_a_way_out() {
        let (subject, text, html) =
            Templates::subscribe_confirm("QW", "https://x/confirm", "https://x/out");
        assert!(subject.contains("QW"));
        for body in [&text, &html] {
            assert!(body.contains("https://x/confirm"));
            // Even the confirmation goes to someone who may never have asked.
            assert!(body.contains("https://x/out"), "no unsubscribe link");
        }

        let (_, text, html) = Templates::subscribe_welcome("QW", "https://x/out");
        assert!(text.contains("https://x/out") && html.contains("https://x/out"));
    }

    #[test]
    fn signup_notice_escapes_attacker_supplied_headers() {
        let (_, text, html) = Templates::signup_notice(
            "QW",
            "someone@example.com",
            Some("dash"),
            Some("203.0.113.7"),
            Some("<script>alert(1)</script>"),
            None,
        );
        assert!(text.contains("someone@example.com"));
        assert!(!html.contains("<script>"), "user agent reached the HTML unescaped");
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn templates_carry_the_link_and_the_product() {
        let (subject, text, html) = Templates::verify("QW", "https://x/y", "123456");
        assert!(subject.contains("QW"));
        assert!(text.contains("https://x/y") && text.contains("123456"));
        assert!(html.contains("href=\"https://x/y\"") && html.contains("123456"));

        let (subject, text, html) = Templates::reset("QW", "https://x/z", 1);
        assert!(subject.contains("QW"));
        assert!(text.contains("https://x/z"));
        assert!(html.contains("https://x/z"));
    }
}

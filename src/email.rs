//! Outbound mail.
//!
//! Shape borrowed from an earlier in-house mailer (lettre 0.11,
//! async, rustls). A service with no working mail relay cannot deliver the
//! verify/reset links its own `/account/register` etc. promise, so — unlike
//! an earlier version of this module — a missing or unreachable relay is not
//! quietly downgraded to "log the message instead": `from_env` refuses to
//! construct at all (see `AccountState::from_env`, which fails startup on
//! this), and `is_healthy` lets a handler refuse a request rather than
//! silently swallowing a send it cannot make. `disabled()` is the deliberate
//! opt-out for tests and local runs that do not want either.

use lettre::message::header::{HeaderName, HeaderValue};
use lettre::message::{header, Mailbox, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

/// How a `Mailer` actually puts a message on the wire.
///
/// Two providers, one interface. SMTP is the original (Brevo relay); the
/// Cloudflare arm exists for a site whose domain is onboarded to Cloudflare
/// Email Sending. A Rust service is not a Worker,
/// so it uses the REST API rather than the `send_email` binding. The binding
/// needs no credential and is the right choice *inside* a Worker; from here a
/// scoped API token is the only option there is.
enum Provider {
    Smtp(Box<AsyncSmtpTransport<Tokio1Executor>>),
    /// Cloudflare Email Sending REST API (feature `cloudflare-email`).
    #[cfg(feature = "cloudflare-email")]
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
    /// (the relay settings of `env.sample`).
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
            #[cfg(feature = "cloudflare-email")]
            return Self::cloudflare_from_env();
            #[cfg(not(feature = "cloudflare-email"))]
            anyhow::bail!("EMAIL_PROVIDER=cloudflare, but signon was built without the cloudflare-email feature");
        }
        let host =
            std::env::var("EMAIL_HOST").map_err(|_| anyhow::anyhow!("EMAIL_HOST is not set"))?;
        let port: u16 = std::env::var("EMAIL_PORT")
            .map_err(|_| anyhow::anyhow!("EMAIL_PORT is not set"))?
            .parse()
            .map_err(|e| anyhow::anyhow!("EMAIL_PORT is not a valid port: {e}"))?;
        let login =
            std::env::var("EMAIL_LOGIN").map_err(|_| anyhow::anyhow!("EMAIL_LOGIN is not set"))?;
        let key =
            std::env::var("EMAIL_KEY").map_err(|_| anyhow::anyhow!("EMAIL_KEY is not set"))?;
        let from =
            std::env::var("EMAIL_FROM").map_err(|_| anyhow::anyhow!("EMAIL_FROM is not set"))?;

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
    #[cfg(feature = "cloudflare-email")]
    fn cloudflare_from_env() -> anyhow::Result<Self> {
        let account_id = std::env::var("CF_ACCOUNT_ID")
            .map_err(|_| anyhow::anyhow!("CF_ACCOUNT_ID is not set"))?;
        let token = std::env::var("CF_EMAIL_TOKEN")
            .map_err(|_| anyhow::anyhow!("CF_EMAIL_TOKEN is not set"))?;
        let from =
            std::env::var("EMAIL_FROM").map_err(|_| anyhow::anyhow!("EMAIL_FROM is not set"))?;
        if account_id.trim().is_empty() || token.trim().is_empty() {
            anyhow::bail!("CF_ACCOUNT_ID and CF_EMAIL_TOKEN must not be empty");
        }

        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(|e| anyhow::anyhow!("build HTTP client for Cloudflare Email: {e}"))?;

        tracing::info!(account = %account_id, %from, "Cloudflare Email Sending configured");
        Ok(Self {
            transport: Some(Provider::Cloudflare {
                account_id,
                token,
                http,
            }),
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
            #[cfg(feature = "cloudflare-email")]
            Provider::Cloudflare {
                account_id,
                token,
                http,
            } => {
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
    /// list and on an account's non-essential mail (the welcome): a one-click
    /// unsubscribe header is what keeps bulk-ish mail out of spam folders,
    /// and Gmail requires it above a volume threshold. Account mail proper
    /// (verification, reset) does not use it — it is transactional and has
    /// nothing to unsubscribe from.
    pub async fn send_with_headers(
        &self,
        to: &str,
        subject: &str,
        text: String,
        html: String,
        headers: &[(String, String)],
    ) {
        // Already logged inside; these callers have nothing to do with a failure.
        let _ = self.deliver(to, subject, text, html, headers).await;
    }

    /// `send_with_headers`, telling the caller how it went — for the mail that
    /// is logged per recipient (`account_mail.rs`): `Err` carries a short
    /// reason for the log, never a credential. A disabled mailer delivers
    /// nowhere and reports `Ok`, as its `is_healthy` does.
    pub async fn deliver(
        &self,
        to: &str,
        subject: &str,
        text: String,
        html: String,
        headers: &[(String, String)],
    ) -> Result<(), String> {
        let Some(transport) = &self.transport else {
            // The crate's own tests: an address that asks to fail, fails —
            // the only way to see a refused send through a disabled mailer.
            // Only mail with list headers (the welcome, the follow-up), so the
            // account can still be confirmed by its code.
            #[cfg(test)]
            if to.contains("fail-delivery") && !headers.is_empty() {
                return Err("test: the relay refused it".to_string());
            }
            tracing::info!(to, subject, body = %text, host = %self.host, "email not sent (mailer disabled)");
            #[cfg(test)]
            outbox::record(to, subject, &text, headers);
            return Ok(());
        };

        let transport = match transport {
            #[cfg(feature = "cloudflare-email")]
            Provider::Cloudflare {
                account_id,
                token,
                http,
            } => {
                return self
                    .send_cloudflare(account_id, token, http, to, subject, text, html, headers)
                    .await;
            }
            Provider::Smtp(transport) => transport,
        };

        let message = match smtp_message(
            &self.from,
            self.from_name.as_deref(),
            to,
            subject,
            text,
            html,
            headers,
        ) {
            Ok(m) => m,
            Err(e) => {
                tracing::error!(%e, to, "build email message");
                return Err(format!("could not build the message: {e}"));
            }
        };

        match transport.send(message).await {
            Ok(_) => {
                tracing::info!(to, host = %self.host, "email sent");
                Ok(())
            }
            Err(e) => {
                tracing::error!(%e, to, host = %self.host, "send email");
                Err(format!("SMTP: {e}"))
            }
        }
    }

    /// The REST call. Field names differ from the Workers binding in ways that
    /// are easy to get wrong and fail only at runtime: `from` takes `address`
    /// (not `email`), and reply-to would be `reply_to` (not `replyTo`).
    #[allow(clippy::too_many_arguments)]
    #[cfg(feature = "cloudflare-email")]
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
    ) -> Result<(), String> {
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
                return Err(format!("Cloudflare Email request failed: {e}"));
            }
        };

        let status = response.status();
        let payload = response.text().await.unwrap_or_default();
        if !status.is_success() {
            // The body carries Cloudflare's numeric error code, which is the
            // only way to tell "domain not onboarded" from "token cannot
            // send". It never echoes the token.
            tracing::error!(%status, to, response = %payload, "Cloudflare Email send rejected");
            return Err(format!("Cloudflare Email rejected it ({status})"));
        }

        // A 200 is not delivery: the result splits recipients into delivered,
        // queued and permanent_bounces, and a bounce here is a silent failure
        // everywhere else.
        match serde_json::from_str::<serde_json::Value>(&payload) {
            Ok(v) => {
                let bounced = v["result"]["permanent_bounces"]
                    .as_array()
                    .is_some_and(|a| !a.is_empty());
                if bounced {
                    tracing::error!(to, response = %payload, "Cloudflare Email permanently bounced");
                    Err("permanently bounced".to_string())
                } else {
                    tracing::info!(to, host = %self.host, "email sent");
                    Ok(())
                }
            }
            Err(_) => {
                tracing::info!(to, host = %self.host, "email sent");
                Ok(())
            }
        }
    }
}

/// The SMTP message, carrying what the Cloudflare arm sends too: `From`
/// with the `EMAIL_FROM_NAME` display name when one is set, both parts, and
/// the caller's extra headers (`List-Unsubscribe` and
/// `List-Unsubscribe-Post` on the mailing list — without them Gmail files
/// bulk-ish mail as spam). A header value with a line break is refused
/// rather than sent: it would let the value start headers of its own.
fn smtp_message(
    from: &str,
    from_name: Option<&str>,
    to: &str,
    subject: &str,
    text: String,
    html: String,
    headers: &[(String, String)],
) -> anyhow::Result<Message> {
    let address: lettre::Address = from
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid EMAIL_FROM address {from}: {e}"))?;
    let name = from_name
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .map(str::to_string);
    let to: Mailbox = to
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid recipient address {to}: {e}"))?;
    let mut builder = Message::builder()
        .from(Mailbox::new(name, address))
        .to(to)
        .subject(subject);
    for (name, value) in headers {
        if value.contains(['\r', '\n']) {
            anyhow::bail!("header {name} has a line break in its value");
        }
        let header_name = HeaderName::new_from_ascii(name.clone())
            .map_err(|e| anyhow::anyhow!("invalid header name {name}: {e}"))?;
        builder = builder.raw_header(HeaderValue::new(header_name, value.clone()));
    }
    Ok(builder.multipart(
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
    )?)
}

/// What the disabled mailer would have sent, for the crate's own tests. One
/// list for the process: tests run concurrently, so each reads only the mail
/// to its own unique addresses.
#[cfg(test)]
pub(crate) mod outbox {
    use std::sync::Mutex;

    #[derive(Clone, Debug)]
    pub(crate) struct Sent {
        pub to: String,
        pub subject: String,
        pub text: String,
        pub headers: Vec<(String, String)>,
    }

    static SENT: Mutex<Vec<Sent>> = Mutex::new(Vec::new());

    pub(crate) fn record(to: &str, subject: &str, text: &str, headers: &[(String, String)]) {
        SENT.lock().unwrap().push(Sent {
            to: to.to_string(),
            subject: subject.to_string(),
            text: text.to_string(),
            headers: headers.to_vec(),
        });
    }

    pub(crate) fn to(address: &str) -> Vec<Sent> {
        SENT.lock().unwrap().iter().filter(|m| m.to == address).cloned().collect()
    }
}

/// The mails of this crate, each in a language (`crate::i18n`): the sentences are in `locales/<lang>.yml`,
/// the layout - the text part and the HTML part, the links - is here, one for all languages. Plain
/// `format!`, no template engine: a handful of fixed layouts is not worth one.
pub(crate) struct Templates;

/// a sentence of a mail in `lang`
fn say(lang: &str, key: &str, args: &[(&str, &str)]) -> String {
    crate::i18n::text_in(lang, key, args)
}

/// A sentence of a mail's HTML part: the sentence itself is the locale file's, every value of `args` is
/// escaped - a product's name, a provider's, a URL are text there - and `markup` goes in as it is: the
/// tags this file builds around a link or a code. [review 2026-11-14]
fn say_html(lang: &str, key: &str, args: &[(&str, &str)], markup: &[(&str, &str)]) -> String {
    let escaped: Vec<(&str, String)> = args.iter().map(|(name, value)| (*name, html_escape(value))).collect();
    let mut all: Vec<(&str, &str)> = escaped.iter().map(|(name, value)| (*name, value.as_str())).collect();
    all.extend_from_slice(markup);
    crate::i18n::text_in(lang, key, &all)
}

/// `<a href="url">`, the URL escaped for the attribute
fn link_to(url: &str) -> String {
    format!("<a href=\"{}\">", html_escape(url))
}

/// a URL shown as its own link
fn linked(url: &str) -> String {
    format!("{}{}</a>", link_to(url), html_escape(url))
}

impl Templates {
    pub(crate) fn verify(lang: &str, product: &str, url: &str, code: &str) -> (String, String, String) {
        let subject = say(lang, "mail-verify-subject", &[("product", product)]);
        let text = format!(
            "{}\n\n{url}\n\n{}\n\n{}\n",
            say(lang, "mail-verify-intro", &[("product", product)]),
            say(lang, "mail-verify-code", &[("code", code)]),
            say(lang, "mail-verify-ignore", &[]),
        );
        let html = format!(
            "<p>{}</p><p>{}</p><p>{}</p><p>{}</p>",
            say_html(lang, "mail-verify-intro", &[("product", product)], &[]),
            linked(url),
            say_html(lang, "mail-verify-code", &[], &[("code", &format!("<strong>{}</strong>", html_escape(code)))]),
            say_html(lang, "mail-verify-ignore", &[], &[]),
        );
        (subject, text, html)
    }

    /// The code that finishes a sign-in through a provider which does not
    /// vouch for the address it reported (Amazon, Facebook). No link: the
    /// code is only useful on the page that is already open.
    #[cfg(feature = "oauth")]
    pub(crate) fn sign_in_code(lang: &str, product: &str, provider: &str, code: &str) -> (String, String, String) {
        let subject = say(lang, "mail-code-subject", &[("product", product)]);
        let names = [("product", product), ("provider", provider)];
        let text = format!(
            "{}\n\n{}\n\n{}\n",
            say(lang, "mail-code-intro", &names),
            say(lang, "mail-code-enter", &[("code", code)]),
            say(lang, "mail-code-note", &[]),
        );
        let html = format!(
            "<p>{}</p><p>{}</p><p>{}</p>",
            say_html(lang, "mail-code-intro", &names, &[]),
            say_html(lang, "mail-code-enter", &[], &[("code", &format!("<strong>{}</strong>", html_escape(code)))]),
            say_html(lang, "mail-code-note", &[], &[]),
        );
        (subject, text, html)
    }

    pub(crate) fn reset(lang: &str, product: &str, url: &str, ttl_hours: u64) -> (String, String, String) {
        let hours = ttl_hours.to_string();
        let subject = say(lang, "mail-reset-subject", &[("product", product)]);
        let text = format!(
            "{}\n\n{url}\n\n{}\n{}\n",
            say(lang, "mail-reset-intro", &[("product", product)]),
            say(lang, "mail-reset-expiry", &[("hours", &hours)]),
            say(lang, "mail-reset-ignore", &[]),
        );
        let html = format!(
            "<p>{}</p><p>{}</p><p>{}</p><p>{}</p>",
            say_html(lang, "mail-reset-intro", &[("product", product)], &[]),
            linked(url),
            say_html(lang, "mail-reset-expiry", &[("hours", &hours)], &[]),
            say_html(lang, "mail-reset-ignore", &[], &[]),
        );
        (subject, text, html)
    }

    /// Sent instead of a verification mail when `routes::register` sees an
    /// address that already has an account - the one place this crate tells
    /// someone that outright, since the recipient is, by construction, the
    /// real owner of the inbox either way. Carries a real, working reset
    /// link (the same one `Templates::reset` would send) so "I forgot I had
    /// an account" resolves in one message instead of a second round trip.
    pub(crate) fn already_registered(
        lang: &str,
        product: &str,
        sign_in_url: &str,
        reset_url: &str,
        reset_ttl_hours: u64,
    ) -> (String, String, String) {
        let hours = reset_ttl_hours.to_string();
        let subject = say(lang, "mail-exists-subject", &[("product", product)]);
        let text = format!(
            "{}\n\n{}:\n{sign_in_url}\n\n{}\n{reset_url}\n\n{}\n",
            say(lang, "mail-exists-intro", &[("product", product)]),
            say(lang, "mail-exists-sign-in", &[]),
            say(lang, "mail-exists-forgot-text", &[("hours", &hours)]),
            say(lang, "mail-exists-ignore", &[]),
        );
        let html = format!(
            "<p>{}</p><p>{}{}</a></p><p>{}</p><p>{}</p>",
            say_html(lang, "mail-exists-intro", &[("product", product)], &[]),
            link_to(sign_in_url),
            say_html(lang, "mail-exists-sign-in", &[], &[]),
            say_html(lang, "mail-exists-forgot-html", &[("hours", &hours)], &[("link", &link_to(reset_url)), ("end", "</a>")]),
            say_html(lang, "mail-exists-ignore", &[], &[]),
        );
        (subject, text, html)
    }

    /// Double opt-in confirmation for the updates-and-news list.
    ///
    /// Someone else can type your address into a signup box, so this message
    /// is the only one that ever reaches an unconfirmed address, and it has to
    /// read as harmless to a person who did not ask for it.
    pub(crate) fn subscribe_confirm(lang: &str, product: &str, confirm_url: &str, unsubscribe_url: &str) -> (String, String, String) {
        let subject = say(lang, "mail-sub-confirm-subject", &[("product", product)]);
        let text = format!(
            "{}\n\n{confirm_url}\n\n{}\n{}\n{unsubscribe_url}\n",
            say(lang, "mail-sub-confirm-intro", &[("product", product)]),
            say(lang, "mail-sub-confirm-nothing", &[]),
            say(lang, "mail-sub-confirm-ignore-text", &[]),
        );
        let html = format!(
            "<p>{}</p><p>{}</p><p>{}</p><p>{}</p>",
            say_html(lang, "mail-sub-confirm-intro", &[("product", product)], &[]),
            linked(confirm_url),
            say_html(lang, "mail-sub-confirm-nothing", &[], &[]),
            say_html(lang, "mail-sub-confirm-ignore-html", &[], &[("link", &link_to(unsubscribe_url)), ("end", "</a>")]),
        );
        (subject, text, html)
    }

    /// Sent once, on confirmation. Carries the unsubscribe link so the
    /// subscriber has one from the very first message rather than having to
    /// wait for a newsletter to arrive.
    pub(crate) fn subscribe_welcome(lang: &str, product: &str, unsubscribe_url: &str) -> (String, String, String) {
        let subject = say(lang, "mail-sub-welcome-subject", &[("product", product)]);
        let text = format!(
            "{}\n\n{}\n{unsubscribe_url}\n",
            say(lang, "mail-sub-welcome-intro", &[("product", product)]),
            say(lang, "mail-sub-welcome-out-text", &[]),
        );
        let html = format!(
            "<p>{}</p><p>{}</p>",
            say_html(lang, "mail-sub-welcome-intro", &[("product", product)], &[]),
            say_html(lang, "mail-sub-welcome-out-html", &[], &[("link", &link_to(unsubscribe_url)), ("end", "</a>")]),
        );
        (subject, text, html)
    }

    /// A site's welcome ([`crate::Welcome`]), with the footer every account
    /// mail that is not about the account itself carries: the site's
    /// [`crate::FooterNote`] if it has one, why the mail came, and the way to
    /// turn it off. The welcome's own text is the site's, in the language the
    /// site wrote it in; the footer's two sentences are in `lang`.
    pub(crate) fn welcome(
        lang: &str,
        product: &str,
        welcome: &crate::Welcome,
        note: Option<&crate::FooterNote>,
        unsubscribe_url: &str,
    ) -> (String, String, String) {
        let mut text = welcome.paragraphs.join("\n\n");
        let mut html: String = welcome
            .paragraphs
            .iter()
            // A single line break inside a paragraph stays one, as in the
            // text part (and the template editor's preview).
            .map(|p| format!("<p>{}</p>", html_escape(p).replace('\n', "<br>")))
            .collect();
        if let Some((label, url)) = &welcome.action {
            text.push_str(&format!("\n\n{label}: {url}"));
            html.push_str(&format!(
                "<p><a href=\"{url}\" style=\"display:inline-block;padding:10px 18px;border-radius:6px;\
                 background:#18181b;color:#ffffff;text-decoration:none;font-weight:600\">{label}</a></p>",
                url = html_escape(url),
                label = html_escape(label),
            ));
        }
        text.push_str("\n\n--\n");
        if let Some(note) = note {
            text.push_str(&note.text);
            let mut line = html_escape(&note.text);
            if let Some((label, url)) = &note.link {
                text.push_str(&format!(" {label}: {url}"));
                line.push_str(&format!(
                    " <a href=\"{url}\" style=\"color:#71717a\">{label}</a>.",
                    url = html_escape(url),
                    label = html_escape(label),
                ));
            }
            text.push('\n');
            html.push_str(&format!(
                "<p style=\"color:#71717a;font-size:12px;margin-top:24px\">{line}</p>"
            ));
        }
        let article = indefinite_article(product);
        text.push_str(&format!(
            "{} {}\n",
            say(lang, "mail-footer-why", &[("article", article), ("product", product)]),
            say(lang, "mail-footer-stop-text", &[("url", unsubscribe_url)]),
        ));
        html.push_str(&format!(
            "<p style=\"color:#71717a;font-size:12px;margin-top:{top}\">{why} {stop}</p>",
            top = if note.is_some() { "8px" } else { "24px" },
            why = say_html(lang, "mail-footer-why", &[("article", article), ("product", product)], &[]),
            stop = say_html(lang, "mail-footer-stop-html", &[], &[
                ("link", &format!("<a href=\"{}\" style=\"color:#71717a\">", html_escape(unsubscribe_url))),
                ("end", "</a>"),
            ]),
        ));
        (welcome.subject.clone(), text, html)
    }

    /// The owner alert of a signup, in the site's language (`lang`).
    /// Plain text only - nobody styles their own ops mail.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn signup_notice(
        lang: &str,
        product: &str,
        email: &str,
        source: Option<&str>,
        ip: Option<&str>,
        user_agent: Option<&str>,
        referer: Option<&str>,
    ) -> (String, String, String) {
        let subject = say(lang, "mail-signup-subject", &[("product", product), ("email", email)]);
        let when = chrono::Utc::now().to_rfc3339();
        // a label and its value, the values in one column
        let row = |key: &str, value: &str| format!("{:<10}{value}\n", format!("{}:", say(lang, key, &[])));
        let body = format!(
            "{intro}\n\n{rows}\n{unconfirmed}\n\n{all}\n\
             psql -d <site db> -c 'SELECT email, confirmed, created_at FROM subscribers \
             ORDER BY id DESC LIMIT 20'\n",
            intro = say(lang, "mail-signup-intro", &[("email", email), ("product", product)]),
            rows = [
                row("mail-signup-when", &when),
                row("mail-signup-source", source.unwrap_or("-")),
                row("mail-signup-address", ip.unwrap_or("-")),
                row("mail-signup-referer", referer.unwrap_or("-")),
                row("mail-signup-agent", user_agent.unwrap_or("-")),
            ].concat(),
            unconfirmed = say(lang, "mail-signup-unconfirmed", &[]),
            all = say(lang, "mail-signup-all", &[]),
        );
        // Same string for both parts: the HTML alternative exists only so the
        // message is not flagged as text-only by filters that dislike that.
        let html = format!("<pre>{}</pre>", html_escape(&body));
        (subject, body, html)
    }
}

/// "a" or "an" before `word`, by its first letter: "an Acme Dash account".
/// Right for product names; a word said otherwise than it is spelt ("an
/// hour", "a user") would need more than this.
fn indefinite_article(word: &str) -> &'static str {
    match word.trim_start().chars().next() {
        Some(c) if "aeiouAEIOU".contains(c) => "an",
        _ => "a",
    }
}

/// Minimal escaping for the one place this crate puts caller-controlled text
/// into HTML. `user_agent` and `referer` are attacker-supplied headers, and
/// they end up in a message a human opens.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn formatted(from_name: Option<&str>, headers: &[(String, String)]) -> anyhow::Result<String> {
        let m = smtp_message(
            "no-reply@example.com",
            from_name,
            "bob@example.com",
            "Hello",
            "text".into(),
            "<p>html</p>".into(),
            headers,
        )?;
        Ok(String::from_utf8(m.formatted()).unwrap())
    }

    #[test]
    fn smtp_carries_the_display_name_and_the_list_headers() {
        let list = [
            (
                "List-Unsubscribe".to_string(),
                "<https://dash.example/news/unsubscribe/t0k>".to_string(),
            ),
            (
                "List-Unsubscribe-Post".to_string(),
                "List-Unsubscribe=One-Click".to_string(),
            ),
        ];
        let m = formatted(Some("Acme Corp"), &list).unwrap();
        let from = m.lines().find(|l| l.starts_with("From: ")).unwrap();
        assert!(
            from.contains("Acme Corp") && from.contains("<no-reply@example.com>"),
            "{from}"
        );
        assert!(
            m.contains("List-Unsubscribe: <https://dash.example/news/unsubscribe/t0k>"),
            "{m}"
        );
        assert!(
            m.contains("List-Unsubscribe-Post: List-Unsubscribe=One-Click"),
            "{m}"
        );
        // Without a display name, the bare address — as before.
        let plain = formatted(None, &[]).unwrap();
        assert!(
            plain.lines().any(|l| l == "From: no-reply@example.com"),
            "{plain}"
        );
        assert!(!plain.contains("List-Unsubscribe"));
    }

    #[test]
    fn a_header_value_cannot_start_headers_of_its_own() {
        let injected = [(
            "List-Unsubscribe".to_string(),
            "<https://x>\r\nBcc: everyone@example.com".to_string(),
        )];
        assert!(formatted(None, &injected).is_err());
        let bad_name = [("Bad Name".to_string(), "x".to_string())];
        assert!(formatted(None, &bad_name).is_err());
    }

    #[test]
    fn subscribe_templates_always_offer_a_way_out() {
        let (subject, text, html) =
            Templates::subscribe_confirm("en", "Demo", "https://x/confirm", "https://x/out");
        assert!(subject.contains("Demo"));
        for body in [&text, &html] {
            assert!(body.contains("https://x/confirm"));
            // Even the confirmation goes to someone who may never have asked.
            assert!(body.contains("https://x/out"), "no unsubscribe link");
        }

        let (_, text, html) = Templates::subscribe_welcome("en", "Demo", "https://x/out");
        assert!(text.contains("https://x/out") && html.contains("https://x/out"));
    }

    #[test]
    fn welcome_footer_carries_the_site_note_and_the_right_article() {
        let welcome = crate::Welcome {
            subject: "Hi".into(),
            paragraphs: vec!["Hello.".into()],
            action: None,
            footer_note: None,
        };
        let note = crate::FooterNote {
            text: "We read every word & reply.".into(),
            link: Some(("Tell us".into(), "https://x/feedback?from=a&b".into())),
        };
        let (_, text, html) = Templates::welcome("en", "Acme Dash", &welcome, Some(&note), "https://x/out");
        assert!(
            text.contains("--\nWe read every word & reply. Tell us: https://x/feedback?from=a&b\n\
                           You get this because you created an Acme Dash account."),
            "{text}"
        );
        assert!(html.contains("We read every word &amp; reply. <a href=\"https://x/feedback?from=a&amp;b\""));
        assert!(html.contains("created an Acme Dash account."), "{html}");

        // No note, no line; and a consonant keeps "a".
        let (_, text, html) = Templates::welcome("en", "Demo", &welcome, None, "https://x/out");
        assert!(text.contains("--\nYou get this because you created a Demo account."), "{text}");
        assert!(!text.contains("Tell us") && !html.contains("Tell us"));

        // A note without a link is just its line.
        let bare = crate::FooterNote { text: "Thanks for reading.".into(), link: None };
        let (_, text, html) = Templates::welcome("en", "Demo", &welcome, Some(&bare), "https://x/out");
        assert!(text.contains("--\nThanks for reading.\nYou get this"), "{text}");
        assert!(html.contains(">Thanks for reading.</p>"), "{html}");
    }

    #[test]
    fn signup_notice_escapes_attacker_supplied_headers() {
        let (_, text, html) = Templates::signup_notice(
            "en",
            "Demo",
            "someone@example.com",
            Some("dash"),
            Some("203.0.113.7"),
            Some("<script>alert(1)</script>"),
            None,
        );
        assert!(text.contains("someone@example.com"));
        assert!(
            !html.contains("<script>"),
            "user agent reached the HTML unescaped"
        );
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn templates_carry_the_link_and_the_product() {
        let (subject, text, html) = Templates::verify("en", "Demo", "https://x/y", "123456");
        assert!(subject.contains("Demo"));
        assert!(text.contains("https://x/y") && text.contains("123456"));
        assert!(html.contains("href=\"https://x/y\"") && html.contains("123456"));

        let (subject, text, html) = Templates::reset("en", "Demo", "https://x/z", 1);
        assert!(subject.contains("Demo"));
        assert!(text.contains("https://x/z"));
        assert!(html.contains("https://x/z"));
    }

    /// [review 2026-11-14] the HTML part of every mail: a value put into it is text there - a product's name,
    /// a provider's, a URL, a code cannot open a tag or end an attribute - and the text part has it as it is
    #[test]
    fn a_value_cannot_be_markup_in_the_html_part() {
        let product = "Demo <b>&\"Co\"";
        let url = "https://x/y?a=1&b=\"><script>alert(1)</script>";
        let all = [
            Templates::verify("en", product, url, "12<3"),
            Templates::reset("de", product, url, 1),
            Templates::already_registered("fr", product, url, url, 2),
            Templates::subscribe_confirm("ru", product, url, url),
            Templates::subscribe_welcome("ja", product, url),
            #[cfg(feature = "oauth")]
            Templates::sign_in_code("zh", product, "Git<Hub>", "12<3"),
        ];
        for (subject, text, html) in &all {
            assert!(!html.contains("<script>") && !html.contains("<b>") && !html.contains("<Hub>") && !html.contains("12<3"), "{html}");
            assert!(html.contains("Demo &lt;b&gt;&amp;&quot;Co&quot;"), "{html}");
            assert!(text.contains(product) && subject.contains(product), "the text part is plain: {text}");
            // only the tags this file writes
            let tags: std::collections::BTreeSet<&str> = html.split('<').skip(1).filter_map(|t| t.split(['>', ' ']).next()).collect();
            assert!(tags.iter().all(|t| ["p", "/p", "a", "/a", "strong", "/strong"].contains(t)), "{tags:?} in {html}");
        }
        let (_, text, html) = &all[0];
        assert!(text.contains(url), "the link as it is in the text part");
        assert!(html.contains("href=\"https://x/y?a=1&amp;b=&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;\""), "{html}");
        assert!(html.contains("<strong>12&lt;3</strong>"));
    }

    /// The one email this crate sends telling someone outright "you already
    /// have an account" — it has to carry both ways back in, not just one,
    /// since the two things a person forgets are different: that they
    /// signed up at all, and their password.
    #[test]
    fn already_registered_carries_both_the_sign_in_and_the_reset_link() {
        let (subject, text, html) =
            Templates::already_registered("en", "Demo", "https://x/sign-in", "https://x/reset", 1);
        assert!(subject.contains("Demo"));
        for body in [&text, &html] {
            assert!(body.contains("https://x/sign-in"), "no sign-in link");
            assert!(body.contains("https://x/reset"), "no reset link");
        }
    }
}

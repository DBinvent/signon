//! Messages to people and to channels (feature `notify`): Slack, Microsoft Teams, Telegram, a generic webhook,
//! and email through the crate's [`Mailer`].
//!
//! A site builds a [`Notifier`] from its own configuration - a list of [`Channel`]s, given in code or read
//! from the environment ([`Notifier::from_env`]) - and calls [`Notifier::send`] with a [`Message`]:
//!
//! ```no_run
//! # async fn tell() {
//! use signon::notify::{Level, Message, Notifier};
//! let notifier = Notifier::from_env();
//! let sent = notifier.send(&Message::new("Disk almost full", "node-2: 91% of /var used").level(Level::Warning)).await;
//! for delivery in sent.iter().filter(|d| d.result.is_err()) {
//!     eprintln!("{}: {:?}", delivery.channel, delivery.result);
//! }
//! # }
//! ```
//!
//! What it holds to:
//! - **Every channel is one HTTP POST (or one mail).** No bot framework and no vendor SDK.
//! - **A channel's address is a secret.** A Slack or Teams webhook URL carries its own signature, a Telegram
//!   URL its bot token. None is ever in a `Debug` text, a log line or an error: an error names the channel by
//!   its kind, and a reason a service answered with is scrubbed of the address before it is kept.
//! - **A send is bounded.** A timeout per request, one retry when the service says to wait (HTTP 429, for
//!   the time it names, when that is short), never a retry of a refused message, and no redirect followed.
//! - **One channel failing does not stop the others.** `send` goes to all at once and answers a
//!   [`Delivery`] per channel.
//!
//! This module uses nothing of the account side - no database, no router - so a service with no accounts
//! can use it alone. It is a library: no route of this crate sends through it by itself.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};

use crate::Mailer;

/// The most characters of a message's text a channel is sent: the rest is cut, with `...` in its place.
/// Telegram takes 4096 characters a message; this leaves room for the title and the link.
pub const MAX_TEXT: usize = 3500;
/// The most characters of a title, and of a link's label, that are sent
pub const MAX_TITLE: usize = 200;
pub const MAX_LINK_LABEL: usize = 100;
/// A link whose URL is longer than this is left out: a URL cannot be cut
pub const MAX_LINK_URL: usize = 1000;
/// [review 2026-11-14] What Telegram takes in one message: 4096 UTF-16 code units, the title and the link
/// counted in. The text is cut to what the two leave.
pub const TELEGRAM_MAX_UNITS: usize = 4096;
/// How long one request may take, unless the notifier is told otherwise
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
/// The longest a send waits when a service says "too many, retry after": a longer wait is an error instead
pub const DEFAULT_MAX_WAIT: Duration = Duration::from_secs(5);

const TELEGRAM_API: &str = "https://api.telegram.org";

/// How much a message matters. It is shown with the title, and sent as it is to a generic webhook.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    #[default]
    Info,
    Warning,
    Severe,
}

impl Level {
    /// The level as a generic webhook gets it
    pub fn name(self) -> &'static str {
        match self {
            Level::Info => "info",
            Level::Warning => "warning",
            Level::Severe => "severe",
        }
    }

    /// What goes ahead of the title: nothing for a plain message
    fn tag(self) -> &'static str {
        match self {
            Level::Info => "",
            Level::Warning => "WARNING: ",
            Level::Severe => "SEVERE: ",
        }
    }
}

/// One message: a title, a text, how much it matters, and at most one link.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub title: String,
    pub text: String,
    pub level: Level,
    /// `(label, URL)`: kept only when the URL is http or https
    pub link: Option<(String, String)>,
}

impl Message {
    pub fn new(title: impl Into<String>, text: impl Into<String>) -> Self {
        Message { title: title.into(), text: text.into(), level: Level::Info, link: None }
    }

    pub fn level(mut self, level: Level) -> Self {
        self.level = level;
        self
    }

    pub fn link(mut self, label: impl Into<String>, url: impl Into<String>) -> Self {
        self.link = Some((label.into(), url.into()));
        self
    }

    /// The title, cut to `MAX_TITLE` characters, with its level ahead of it
    fn headline(&self) -> String {
        format!("{}{}", self.level.tag(), cut_chars(&self.title, MAX_TITLE))
    }

    /// The text, cut to `MAX_TEXT` characters
    fn body(&self) -> String {
        cut_chars(&self.text, MAX_TEXT)
    }

    /// The link, when its URL is one a client may open and no longer than `MAX_LINK_URL`: its label, cut to
    /// `MAX_LINK_LABEL` characters, and the URL
    fn web_link(&self) -> Option<(String, &str)> {
        let (label, url) = self.link.as_ref()?;
        let web = (url.starts_with("https://") || url.starts_with("http://")) && url.chars().count() <= MAX_LINK_URL;
        web.then(|| (cut_chars(label, MAX_LINK_LABEL), url.as_str()))
    }
}

/// `s` cut to at most `max` characters, with `...` in place of the rest
fn cut_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let cut: String = s.chars().take(max).collect();
    format!("{cut}...")
}

/// `s` cut to at most `max` UTF-16 code units - how Telegram counts - the `...` of the cut counted in
fn cut_utf16(s: &str, max: usize) -> String {
    if s.encode_utf16().count() <= max {
        return s.to_string();
    }
    let room = max.saturating_sub(3);
    let (mut used, mut out) = (0, String::new());
    for c in s.chars() {
        if used + c.len_utf16() > room {
            break;
        }
        used += c.len_utf16();
        out.push(c);
    }
    out.push_str("...");
    out
}

/// Where a message goes. Every address here is a secret but an email address and a Telegram chat id.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Channel {
    /// A Slack incoming webhook
    Slack { webhook_url: String },
    /// A Microsoft Teams Workflows webhook ("When a Teams webhook request is received"): an Adaptive Card
    Teams { webhook_url: String },
    /// A Telegram bot's `sendMessage` to one chat
    Telegram { bot_token: String, chat_id: String },
    /// Any receiver of a JSON POST: `{title, text, level, link}`. `bearer` is sent as its Authorization.
    Webhook { url: String, bearer: Option<String> },
    /// A mail through the notifier's [`Mailer`]
    Email { to: String },
}

impl Channel {
    /// The channel's kind: `slack`, `teams`, `telegram`, `webhook`, `email`
    pub fn kind(&self) -> &'static str {
        match self {
            Channel::Slack { .. } => "slack",
            Channel::Teams { .. } => "teams",
            Channel::Telegram { .. } => "telegram",
            Channel::Webhook { .. } => "webhook",
            Channel::Email { .. } => "email",
        }
    }

    /// The channel as a log line and a [`Delivery`] name it: its kind, and what of its address is no secret
    /// (the chat, the mail address). [review 2026-11-14] A webhook is named by its kind alone: its host can
    /// be a tenant's own, and so part of the secret; [`Delivery::index`] tells two webhooks apart.
    pub fn label(&self) -> String {
        match self {
            Channel::Slack { .. } | Channel::Teams { .. } | Channel::Webhook { .. } => self.kind().to_string(),
            Channel::Telegram { chat_id, .. } => format!("telegram chat {chat_id}"),
            Channel::Email { to } => format!("email {to}"),
        }
    }

    /// What of this channel must never be shown: its URL, the path and the query of it, each longer part of
    /// the path alone (a signature is one), its tokens - and each of these as it reads percent-decoded, the
    /// way an error page may repeat it. [review 2026-11-14]
    fn secrets(&self) -> Vec<String> {
        let of_url = |url: &str| {
            let mut out = vec![url.to_string()];
            if let Ok(u) = reqwest::Url::parse(url) {
                out.push(u.path().to_string());
                out.extend(u.query().map(str::to_string));
                out.extend(u.path().split('/').filter(|part| part.len() >= 8).map(str::to_string));
            }
            out
        };
        let mut out = match self {
            Channel::Slack { webhook_url } | Channel::Teams { webhook_url } => of_url(webhook_url),
            Channel::Telegram { bot_token, .. } => vec![bot_token.clone()],
            Channel::Webhook { url, bearer } => {
                let mut out = of_url(url);
                out.extend(bearer.clone());
                out
            }
            Channel::Email { .. } => Vec::new(),
        };
        let decoded: Vec<String> = out.iter().map(|s| percent_decoded(s)).filter(|d| !out.contains(d)).collect();
        out.extend(decoded);
        out
    }
}

/// `s` with its `%XX` escapes read as the bytes they stand for
fn percent_decoded(s: &str) -> String {
    let bytes = s.as_bytes();
    let (mut out, mut i) = (Vec::with_capacity(bytes.len()), 0);
    while i < bytes.len() {
        let hex = |b: u8| (b as char).to_digit(16);
        match (bytes[i], bytes.get(i + 1).copied().and_then(hex), bytes.get(i + 2).copied().and_then(hex)) {
            (b'%', Some(hi), Some(lo)) => {
                out.push((hi * 16 + lo) as u8);
                i += 3;
            }
            (b, _, _) => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// an address is a secret: a channel prints as its label
impl fmt::Debug for Channel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Channel({})", self.label())
    }
}

/// Why a message did not reach a channel. No variant carries an address or a token.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum NotifyError {
    /// The channel cannot be used as it is set up: an address that is no https URL, a token left empty,
    /// an email channel with no mailer
    Config(String),
    /// The service answered with an error: its status, and its reason in short
    Refused { status: u16, reason: String },
    /// The service asked to wait longer than a send does - or said "too many" again after the one wait.
    /// `retry_after_secs` is the wait it named; 0 when it named one that cannot be read
    RateLimited { retry_after_secs: u64 },
    /// No answer in time, or no connection
    Unreachable(String),
    /// The mailer did not take the mail
    Mail(String),
}

impl NotifyError {
    /// [i18n] The error's message in `lang`, its code first (`SO-E040` to `SO-E044`): the code is the same
    /// in every language. A reason a service answered with, or a mailer's, is as it came.
    pub fn message_in(&self, lang: &str) -> String {
        match self {
            NotifyError::Config(why) => crate::i18n::text_in(lang, "err-notify-config", &[("why", why)]),
            NotifyError::Refused { status, reason } => {
                let reason = if reason.is_empty() { String::new() } else { format!(": {reason}") };
                crate::i18n::text_in(lang, "err-notify-refused", &[("status", &status.to_string()), ("reason", &reason)])
            }
            NotifyError::RateLimited { retry_after_secs } => {
                crate::i18n::text_in(lang, "err-notify-rate", &[("secs", &retry_after_secs.to_string())])
            }
            NotifyError::Unreachable(why) => crate::i18n::text_in(lang, "err-notify-unreachable", &[("why", why)]),
            NotifyError::Mail(why) => crate::i18n::text_in(lang, "err-notify-mail", &[("why", why)]),
        }
    }

    /// The error's code, `SO-Ennn`
    pub fn code(&self) -> String {
        self.message_in(crate::i18n::DEFAULT_LANG).split(' ').next().unwrap_or_default().to_string()
    }
}

/// the message with its code, in the language of the request this runs for (English outside one)
impl fmt::Display for NotifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message_in(crate::i18n::current()))
    }
}

impl std::error::Error for NotifyError {}

/// What became of a message on one channel
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delivery {
    /// The channel's place in [`Notifier::channels`]
    pub index: usize,
    /// The channel's [`Channel::label`]
    pub channel: String,
    pub result: Result<(), NotifyError>,
}

struct Inner {
    channels: Vec<Channel>,
    /// [review 2026-11-14] the client, or why there is none: a send then fails as not set up - never
    /// through a default client, which would follow redirects and wait without a limit
    http: Result<reqwest::Client, String>,
    mailer: Option<Arc<Mailer>>,
    max_wait: Duration,
    allow_http: bool,
    telegram_api: String,
}

/// The channels of a site and the means to send to them. A clone shares both.
#[derive(Clone)]
pub struct Notifier {
    inner: Arc<Inner>,
}

impl fmt::Debug for Notifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Notifier").field("channels", &self.inner.channels).finish()
    }
}

fn http_client(timeout: Duration) -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(timeout)
        // a redirect would carry the message, and for a bearer its token, to an address nobody set up
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("signon-notify/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| e.to_string())
}

impl Notifier {
    /// A notifier of these channels: a 5 s timeout a request, https addresses only, no mailer yet
    pub fn new(channels: Vec<Channel>) -> Self {
        Notifier {
            inner: Arc::new(Inner {
                channels,
                http: http_client(DEFAULT_TIMEOUT),
                mailer: None,
                max_wait: DEFAULT_MAX_WAIT,
                allow_http: false,
                telegram_api: TELEGRAM_API.to_string(),
            }),
        }
    }

    /// The channels the environment names; none set is a notifier that sends nowhere.
    ///
    /// - `NOTIFY_SLACK_WEBHOOK` - a Slack incoming webhook URL
    /// - `NOTIFY_TEAMS_WEBHOOK` - a Teams Workflows webhook URL
    /// - `NOTIFY_TELEGRAM_TOKEN` and `NOTIFY_TELEGRAM_CHAT` - a bot's token, and its chats, comma separated
    /// - `NOTIFY_WEBHOOK_URL`, with `NOTIFY_WEBHOOK_BEARER` when the receiver wants a token
    /// - `NOTIFY_EMAIL_TO` - mail addresses, comma separated (sent once a mailer is attached)
    pub fn from_env() -> Self {
        Self::from_vars(|name| std::env::var(name).ok())
    }

    /// [`Notifier::from_env`] over any source of settings: `get` answers a name's value. A site that keeps
    /// its settings elsewhere - a config table, a secret store - builds its notifier through this.
    pub fn from_vars(get: impl Fn(&str) -> Option<String>) -> Self {
        let set = |name: &str| get(name).map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
        let list = |name: &str| -> Vec<String> {
            set(name).map(|v| v.split(',').map(|p| p.trim().to_string()).filter(|p| !p.is_empty()).collect()).unwrap_or_default()
        };
        let mut channels = Vec::new();
        if let Some(webhook_url) = set("NOTIFY_SLACK_WEBHOOK") {
            channels.push(Channel::Slack { webhook_url });
        }
        if let Some(webhook_url) = set("NOTIFY_TEAMS_WEBHOOK") {
            channels.push(Channel::Teams { webhook_url });
        }
        if let Some(bot_token) = set("NOTIFY_TELEGRAM_TOKEN") {
            for chat_id in list("NOTIFY_TELEGRAM_CHAT") {
                channels.push(Channel::Telegram { bot_token: bot_token.clone(), chat_id });
            }
        }
        if let Some(url) = set("NOTIFY_WEBHOOK_URL") {
            channels.push(Channel::Webhook { url, bearer: set("NOTIFY_WEBHOOK_BEARER") });
        }
        for to in list("NOTIFY_EMAIL_TO") {
            channels.push(Channel::Email { to });
        }
        Self::new(channels)
    }

    fn rebuilt(self, change: impl FnOnce(&mut Inner)) -> Self {
        let mut inner = Inner {
            channels: self.inner.channels.clone(),
            http: self.inner.http.clone(),
            mailer: self.inner.mailer.clone(),
            max_wait: self.inner.max_wait,
            allow_http: self.inner.allow_http,
            telegram_api: self.inner.telegram_api.clone(),
        };
        change(&mut inner);
        Notifier { inner: Arc::new(inner) }
    }

    /// One more channel, after the ones it has
    pub fn with_channel(self, channel: Channel) -> Self {
        self.rebuilt(|i| i.channels.push(channel))
    }

    /// The mailer the email channels send through. Without one an email channel is an error of its own
    /// and the other channels go on. A disabled mailer ([`Mailer::disabled`]) takes a mail and sends it
    /// nowhere, as everywhere in this crate: the delivery then reads `Ok` though nobody got a mail.
    pub fn with_mailer(self, mailer: Arc<Mailer>) -> Self {
        self.rebuilt(|i| i.mailer = Some(mailer))
    }

    /// Another timeout of one request
    pub fn with_timeout(self, timeout: Duration) -> Self {
        self.rebuilt(|i| i.http = http_client(timeout))
    }

    /// How long a send waits when a service says to retry later; with `Duration::ZERO` it never waits and
    /// never sends a second time
    pub fn with_max_wait(self, max_wait: Duration) -> Self {
        self.rebuilt(|i| i.max_wait = max_wait)
    }

    /// Lets a webhook address be plain `http://`: for a receiver on a private network. Without it an
    /// address that is not https is refused before anything is sent.
    pub fn allow_http(self, allow: bool) -> Self {
        self.rebuilt(|i| i.allow_http = allow)
    }

    /// Another base of Telegram's API (a self-hosted Bot API server). It is held to https as every
    /// address is: a plain `http://` base needs [`Notifier::allow_http`] too.
    pub fn with_telegram_api(self, base: impl Into<String>) -> Self {
        let base = base.into().trim_end_matches('/').to_string();
        self.rebuilt(|i| i.telegram_api = base)
    }

    pub fn channels(&self) -> &[Channel] {
        &self.inner.channels
    }

    /// No channel at all: `send` does nothing
    pub fn is_empty(&self) -> bool {
        self.inner.channels.is_empty()
    }

    /// Sends `message` to every channel at once and answers what became of it on each, in the channels'
    /// order. A failure is also logged (`tracing`, by the channel's place and label). It answers no error
    /// of its own. It runs on a tokio runtime, as the HTTP client does: each send is a task of it.
    pub async fn send(&self, message: &Message) -> Vec<Delivery> {
        let mut sends = tokio::task::JoinSet::new();
        let mut place = std::collections::HashMap::new();
        for (index, channel) in self.inner.channels.iter().cloned().enumerate() {
            let (this, message) = (self.clone(), message.clone());
            let task = sends.spawn(async move { this.send_to(&channel, &message).await });
            place.insert(task.id(), index);
        }
        let mut results: Vec<Option<Result<(), NotifyError>>> = vec![None; self.inner.channels.len()];
        while let Some(done) = sends.join_next_with_id().await {
            // [review 2026-11-14] a send that panicked is that channel's failure, with what it said
            let (id, result) = match done {
                Ok((id, result)) => (id, result),
                Err(e) => (e.id(), Err(NotifyError::Unreachable(format!("{}: {e}", crate::i18n::text("notify-not-finished", &[]))))),
            };
            if let Some(index) = place.get(&id) {
                results[*index] = Some(result);
            }
        }
        self.inner.channels.iter().zip(results).enumerate().map(|(index, (channel, result))| {
            let result = result.unwrap_or_else(|| Err(NotifyError::Unreachable(crate::i18n::text("notify-not-finished", &[]))));
            let channel = channel.label();
            if let Err(e) = &result {
                // [review 2026-11-14] a log line is English, whatever the language of the request this runs in
                tracing::warn!(index, channel = %channel, error = %e.message_in(crate::i18n::DEFAULT_LANG), "notification not delivered");
            }
            Delivery { index, channel, result }
        }).collect()
    }

    /// Sends `message` to one channel, which need not be one of the notifier's own
    pub async fn send_to(&self, channel: &Channel, message: &Message) -> Result<(), NotifyError> {
        let secrets = channel.secrets();
        match channel {
            Channel::Slack { webhook_url } => self.post(webhook_url, None, &slack_payload(message), &secrets).await,
            Channel::Teams { webhook_url } => self.post(webhook_url, None, &teams_payload(message), &secrets).await,
            Channel::Telegram { bot_token, chat_id } => {
                if bot_token.is_empty() || chat_id.is_empty() {
                    return Err(NotifyError::Config(crate::i18n::text("notify-telegram-incomplete", &[])));
                }
                let url = format!("{}/bot{}/sendMessage", self.inner.telegram_api, bot_token);
                self.post(&url, None, &telegram_payload(chat_id, message), &secrets).await
            }
            Channel::Webhook { url, bearer } => self.post(url, bearer.as_deref(), &webhook_payload(message), &secrets).await,
            Channel::Email { to } => {
                let mailer = self.inner.mailer.as_ref()
                    .ok_or_else(|| NotifyError::Config(crate::i18n::text("notify-no-mailer", &[])))?;
                let (subject, text, html) = email_parts(message);
                mailer.deliver(to, &subject, text, html, &[]).await.map_err(NotifyError::Mail)
            }
        }
    }

    /// The address as a request may go to it: an https URL, or http where the notifier allows it
    fn checked(&self, url: &str) -> Result<reqwest::Url, NotifyError> {
        let parsed = reqwest::Url::parse(url).map_err(|_| NotifyError::Config(crate::i18n::text("notify-not-url", &[])))?;
        match parsed.scheme() {
            "https" => Ok(parsed),
            "http" if self.inner.allow_http => Ok(parsed),
            _ => Err(NotifyError::Config(crate::i18n::text("notify-not-https", &[]))),
        }
    }

    /// One POST of `body` as JSON. A 2xx is delivered. A 429 is waited out once, for the time the service
    /// names, when that is within `max_wait`. Anything else is the error, with the service's reason
    /// scrubbed of `secrets`.
    async fn post(&self, url: &str, bearer: Option<&str>, body: &Value, secrets: &[String]) -> Result<(), NotifyError> {
        let url = self.checked(url)?;
        let http = self.inner.http.as_ref().map_err(|e| NotifyError::Config(crate::i18n::text("notify-no-client", &[("why", e)])))?;
        let mut waited = false;
        loop {
            let mut request = http.post(url.clone()).json(body);
            if let Some(token) = bearer {
                request = request.bearer_auth(token);
            }
            let response = request.send().await
                .map_err(|e| NotifyError::Unreachable(scrub(&e.without_url().to_string(), secrets)))?;
            let status = response.status();
            if status.is_success() {
                return Ok(());
            }
            let header = response.headers().get(reqwest::header::RETRY_AFTER).and_then(|v| v.to_str().ok()).map(str::to_string);
            // [review 2026-11-14] scrubbed whole, before it is cut to a reason: a secret across the cut would
            // otherwise keep its first part
            let text = scrub(&response.text().await.unwrap_or_default(), secrets);
            let (reason, body_wait) = reason_of(&text);
            if status.as_u16() == 429 {
                // the wait the service names: in its header (seconds, or a date), else in its body; with
                // no header at all, a second. A header that cannot be read is no wait to trust.
                let wait = match &header {
                    Some(value) => retry_after(value, chrono::Utc::now()).or(body_wait),
                    None => body_wait.or(Some(1)),
                };
                match wait {
                    Some(secs) if !waited && !self.inner.max_wait.is_zero() && Duration::from_secs(secs) <= self.inner.max_wait => {
                        waited = true;
                        tokio::time::sleep(Duration::from_secs(secs)).await;
                        continue;
                    }
                    _ => return Err(NotifyError::RateLimited { retry_after_secs: wait.unwrap_or(0) }),
                }
            }
            return Err(NotifyError::Refused { status: status.as_u16(), reason });
        }
    }
}

/// [review 2026-11-14] The seconds a `Retry-After` header asks for: a count of seconds (a fraction rounds
/// up), or an HTTP date, read from `now`; a date already past is no wait. Anything else is not known.
fn retry_after(value: &str, now: chrono::DateTime<chrono::Utc>) -> Option<u64> {
    let value = value.trim();
    if let Ok(secs) = value.parse::<u64>() {
        return Some(secs);
    }
    if let Ok(secs) = value.parse::<f64>() {
        return (secs.is_finite() && secs >= 0.0).then(|| secs.ceil() as u64);
    }
    let date = chrono::DateTime::parse_from_rfc2822(value).ok()?;
    Some((date.with_timezone(&chrono::Utc) - now).num_seconds().max(0) as u64)
}

/// The reason in a service's error answer, in one short line, and the wait it names in its body (Telegram's
/// `parameters.retry_after`). A JSON answer gives its `description`, `error` or `message`.
fn reason_of(body: &str) -> (String, Option<u64>) {
    let short = |s: &str| s.split_whitespace().collect::<Vec<_>>().join(" ").chars().take(200).collect::<String>();
    match serde_json::from_str::<Value>(body) {
        Ok(json) => {
            let wait = json.pointer("/parameters/retry_after").and_then(Value::as_u64);
            let reason = ["description", "error", "message"].iter()
                .find_map(|k| json.get(k).and_then(Value::as_str))
                .map(short)
                .unwrap_or_else(|| short(body));
            (reason, wait)
        }
        Err(_) => (short(body), None),
    }
}

/// `text` with every one of `secrets` taken out: a receiver's error page may repeat the address it was
/// asked at. A secret under 4 characters is left: taking it out would cut ordinary words.
fn scrub(text: &str, secrets: &[String]) -> String {
    let mut out = text.to_string();
    let mut by_length: Vec<&String> = secrets.iter().filter(|s| s.len() >= 4).collect();
    by_length.sort_by_key(|s| std::cmp::Reverse(s.len()));
    for secret in by_length {
        out = out.replace(secret.as_str(), "***");
    }
    out
}

/// Slack reads `&`, `<` and `>` as markup: a message's own are escaped
fn slack_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// The body of a Slack incoming webhook: the title in bold, the text, the link
pub fn slack_payload(message: &Message) -> Value {
    let mut text = format!("*{}*\n{}", slack_escape(&message.headline()), slack_escape(&message.body()));
    if let Some((label, url)) = message.web_link() {
        // [review 2026-11-14] the URL is escaped as the text is; a `|` would end it, so it goes as %7C
        text.push_str(&format!("\n<{}|{}>", slack_escape(url).replace('|', "%7C"), slack_escape(&label).replace('|', "/")));
    }
    json!({ "text": text })
}

/// The body of a Teams Workflows webhook: one Adaptive Card - the title, the text, the link as its button
pub fn teams_payload(message: &Message) -> Value {
    let color = match message.level {
        Level::Info => "Default",
        Level::Warning => "Warning",
        Level::Severe => "Attention",
    };
    let mut card = json!({
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.4",
        "body": [
            { "type": "TextBlock", "text": message.headline(), "weight": "Bolder", "size": "Medium", "wrap": true, "color": color },
            { "type": "TextBlock", "text": message.body(), "wrap": true },
        ],
    });
    if let Some((label, url)) = message.web_link() {
        card["actions"] = json!([{ "type": "Action.OpenUrl", "title": label, "url": url }]);
    }
    json!({
        "type": "message",
        "attachments": [{ "contentType": "application/vnd.microsoft.card.adaptive", "contentUrl": null, "content": card }],
    })
}

/// The body of Telegram's `sendMessage`: plain text - no markup to escape - with no link preview. The
/// whole is held to `TELEGRAM_MAX_UNITS`: the title and the link are kept, the text is cut to what they leave.
pub fn telegram_payload(chat_id: &str, message: &Message) -> Value {
    let head = message.headline();
    let link = message.web_link().map(|(label, url)| format!("\n{label}: {url}")).unwrap_or_default();
    let taken = head.encode_utf16().count() + 1 + link.encode_utf16().count();
    let body = cut_utf16(&message.body(), TELEGRAM_MAX_UNITS.saturating_sub(taken));
    json!({ "chat_id": chat_id, "text": format!("{head}\n{body}{link}"), "link_preview_options": { "is_disabled": true } })
}

/// The body a generic webhook gets: the message as it is, its level by name
pub fn webhook_payload(message: &Message) -> Value {
    let mut body = json!({ "title": message.title, "text": message.body(), "level": message.level.name() });
    if let Some((label, url)) = message.web_link() {
        body["link"] = json!({ "label": label, "url": url });
    }
    body
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// A mail of the message: its subject, its text and its HTML
fn email_parts(message: &Message) -> (String, String, String) {
    let subject = message.headline().split_whitespace().collect::<Vec<_>>().join(" "); // one line: it is a header
    let body = message.body();
    let mut text = body.clone();
    let mut html = format!("<p>{}</p>", html_escape(&body).replace('\n', "<br>"));
    if let Some((label, url)) = message.web_link() {
        text.push_str(&format!("\n\n{label}: {url}"));
        html.push_str(&format!("<p><a href=\"{}\">{}</a></p>", html_escape(url), html_escape(&label)));
    }
    (subject, text, html)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, StatusCode};
    use axum::routing::post;
    use axum::Router;
    use std::sync::Mutex;

    /// what the receivers got: the path, the Authorization, the body
    type Got = Arc<Mutex<Vec<(String, Option<String>, Value)>>>;

    const SLACK_PATH: &str = "/services/T0SECRET/B0SECRET/slack-signature-xyz";
    const TEAMS_PATH: &str = "/workflows/teams-secret-path";
    const BOT_TOKEN: &str = "123456:bot-token-secret";

    /// The receivers of a test, on a port of their own: Slack, Teams and Telegram answer as the real ones do;
    /// `/hook` wants its bearer; `/busy` says "retry after 1" once, then takes it; `/slow` says "after 60";
    /// `/echo` refuses and repeats the path it was asked at, as an error page does; `/moved` redirects.
    async fn receivers() -> (String, Got) {
        let got: Got = Arc::new(Mutex::new(Vec::new()));
        let record = |got: Got, path: &'static str| {
            post(move |headers: HeaderMap, axum::Json(body): axum::Json<Value>| {
                let got = got.clone();
                async move {
                    let auth = headers.get("authorization").and_then(|v| v.to_str().ok()).map(str::to_string);
                    got.lock().unwrap().push((path.to_string(), auth, body));
                    "ok"
                }
            })
        };
        let busy = Arc::new(Mutex::new(0u32));
        let app = Router::new()
            .route(SLACK_PATH, record(got.clone(), "slack"))
            .route(TEAMS_PATH, record(got.clone(), "teams"))
            .route(&format!("/bot{BOT_TOKEN}/sendMessage"), record(got.clone(), "telegram"))
            .route("/hook", record(got.clone(), "hook"))
            .route("/busy", post({
                let (busy, got) = (busy.clone(), got.clone());
                move |axum::Json(body): axum::Json<Value>| {
                    let (busy, got) = (busy.clone(), got.clone());
                    async move {
                        let mut calls = busy.lock().unwrap();
                        *calls += 1;
                        if *calls == 1 {
                            return (StatusCode::TOO_MANY_REQUESTS, [("retry-after", "1")], "slow down").into_response();
                        }
                        got.lock().unwrap().push(("busy".to_string(), None, body));
                        "ok".into_response()
                    }
                }
            }))
            .route("/slow", post(|| async { (StatusCode::TOO_MANY_REQUESTS, [("retry-after", "60")], "later") }))
            // "too many" every time, each call counted: after 1 s, at once, and with no time it names
            .route("/always", post({
                let got = got.clone();
                move || { got.lock().unwrap().push(("always".to_string(), None, Value::Null)); async { (StatusCode::TOO_MANY_REQUESTS, [("retry-after", "1")], "again") } }
            }))
            .route("/at-once", post({
                let got = got.clone();
                move || { got.lock().unwrap().push(("at-once".to_string(), None, Value::Null)); async { (StatusCode::TOO_MANY_REQUESTS, [("retry-after", "0")], "now") } }
            }))
            .route("/unreadable", post({
                let got = got.clone();
                move || { got.lock().unwrap().push(("unreadable".to_string(), None, Value::Null)); async { (StatusCode::TOO_MANY_REQUESTS, [("retry-after", "soon")], "?") } }
            }))
            .route("/dated", post(|| async {
                let at = (chrono::Utc::now() + chrono::Duration::seconds(90)).to_rfc2822();
                (StatusCode::TOO_MANY_REQUESTS, [("retry-after", at)], "later")
            }))
            // an error page that repeats the path it was asked at, 190 characters in: across the cut of a reason
            .route("/long/{secret}", post(|uri: axum::http::Uri| async move {
                (StatusCode::NOT_FOUND, format!("{} {}", "x".repeat(190), uri.path()))
            }))
            // one that repeats its path as it reads decoded
            .route("/decoded/{secret}", post(|axum::extract::Path(secret): axum::extract::Path<String>| async move {
                (StatusCode::NOT_FOUND, format!("no hook named {secret}"))
            }))
            .route("/bot-limited/sendMessage", post(|| async {
                (StatusCode::TOO_MANY_REQUESTS, axum::Json(json!({"ok": false, "error_code": 429,
                    "description": "Too Many Requests: retry after 40", "parameters": {"retry_after": 40}})))
            }))
            .route("/echo/{secret}", post(|uri: axum::http::Uri| async move {
                (StatusCode::NOT_FOUND, format!("Cannot POST {}", uri.path()))
            }))
            .route("/bad", post(|| async {
                (StatusCode::BAD_REQUEST, axum::Json(json!({"ok": false, "description": "Bad Request: chat not found"})))
            }))
            .route("/moved", post(|| async { (StatusCode::FOUND, [("location", "/hook")]) }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (base, got)
    }
    use axum::response::IntoResponse;

    fn message() -> Message {
        Message::new("Disk <almost> full", "node-2 & node-3: 91% of /var used")
            .level(Level::Warning)
            .link("Open the node", "https://panel.example/n/2")
    }

    /// a notifier of test receivers: plain http to this host allowed, Telegram's API at the receivers
    fn notifier(base: &str, channels: Vec<Channel>) -> Notifier {
        Notifier::new(channels).allow_http(true).with_telegram_api(base)
    }

    /// each service's body, as its documentation asks for it
    #[test]
    fn each_channel_gets_its_own_shape() {
        let m = message();
        assert_eq!(slack_payload(&m), json!({
            "text": "*WARNING: Disk &lt;almost&gt; full*\nnode-2 &amp; node-3: 91% of /var used\n<https://panel.example/n/2|Open the node>"
        }));
        let teams = teams_payload(&m);
        assert_eq!(teams["type"], "message");
        let card = &teams["attachments"][0];
        assert_eq!(card["contentType"], "application/vnd.microsoft.card.adaptive");
        assert_eq!(card["content"]["type"], "AdaptiveCard");
        assert_eq!(card["content"]["body"][0]["text"], "WARNING: Disk <almost> full");
        assert_eq!(card["content"]["body"][0]["color"], "Warning");
        assert_eq!(card["content"]["body"][1]["text"], "node-2 & node-3: 91% of /var used");
        assert_eq!(card["content"]["actions"][0], json!({"type": "Action.OpenUrl", "title": "Open the node", "url": "https://panel.example/n/2"}));
        assert_eq!(telegram_payload("-1001", &m), json!({
            "chat_id": "-1001",
            "text": "WARNING: Disk <almost> full\nnode-2 & node-3: 91% of /var used\nOpen the node: https://panel.example/n/2",
            "link_preview_options": {"is_disabled": true},
        }));
        assert_eq!(webhook_payload(&m), json!({
            "title": "Disk <almost> full", "text": "node-2 & node-3: 91% of /var used", "level": "warning",
            "link": {"label": "Open the node", "url": "https://panel.example/n/2"},
        }));
        let (subject, text, html) = email_parts(&m);
        assert_eq!(subject, "WARNING: Disk <almost> full");
        assert_eq!(text, "node-2 & node-3: 91% of /var used\n\nOpen the node: https://panel.example/n/2");
        assert_eq!(html, "<p>node-2 &amp; node-3: 91% of /var used</p><p><a href=\"https://panel.example/n/2\">Open the node</a></p>");
    }

    /// a plain message has no tag and no link part; a link that is no web address is left out everywhere
    #[test]
    fn a_plain_message_and_a_link_that_is_no_web_address() {
        let plain = Message::new("Up again", "all nodes answer");
        assert_eq!(slack_payload(&plain), json!({"text": "*Up again*\nall nodes answer"}));
        assert!(teams_payload(&plain)["attachments"][0]["content"].get("actions").is_none());
        assert_eq!(teams_payload(&plain)["attachments"][0]["content"]["body"][0]["color"], "Default");
        assert!(webhook_payload(&plain).get("link").is_none());
        assert_eq!(webhook_payload(&plain)["level"], "info");
        let script = Message::new("t", "x").link("click", "javascript:alert(1)");
        assert_eq!(slack_payload(&script), json!({"text": "*t*\nx"}));
        assert!(teams_payload(&script)["attachments"][0]["content"].get("actions").is_none());
        assert!(!telegram_payload("1", &script)["text"].as_str().unwrap().contains("javascript"));
        assert!(!email_parts(&script).2.contains("javascript"));
        assert_eq!(teams_payload(&Message::new("t", "x").level(Level::Severe))["attachments"][0]["content"]["body"][0]["color"], "Attention");
        assert_eq!(Message::new("t", "x").level(Level::Severe).headline(), "SEVERE: t");
    }

    /// a text past the limit is cut, by characters, and says so; a header is one line
    #[test]
    fn a_long_text_is_cut_and_a_subject_is_one_line() {
        let long = Message::new("t", "ж".repeat(MAX_TEXT + 10));
        let body = long.body();
        assert_eq!(body.chars().count(), MAX_TEXT + 3);
        assert!(body.ends_with("..."));
        assert_eq!(Message::new("t", "short").body(), "short");
        assert_eq!(email_parts(&Message::new("two\r\nlines", "x")).0, "two lines");
    }

    /// through the wire: every channel's receiver gets its body, the webhook its bearer, and each delivery
    /// is named by its channel
    #[tokio::test]
    async fn every_channel_is_delivered() {
        let (base, got) = receivers().await;
        let mailer = Arc::new(Mailer::disabled());
        let n = notifier(&base, vec![
            Channel::Slack { webhook_url: format!("{base}{SLACK_PATH}") },
            Channel::Teams { webhook_url: format!("{base}{TEAMS_PATH}") },
            Channel::Telegram { bot_token: BOT_TOKEN.into(), chat_id: "-1001".into() },
            Channel::Webhook { url: format!("{base}/hook"), bearer: Some("hook-bearer-secret".into()) },
            Channel::Email { to: "ops-notify-test@example.com".into() },
        ]).with_mailer(mailer);
        let m = message();
        let sent = n.send(&m).await;
        let labels: Vec<&str> = sent.iter().map(|d| d.channel.as_str()).collect();
        assert_eq!(labels, ["slack", "teams", "telegram chat -1001", "webhook", "email ops-notify-test@example.com"]);
        assert_eq!(sent.iter().map(|d| d.index).collect::<Vec<_>>(), [0, 1, 2, 3, 4], "each by its place");
        assert!(sent.iter().all(|d| d.result.is_ok()), "{sent:?}");
        let got = got.lock().unwrap();
        let of = |name: &str| got.iter().find(|(p, _, _)| p == name).unwrap_or_else(|| panic!("{name} got nothing")).clone();
        assert_eq!(of("slack").2, slack_payload(&m));
        assert_eq!(of("teams").2, teams_payload(&m));
        assert_eq!(of("telegram").2, telegram_payload("-1001", &m));
        assert_eq!(of("hook").2, webhook_payload(&m));
        assert_eq!(of("hook").1.as_deref(), Some("Bearer hook-bearer-secret"));
        assert_eq!(of("slack").1, None, "a bearer is the webhook's alone");
        let mail = crate::email::outbox::to("ops-notify-test@example.com");
        assert_eq!(mail.len(), 1, "the mail went through the mailer");
        assert_eq!(mail[0].subject, "WARNING: Disk <almost> full");
        assert_eq!(mail[0].text, "node-2 & node-3: 91% of /var used\n\nOpen the node: https://panel.example/n/2");
    }

    /// one channel down does not stop the others, and its error is its own
    #[tokio::test]
    async fn a_failing_channel_does_not_stop_the_others() {
        let (base, got) = receivers().await;
        let closed = {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            format!("http://{}/hook", l.local_addr().unwrap())
        };
        let n = notifier(&base, vec![
            Channel::Webhook { url: closed, bearer: None },
            Channel::Email { to: "nobody@example.com".into() },
            Channel::Telegram { bot_token: BOT_TOKEN.into(), chat_id: "7".into() },
        ]);
        let sent = n.send(&message()).await;
        assert!(matches!(sent[0].result, Err(NotifyError::Unreachable(_))), "{:?}", sent[0]);
        assert!(matches!(sent[1].result, Err(NotifyError::Config(_))), "no mailer attached: {:?}", sent[1]);
        assert_eq!(sent[2].result, Ok(()));
        assert_eq!(got.lock().unwrap().len(), 1, "telegram got its message");
        assert!(Notifier::new(Vec::new()).send(&message()).await.is_empty());
        assert!(Notifier::new(Vec::new()).is_empty());
    }

    /// "too many": a short wait is waited out once and the message goes; a long one is an error at once,
    /// by the header or by Telegram's body
    #[tokio::test]
    async fn a_rate_limit_is_waited_out_once_when_it_is_short() {
        let (base, got) = receivers().await;
        let n = notifier(&base, Vec::new());
        let started = std::time::Instant::now();
        let busy = Channel::Webhook { url: format!("{base}/busy"), bearer: None };
        assert_eq!(n.send_to(&busy, &message()).await, Ok(()));
        assert!(started.elapsed() >= Duration::from_secs(1), "it waited the second it was told");
        assert_eq!(got.lock().unwrap().iter().filter(|(p, _, _)| p == "busy").count(), 1);

        let started = std::time::Instant::now();
        let slow = Channel::Webhook { url: format!("{base}/slow"), bearer: None };
        assert_eq!(n.send_to(&slow, &message()).await, Err(NotifyError::RateLimited { retry_after_secs: 60 }));
        let telegram = Channel::Telegram { bot_token: "-limited".into(), chat_id: "1".into() };
        assert_eq!(n.send_to(&telegram, &message()).await, Err(NotifyError::RateLimited { retry_after_secs: 40 }));
        assert!(started.elapsed() < Duration::from_secs(3), "a long wait is not waited");

        // a notifier that never waits: a long wait is an error, and so is one of no time at all - it is not
        // sent a second time
        let never = notifier(&base, Vec::new()).with_max_wait(Duration::ZERO);
        assert_eq!(never.send_to(&slow, &message()).await, Err(NotifyError::RateLimited { retry_after_secs: 60 }));
        let at_once = Channel::Webhook { url: format!("{base}/at-once"), bearer: None };
        assert_eq!(never.send_to(&at_once, &message()).await, Err(NotifyError::RateLimited { retry_after_secs: 0 }));
        assert_eq!(got.lock().unwrap().iter().filter(|(p, _, _)| p == "at-once").count(), 1, "sent once, never again");
    }

    /// [review 2026-11-14] "too many" a second time, after the one wait, is the error: no third request. A
    /// wait named as a date is read as one; a wait that cannot be read is not waited and not retried
    #[tokio::test]
    async fn a_second_rate_limit_is_the_error_and_a_dated_wait_is_read() {
        let (base, got) = receivers().await;
        let n = notifier(&base, Vec::new());
        let hits = |name: &str| got.lock().unwrap().iter().filter(|(p, _, _)| p == name).count();
        let always = Channel::Webhook { url: format!("{base}/always"), bearer: None };
        assert_eq!(n.send_to(&always, &message()).await, Err(NotifyError::RateLimited { retry_after_secs: 1 }));
        assert_eq!(hits("always"), 2, "the first, and the one retry");

        let started = std::time::Instant::now();
        let dated = Channel::Webhook { url: format!("{base}/dated"), bearer: None };
        match n.send_to(&dated, &message()).await {
            Err(NotifyError::RateLimited { retry_after_secs }) => assert!((85..=90).contains(&retry_after_secs), "{retry_after_secs}"),
            other => panic!("{other:?}"),
        }
        let unreadable = Channel::Webhook { url: format!("{base}/unreadable"), bearer: None };
        assert_eq!(n.send_to(&unreadable, &message()).await, Err(NotifyError::RateLimited { retry_after_secs: 0 }));
        assert_eq!(hits("unreadable"), 1, "a wait that cannot be read is not retried after a guess");
        assert!(started.elapsed() < Duration::from_secs(3));

        let now = chrono::DateTime::parse_from_rfc2822("Wed, 21 Oct 2026 07:28:00 GMT").unwrap().with_timezone(&chrono::Utc);
        assert_eq!(retry_after("120", now), Some(120));
        assert_eq!(retry_after(" 0 ", now), Some(0));
        assert_eq!(retry_after("1.2", now), Some(2), "a fraction rounds up");
        assert_eq!(retry_after("Wed, 21 Oct 2026 07:29:30 GMT", now), Some(90));
        assert_eq!(retry_after("Wed, 21 Oct 2026 07:00:00 GMT", now), Some(0), "a date already past");
        assert_eq!(retry_after("soon", now), None);
        assert_eq!(retry_after("-5", now), None);
    }

    /// [review 2026-11-14] what Telegram takes: the whole message within 4096 UTF-16 units, the title and
    /// the link kept, the text cut; a long title, a long label and an over-long URL each within their own limit
    #[test]
    fn a_telegram_message_fits_with_its_title_and_link() {
        let units = |v: &Value| v["text"].as_str().unwrap().encode_utf16().count();
        let long = Message::new("T".repeat(600), "\u{1F600}".repeat(MAX_TEXT))
            .level(Level::Severe)
            .link("L".repeat(300), format!("https://panel.example/{}", "p".repeat(900)));
        let payload = telegram_payload("1", &long);
        assert!(units(&payload) <= TELEGRAM_MAX_UNITS, "{} units", units(&payload));
        let text = payload["text"].as_str().unwrap();
        assert!(text.starts_with(&format!("SEVERE: {}...\n", "T".repeat(MAX_TITLE))), "the title, cut to its own limit");
        assert!(text.ends_with(&format!("\n{}...: https://panel.example/{}", "L".repeat(MAX_LINK_LABEL), "p".repeat(900))), "the link whole");
        assert!(text.contains("\u{1F600}...\n"), "the text is what was cut");
        assert!(units(&payload) > TELEGRAM_MAX_UNITS - 8, "and no more than needed");

        // a URL past its limit is no link, on any channel; a short message is sent as it is
        let no_link = Message::new("t", "x").link("open", format!("https://panel.example/{}", "p".repeat(MAX_LINK_URL)));
        assert_eq!(telegram_payload("1", &no_link)["text"], "t\nx");
        assert_eq!(slack_payload(&no_link), json!({"text": "*t*\nx"}));
        assert!(webhook_payload(&no_link).get("link").is_none());
        assert_eq!(cut_utf16("abc", 3), "abc");
        assert_eq!(cut_utf16("abcdef", 5), "ab...");
        assert_eq!(cut_utf16("\u{1F600}\u{1F600}\u{1F600}", 5), "\u{1F600}...", "a pair is never split");
    }

    /// [review 2026-11-14] a link's URL is escaped for Slack as its text is, and cannot end the link early
    #[test]
    fn a_slack_link_is_escaped() {
        let m = Message::new("t", "x").link("a|b <c>", "https://x.example/?a=1&b=<2>|3");
        assert_eq!(slack_payload(&m), json!({"text": "*t*\nx\n<https://x.example/?a=1&amp;b=&lt;2&gt;%7C3|a/b &lt;c&gt;>"}));
    }

    /// [review 2026-11-14] one more channel goes after the ones a notifier has, and keeps its settings
    #[tokio::test]
    async fn a_channel_can_be_added() {
        let (base, got) = receivers().await;
        let n = notifier(&base, vec![Channel::Email { to: "x@example.com".into() }])
            .with_channel(Channel::Webhook { url: format!("{base}/hook"), bearer: None });
        assert_eq!(n.channels().len(), 2);
        let sent = n.send(&message()).await;
        assert!(matches!(sent[0].result, Err(NotifyError::Config(_))));
        assert_eq!((sent[1].index, sent[1].channel.as_str(), &sent[1].result), (1, "webhook", &Ok(())), "plain http still allowed");
        assert_eq!(got.lock().unwrap().len(), 1);
    }

    /// a refusal is the service's status and reason; no error, Debug text or label carries an address or a
    /// token, even when the receiver's own answer repeats the path
    #[tokio::test]
    async fn an_error_never_carries_the_address() {
        let (base, _got) = receivers().await;
        let n = notifier(&base, Vec::new());
        let bad = Channel::Webhook { url: format!("{base}/bad"), bearer: None };
        assert_eq!(n.send_to(&bad, &message()).await,
            Err(NotifyError::Refused { status: 400, reason: "Bad Request: chat not found".into() }));

        let secret_path = "/echo/slack-signature-very-secret";
        let echo = Channel::Slack { webhook_url: format!("{base}{secret_path}?sig=query-secret-1") };
        let refused = n.send_to(&echo, &message()).await.unwrap_err();
        assert_eq!(refused, NotifyError::Refused { status: 404, reason: "Cannot POST ***".into() });
        let unknown_bot = Channel::Telegram { bot_token: "999:unknown-bot-token".into(), chat_id: "1".into() };
        let closed = Channel::Slack { webhook_url: "http://127.0.0.1:1/services/closed-port-secret".into() };
        let all = Notifier::new(vec![echo.clone(), unknown_bot.clone(), closed.clone(),
            Channel::Webhook { url: format!("{base}/hook"), bearer: Some("hook-bearer-secret".into()) }]).allow_http(true).with_telegram_api(&base);
        let mut shown = format!("{all:?} {echo:?} {unknown_bot:?} {closed:?}");
        for d in all.send(&message()).await {
            shown.push_str(&format!(" {} {:?} {}", d.channel, d.result, d.result.as_ref().err().map(|e| e.to_string()).unwrap_or_default()));
        }
        for secret in ["slack-signature-very-secret", "query-secret-1", "unknown-bot-token", "closed-port-secret", "hook-bearer-secret"] {
            assert!(!shown.contains(secret), "{secret} in {shown}");
        }
        assert!(shown.contains("telegram chat 1") && shown.contains("webhook"), "{shown}");
        assert!(!shown.contains("127.0.0.1"), "[review 2026-11-14] not the host of an address either: {shown}");

        // [review 2026-11-14] a secret across the cut of a reason, one repeated as it reads decoded, a part
        // of the path alone, and a short bearer: none is in the reason
        let long = Channel::Slack { webhook_url: format!("{base}/long/straddling-secret-0123456789") };
        let reason = match n.send_to(&long, &message()).await {
            Err(NotifyError::Refused { status: 404, reason }) => reason,
            other => panic!("{other:?}"),
        };
        assert!(!reason.contains("stradd") && reason.ends_with("***"), "{reason}");
        let decoded = Channel::Webhook { url: format!("{base}/decoded/sig%2Bnature%20secret"), bearer: None };
        assert_eq!(n.send_to(&decoded, &message()).await, Err(NotifyError::Refused { status: 404, reason: "no hook named ***".into() }));
        let c = Channel::Webhook { url: "https://h.example/in/tenant-signature-1/x?key=v1".into(), bearer: Some("b4rr".into()) };
        assert_eq!(scrub("at tenant-signature-1 with b4rr, key=v1, in x", &c.secrets()), "at *** with ***, ***, in x",
            "a part of the path, the bearer, the query; a part of one letter is no secret");
        assert_eq!(percent_decoded("a%2Fb%zz%4"), "a/b%zz%4", "a broken escape stays as it is");
    }

    /// an address that is not https is refused before anything is sent; a redirect is not followed
    #[tokio::test]
    async fn only_https_unless_allowed_and_no_redirect_is_followed() {
        let (base, got) = receivers().await;
        let strict = Notifier::new(Vec::new());
        let plain = Channel::Webhook { url: format!("{base}/hook"), bearer: None };
        assert_eq!(strict.send_to(&plain, &message()).await, Err(NotifyError::Config("the address is not an https URL".into())));
        for bad in ["", "not a url", "ftp://host/x", "file:///etc/passwd"] {
            let c = Channel::Slack { webhook_url: bad.into() };
            assert!(matches!(notifier(&base, Vec::new()).send_to(&c, &message()).await, Err(NotifyError::Config(_))), "{bad}");
        }
        assert!(matches!(strict.send_to(&Channel::Telegram { bot_token: String::new(), chat_id: "1".into() }, &message()).await,
            Err(NotifyError::Config(_))));
        assert!(got.lock().unwrap().is_empty(), "nothing was sent");

        let moved = Channel::Webhook { url: format!("{base}/moved"), bearer: Some("hook-bearer-secret".into()) };
        assert_eq!(notifier(&base, Vec::new()).send_to(&moved, &message()).await, Err(NotifyError::Refused { status: 302, reason: String::new() }));
        assert!(got.lock().unwrap().is_empty(), "the redirect's target got nothing");
    }

    /// the channels a set of settings names: empty values name none, a list is one channel each
    #[test]
    fn the_settings_name_the_channels() {
        let vars = |pairs: &'static [(&'static str, &'static str)]| {
            move |name: &str| pairs.iter().find(|(k, _)| *k == name).map(|(_, v)| v.to_string())
        };
        assert!(Notifier::from_vars(vars(&[])).is_empty());
        assert!(Notifier::from_vars(vars(&[("NOTIFY_SLACK_WEBHOOK", "  "), ("NOTIFY_TELEGRAM_CHAT", "1")])).is_empty(),
            "a blank value and a chat with no token name nothing");
        let n = Notifier::from_vars(vars(&[
            ("NOTIFY_SLACK_WEBHOOK", "https://hooks.slack.example/s"),
            ("NOTIFY_TEAMS_WEBHOOK", "https://teams.example/w"),
            ("NOTIFY_TELEGRAM_TOKEN", "1:tok"), ("NOTIFY_TELEGRAM_CHAT", "-100, 42 ,"),
            ("NOTIFY_WEBHOOK_URL", "https://hook.example/in"), ("NOTIFY_WEBHOOK_BEARER", "b"),
            ("NOTIFY_EMAIL_TO", "a@example.com,b@example.com"),
        ]));
        assert_eq!(n.channels(), [
            Channel::Slack { webhook_url: "https://hooks.slack.example/s".into() },
            Channel::Teams { webhook_url: "https://teams.example/w".into() },
            Channel::Telegram { bot_token: "1:tok".into(), chat_id: "-100".into() },
            Channel::Telegram { bot_token: "1:tok".into(), chat_id: "42".into() },
            Channel::Webhook { url: "https://hook.example/in".into(), bearer: Some("b".into()) },
            Channel::Email { to: "a@example.com".into() },
            Channel::Email { to: "b@example.com".into() },
        ]);
        let kinds: Vec<&str> = n.channels().iter().map(Channel::kind).collect();
        assert_eq!(kinds, ["slack", "teams", "telegram", "telegram", "webhook", "email", "email"]);
    }

    /// [i18n] an error has its code, the same in every language, and its text in the language asked for
    #[test]
    fn an_error_has_its_code_in_every_language() {
        let errors = [
            (NotifyError::Config("x".into()), "SO-E040"),
            (NotifyError::Refused { status: 404, reason: "gone".into() }, "SO-E041"),
            (NotifyError::RateLimited { retry_after_secs: 60 }, "SO-E042"),
            (NotifyError::Unreachable("timeout".into()), "SO-E043"),
            (NotifyError::Mail("relay".into()), "SO-E044"),
        ];
        for (e, code) in &errors {
            assert_eq!(e.code(), *code);
            for lang in crate::i18n::LANGS {
                assert!(e.message_in(lang).starts_with(&format!("{code} ")), "{lang}: {}", e.message_in(lang));
            }
        }
        assert_eq!(errors[1].0.to_string(), "SO-E041 refused with 404: gone");
        assert_eq!(NotifyError::Refused { status: 302, reason: String::new() }.to_string(), "SO-E041 refused with 302");
        assert_eq!(errors[2].0.to_string(), "SO-E042 too many messages, retry after 60 s");
        assert_eq!(errors[0].0.to_string(), "SO-E040 not set up: x");
        assert_ne!(errors[3].0.message_in("de"), errors[3].0.message_in("en"));
        assert!(errors[3].0.message_in("ru").ends_with(": timeout"), "the reason as it came");
    }

    #[test]
    fn a_reason_is_one_short_line_and_a_secret_is_scrubbed() {
        assert_eq!(reason_of("invalid_payload\n"), ("invalid_payload".to_string(), None));
        assert_eq!(reason_of(r#"{"error": "no such hook"}"#).0, "no such hook");
        assert_eq!(reason_of(r#"{"ok":false,"description":"flood","parameters":{"retry_after":7}}"#), ("flood".to_string(), Some(7)));
        assert_eq!(reason_of(&"x".repeat(500)).0.len(), 200);
        assert_eq!(scrub("at /a/long-secret and long-secret-2", &["long-secret".into(), "long-secret-2".into(), "at".into()]),
            "at /a/*** and ***", "the longer secret first; a short word is left");
        assert_eq!(scrub("a tok3 b", &["tok3".into()]), "a *** b", "four characters are scrubbed");
    }
}

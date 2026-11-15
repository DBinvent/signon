# signon

Rust crate for user management, shared by the web back offices that mount it.

Registration, email verification, login sessions, password reset, OAuth2 SSO
and the updates-and-news mailing list — one implementation, one schema, one
set of security invariants. Each site keeps its **own database**; nothing is
shared between sites but the code.

`DESIGN.md` has the reasoning: what was taken from the implementations that
came before, what was fixed, and what was deliberately left out.
`web/` holds the frontend half — an API client and the React screens the four
Next.js apps mount.

## Using it

```rust
let db_url = "postgres:///mysite?host=/var/run/postgresql&user=mysite";
signon::migrate(&db_url).await?;                       // schema_guard, idempotent

let pool = sqlx::postgres::PgPoolOptions::new()
    .max_connections(5)
    .connect(&db_url)
    .await?;

let config = signon::Config::new("Acme", "https://dash.example.com").with_env();
let state = signon::AccountState::from_env(pool, config).await?;
signon::spawn_housekeeping(state.pool.clone());        // optional row sweep

let app = axum::Router::new()
    .route("/health", axum::routing::get(health))
    .nest("/account", signon::router(state));
```

`CurrentUser` gates a route on a live session, and re-reads roles from the
database per request, so a revocation takes effect immediately:

```rust
async fn my_thing(user: signon::CurrentUser) -> impl axum::response::IntoResponse {
    user.require_role("admin")?;
    // ...
}
```

## Endpoints (mounted at `/account`)

Reached from a browser as `/api/account/...` — every site`s Worker forwards
`/api/*` to its backend and strips the prefix.

| method | path | notes |
|---|---|---|
| POST | `/register` | `{email, password, display_name?, emails?, another?}` → `201`, identical body (and `signon_browser` cookie) whether or not the address was taken; `emails` (default true) is the sign-up form's pre-ticked "email me" box; `409 {error:"registered_here", hint}` when this browser already has an account here — decided by the cookie alone, `another: true` goes through |
| POST | `/verify` | `{id, token}` from the mail link; signs the user in on success |
| GET | `/verify/{id}/{token}` | same, for a link that hits the API directly |
| POST | `/verify/code` | `{email, code}` — the six-digit path, attempt-capped |
| POST | `/verify/resend` | `{email}` → always `200`; sends only if unverified and past the cooldown |
| POST | `/login` | `{email, password}` → session cookie |
| POST | `/logout` | deletes the session row, clears the cookie |
| GET | `/me` | account, roles, linked providers, `has_password`, `emails_enabled` |
| POST | `/emails` | signed in: `{enabled}` — the profile page's switch for the welcome and news |
| POST | `/emails/unsubscribe` | `{token, enabled?}` — the page behind a mailed unsubscribe link (`enabled: true` is its undo); `404` for a token that names no account |
| POST | `/emails/unsubscribe/{token}` | RFC 8058 one-click, posted by the mail client (`List-Unsubscribe`); always `200`; exempt from the origin guard |
| POST | `/password` | `{current_password?, new_password}`; revokes every other session |
| POST | `/password-reset/request` | `{email}` → always `200` |
| POST | `/password-reset/confirm` | `{token, new_password}`; revokes every session |
| GET | `/sessions` | live sessions, with the current one flagged |
| DELETE | `/sessions/{id}` | revoke one (scoped to the caller in SQL) |
| DELETE | `/sessions` | revoke all but the current |
| GET | `/oauth` | `{providers, custom_sso}` — providers this site signs in with now, and whether to offer the custom SSO button (federated: a live customer connection, shown only alongside at least one provider) |
| GET | `/oauth/{provider}/start` | `?redirect_to=/path` — site-relative only |
| GET | `/oauth/{provider}/callback` | redirects back into the site |
| POST | `/oauth/{provider}/callback` | Apple only (`form_post`) — exempt from the origin guard, as is one-click unsubscribe; nothing else is |
| GET | `/oauth/pending?token=` | Amazon/Facebook/Microsoft: the sign-in waiting on an emailed code |
| POST | `/oauth/pending/{email,resend,confirm}` | set the address, resend, or finish with the code |
| POST | `/sso/discover` | feature `sso-broker`: `{email, redirect_to?}` → `{sso:true, name, href}` or `{sso:false}` — asked of the SSO service, domain only |
| POST | `/sso/finish` | feature `sso-broker`: `{ticket}` + the `ta_sso_bind` cookie → `{status:"ok"}` (session) or `"no_profile"` (with a `token` for `create-profile`, and `email` — null when the profile will have none); `409` when an address typed on a customer connection's button (`email_typed`) already has an account. No mailed-code step: an address the provider does not vouch for (Amazon, Facebook, Microsoft) never enters an account, and the profile it creates has no email |
| POST | `/sso/create-profile` | feature `sso-broker`: `{token, emails?, another?}` — the "No profile exists. Create one?" answer, with its "email me" box; the `registered_here` question comes before the token is spent |

Mounted separately at `/news` (`signon::subscribe_router`) — the
updates-and-news mailing list, ported from a landing site's Cloudflare D1
waitlist onto the site's own Postgres. Optional: a site that does not want a list
simply does not mount it.

| method | path | notes |
|---|---|---|
| POST | `/subscribe` | `{email, source?}` → `200`, identical body whether or not the address is already on the list |
| POST | `/confirm` | `{token}` — double opt-in; nothing but the confirmation itself is sent to an unconfirmed address |
| GET | `/confirm/{token}` | same, for a link that hits the API directly |
| POST | `/unsubscribe` | `{token}` — idempotent, and the token keeps working afterwards |
| GET | `/unsubscribe/{token}` | same |

`signon::active_subscribers(&pool)` returns `(email, unsubscribe_token)`
for everyone confirmed and still subscribed — what a newsletter send needs.
Sending the newsletter is not this crate's job; collecting the list is.

Every credential rejection is the same `401 {"error":"invalid credentials"}`,
whichever check failed.

**Mail to an account that is not about the account** — the welcome today
(`account_mail.rs`). A site opts in with `Config::with_welcome(Welcome
{subject, paragraphs, action})`; without it nothing is sent, so a site that
does not opt in is unchanged. With the `welcome-remote` feature the text can live
elsewhere: `Config::welcome_url` (`WELCOME_TEMPLATE_URL`, empty turns it off)
is read when a welcome goes out — `GET` answering `{subject, body,
action_label, action_url}`, the body one paragraph per blank-line block,
`{site}` and `{product}` filled in, a button kept only with an http(s) URL.
When configured it alone decides: a 404 (the source's way to say not
approved, or switched off), an error or 1.5 s without an answer means **no
welcome** — the built-in `Config::welcome` never stands in — and the account
is not marked as welcomed. It goes once when an account becomes usable with a
confirmed address: after verification for a password sign-up, at creation
when a sibling site or a provider already vouches for the address. A site can
also put a line on top of the footer of the welcome and the follow-up, with an
optional link: `Config::with_footer_note(FooterNote {text, link})`. A template
answer carrying `footer: {text, label, url}` overrides it - a site whose
template source has an editor for that line sends it this way - and an
empty `text` means no line.

Every such send is logged in `mail_log` — one row per account per kind
(`welcome`, `followup`), claimed before it goes and then marked `sent` or
`failed` with the relay's reason (`Mailer::deliver` reports it). That row is
what keeps a kind to once per account, and what two **manual runs** work from,
started by a site's template admin through `mail_admin_router` (a host
nests it, for example at `/internal/mail`, behind
`Authorization: Bearer <MAIL_ADMIN_KEY>`; 404 without the key):
`GET /audience?kind=welcome|followup&days=N` → `{count, ready}`, and
`POST /send {kind, days}` → `{sent, failed, skipped, remaining}`, up to 200
accounts a call. `welcome` reaches accounts that never got one (signed up
while it was off, or its send failed — a failed row is tried again, a sent
one never); `followup` reaches accounts welcomed more than `days` days ago
that have not had it. Its text only ever comes from `Config::followup_url`
(`FOLLOWUP_TEMPLATE_URL`) — there is no built-in follow-up. The log is
internal, shown to nobody. Opt-out:
`users.emails_off_at`, set from the sign-up box, a mailed link or the
profile switch. Every such mail carries the unsubscribe link
(`account_unsubscribe_path`, default `/account/unsubscribe?token={token}`;
`users.unsubscribe_token`, in the clear like the list's) and the one-click
`List-Unsubscribe` / `List-Unsubscribe-Post` headers. Verification, reset
and sign-in-code mail go out regardless.

**`signon_browser`** — a long-lived (400 days) random, HttpOnly, host-only
cookie, set on every sign-in and every `/register` answer; its hash and the
accounts it created or signed in to are in `user_browsers`. Only used to ask
before a second account is registered from one browser — a nudge, not a
security boundary.

## Environment

| variable | meaning |
|---|---|
| `APP_BASE_URL` | public site origin, e.g. `https://dash.example.com` |
| `PUBLIC_BASE_URL` | public prefix reaching *this service*, if not `<APP_BASE_URL>/api` |
| `ALLOWED_ORIGINS` | comma separated; defaults to `APP_BASE_URL` alone |
| `INSECURE_COOKIES=1` | drops `Secure` from the session cookie — local plain HTTP only |
| `CLIENT_IP_KEY` | 16+ characters; shared with the site's Worker. With it, `X-Client-IP` (sent with `X-Client-IP-Key` = this value) replaces `CF-Connecting-IP` for rate limits, sessions, audit events and the recorded sign-up / sign-in addresses — needed when the Worker forwards to another zone, where Cloudflare reports the Worker's own address for every visitor. Unset (or a wrong key): both headers are stripped and ignored |
| `FOLLOWUP_TEMPLATE_URL` | feature `welcome-remote`: where the follow-up's text is read; empty turns it off. No built-in follow-up |
| `MAIL_ADMIN_KEY` | at least 16 characters: the key `mail_admin_router` requires (manual catch-up / follow-up runs). Unset: those routes are 404 |
| `WELCOME_TEMPLATE_URL` | feature `welcome-remote`: where the welcome's current text is read at send time; empty turns it off. Unset: whatever the site set with `Config::with_default_welcome_url`, else none |
| `EMAIL_PROVIDER` | `smtp` (default) or `cloudflare` (needs the `cloudflare-email` feature, on by default) |
| `EMAIL_HOST` `EMAIL_PORT` `EMAIL_LOGIN` `EMAIL_KEY` `EMAIL_FROM` | SMTP relay — **all five required**; `AccountState::from_env` fails startup without them |
| `CF_ACCOUNT_ID` `CF_EMAIL_TOKEN` `EMAIL_FROM` | Cloudflare Email Sending — required when `EMAIL_PROVIDER=cloudflare` |
| `EMAIL_FROM_NAME` | optional display name on the envelope sender |
| `NOTIFY_TO` | comma separated; who gets "someone subscribed" alerts. Unset means nobody is told |
| `OAUTH_<PROVIDER>_CLIENT_ID` / `_CLIENT_SECRET` | enables that provider — `GITHUB`, `LINKEDIN`, `GOOGLE`, `AMAZON`, `FACEBOOK`, `MICROSOFT` |
| `OAUTH_APPLE_CLIENT_ID` `_TEAM_ID` `_KEY_ID` `_PRIVATE_KEY[_PATH]` | Apple: a Services ID and a `.p8` key instead of a secret |
| `OAUTH_<PROVIDER>_REDIRECT_URI` | override, when it is not `<api_base>/account/oauth/<key>/callback` |

Two providers, one interface. **SMTP** is the default: `EMAIL_PORT` picks the
TLS mode (`465` implicit, anything else STARTTLS), and `EMAIL_FROM` must be a
verified sender on the relay — a relay-internal login handle gets a `250 OK`
and is then silently dropped downstream.

**Cloudflare Email Sending** (`EMAIL_PROVIDER=cloudflare`) goes through the
REST API, because a Rust service is not a Worker. Inside a Worker the
`send_email` binding needs no credential and is the right choice; from here a
token is the only option, and it needs the account-level *Email Sending* send
permission — a token that can only read `email/sending/zones` passes the
health probe and then fails every send with `10000 Authentication error`. The
`from` domain must be onboarded (`wrangler email sending enable <domain>`).

Cloudflare Email Sending is for **transactional** mail. The confirmation,
welcome and owner-alert messages qualify; an actual newsletter broadcast does
not, and needs a bulk-mail provider.

To check a configuration end to end without booting a service:

```sh
EMAIL_PROVIDER=cloudflare CF_ACCOUNT_ID=... CF_EMAIL_TOKEN=... \
  EMAIL_FROM=no-reply@example.com EMAIL_FROM_NAME=Acme \
  cargo run --example send_test -- you@example.com
```

For a run with no relay at all, construct the state with
`AccountState::from_env_with_mailer(pool, config, Mailer::disabled())`; the
services built on this crate expose that as `EMAIL_DISABLED=1`.

## Schema

`schema.yaml`, applied by `signon::migrate` through `schema_guard_tokio` —
diffed against the live database on every boot, never destructive, so four
repos share one file with no ordered migration chain. Tables: `users`,
`user_identities`, `password_resets`, `sessions`, `roles`, `user_roles`,
`auth_events`, `oauth_states`, `pending_identities`, `subscribers`,
`user_browsers`. `users` also keeps `signup_ip`, `last_login_ip`,
`emails_off_at` and `unsubscribe_token` — all nullable, so existing rows read
as "mail on". `mail_log` is the per-account send log (above).

To apply it to a database without booting a service:

```sh
cargo run --example migrate -- 'postgres:///mysite?host=/var/run/postgresql&user=mysite'
```

## Tests

`cargo test` covers the pure logic — token shapes, password policy, the rate
limiter window, redirect validation, email normalisation, mail-template
contents, the PKCE challenge and the provider registry.

Everything that needs a database and a real request path is exercised from
outside, by a smoke script that drives a *running* service of a site over HTTP
and reads the verification, reset and subscription links back out of its log.
The script is the site's, not part of this repository; a service runs for it
with the mailer off and plain-HTTP cookies allowed:

```sh
EMAIL_DISABLED=1 INSECURE_COOKIES=1 APP_BASE_URL=http://127.0.0.1:8196 \
  db='postgres:///mysite?host=/var/run/postgresql&user=mysite' PORT=8196 \
  ./target/debug/my-server > /tmp/my-server.log 2>&1 &
```

41 checks: registration, the enumeration guards, verification and its replay
rejection, sessions, password change, reset, and the whole mailing-list
round trip.

The sign-in flows have their own suite, `src/flow_tests.rs`, run by
`cargo test --features sso-broker` (or `--all-features`): the real router
driven in-process against a scratch Postgres (`SIGNON_TEST_DB`, default
`postgres:///signon_test` over the local socket — skipped with a note when
there is none), an in-process mock provider and a mock SSO service. Apple's
form_post, the Amazon/Facebook code step, state replay, and the brokered
finish: tickets, browser binding, "Create one?", enforcement; and the
welcome (once, after confirmation, not when unticked, not without
`with_welcome`), the unsubscribe page / one-click / profile switch, the
`registered_here` question on sign-up and on a created profile, and the
forwarded client address counting only with `CLIENT_IP_KEY`. The disabled
mailer records what it would have sent into a test-only outbox the tests
read. Customer
connections (OIDC and SAML end to end) are tested where they now run, in
the SSO service. The SAML verifier is checked here against
fixtures signed by `signxml` and the C14N against libxml2
(`tests/fixtures/`, `--features saml`). Only the C14N cases are checked in.
No private key is: the tests that sign - the mock provider's id_tokens, the
`test-support` SAML responses - make their own with `openssl` the first time
they run on a machine, under `tests/fixtures/`, where `.gitignore` keeps them
(`src/fixture_keys.rs`). The SAML documents are not pushed either: where
`tests/fixtures/saml/` is missing, the tests make the whole set - two
throwaway keys, their certificates, the good documents and every attack
variant (`src/saml/fixture_gen.rs`). A set made that way is signed by this
crate's own signer, so it checks the verifier's rules but not its C14N
against another implementation; the set signed by `signxml` does, on the
machine that has it.

## Languages and codes

What this crate says to a person - the API's error texts and the mail it sends - is in six
languages: English, Russian, French, German, Simplified Chinese and Japanese
(`locales/<lang>.yml`; all but English were written with the code and are not reviewed by a
native speaker).

- **The language is a request's.** The first language of its `Accept-Language` that there are
  messages in; else the site's own, `Config::lang` (`APP_LANG`, English when not set). The
  routers of this crate do this themselves; a site puts its own routes under the same rule
  with `axum::middleware::from_fn_with_state(state, signon::request_language)`.
- **A mail is in the language of the request that caused it** - a confirmation, a reset, a
  sign-in code. A mail nobody's request causes - the owner's alert of a signup, the footer of
  an admin's catch-up run - is in the site's. A site's own welcome text is the site's, in the
  language it was written in.
- **An error carries its code**, the same in every language:
  `{"error": "invalid credentials", "code": "SO-E001"}`. A client that acts on an error
  reads the code, and shows the text. Two answers are states a client switches on, and keep
  their word in `error` in every language - `registered_here` and `sso required`; their code
  (`SO-E025`, `SO-E026`) and their sentence (`message`) are beside it. A `note` beside a
  status that went well is in the request's language too.
- **In a mail's HTML part every value is escaped** - a product's name, a URL, a code - and
  a value is never read for `%{name}` places itself.
- Traditional Chinese (`zh-TW`, `zh-HK`, `zh-Hant`) is not the Chinese there is: such a
  request gets its next language, or the site's.
- Log lines are English.

| Code | Text (English) |
|---|---|
| `SO-E001` | invalid credentials |
| `SO-E002` | too many requests, try again later |
| `SO-E003` | internal error |
| `SO-E004` | email delivery is currently unavailable, try again shortly |
| `SO-E005` | forbidden |
| `SO-E006` | not found |
| `SO-E007` | invalid email |
| `SO-E008` | a valid email is required |
| `SO-E009` | invalid link |
| `SO-E010` | that confirmation link is no longer valid |
| `SO-E011` | that unsubscribe link is not valid |
| `SO-E012` | this unsubscribe link is not valid |
| `SO-E013` | no email address to send to yet |
| `SO-E014` | this account has no email address to sign in with, so it cannot have a password |
| `SO-E015` | kind must be welcome or followup |
| `SO-E016` | days must be 0 to 365 |
| `SO-E017` | the template is not approved or not enabled for sending |
| `SO-E018` | unknown provider |
| `SO-E019` | method not allowed |
| `SO-E020` | single sign-on is unavailable, try again shortly |
| `SO-E021` | an account with this address already exists - sign in to it another way |
| `SO-E022` | password must be at least %{min} characters |
| `SO-E023` | password must be at most %{max} characters |
| `SO-E024` | password must not be your email address |
| `SO-E025` | an account was already created in this browser |
| `SO-E026` | this address signs in through its organization's single sign-on |
| `SO-E040` | not set up: %{why} |
| `SO-E041` | refused with %{status} |
| `SO-E042` | too many messages, retry after %{secs} s |
| `SO-E043` | not reached: %{why} |
| `SO-E044` | mail not sent: %{why} |

A new message is a key in every `locales/*.yml`; `cargo test i18n` holds that each language
has every key, with the same code and the same `%{name}` places.

## Notifications (feature `notify`)

Messages to people and to channels: Slack, Microsoft Teams, Telegram, a generic
webhook, and email through the crate's `Mailer`. A library with no routes and
no table - it uses nothing of the account side, so a service with no accounts
can use it alone. Off by default: `features = ["notify"]`.

```rust
use signon::notify::{Channel, Level, Message, Notifier};

let notifier = Notifier::from_env();          // or Notifier::new(vec![Channel::Slack { .. }, ..])
let sent = notifier
    .send(&Message::new("Disk almost full", "node-2: 91% of /var used")
        .level(Level::Warning)
        .link("Open the node", "https://panel.example.com/n/2"))
    .await;
for d in sent.iter().filter(|d| d.result.is_err()) {
    eprintln!("{}: {:?}", d.channel, d.result);
}
```

| Channel | What is sent | Set by |
|---|---|---|
| Slack | an incoming webhook: `{"text": ...}` | `NOTIFY_SLACK_WEBHOOK` |
| Teams | a Workflows webhook: one Adaptive Card | `NOTIFY_TEAMS_WEBHOOK` |
| Telegram | the Bot API's `sendMessage`, plain text | `NOTIFY_TELEGRAM_TOKEN`, `NOTIFY_TELEGRAM_CHAT` (comma separated) |
| Webhook | `{title, text, level, link}` as JSON, with a bearer if set | `NOTIFY_WEBHOOK_URL`, `NOTIFY_WEBHOOK_BEARER` |
| Email | a mail through `Notifier::with_mailer` | `NOTIFY_EMAIL_TO` (comma separated) |

`Notifier::from_vars` reads the same names from any source - a config table,
a secret store - for a service that does not keep them in its environment.

What it holds to:

- **An address is a secret.** A Slack or Teams webhook URL carries its own
  signature, a Telegram URL its bot token. None is in a `Debug` text, a log
  line or an error; a reason a service answers with is scrubbed of the
  address first.
- **A send is bounded.** 5 s a request; one retry when the service answers
  429 and names a wait of at most 5 s (seconds or a date in `Retry-After`, or
  Telegram's `retry_after`); a second 429, a longer wait or one that cannot be
  read is the error; a refused message is never retried; a redirect is never
  followed; an address must be https (`allow_http` is for a receiver on a
  private network).
- **One channel failing does not stop the others.** `send` goes to all at
  once and answers a `Delivery` per channel, in the channels' order, each with
  its place (`index`) and its label. A webhook's label is its kind alone.
- **Limits.** A text over 3500 characters is cut, a title over 200, a link's
  label over 100; a link that is not http(s), or whose URL is over 1000
  characters, is left out. A Telegram message is held to its 4096 UTF-16
  units, the title and the link kept.
- An email channel needs `Notifier::with_mailer`. A disabled mailer takes
  the mail and sends it nowhere, so that delivery reads `Ok`.

Not built: a channel per user, a queue that outlives the process, and
codes for a second sign-in factor. Nothing in the account routes sends
through this by itself.

### More messengers, by template (feature `notify-templates`)

A messenger beyond those five is a **template**: where a request goes, its
headers and its body, with places a message fills. Off by default:
`features = ["notify-templates"]` (it turns `notify` on).

The templates are set **when the crate is built, not when it runs**.
`build.rs` reads them from a TOML file, checks them and writes them out as
Rust: a name it does not know, a param nothing uses, a body that is no body
stops the build with the template and what is wrong. No file is read, and no
TOML parsed, at run time.

- The crate's own file, [`notify-templates.toml`](notify-templates.toml), has
  sixteen: `discord`, `google_chat`, `mattermost`, `rocket_chat`, `wecom`,
  `lark`, `dingtalk`, `webex`, `pushover`, `pagerduty`, `opsgenie`, `ntfy`,
  `ntfy_token`, `gotify`, `zulip`, `matrix`. Its head says what a template
  may hold.
- A site that wants another set names its own file at build time, and that
  file is then the whole set:

  ```toml
  # .cargo/config.toml of the site
  [env]
  SIGNON_NOTIFY_TEMPLATES = { value = "notify-templates.toml", relative = true }
  ```

At run time a site gives only a template's params - its address, its token -
each as `NOTIFY_<TEMPLATE>_<PARAM>`, and a template is in use when all of
them are set (`NOTIFY_GOTIFY_SERVER` and `NOTIFY_GOTIFY_TOKEN`). In code it
is `Channel::template("gotify", &[("server", ..), ("token", ..)])`. Every
param is held as a secret, as a webhook's address is.

```toml
[matrix]
params = ["homeserver", "token", "room"]
url = "{homeserver}/_matrix/client/v3/rooms/{room}/send/m.room.message/{unique}"
method = "PUT"
[matrix.headers]
Authorization = "Bearer {token}"
[matrix.json]
msgtype = "m.text"
body = "{title}\n{text}\n{link_url}"
```

What fills a `{name}`: `{title}`, `{text}`, `{level}` (in the template's own
words for info, warning and severe), `{link_url}`, `{link_label}`, a param of
the template, and **`{unique}`** - a new id for every message sent, 32 hex
digits, for a field that must not repeat (Matrix's transaction id, a
deduplication key). `{{` and `}}` are plain braces.

- A body is JSON (`json`, any shape) or a form (`form`); a value goes into it
  as text and is escaped by the encoder, so no character of a message can
  break it. In an address a value is one percent-encoded part - but the
  param the address starts with, which is an address itself.
- `max_chars`, `max_title` and `max_link` hold a message to what the service
  takes, to the character: a longer text or title is cut, a longer link left
  out.
- `ok_field` and `ok_value` are for a service that answers 200 either way and
  says in its body whether it took the message (WeCom, Lark, DingTalk).
- A template sends what it is told and computes nothing: a signed request
  (Lark's and DingTalk's signature check) is not one.
- The sixteen are written from each service's public documentation and tried
  against a receiver of our own, not against the services: send one message
  through a template before relying on it.

## SSO (features `oauth`, `sso`, `saml`, `sso-broker`, `test-support`)

`oauth` (default) is the seven social providers, signed in to in-process, with
credentials from the environment (or a live [`sso::SsoRegistry`] a service
replaces at runtime). That is what a site with no SSO service of its own runs.

A product with several sites can federate instead: one SSO service runs every
protocol for its sites and hands each site verified identities as single-use
tickets. The features split along that line:

- `sso` and `saml` are libraries only, no routes — a generic OIDC relying
  party (`oidc.rs`) and a SAML 2.0 SP with a deliberately narrow pure-Rust
  XML-DSig verifier (`c14n.rs`, `saml.rs`, pending external review). The SSO
  service links them.
- `sso-broker` is the site side (`broker.rs`): the provider list, discovery
  and enforcement come from the SSO service, `/sso/finish` redeems a ticket
  into a session, and a sign-in with no matching profile asks before creating
  one. With a broker set, providers this process loaded from `OAUTH_*` are
  dropped, so no in-process provider path runs beside the service.
  [`broker::BrokerHooks`] is a site's own policy after a sign-in (dash: team
  membership).
- `test-support` exposes test signers (`testing.rs`: id_tokens, and a
  signed SAML Response with `saml`) for other crates' tests. Enable it from
  `[dev-dependencies]` only — the keys are test keys, made by `openssl` on
  the machine that runs the tests, and `testing::saml::idp_cert_pem()` is the
  certificate of the one this machine signs with.

Design and invariants: `DESIGN.md`, section 5.

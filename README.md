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

## Architecture

Where signon stands among the services that use it (YT Cluster's first):

1. **Authentication, in signon:** email and password, OAuth2 and OIDC sign-in, SAML 2.0
   (features `oauth`, `sso`, `saml`), sessions; for a program, a service account
   (feature `service-accounts`).
2. **Authorization, in the services:** signon decides the levels - roles, key-range
   permissions (feature `permissions`), leveled attributes (LABAC, feature `labac`) - and a
   service enforces them. ytproxy rewrites each SQL statement with labac's predicate, or a
   database's RLS policies compare with `labac.ids()`; an etcd server checks key ranges.
3. **Service accounts to PostgreSQL roles:** each service account names the PostgreSQL role
   it uses; ytproxy connects as that role, and labac applies to the account as to a person.
4. **A guardrail for the LLM paths** (ClickHouse and DataFusion over the cluster's tables):
   the model's statement runs as the asking subject - the same labac predicate added to what
   it reads, its tables limited to the ones the subject reaches. Described here, built later.

signon depends on no other service: an etcd server depends on signon, never the reverse. Its
tables stay in the site's database; with PostgreSQL not answering, or a feature's tables not
there, a basic file config serves the role mappings (see `permissions`), and the other table
operations are skipped.

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

## Without a browser (`signon::api`), and key-range permissions (feature `permissions`)

For a service that is not a web page - an etcd server's Auth API first - over the same
accounts and sessions:

| call | what |
|---|---|
| `api::sign_in(&state, email, password, client, via)` | `client` is each caller's own address (one value for all puts every caller in one limit). `/login`'s checks - its limits (shared: one count per address), SSO enforcement, one answer for a wrong password and an unverified or suspended account - then a session with no cookie: `SignedIn { token, user_id, expires_in }`. `via` is stored on the session (`etcd`), so `revoke_sessions_via` ends them all |
| `api::identity(&pool, token)` | the account and its roles now, `None` for an unknown, expired, unverified or suspended one. Its `last_seen_at` is written at most once a minute (`TOUCH_EVERY`): a caller checks per request, and a replicated database would carry a write per request |
| `api::sign_out(&pool, token)` | ends that session |
| `api::account`, `accounts`, `roles`, `add_role`, `delete_role`, `revoke_role` | accounts by address and role management, for a caller's user and role calls |
| `api::add_account(&pool, email, password)` | a verified account with a password, from a tool rather than the sign-up page - the first `root` of an etcd server. The password policy holds; `None` for a taken address |

With the `permissions` feature, `signon::migrate` also applies
`schema_permissions.yaml`: the table `role_permissions` - what a role may do (`READ` 1,
`WRITE` 2, `READWRITE` 3) on a range of keys of one key space (`scope`, `etcd` for an etcd
server). A range is etcd's: an empty end is the key alone, a zero byte every key from
the key on. `permissions::grant` (the same range again replaces), `revoke`, `of_role`,
`of_user`, and `permits(&perms, key, range_end, want)`: the range must lie inside what
the grants giving `want` cover together. `delete_role` takes a role's permissions with
it, also from a build without the feature.

**The file config, a functional backup.** With PostgreSQL not answering, or the table not
there, `of_user` and `of_role` answer from a file - `permissions::set_file(path)`, or
`SIGNON_PERMISSIONS_FILE`, TOML - and `grant` and `revoke` are skipped (`false`, said in the
log, as for no such role). The file answers as it is written: a permission revoked in the
table stands in the file until the table answers again - keep the two in step.

```toml
[roles.reader]
permissions = [{ scope = "etcd", key = "/app/", range_end = "/app0", perm = 1 }]
[roles.all]
permissions = [{ scope = "etcd", key = "", range_end = "\u0000", perm = 3 }]
[users]
"4f0c7f8e-0000-4000-8000-000000000001" = ["reader"]
```

## LABAC: Leveled Attribute-Based Access Control (feature `labac`)

`signon::migrate` also applies `schema_labac.yaml`, and `signon::labac` decides on it:

- **Named levels** (the security access level `sal`, or any other name): a person's own level,
  compared with a row's - the person reaches a row whose level of that name is the same or lower,
  whatever its department. A mapping rule gives one (`level_name`, `level_value`: a number, or
  `$1` a capture of the claim - `clearance = L5` gives `sal = 5`; the highest matched rule
  counts); a row for one person stands over the rules (`set_level(&pool, user, "sal", Some(3))`,
  table `labac_levels`; `None` takes it away) and takes effect at once - the subject's version
  moves. No rule and no row is level 0: no row of a table that declares the level. The ceiling is
  the action scale's and caps no named level. With `Opa::with_named_levels(url, names)` an OPA
  server's answer is the person's level of those names instead (`own_levels`).
- **A level asked** is never above the person's own: the token page mints a token for a level
  (`GET /labac/token?level=2` - `sal` - or `?level.review=1`; above its own: 403), which is that
  token's top, and a session through ytproxy may lower it further (`SET labac.level = 2`).
- **Every resource of a kind**: an ACL entry on resource `*` gives its group, or its one person,
  the entry's level on every resource of the kind - also on ids `labac_resources` does not list,
  and on private ones (`Acl::any`). No resource may have the id `*`. ytproxy and the rls policies
  then leave the kind's condition out for that action and compare the levels only: a reviewer of
  every department, below the top secret rows.

- **Mapping rules** (`labac_rules`, `add_rule`): an IdP attribute or group - a SAML attribute,
  an OIDC `groups` claim, a SCIM group - matched by name, prefix, regex (with captures) or id,
  gives an ABAC group, a label (`department = $1`) with a level, optionally a ceiling, and
  optionally a `pg_role`: the PostgreSQL group role ytproxy logs in to a node as for the person.
  `remap(&pool, user_id, &claims)` runs them at each sign-in and SCIM change
  (`claims_of_oidc`, `claims_of_saml` read the claims); the result is the account's
  **subject** - groups, labels, ceiling, PostgreSQL roles in rule order - with a version every change bumps, told to the
  embedder's `SubjectHook` (YT Cluster writes an etcd key ytproxy and yui watch).
- **Resources and entries** (`labac_resources`, `labac_entries`, `labac_actions`): a resource
  has a kind, an id, a parent, labels and a private flag; an entry gives an ABAC group (`*`
  any) a level on a resource, with a label condition (`key` relative, `key=value` literal) and
  a shared flag - with a `user_id`, to that one person, counted only while the person is in
  the entry's group; an action is a level per kind, else select 1, insert 2, update 3,
  soft_delete 4 (an UPDATE that sets the table's soft-delete column), delete 5, ddl 6
  (`labac::ACTIONS`).
- **The approval scale** (`labac::APPROVAL_ACTIONS`): the same levels read as what people decide -
  view 1, comment 2, recommend 3, approve 4, veto 5, override 6 - unless a kind sets its own
  (`set_action`). A level gives its action and every one below: to approve is not yet to veto.
  `acl.allowed(&subject, kind, id, "approve")` answers it; what an approval is of, and what a veto
  does, is the caller's - an etcd server counts the approvals of a queue's messages by it.
- **OPA** (feature `opa`): `Opa::new(url, kinds, cache_for)` - for its kinds (all, when none are
  named) an OPA server is asked once per subject version and kind, `POST url` with
  `{"input": {"subject", "kind", "resources"}}`, and answers `{"result": {"<id>": level}}`; a level
  it gives is the resource's (raising or lowering signon's own), the ceiling still caps it, a
  resource it does not name keeps signon's level, and no answer grants nothing of that kind.
  `opa.reach(&acl, &subject, kind, action)` is `reach` with it.
- **The evaluator** (`load_acl`, `Acl`): `level(subject, kind, id)` - the highest matching
  entry, on the resource or shared down from a parent (a private resource takes only its own);
  0 denies, the ceiling caps, and `Why` names the entry; `allowed`, `reach` (the ids allowed an
  action), `predicate` (`{column} = ANY($n)` with the ids, for ytproxy).
- **The token:** `issue(key, &subject, ttl)` - a JWT of the account and its version, HS256;
  `current(&pool, key, token)` answers the subject only while the version is the current one.
  `Config::with_labac(LabacConfig { token_key, token_ttl, .. })` opens `GET /labac/token`
  to a signed-in person: a page with the token and a copy button (the password of a database
  login through ytproxy, for psql and the like), or with `Accept: application/json`
  `{token, expires_at, version}` (an app's `SET labac.token`); 8 hours unless set; 403 for an
  account no rule has mapped yet.
- **The SQL half, optional:** `apply_sql(&pool, key)` - only where the configuration asks for
  it - makes `labac.enter(token)` (SECURITY DEFINER: checks the HMAC ytproxy signed with,
  through pgcrypto, and an expiry, and holds the signed token for the transaction;
  `enter_token` makes one) and `labac.ids(kind, action)`, what an RLS policy compares a column
  with - SECURITY DEFINER too, checking the held token again, so a value a session sets with
  `set_config` itself is no subject. Held for the transaction: ytproxy calls `labac.enter`
  inside it (in autocommit it is gone with the statement, and every policy denies). The SQL
  is schema_guard's since its 2.5.0 (`schema_guard_tokio::labac::SQL`), and so are the policies:
  a table's `security: {schemaPath, alias, softDelete}` in its schema_guard YAML, deployed under
  schema_guard's `Rls` mode - the `alias` is the resource kind here, the `schemaPath` where a
  row's value of it is.
- **One remap of an account at a time:** a sign-in and a SCIM change at once each go on from
  the version the other wrote.

## Service accounts (feature `service-accounts`)

`schema_service.yaml`'s `service_accounts`: a program's account, its name the OAuth2 client id,
mapped to the PostgreSQL role it uses (`service::create`). Three ways in, each switched on by
`Config::with_service_accounts(ServiceConfig { .. })` and each secret kept hashed:

| way | made by | checked by |
|---|---|---|
| OAuth2 client credentials | `rotate_client_secret` (shown once) | `POST /token` (`grant_type=client_credentials`, form or HTTP Basic): a short JWT of the account, its role and groups (`service::verify`) |
| an API key | `rotate_api_key` (`sk_...`, shown once) | `by_api_key` |
| a PostgreSQL password | `set_pg_password` (argon2) | `by_pg_password` - ytproxy, when the program signs in through it |

`set_enabled(.., false)` closes every way at once; `ServiceAccount::subject()` is labac's view.
`service::current(&pool, key, token)` is how a token is taken: signed, not expired, its account
enabled and not rotated or switched since the token was issued, with the role and groups as they
are now (`verify` checks the signature alone). `/token` is rate limited per client id.

**1.1 and struct literals:** 1.1 adds fields to `saml::Assertion` (`groups`, `attributes`),
`jwt::IdClaims` (`groups`) and `Config` (`signed_in_page`, `service`). A caller that builds one
of them by a struct literal, rather than receiving it or with `Config::new`, adds them.

## After a sign-in: a page for a broken redirect

The redirect after an SSO sign-in (`303`) carries a page of its own: the sign-in worked, the link
to go on, a meta refresh - for a browser, or a proxy, that does not follow it. A site replaces
it with `Config::with_signed_in_page(html)`, `{url}` filled in escaped.

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

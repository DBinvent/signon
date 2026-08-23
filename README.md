# user_mgmt

Rust crate for user management, shared by the four backoffice sites.

Registration, email verification, login sessions, password reset, OAuth2 SSO
and the updates-and-news mailing list — one implementation, one schema, one
set of security invariants, used by `dash-ta`, `register-ta`, `dash-qw` and
`dash-db`. Each site keeps its **own database**; nothing is shared between
them but the code.

`DESIGN.md` has the reasoning: what was taken from the three implementations
that came before, what was fixed, and what was deliberately left out.
`web/` holds the frontend half — an API client and the React screens the four
Next.js apps mount.

## Using it

```rust
let db_url = "postgres:///dashqw?host=/var/run/postgresql&user=dashqw";
user_mgmt::migrate(&db_url).await?;                       // schema_guard, idempotent

let pool = sqlx::postgres::PgPoolOptions::new()
    .max_connections(5)
    .connect(&db_url)
    .await?;

let config = user_mgmt::Config::new("QW", "https://dash.knownby.work").with_env();
let state = user_mgmt::AccountState::from_env(pool, config).await?;
user_mgmt::spawn_housekeeping(state.pool.clone());        // optional row sweep

let app = axum::Router::new()
    .route("/health", axum::routing::get(health))
    .nest("/account", user_mgmt::router(state));
```

`CurrentUser` gates a route on a live session, and re-reads roles from the
database per request, so a revocation takes effect immediately:

```rust
async fn my_thing(user: user_mgmt::CurrentUser) -> impl axum::response::IntoResponse {
    user.require_role("admin")?;
    // ...
}
```

## Endpoints (mounted at `/account`)

Reached from a browser as `/api/account/...` — every site`s Worker forwards
`/api/*` to its backend and strips the prefix.

| method | path | notes |
|---|---|---|
| POST | `/register` | `{email, password, display_name?}` → `201`, identical body whether or not the address was taken |
| POST | `/verify` | `{id, token}` from the mail link; signs the user in on success |
| GET | `/verify/{id}/{token}` | same, for a link that hits the API directly |
| POST | `/verify/code` | `{email, code}` — the six-digit path, attempt-capped |
| POST | `/verify/resend` | `{email}` → always `200`; sends only if unverified and past the cooldown |
| POST | `/login` | `{email, password}` → session cookie |
| POST | `/logout` | deletes the session row, clears the cookie |
| GET | `/me` | account, roles, linked providers, `has_password` |
| POST | `/password` | `{current_password?, new_password}`; revokes every other session |
| POST | `/password-reset/request` | `{email}` → always `200` |
| POST | `/password-reset/confirm` | `{token, new_password}`; revokes every session |
| GET | `/sessions` | live sessions, with the current one flagged |
| DELETE | `/sessions/{id}` | revoke one (scoped to the caller in SQL) |
| DELETE | `/sessions` | revoke all but the current |
| GET | `/oauth` | providers this deployment has credentials for |
| GET | `/oauth/{provider}/start` | `?redirect_to=/path` — site-relative only |
| GET | `/oauth/{provider}/callback` | redirects back into the site |

Mounted separately at `/news` (`user_mgmt::subscribe_router`) — the
updates-and-news mailing list, ported from `trust-atria-landing`'s Cloudflare
D1 waitlist onto the home Postgres. Optional: a site that does not want a list
simply does not mount it.

| method | path | notes |
|---|---|---|
| POST | `/subscribe` | `{email, source?}` → `200`, identical body whether or not the address is already on the list |
| POST | `/confirm` | `{token}` — double opt-in; nothing but the confirmation itself is sent to an unconfirmed address |
| GET | `/confirm/{token}` | same, for a link that hits the API directly |
| POST | `/unsubscribe` | `{token}` — idempotent, and the token keeps working afterwards |
| GET | `/unsubscribe/{token}` | same |

`user_mgmt::active_subscribers(&pool)` returns `(email, unsubscribe_token)`
for everyone confirmed and still subscribed — what a newsletter send needs.
Sending the newsletter is not this crate's job; collecting the list is.

Every credential rejection is the same `401 {"error":"invalid credentials"}`,
whichever check failed.

## Environment

| variable | meaning |
|---|---|
| `APP_BASE_URL` | public site origin, e.g. `https://dash.ta.com` |
| `PUBLIC_BASE_URL` | public prefix reaching *this service*, if not `<APP_BASE_URL>/api` |
| `ALLOWED_ORIGINS` | comma separated; defaults to `APP_BASE_URL` alone |
| `INSECURE_COOKIES=1` | drops `Secure` from the session cookie — local plain HTTP only |
| `EMAIL_PROVIDER` | `smtp` (default) or `cloudflare` |
| `EMAIL_HOST` `EMAIL_PORT` `EMAIL_LOGIN` `EMAIL_KEY` `EMAIL_FROM` | SMTP relay — **all five required**; `AccountState::from_env` fails startup without them |
| `CF_ACCOUNT_ID` `CF_EMAIL_TOKEN` `EMAIL_FROM` | Cloudflare Email Sending — required when `EMAIL_PROVIDER=cloudflare` |
| `EMAIL_FROM_NAME` | optional display name on the envelope sender |
| `NOTIFY_TO` | comma separated; who gets "someone subscribed" alerts. Unset means nobody is told |
| `OAUTH_<PROVIDER>_CLIENT_ID` / `_CLIENT_SECRET` | enables that provider — `GITHUB`, `LINKEDIN`, `GOOGLE` |
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
`from` domain must be onboarded (`wrangler email sending enable <domain>`);
`knownby.work` and `dbinvent.com` already are.

Cloudflare Email Sending is for **transactional** mail. The confirmation,
welcome and owner-alert messages qualify; an actual newsletter broadcast does
not, and needs a bulk-mail provider.

To check a configuration end to end without booting a service:

```sh
EMAIL_PROVIDER=cloudflare CF_ACCOUNT_ID=... CF_EMAIL_TOKEN=... \
  EMAIL_FROM=no-reply@knownby.work EMAIL_FROM_NAME=QW \
  cargo run --example send_test -- you@example.com
```

For a run with no relay at all, construct the state with
`AccountState::from_env_with_mailer(pool, config, Mailer::disabled())`; the
four services expose that as `EMAIL_DISABLED=1`.

## Schema

`schema.yaml`, applied by `user_mgmt::migrate` through `schema_guard_tokio` —
diffed against the live database on every boot, never destructive, so four
repos share one file with no ordered migration chain. Tables: `users`,
`user_identities`, `password_resets`, `sessions`, `roles`, `user_roles`,
`auth_events`, `oauth_states`, `subscribers`.

To apply it to a database without booting a service:

```sh
cargo run --example migrate -- 'postgres:///dashqw?host=/var/run/postgresql&user=dashqw'
```

## Tests

`cargo test` covers the pure logic — token shapes, password policy, the rate
limiter window, redirect validation, email normalisation, mail-template
contents, the PKCE challenge and the provider registry.

Everything that needs a database and a real request path is exercised by
`../raw/scripts/um_smoke.py`, which drives a *running* service over HTTP and
reads the verification, reset and subscription links back out of its log:

```sh
EMAIL_DISABLED=1 INSECURE_COOKIES=1 APP_BASE_URL=http://127.0.0.1:8196 \
  db='postgres:///dashqw?host=/var/run/postgresql&user=dashqw' PORT=8196 \
  ./target/debug/qw-server > /tmp/qw.log 2>&1 &
python3 ../raw/scripts/um_smoke.py http://127.0.0.1:8196 /tmp/qw.log
```

41 checks: registration, the enumeration guards, verification and its replay
rejection, sessions, password change, reset, and the whole mailing-list
round trip.

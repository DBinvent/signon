# user_mgmt — design & pattern analysis

Shared user-management crate for the four backoffice sites:

| site      | frontend                  | backend crate                  | db       |
|-----------|---------------------------|--------------------------------|----------|
| dash-ta   | `trust-atria-bo/dash`     | `trust-atria-bo/crates/dashta` | dashta   |
| register-ta | `trust-atria-bo/register` | `trust-atria-bo/crates/register-bo` | registerta |
| dash-qw   | `qw-bo/dash`              | `qw-bo/server`                 | qwbo     |
| dash-db   | `dbinvent-bo/dash`        | `dbinvent-bo/server`           | dbinventbo |

Each site keeps its **own database** — no shared identity across sites. What is
shared is the *code*: one schema, one set of handlers, one cookie/session
mechanism, one set of security invariants.

## 1. Prior art actually read before writing this

Three real implementations already exist on this host. This crate is not a
greenfield design; it is the merge of the two good ones plus fixes for what
each got wrong.

### `trust-atria-bo/crates/bo-account` (2026-08-22, argon2 + sqlx + axum)

The direct ancestor. Already correct on the things that are easy to get wrong:

- argon2 PHC hashes, never a raw or reversible password;
- **email-enumeration resistance** — register returns the same `201` whether or
  not the address was already taken; reset-request and resend-verify always
  return `200`; every credential failure (no account / wrong password /
  unverified / suspended / bad token) returns one identical `401` body;
- **timing** — `login` runs argon2 against a real-but-never-matched dummy hash
  when no user row is found, so a nonexistent address is not measurably faster;
- **one-query check-and-consume** for verify and reset tokens (`UPDATE … WHERE
  token = $1 AND used = false RETURNING …`), so there is no window between
  validating a token and spending it;
- DB-backed opaque sessions rather than JWT, so logout and password change can
  revoke server-side;
- random verify token, **not** a hash of the email (the flaw it caught in
  `xpc_backend`: an email address is not a secret, so a hash of it proves
  nothing about inbox access).

All of that is carried over unchanged. What it was missing is in §3.

### `dbinvent-bo/backend` (the 2021 Rocket/diesel "user cabinet")

The richest feature set — multi-step signup, short-code *and* link email
confirmation with an attempt counter, resend cooldown, password reset with a
rate interval, session listing/revocation, roles, LinkedIn + GitHub OAuth. Its
*flows* are the model for the UI. Its *mechanisms* are not reusable:

- `Hasher::trim_and_hash` is **unsalted SHA-1** (`src/util/mod.rs:17`), and the
  seed data hashes passwords with `encode(digest('root','sha1'),'hex')`. Not
  salvageable — a straight rainbow-table target.
- The JWT signing key is a **string literal checked into the repo**
  (`src/auth/token.rs:19`).
- `CREATE UNIQUE INDEX users_login_pass_not_deleted_unique ON users(login, password)`
  — uniqueness *on the password column*, which leaks "someone else already has
  this password" as an insert failure.
- `AuthError::tag()` does `unsafe { *(self as *const Self as *const i32) }` to
  read an enum discriminant — UB on a non-`#[repr(i32)]` enum.
- JWT claims carry `verified` and `roles`, so a suspension or role change only
  takes effect when the token expires.
- Rocket 0.4 + `pear_codegen` needs a nightly rustc that no longer exists in a
  window compatible with the rest of the workspace (see
  `dbinvent-bo/.claude/CLAUDE.md`).

Taken from it: the flow shapes, the short-code idea, the attempts counter, the
resend cooldown, session listing, roles, and the OAuth provider details in
`dbinvent-bo/backend/auth.md` (still accurate for GitHub; LinkedIn's has since
moved to OIDC — see §5).

### `xpc_backend`

Source of the `schema_guard_tokio` startup-migration pattern and the `lettre`
0.11 async sender shape. Its `email_verify` = sha256(email) scheme is the one
`bo-account` correctly rejected.

## 2. Decisions

**Sessions: opaque, DB-backed, hashed at rest — not JWT.**
The browser only ever talks same-origin to its own site (the Worker `/api/*`
proxy already in every `worker.ts`), so there is no cross-site cookie problem
to design around, and a DB session can be revoked. JWT would put `verified`
and `roles` in a bearer blob that stays valid after suspension.

**Password hashing: argon2id via the `argon2` crate's defaults.**
Defaults are the OWASP-recommended parameters; pinning our own numbers here
would only mean not tracking the crate's updates.

**Password policy: length only (8–256), plus "not equal to the email".**
Composition rules (must contain a digit, a symbol…) are explicitly discouraged
by NIST SP 800-63B; length is what matters. 256 is a hard cap because argon2
cost is linear in input length — an unbounded password field is a cheap DoS.

**Schema: `schema_guard` YAML applied at startup, not diesel migrations.**
Matches `xpc_backend` and `bo-account`; one `schema.yaml` file is diffed
against the live database on every boot, so all four services converge on the
same schema without an ordered migration chain per repo.

**Every site gets its own database.** No cross-site SSO between dash-ta and
dash-db; they are different products with different customers.

## 3. What this crate adds over `bo-account`

1. **Session tokens are hashed at rest.** In `bo-account` the cookie value *is*
   `sessions.id`, so anyone who can read the table (a backup, a log, a SQL
   injection anywhere else in the app) holds live sessions. Here the cookie is
   32 random bytes and the table stores only `sha256(token)`; `sessions.id`
   stays a separate uuid used for listing and revoking.
2. **Password change / reset revokes every other session** for that user. A
   reset that leaves the attacker's session alive is not a recovery.
3. **`user_identities` table** instead of two nullable `oauth_*` columns on
   `users` — one account can hold GitHub *and* LinkedIn, which the column pair
   cannot express.
4. **OAuth2 with `state` + PKCE**, and linking only on a **provider-verified**
   email. Auto-linking an unverified provider email to an existing local
   account is a full account takeover (register at the IdP with the victim's
   address, log in as them).
5. **Rate limiting** on every unauthenticated endpoint that sends mail or
   checks a credential — `bo-account`'s open item. Per-IP *and* per-email
   sliding windows; the 60s per-account resend cooldown does not stop someone
   registering ten thousand distinct addresses.
6. **Roles** (`roles`, `user_roles`) — dash-db needs `admin` for the existing
   admin dashboard; carried in the extractor, read from the DB per request, so
   revocation is immediate.
7. **`auth_events` audit table** — register/login/logout/verify/reset/oauth,
   with IP and user agent.
8. **Origin check** on state-changing requests. `SameSite=Lax` + a JSON-only
   API is already most of the way there (a cross-site form post cannot set
   `Content-Type: application/json`), but an explicit allow-list is one line
   of middleware and removes the argument.
9. **Short-code verification** alongside the link, from the user-cabinet flow —
   with a 5-attempt cap, since a 6-digit code is otherwise brute-forceable.
10. **`/account/me`, `/account/sessions`** so a frontend can render account
    state and "sign out other devices" without each site reinventing it.

## 4. Security invariants (the contract every handler upholds)

- One `401 {"error":"invalid credentials"}` for every credential rejection,
  whichever check failed.
- Endpoints that take an email address and send mail always answer `200` with
  the same body, existing account or not — *provided the mail relay is up*.
  If `Mailer::is_healthy` fails, `register`/`resend_verify`/
  `password_reset_request` answer `503` for every caller, checked before any
  per-address DB lookup — the uniformity is what's load-bearing, not the
  status code: a `503` that only showed up for addresses that would actually
  have triggered a send would leak which addresses those were during an
  outage. A service with no mail relay configured at all does not reach this
  point — `AccountState::from_env` fails at startup instead (`Mailer::from_env`).
- A secret is never compared in application code. Link and session tokens are
  *looked up by their own hash*, and the short code is matched inside the same
  guarded `UPDATE` that spends it — so validation and consumption cannot be
  separated, and there is no Rust-side comparison to be timed.
- Passwords and tokens never reach a log line, a `Debug` impl, or an error body.
- Payload limits are checked before anything touches the database.
- Cookies: `HttpOnly`, `SameSite=Lax`, `Secure` (configurable off only for
  local plain-HTTP dev), `Path=/`.

## 5. OAuth2 / SSO

`dbinvent-bo/backend/auth.md` documents the flows that were live in 2021.
GitHub's is unchanged (authorize → access_token → `GET /user`, plus
`/user/emails` for a verified address, which the old code did not fetch —
it took whatever `/user` returned, which is `null` for most accounts).

LinkedIn's has changed: `r_liteprofile` / `r_emailaddress` and the
`/v2/me` + `/v2/clientAwareMemberHandles` pair are retired in favour of
**OIDC** — scope `openid profile email`, one `GET /v2/userinfo` call returning
`sub`, `name`, `email`, `email_verified`. This crate implements the OIDC shape
for LinkedIn and Google, and the two-step App shape for GitHub, behind one
`Provider` description so a fourth provider is a table entry, not a new module.

Provider credentials come from the environment
(`OAUTH_<PROVIDER>_CLIENT_ID` / `OAUTH_<PROVIDER>_CLIENT_SECRET`); a provider
with no credentials configured is simply absent from `GET /account/oauth`, so
the frontend renders no button for it and no site is forced to enable SSO.

## 6. Updates-and-news mailing list

`trust-atria-landing` already has this: a footer signup box posting to
`/waitlist`, stored in Cloudflare D1, with an owner alert per signup
(`worker/src/index.ts` `handleWaitlist`, `worker/src/notify.ts`,
`migrations/0001_create_waitlist.sql`). dash-qw and dash-db needed the same
thing, and neither has a D1 database — they have the home Postgres and a Rust
backend already running. So the feature moved into this crate
(`subscribe_router`, mounted at `/news`) and the storage moved into the
`subscribers` table.

Three deliberate differences from the D1 original:

- **Double opt-in.** Anyone can type someone else's address into a signup box.
  A waitlist the owner personally follows up on can live with that; a
  recurring "updates and news" list cannot — that is the difference between a
  mailing list and a way to send mail to strangers. Nothing but the
  confirmation itself is ever sent to an unconfirmed address.
- **An unsubscribe link in every message**, starting with the confirmation.
  Its token is the one secret in this schema stored *unhashed*, and that is
  forced rather than sloppy: every future newsletter has to rebuild that link
  next to the address, which a hash makes impossible. What it grants is
  removal from a mailing list, so a database read that yields it costs nothing
  an attacker with database access could not already do.
- **The same enumeration guard as the account endpoints.** The D1 version
  answers `201` for a new signup and `200` for a duplicate, which tells a
  caller whether an address is already on the list. Here both answer
  identically, and so does the UI.

Unsubscribing sets a timestamp rather than deleting the row, so resubscribing
is a state change and a mis-click is recoverable.

Signup lives on four surfaces now: both dash sites, and both marketing sites
(`qw/landing`, `dbinvent`). The marketing sites do not talk to Postgres — each
one's Worker forwards `/api/news/*` to the same backend the dash site uses, so
there is one list per product and one copy of the logic. That is also why the
confirm and unsubscribe *pages* only exist on the dash sites: the backend
builds mail links against a single `APP_BASE_URL`.

**Mail provider.** Two are supported behind one interface: SMTP (the Brevo
relay) and Cloudflare Email Sending, chosen with `EMAIL_PROVIDER`. Cloudflare
goes through the REST API rather than the `send_email` Workers binding,
because the sender is a Rust service and not a Worker — the binding needs no
credential and would be the better choice inside a Worker, but from here a
scoped API token is the only option there is. The health probe is a cheap
authenticated `GET email/sending/zones`, since REST has no SMTP `NOOP`.

One limit worth stating plainly: Cloudflare Email Sending is for
**transactional** mail. The confirmation, welcome and owner-alert messages
qualify. An actual newsletter broadcast does not, and will need a bulk-mail
provider — which is a second reason sending the newsletter is out of scope
here. `user_mgmt::active_subscribers` hands over `(email, unsubscribe_token)`
and stops there.

Every list message carries `List-Unsubscribe` and `List-Unsubscribe-Post`
(RFC 8058), so a mail client's own unsubscribe button works without opening a
browser — which is also why the unsubscribe endpoint accepts POST as well as
GET.

## 7. Deliberately not built

- **MFA/TOTP.** Nothing in the four products asks for it yet; the schema leaves
  room (`user_credentials` is not needed — a `totp_secret` column can be added
  to `users` when it is).
- **Account deletion / soft-delete columns.** No product has the feature; unused
  `deleted_on` columns are how the 2021 schema ended up with six of them.
- **i18n of the emails.** The user-cabinet had en/ru templates; none of the four
  current frontends is localised.
- **Cross-site SSO.** Explicitly not a goal — see §2.
- **Sending the newsletter.** This crate collects the list; something else
  decides what goes out and when. That keeps a scheduled bulk-send job, its
  retry behaviour and its bounce handling out of a request-path crate.

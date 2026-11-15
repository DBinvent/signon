# signon — design & pattern analysis

Shared user-management crate for web back offices. Several sites mount it, each with
its own frontend, its own backend and its own database.

Each site keeps its **own database** - no shared identity across sites. What is
shared is the *code*: one schema, one set of handlers, one cookie/session
mechanism, one set of security invariants.

## 1. What this design keeps, and what it avoids

This crate is not a greenfield design. It merges an earlier account crate with the
flows of an older, richer account service, and fixes what each got wrong.

### Kept from the earlier account crate (argon2 + sqlx + axum)

The direct ancestor. Already correct on the things that are easy to get wrong:

- argon2 PHC hashes, never a raw or reversible password;
- **email-enumeration resistance** - register returns the same `201` whether or
  not the address was already taken; reset-request and resend-verify always
  return `200`; every credential failure (no account / wrong password /
  unverified / suspended / bad token) returns one identical `401` body;
- **timing** - `login` runs argon2 against a real-but-never-matched dummy hash
  when no user row is found, so a nonexistent address is not measurably faster;
- **one-query check-and-consume** for verify and reset tokens (`UPDATE ... WHERE
  token = $1 AND used = false RETURNING ...`), so there is no window between
  validating a token and spending it;
- DB-backed opaque sessions rather than JWT, so logout and password change can
  revoke server-side;
- a random verify token, **not** a hash of the email: an email address is not a
  secret, so a hash of it proves nothing about inbox access.

All of that is carried over unchanged. What it was missing is in section 3.

### The flows of the older account service, not its mechanisms

The richest feature set - multi-step signup, short-code *and* link email
confirmation with an attempt counter, resend cooldown, password reset with a
rate interval, session listing/revocation, roles, LinkedIn + GitHub OAuth. Its
*flows* are the model for the UI. Mechanisms common in account code of that
generation, which this crate deliberately does not have:

- passwords under an unsalted fast hash (SHA-1): a rainbow-table target;
- a JWT signing key as a string literal in the source;
- a unique index over `(login, password)`, which leaks "someone else already has
  this password" as an insert failure;
- an enum discriminant read through an unsafe pointer cast: undefined behaviour
  on an enum with no `repr`;
- JWT claims that carry `verified` and `roles`, so a suspension or a role change
  only takes effect when the token expires.

Taken from it: the flow shapes, the short-code idea, the attempts counter, the
resend cooldown, session listing, roles, and the OAuth provider details (still
accurate for GitHub; LinkedIn's has since moved to OIDC - see section 5).

### Startup migration and mail

The `schema_guard_tokio` startup-migration pattern and the `lettre` 0.11 async
sender shape come from a third backend.

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
One `schema.yaml` file is diffed against the live database on every boot, so every
service that mounts this crate converges on the same schema without an ordered
migration chain per repo.

**Every site gets its own database.** No cross-site SSO between two sites: they
are different products with different customers.

## 3. What this crate adds over the earlier account crate

1. **Session tokens are hashed at rest.** In the earlier crate the cookie value *is*
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
   checks a credential - the earlier crate's open item. Per-IP *and* per-email
   sliding windows; the 60s per-account resend cooldown does not stop someone
   registering ten thousand distinct addresses.
6. **Roles** (`roles`, `user_roles`) - a site needs `admin` for its admin
   dashboard; carried in the extractor, read from the DB per request, so
   revocation is immediate.
7. **`auth_events` audit table** — register/login/logout/verify/reset/oauth,
   with IP and user agent.
8. **Origin check** on state-changing requests. `SameSite=Lax` + a JSON-only
   API is already most of the way there (a cross-site form post cannot set
   `Content-Type: application/json`), but an explicit allow-list is one line
   of middleware and removes the argument.
9. **Short-code verification** alongside the link, from the older service's flow -
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
  separated, and there is no Rust-side comparison to be timed. The one
  exception is `CLIENT_IP_KEY`, a configuration secret shared with the site's
  Worker, compared with `token::constant_time_eq` (over sha256 of both sides,
  so the length doesn't leak either).
- The client address is the tunnel's `CF-Connecting-IP` unless the site's
  Worker vouches for another with `CLIENT_IP_KEY` (`routes::forwarded_client_ip`,
  ahead of every handler). A forwarded `X-Client-IP` without the right key is
  stripped, never trusted — the tunnel hostname is public. Without this, a
  Worker forwarding to another zone makes every visitor the Worker's own
  address, and the per-address rate limits a single global bucket.
- Passwords and tokens never reach a log line, a `Debug` impl, or an error body.
- Payload limits are checked before anything touches the database.
- Cookies: `HttpOnly`, `SameSite=Lax`, `Secure` (configurable off only for
  local plain-HTTP dev), `Path=/`. That holds for `signon_browser` too, the
  long-lived per-site mark that asks before a second sign-up from one
  browser (`user_browsers`): it is set on every `/register` answer alike, so
  it cannot tell a new address from a taken one, and the question it raises
  (`409 registered_here`) depends on the cookie alone, never on the address
  being registered.

## 5. OAuth2 / SSO

The older service's flows date from 2021. GitHub's is unchanged (authorize ->
access_token -> `GET /user`, plus `/user/emails` for a verified address, which
the old code did not fetch - it took whatever `/user` returned, which is `null`
for most accounts).

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

**2026-10 additions:**

- Apple, Amazon, Facebook and Microsoft join the table. Apple is OIDC without a
  userinfo endpoint — identity comes from an `id_token` verified against
  Apple's JWKS (`jwt.rs`), its callback is a cross-site `form_post`, and its
  client secret is an ES256 JWT minted per exchange from a `.p8` key.
  Amazon and Facebook never vouch for an address, so their first sign-in
  parks a *pending identity* and finishes only after a mailed six-digit code
  — the same "never link on a bare address" rule as above, met a different
  way. Microsoft (the `common` endpoint, Graph OIDC userinfo, its own
  `ProfileShape`) is in the same group: its `email` is whatever a tenant
  administrator set, unverified and mutable (the "nOAuth" takeover), and it
  sends no `email_verified`.
- Providers come from a live `SsoRegistry` (environment by default) a
  service can replace at runtime.
- Features `sso` and `saml` are protocol libraries with no routes: a generic
  OIDC RP (`oidc.rs`) and a SAML SP with a deliberately narrow pure-Rust
  XML-DSig verifier (`c14n.rs`, `saml.rs`), pending external review.
  Customer connections, their flows and their data live in a separate SSO
  service, which links them. An earlier cut (2026-10-04) ran those flows in this crate; they moved
  out so one service holds every SSO secret.
- Feature `sso-broker` (`broker.rs`) is what a site federated through that
  service runs: tickets redeemed into sessions, bound to the browser that
  started the sign-in, and an explicit "Create one?" before any account is
  made from a sign-in. There is no mailed-code step there: an address no one
  vouches for (Amazon, Facebook, Microsoft) or one typed on a customer connection's
  button (`email_typed`) never enters an existing account, and a sign-in with
  no vouched address makes an account with **no email** (`users.email`
  NULL) — an unvouched address on `users.email` would let a later vouched
  sign-in at that address merge into an account someone else created.
- The origin guard has two exemptions: Apple's in-process `form_post`
  callback, an IdP posting back with our single-use state, and the RFC 8058
  one-click unsubscribe (`/emails/unsubscribe/{token}`), which a mail client
  posts from wherever it runs and which can only turn that account's
  non-essential mail off. (The SAML ACS is the SSO service's, not a site's.)

## 6. Updates-and-news mailing list

This began as a landing site's footer signup box: a post to `/waitlist`, stored
in Cloudflare D1, with an owner alert per signup. Other sites needed the same
thing and had no D1 database - they had Postgres and a Rust backend already
running. So the feature moved into this crate
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

Signup can live on two surfaces of a product: its dash site and its marketing
site. A marketing site does not talk to Postgres - its Worker forwards
`/api/news/*` to the same backend the dash site uses, so there is one list per
product and one copy of the logic. That is also why the confirm and
unsubscribe *pages* only exist on the dash site: the backend
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
here. `signon::active_subscribers` hands over `(email, unsubscribe_token)`
and stops there.

Every list message carries `List-Unsubscribe` and `List-Unsubscribe-Post`
(RFC 8058), so a mail client's own unsubscribe button works without opening a
browser — which is also why the unsubscribe endpoint accepts POST as well as
GET.

### Not the list: mail to an account (2026-10-06)

The welcome (`account_mail.rs`) goes to *account holders*, so it is opt-out
rather than double opt-in: the sign-up form and the SSO "Create one?" prompt
carry a pre-ticked "email me" box, and turning it off is one click away in
every such mail (an unsubscribe page and the one-click headers) and on the
profile page. It shares nothing with the list — no token, no table:
`users.emails_off_at` and `users.unsubscribe_token` (in the clear, for the
list's reason). A site opts in with `Config::with_welcome`; with none, nothing
is sent, so a deployment of this crate does not start mailing anyone because
it upgraded. Each send is claimed in `mail_log` (one row per account per
kind) before it goes and marked sent or failed after, so the several places
an account can become usable (verification, a vouched SSO or provider
sign-in, a sibling site's cross-verify) can all call it and only the first
sends — and a manual catch-up or follow-up run (`mail_admin_router`, behind
`MAIL_ADMIN_KEY`) finds exactly who is still owed one. Verification, reset
and code mail are the account working, and are never affected.

## 7. Deliberately not built

- **Notifications to a user's own channels.** Feature `notify` sends to the
  channels a site sets up (Slack, Teams, Telegram, a webhook, mail); a channel
  per account, with its proof of ownership, is not built.
- **MFA/TOTP.** No site asks for it yet; the schema leaves
  room (`user_credentials` is not needed — a `totp_secret` column can be added
  to `users` when it is).
- **Account deletion / soft-delete columns.** No product has the feature; unused
  `deleted_on` columns are how the older schema ended up with six of them.
- **Translated frontends.** The API's errors and the mail are in six languages
  (`i18n.rs`, `locales/`); the web components under `web/` are English.
- **Cross-site SSO.** Explicitly not a goal — see §2.
- **Sending the newsletter.** This crate collects the list; something else
  decides what goes out and when. That keeps a scheduled bulk-send job, its
  retry behaviour and its bounce handling out of a request-path crate.

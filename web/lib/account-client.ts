// Typed client for the `signon` account API.
//
// Generated file — the source of truth is ../../signon/web/lib/account-client.ts.
// Edit it there and re-run `signon/web/sync.sh <this-app>`; a local edit
// will be overwritten.
//
// Every call is a *relative* fetch, on purpose. The browser only ever talks to
// its own origin; each site's Worker forwards /api/* to the backend server
// side. An absolute fetch to the backend origin would turn this into a
// cross-origin request, needing CORS and breaking the SameSite cookie — see
// the comment at the top of each app's src/worker.ts.

const BASE = process.env.NEXT_PUBLIC_ACCOUNT_API ?? '/api/account'

export type Identity = {
  /** A social provider's key (apple, amazon, google, …), or "sso" for a customer's own IdP. */
  provider: string
  email: string | null
  linked_at: string
}

export type Account = {
  id: string
  /**
   * Null for an account with no address: made from a sign-in through the SSO
   * service whose provider gave none, or gave one it does not vouch for. Such
   * an account signs in only through its connected accounts.
   */
  email: string | null
  display_name: string | null
  email_verified: boolean
  /** False for an SSO-only account — offer "set a password", not "change". */
  has_password: boolean
  roles: string[]
  identities: Identity[]
  /** The welcome and news — off from the sign-up box, a mailed link, or the profile page. */
  emails_enabled: boolean
}

export type SessionInfo = {
  id: string
  current: boolean
  ip: string | null
  user_agent: string | null
  created_at: string
  last_seen_at: string
  expires_at: string
}

export type Provider = {
  key: string
  name: string
  start: string
  /**
   * Where a site runs sign-in through the SSO service: a path on this site
   * that its Worker forwards there (`/sso/start/google`). Absent on a site
   * that runs the provider flow in-process.
   */
  href?: string
}

export type ProviderList = {
  providers: Provider[]
  /**
   * Some customer has a live SSO connection on this site, so "Sign in with
   * SSO" is worth offering. Says nothing about which customer.
   */
  custom_sso: boolean
}

/**
 * Where a customer connection's sign-in begins. `href` is a path on this site
 * that its Worker forwards to the SSO service (`/sso/org/acme/start?…`);
 * `start` is the in-process path, relative to the API mount
 * (`/account/sso/acme/start`). The server sends at least one, and `href` wins
 * — pass either shape to `startSso`.
 */
export type SsoStart = { href?: string; start?: string }

/** Home-realm discovery: the connection that owns the address's domain, or none. */
export type SsoDiscovery = ({ sso: true; name: string } & SsoStart) | { sso: false }

/**
 * A provider sign-in parked until the user proves the address (Amazon and
 * Facebook do not vouch for the email they report). `email` is null when the
 * provider gave none — Facebook phone-only accounts.
 */
export type PendingSignIn = {
  provider: string
  provider_name: string
  email: string | null
  needs_email: boolean
  code_sent: boolean
}

/**
 * A sign-in that proved who someone is, on a site that has no profile for
 * them yet. The site asks before creating one: `token` is what
 * `createProfile` takes — single use, and it lapses with the sign-in.
 * `provider_name` is set for a social provider, `connection_name` for a
 * customer's own IdP. `email` is the address the profile will have — null
 * when it will have none (the provider gave no address it vouches for).
 */
export type NoProfile = {
  status: 'no_profile'
  token: string
  email: string | null
  name?: string | null
  provider_name?: string | null
  connection_name?: string | null
}

/**
 * What redeeming a sign-in ticket comes to: signed in, or no profile yet.
 * (No emailed-code step here: an address the provider does not vouch for is
 * simply not given to the profile.) A 409 `AccountError` instead means the
 * address typed on a customer connection's button already has an account —
 * one this sign-in may not enter.
 */
export type SsoFinish = { status: 'ok'; redirect_to: string; user: Account } | NoProfile

/** A non-2xx answer. `status` lets a caller tell 429 from 401 without parsing. */
export class AccountError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.name = 'AccountError'
    this.status = status
  }
}

/**
 * The 403 for an address whose domain enforces single sign-on — from login,
 * register and the pending-identity steps alike. A subclass so existing
 * `instanceof AccountError` handling still catches it, while a form that
 * checks for it first can offer the way in (`href` or `start` — the error is
 * itself an `SsoStart` for `startSso`) instead of a dead end. Decided from the
 * domain before any account lookup, so it says nothing about whether the
 * address has an account.
 */
export class SsoRequiredError extends AccountError {
  connection: string
  href?: string
  start?: string
  constructor(connection: string, to: SsoStart) {
    super(403, `${connection} requires single sign-on.`)
    this.name = 'SsoRequiredError'
    this.connection = connection
    this.href = to.href
    this.start = to.start
  }
}

/**
 * The 409 for a sign-up from a browser that already created or signed in to an
 * account on this site. A nudge, not a refusal: the same call with
 * `another: true` goes through. `hint` is that account's address, masked
 * (`v•••@chase.com`), or null for one with no address. Decided by the
 * browser's cookie alone, never by the address being registered.
 */
export class RegisteredHereError extends AccountError {
  hint: string | null
  constructor(hint: string | null) {
    super(409, 'This browser already has an account here.')
    this.name = 'RegisteredHereError'
    this.hint = hint
  }
}

/** What a new account starts with, and the answer to a `RegisteredHereError`. */
export type SignUpChoices = {
  /** The pre-ticked "email me" box. Omitted means yes. */
  emails?: boolean
  /** "Create another account anyway". */
  another?: boolean
}

/**
 * The server hands out `start` paths relative to its own mount point
 * (`/account/sso/acme/start`); the browser reaches that mount at BASE.
 */
function fromMount(path: string): string {
  return BASE + path.replace(/^\/account(?=[/?]|$)/, '')
}

/** A path on this origin, with each param added only where it is not already set. */
function siteUrl(path: string, params: Record<string, string | undefined>): string {
  const url = new URL(path, window.location.origin)
  for (const [name, value] of Object.entries(params)) {
    if (value && !url.searchParams.has(name)) url.searchParams.set(name, value)
  }
  return url.href
}

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response
  try {
    response = await fetch(BASE + path, {
      // The session cookie is HttpOnly; without this the browser would not
      // send it back and every authenticated call would 401.
      credentials: 'same-origin',
      ...init,
      headers: {
        'content-type': 'application/json',
        ...(init?.headers ?? {}),
      },
    })
  } catch {
    throw new AccountError(0, 'Could not reach the server. Check your connection and try again.')
  }

  const text = await response.text()
  let body: unknown = null
  try {
    body = text ? JSON.parse(text) : null
  } catch {
    // A non-JSON body from a proxy or an error page. Fall through to the
    // status-based message rather than showing the caller raw HTML.
  }

  if (!response.ok) {
    const error = body as {
      error?: string
      connection?: string
      href?: string
      start?: string
      hint?: string | null
    } | null
    if (response.status === 409 && error?.error === 'registered_here') {
      throw new RegisteredHereError(error.hint ?? null)
    }
    if (response.status === 403 && error?.error === 'sso required' && (error.href || error.start)) {
      throw new SsoRequiredError(error.connection ?? 'Your organization', {
        href: error.href,
        start: error.start,
      })
    }
    const message =
      error?.error ??
      (response.status === 429
        ? 'Too many attempts. Try again in a few minutes.'
        : 'Something went wrong. Try again.')
    throw new AccountError(response.status, message)
  }

  return (body ?? {}) as T
}

const post = <T>(path: string, payload?: unknown) =>
  call<T>(path, { method: 'POST', body: JSON.stringify(payload ?? {}) })

export const account = {
  register: (email: string, password: string, displayName?: string, choices?: SignUpChoices) =>
    post<{ status: string; note: string }>('/register', {
      email,
      password,
      display_name: displayName || undefined,
      ...choices,
    }),

  /** The profile page switch for the welcome and news. */
  setEmails: (enabled: boolean) => post<{ emails_enabled: boolean }>('/emails', { enabled }),

  /**
   * The page behind a mailed unsubscribe link — `enabled: true` is its undo.
   * 404 for a link that names no account.
   */
  unsubscribe: (token: string, enabled = false) =>
    post<{ emails_enabled: boolean }>('/emails/unsubscribe', { token, enabled }),

  /** Confirms an address from the mailed link, and signs the user in. */
  verify: (id: string, token: string) =>
    post<{ status: string; user: Account }>('/verify', { id, token }),

  /** Confirms with the six-digit code instead. Attempt-capped server side. */
  verifyCode: (email: string, code: string) =>
    post<{ status: string; user: Account }>('/verify/code', { email, code }),

  resendVerify: (email: string) => post<{ status: string }>('/verify/resend', { email }),

  login: (email: string, password: string) =>
    post<{ status: string; user: Account }>('/login', { email, password }),

  logout: () => post<{ status: string }>('/logout'),

  me: () => call<Account>('/me'),

  changePassword: (newPassword: string, currentPassword?: string) =>
    post<{ status: string }>('/password', {
      current_password: currentPassword,
      new_password: newPassword,
    }),

  requestReset: (email: string) => post<{ status: string }>('/password-reset/request', { email }),

  confirmReset: (token: string, newPassword: string) =>
    post<{ status: string }>('/password-reset/confirm', { token, new_password: newPassword }),

  sessions: () => call<{ items: SessionInfo[] }>('/sessions'),

  revokeSession: (id: string) => call<{ status: string }>(`/sessions/${id}`, { method: 'DELETE' }),

  revokeOtherSessions: () =>
    call<{ status: string; revoked: number }>('/sessions', { method: 'DELETE' }),

  /** Empty, and `custom_sso` false, when the deployment has no SSO configured. */
  providers: () => call<ProviderList>('/oauth'),

  /**
   * Full-page navigation, not fetch: the provider redirects the browser, and
   * the callback sets a cookie — neither survives an XHR. `href` where the
   * site runs sign-in through the SSO service. Otherwise the in-process flow,
   * built from `key` rather than the server's `start` path, which is relative
   * to the mount point rather than to the public /api prefix.
   */
  startOauth: (provider: Provider, redirectTo = '/') => {
    if (provider.href) {
      window.location.href = siteUrl(provider.href, { redirect_to: redirectTo })
      return
    }
    window.location.href = `${BASE}/oauth/${encodeURIComponent(
      provider.key
    )}/start?redirect_to=${encodeURIComponent(redirectTo)}`
  },

  /**
   * Which customer connection, if any, owns this address's domain. Reads the
   * domain only, never an account, so every address at a domain gets the
   * same answer. Rate-limited per IP.
   */
  discoverSso: (email: string, redirectTo?: string) =>
    post<SsoDiscovery>('/sso/discover', { email, redirect_to: redirectTo }),

  /**
   * Full-page navigation into a customer connection, for the same reasons as
   * startOauth. `to` is any way in the server handed out (discovery's, an
   * SsoRequiredError, or `{ start: ssoStartPath(slug) }`): its `href` as is,
   * else its `start` through the API mount. The extras are added only where
   * the server did not already put them in.
   */
  startSso: (to: SsoStart, extra: { loginHint?: string; redirectTo?: string } = {}) => {
    window.location.href = siteUrl(to.href || fromMount(to.start ?? ''), {
      login_hint: extra.loginHint,
      redirect_to: extra.redirectTo,
    })
  },

  /**
   * Redeems the one-time ticket a sign-in through the SSO service ends with
   * (`/account/sso/finish?ticket=`). Call it once per ticket: a second
   * attempt answers 401, the same as an expired ticket or one minted for
   * another site or another browser.
   */
  ssoFinish: (ticket: string) => post<SsoFinish>('/sso/finish', { ticket }),

  /**
   * Creates the profile a `no_profile` answer offered, and starts a session.
   * 409 when its typed address has meanwhile got an account.
   */
  createProfile: (token: string, choices?: SignUpChoices) =>
    post<{ status: string; user: Account; redirect_to: string }>('/sso/create-profile', {
      token,
      ...choices,
    }),

  // The pending-identity code step (Amazon, Facebook, Microsoft). Every call takes the
  // ?token= the callback put on /account/oauth/confirm, and every one answers
  // 401 once that token is unknown or expired.

  pendingSignIn: (token: string) =>
    call<PendingSignIn>(`/oauth/pending?token=${encodeURIComponent(token)}`),

  /** Sets the address to confirm (none from the provider, or a different one) and mails a code. */
  pendingEmail: (token: string, email: string) =>
    post<{ status: string }>('/oauth/pending/email', { token, email }),

  /** Silently sends nothing while the server's resend cooldown is running. */
  pendingResend: (token: string) => post<{ status: string }>('/oauth/pending/resend', { token }),

  /**
   * Links the identity, or creates the account, and starts a session.
   * Attempt-capped. A site that asks before creating an account answers
   * `no_profile` instead of creating one — finish with `createProfile`.
   */
  pendingConfirm: (token: string, code: string) =>
    post<{ status: 'ok'; user: Account; redirect_to: string } | NoProfile>('/oauth/pending/confirm', {
      token,
      code,
    }),
}

/**
 * The in-process start path for a connection known only by its slug — the
 * `?error=sso_required&sso=<slug>` a refused social sign-in lands with. Pass
 * it to `startSso` as `{ start }`.
 */
export function ssoStartPath(slug: string): string {
  return `/account/sso/${encodeURIComponent(slug)}/start`
}

/** Mirrors the server-side policy in signon/src/password.rs. */
export const PASSWORD_MIN_LEN = 8
export const PASSWORD_MAX_LEN = 256

export function passwordProblem(password: string, email: string | null): string | null {
  if (password.length < PASSWORD_MIN_LEN) {
    return `Use at least ${PASSWORD_MIN_LEN} characters.`
  }
  if (password.length > PASSWORD_MAX_LEN) {
    return `Use at most ${PASSWORD_MAX_LEN} characters.`
  }
  if (email && password.trim().toLowerCase() === email.trim().toLowerCase()) {
    return 'Your password cannot be your email address.'
  }
  return null
}

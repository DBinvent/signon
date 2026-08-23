// Typed client for the `user_mgmt` account API.
//
// Generated file — the source of truth is ../../user_mgmt/web/lib/account-client.ts.
// Edit it there and re-run `user_mgmt/web/sync.sh <this-app>`; a local edit
// will be overwritten.
//
// Every call is a *relative* fetch, on purpose. The browser only ever talks to
// its own origin; each site's Worker forwards /api/* to the backend server
// side. An absolute fetch to the backend origin would turn this into a
// cross-origin request, needing CORS and breaking the SameSite cookie — see
// the comment at the top of each app's src/worker.ts.

const BASE = process.env.NEXT_PUBLIC_ACCOUNT_API ?? '/api/account'

export type Identity = {
  provider: string
  email: string | null
  linked_at: string
}

export type Account = {
  id: string
  email: string
  display_name: string | null
  email_verified: boolean
  /** False for an SSO-only account — offer "set a password", not "change". */
  has_password: boolean
  roles: string[]
  identities: Identity[]
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
}

/** A non-2xx answer. `status` lets a caller tell 429 from 401 without parsing. */
export class AccountError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.name = 'AccountError'
    this.status = status
  }
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
    const message =
      (body as { error?: string } | null)?.error ??
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
  register: (email: string, password: string, displayName?: string) =>
    post<{ status: string; note: string }>('/register', {
      email,
      password,
      display_name: displayName || undefined,
    }),

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

  /** Empty when the deployment has no SSO credentials configured. */
  providers: () => call<{ providers: Provider[] }>('/oauth'),

  /**
   * Full-page navigation, not fetch: the provider redirects the browser, and
   * the callback sets a cookie — neither survives an XHR. Built from `key`
   * rather than the server's `start` path, which is relative to the mount
   * point rather than to the public /api prefix.
   */
  startOauth: (provider: Provider, redirectTo = '/') => {
    window.location.href = `${BASE}/oauth/${encodeURIComponent(
      provider.key
    )}/start?redirect_to=${encodeURIComponent(redirectTo)}`
  },
}

/** Mirrors the server-side policy in user_mgmt/src/password.rs. */
export const PASSWORD_MIN_LEN = 8
export const PASSWORD_MAX_LEN = 256

export function passwordProblem(password: string, email: string): string | null {
  if (password.length < PASSWORD_MIN_LEN) {
    return `Use at least ${PASSWORD_MIN_LEN} characters.`
  }
  if (password.length > PASSWORD_MAX_LEN) {
    return `Use at most ${PASSWORD_MAX_LEN} characters.`
  }
  if (password.trim().toLowerCase() === email.trim().toLowerCase()) {
    return 'Your password cannot be your email address.'
  }
  return null
}

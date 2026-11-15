// Signed-in account screen: who you are, your password, your linked providers,
// and where you are signed in.
//
// Generated file — the source of truth is
// ../../signon/web/components/account/account-panel.tsx. Edit it there and
// re-run `signon/web/sync.sh <this-app>`.

'use client'

import { useCallback, useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import {
  account,
  AccountError,
  passwordProblem,
  PASSWORD_MIN_LEN,
  type Account,
  type Provider,
  type SessionInfo,
} from '@/lib/account-client'
import { Checkbox, Field, Notice, SubmitButton, TextLink } from './ui'

/**
 * How an identity's provider key reads on screen. The server's own names
 * cover only the providers configured right now — an identity can outlive
 * its provider's credentials — and "sso", a customer's own IdP, is never in
 * that list at all.
 */
const PROVIDER_NAMES: Record<string, string> = {
  apple: 'Apple',
  amazon: 'Amazon',
  google: 'Google',
  facebook: 'Facebook',
  linkedin: 'LinkedIn',
  github: 'GitHub',
  microsoft: 'Microsoft',
  sso: 'Organization SSO',
}

function providerName(key: string, configured: Provider[]): string {
  return PROVIDER_NAMES[key] ?? configured.find((p) => p.key === key)?.name ?? key
}

export function AccountPanel() {
  const router = useRouter()
  const [me, setMe] = useState<Account | null>(null)
  const [sessions, setSessions] = useState<SessionInfo[]>([])
  const [providers, setProviders] = useState<Provider[]>([])
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    try {
      const who = await account.me()
      setMe(who)
      const [list, oauth] = await Promise.all([
        account.sessions().catch(() => ({ items: [] as SessionInfo[] })),
        account.providers().catch(() => ({ providers: [] as Provider[] })),
      ])
      setSessions(list.items)
      setProviders(oauth.providers)
    } catch {
      // Not signed in, or the session expired underneath us.
      router.push('/account/sign-in')
    } finally {
      setLoading(false)
    }
  }, [router])

  useEffect(() => {
    void load()
  }, [load])

  if (loading) {
    return <p className="p-6 text-sm text-muted-foreground">Loading your account…</p>
  }
  if (!me) return null

  const unlinked = providers.filter((p) => !me.identities.some((i) => i.provider === p.key))

  return (
    <div className="mx-auto w-full max-w-2xl space-y-6 px-6 py-10">
      <section className="rounded-xl border border-border bg-card p-6">
        <h2 className="text-lg font-semibold tracking-tight">Account</h2>
        <dl className="mt-4 space-y-2 text-sm">
          <Row
            label="Email"
            value={me.email ?? <span className="text-muted-foreground">no email</span>}
          />
          <Row label="Name" value={me.display_name ?? '—'} />
          <Row label="Roles" value={me.roles.length ? me.roles.join(', ') : '—'} />
        </dl>
        <div className="mt-5">
          <button
            type="button"
            onClick={async () => {
              await account.logout().catch(() => {})
              router.push('/account/sign-in')
            }}
            className="rounded-md border border-border px-3 py-1.5 text-sm transition hover:bg-accent
                       hover:text-accent-foreground"
          >
            Sign out
          </button>
        </div>
      </section>

      {me.email ? <EmailsSection enabled={me.emails_enabled} /> : null}

      {me.email ? (
        <PasswordSection hasPassword={me.has_password} email={me.email} />
      ) : (
        // Password sign-in is by address, so there is nothing a password on
        // this account could ever be used for — the server refuses one too.
        <section className="rounded-xl border border-border bg-card p-6">
          <h2 className="text-lg font-semibold tracking-tight">Password</h2>
          <p className="mt-1.5 text-sm text-muted-foreground">
            This account has no email address, so it signs in only through its connected accounts
            below and cannot have a password.
          </p>
        </section>
      )}

      <section className="rounded-xl border border-border bg-card p-6">
        <h2 className="text-lg font-semibold tracking-tight">Connected accounts</h2>
        {me.identities.length === 0 && unlinked.length === 0 ? (
          <p className="mt-2 text-sm text-muted-foreground">
            Single sign-on is not enabled on this site.
          </p>
        ) : (
          <>
            <ul className="mt-4 space-y-2 text-sm">
              {me.identities.map((identity, i) => (
                // Not keyed by provider alone: two organizations' SSO are two
                // "sso" identities.
                <li key={`${identity.provider}-${i}`} className="flex items-center justify-between gap-4">
                  <span>{providerName(identity.provider, providers)}</span>
                  <span className="text-muted-foreground">{identity.email ?? 'linked'}</span>
                </li>
              ))}
              {me.identities.length === 0 ? (
                <li className="text-muted-foreground">Nothing connected yet.</li>
              ) : null}
            </ul>
            {unlinked.length > 0 ? (
              <div className="mt-4 flex flex-wrap gap-2">
                {unlinked.map((provider) => (
                  <button
                    key={provider.key}
                    type="button"
                    // Starting the flow while signed in links the provider to
                    // this account instead of creating a second one — the
                    // server reads the session (in-process: at start, as
                    // link_user_id; federated: at /sso/finish).
                    onClick={() => account.startOauth(provider, '/account/profile')}
                    className="rounded-md border border-border px-3 py-1.5 text-sm transition
                               hover:bg-accent hover:text-accent-foreground"
                  >
                    Connect {provider.name}
                  </button>
                ))}
              </div>
            ) : null}
          </>
        )}
      </section>

      <SessionsSection sessions={sessions} onChange={load} />

      <p className="text-center text-sm text-muted-foreground">
        <TextLink href="/">Back to the dashboard</TextLink>
      </p>
    </div>
  )
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-4">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="text-right">{value}</dd>
    </div>
  )
}

/**
 * The welcome and news, on or off — the same switch the sign-up box and every
 * mailed unsubscribe link set. Account mail (confirmations, password resets)
 * is not affected; it is the account working, not news.
 */
function EmailsSection({ enabled: initial }: { enabled: boolean }) {
  const [enabled, setEnabled] = useState(initial)
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function toggle(next: boolean) {
    setPending(true)
    setError(null)
    try {
      const { emails_enabled } = await account.setEmails(next)
      setEnabled(emails_enabled)
    } catch (err) {
      setError(err instanceof AccountError ? err.message : 'Could not save that. Try again.')
    } finally {
      setPending(false)
    }
  }

  return (
    <section className="rounded-xl border border-border bg-card p-6">
      <h2 className="text-lg font-semibold tracking-tight">Emails</h2>
      <div className="mt-4 space-y-3">
        {error ? <Notice kind="error">{error}</Notice> : null}
        <Checkbox
          name="emails"
          label="Product news and tips"
          hint="Account emails — address confirmations, password resets — are always sent."
          checked={enabled}
          onChange={(e) => toggle(e.target.checked)}
          disabled={pending}
        />
      </div>
    </section>
  )
}

function PasswordSection({ hasPassword, email }: { hasPassword: boolean; email: string }) {
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [done, setDone] = useState(false)

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    setDone(false)
    const problem = passwordProblem(next, email)
    if (problem) {
      setError(problem)
      return
    }
    setPending(true)
    try {
      await account.changePassword(next, hasPassword ? current : undefined)
      setDone(true)
      setCurrent('')
      setNext('')
    } catch (err) {
      setError(
        err instanceof AccountError && err.status === 401
          ? 'That current password did not match.'
          : err instanceof AccountError
            ? err.message
            : 'Something went wrong.'
      )
    } finally {
      setPending(false)
    }
  }

  return (
    <section className="rounded-xl border border-border bg-card p-6">
      <h2 className="text-lg font-semibold tracking-tight">
        {hasPassword ? 'Change password' : 'Set a password'}
      </h2>
      {!hasPassword ? (
        <p className="mt-1.5 text-sm text-muted-foreground">
          You signed up through a connected account, so there is no password yet. Setting one lets
          you sign in without it.
        </p>
      ) : null}
      <form onSubmit={onSubmit} className="mt-4 space-y-4">
        {error ? <Notice kind="error">{error}</Notice> : null}
        {done ? <Notice kind="success">Password updated. Other sessions were signed out.</Notice> : null}
        {hasPassword ? (
          <Field
            label="Current password"
            name="current"
            type="password"
            autoComplete="current-password"
            required
            value={current}
            onChange={(e) => setCurrent(e.target.value)}
            disabled={pending}
          />
        ) : null}
        <Field
          label="New password"
          name="next"
          type="password"
          autoComplete="new-password"
          required
          minLength={PASSWORD_MIN_LEN}
          value={next}
          onChange={(e) => setNext(e.target.value)}
          disabled={pending}
        />
        <SubmitButton pending={pending}>{hasPassword ? 'Change password' : 'Set password'}</SubmitButton>
      </form>
    </section>
  )
}

function SessionsSection({
  sessions,
  onChange,
}: {
  sessions: SessionInfo[]
  onChange: () => void | Promise<void>
}) {
  const others = sessions.filter((s) => !s.current).length

  return (
    <section className="rounded-xl border border-border bg-card p-6">
      <div className="flex items-center justify-between gap-4">
        <h2 className="text-lg font-semibold tracking-tight">Where you are signed in</h2>
        {others > 0 ? (
          <button
            type="button"
            onClick={async () => {
              await account.revokeOtherSessions().catch(() => {})
              await onChange()
            }}
            className="rounded-md border border-border px-3 py-1.5 text-sm transition hover:bg-accent
                       hover:text-accent-foreground"
          >
            Sign out the other {others === 1 ? 'session' : `${others} sessions`}
          </button>
        ) : null}
      </div>
      <ul className="mt-4 space-y-3 text-sm">
        {sessions.map((session) => (
          <li key={session.id} className="flex items-start justify-between gap-4">
            <div className="min-w-0">
              <p className="truncate">
                {session.user_agent ?? 'Unknown device'}
                {session.current ? (
                  <span className="ml-2 rounded bg-success/15 px-1.5 py-0.5 text-xs text-success">
                    this one
                  </span>
                ) : null}
              </p>
              <p className="text-xs text-muted-foreground">
                {session.ip ?? 'unknown address'} · last used{' '}
                {new Date(session.last_seen_at).toLocaleString()}
              </p>
            </div>
            {!session.current ? (
              <button
                type="button"
                onClick={async () => {
                  await account.revokeSession(session.id).catch(() => {})
                  await onChange()
                }}
                className="shrink-0 text-xs text-muted-foreground underline-offset-4 hover:underline"
              >
                Revoke
              </button>
            ) : null}
          </li>
        ))}
      </ul>
    </section>
  )
}

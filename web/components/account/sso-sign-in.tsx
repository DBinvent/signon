// "Sign in with SSO" — a work email in, the customer's own identity provider
// out — and the notice every form shows when a domain insists on it.
//
// Generated file — the source of truth is
// ../../signon/web/components/account/sso-sign-in.tsx. Edit it there and
// re-run `signon/web/sync.sh <this-app>`.
//
// The address only picks the IdP: discovery reads its domain and never looks
// up an account, so every address at a domain gets the same answer. Who
// actually signs in is whoever the IdP says, which may be a different alias
// at that domain.

'use client'

import { useState } from 'react'
import { account, AccountError } from '@/lib/account-client'
import { Field, Notice, SubmitButton } from './ui'

export function SsoSignIn({ redirectTo = '/' }: { redirectTo?: string }) {
  const [open, setOpen] = useState(false)
  const [email, setEmail] = useState('')
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [none, setNone] = useState(false)
  const [leaving, setLeaving] = useState<string | null>(null)

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault()
    setPending(true)
    setError(null)
    setNone(false)
    try {
      const found = await account.discoverSso(email, redirectTo)
      if (found.sso) {
        setLeaving(found.name)
        // The server's path normally carries login_hint and redirect_to
        // already; they are added only where it does not.
        account.startSso(found, { loginHint: email, redirectTo })
      } else {
        setNone(true)
      }
    } catch (err) {
      setError(
        err instanceof AccountError && err.status === 400
          ? 'Enter a valid email address.'
          : err instanceof AccountError
            ? err.message
            : 'Something went wrong. Try again.'
      )
    } finally {
      // Not left set while the IdP loads: coming Back from it can restore
      // this page from the back-forward cache, and a button stuck on
      // "Working…" would be a dead end.
      setPending(false)
    }
  }

  if (!open) {
    return (
      <button
        type="button"
        onClick={() => setOpen(true)}
        className="flex h-10 w-full items-center justify-center gap-2.5 rounded-md border border-border
                   bg-background px-4 text-sm font-medium transition hover:bg-accent hover:text-accent-foreground"
      >
        <OrganizationIcon className="size-[18px]" />
        Sign in with SSO
      </button>
    )
  }

  return (
    <form onSubmit={onSubmit} className="space-y-3 rounded-md border border-border p-4">
      <Field
        label="Work email"
        // Not "email": the sign-in form above already owns that id.
        name="sso-email"
        type="email"
        autoComplete="email"
        required
        autoFocus
        hint="Your organization's sign-in page opens next."
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        disabled={pending}
      />
      {none ? (
        <Notice kind="info">
          Your organization hasn&apos;t set up SSO here - use another sign-in method.
        </Notice>
      ) : null}
      {error ? <Notice kind="error">{error}</Notice> : null}
      {leaving ? <Notice kind="info">Taking you to {leaving}…</Notice> : null}
      <SubmitButton pending={pending}>Continue with SSO</SubmitButton>
    </form>
  )
}

/**
 * What login, register and the pending-identity code step show for an
 * address whose domain enforces single sign-on: not an error to retry, but
 * the one way in that will work. `connection` is null when only the slug is
 * known — the `?error=sso_required` marker a refused social sign-in lands with.
 * `href` and `start` are the server's way in, as `startSso` takes them.
 */
export function SsoRequiredNotice({
  connection,
  href,
  start,
  loginHint,
  redirectTo = '/',
}: {
  connection: string | null
  href?: string
  start?: string
  loginHint?: string
  redirectTo?: string
}) {
  return (
    <div className="space-y-3">
      <Notice kind="info">
        {connection
          ? `${connection} requires single sign-on for this address.`
          : 'Your organization requires single sign-on for that address.'}{' '}
        Sign in through your organization instead.
      </Notice>
      <SubmitButton
        type="button"
        onClick={() => account.startSso({ href, start }, { loginHint, redirectTo })}
      >
        Continue with single sign-on
      </SubmitButton>
    </div>
  )
}

/** Lucide's building-2 — an organization, not a brand. */
function OrganizationIcon({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={2}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
      className={className}
    >
      <path d="M10 12h4" />
      <path d="M10 8h4" />
      <path d="M14 21v-3a2 2 0 0 0-4 0v3" />
      <path d="M6 10H4a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2V9a2 2 0 0 0-2-2h-2" />
      <path d="M6 21V5a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v16" />
    </svg>
  )
}

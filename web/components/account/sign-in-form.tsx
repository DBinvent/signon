// Sign in.
//
// Generated file — the source of truth is
// ../../signon/web/components/account/sign-in-form.tsx. Edit it there and
// re-run `signon/web/sync.sh <this-app>`.

'use client'

import { useState } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import {
  account,
  AccountError,
  SsoRequiredError,
  ssoStartPath,
  type SsoStart,
} from '@/lib/account-client'
import { AccountShell, Field, Notice, SubmitButton, TextLink } from './ui'
import { OauthButtons } from './oauth-buttons'
import { SsoRequiredNotice } from './sso-sign-in'

/**
 * The SSO and OAuth callbacks cannot return a JSON body — they are browser
 * redirects — so they signal failure with ?error= markers instead.
 * `sso_required` with a slug gets the SSO notice instead of a message.
 */
function markerMessage(params: { get(name: string): string | null }): string | null {
  switch (params.get('error')) {
    case 'oauth':
      return 'That sign-in did not complete. Try again.'
    case 'sso':
      return "Single sign-on did not complete. Try again, or ask your organization's administrator."
    case 'sso_required':
      return params.get('sso') ? null : 'Your organization requires single sign-on for that address.'
    default:
      return null
  }
}

export function SignInForm({ redirectTo = '/' }: { redirectTo?: string }) {
  const router = useRouter()
  const params = useSearchParams()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(() => markerMessage(params))
  // A social sign-in refused because the domain enforces SSO lands with the
  // connection's slug only; a refused password login carries its name too.
  const [ssoRequired, setSsoRequired] = useState<({ connection: string | null } & SsoStart) | null>(
    () => {
      const slug = params.get('sso')
      return params.get('error') === 'sso_required' && slug
        ? { connection: null, start: ssoStartPath(slug) }
        : null
    }
  )
  const [unverified, setUnverified] = useState(false)
  const [resent, setResent] = useState(false)

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault()
    setPending(true)
    setError(null)
    setSsoRequired(null)
    setUnverified(false)
    try {
      await account.login(email, password)
      router.push(redirectTo)
    } catch (err) {
      // Not a failed login but a different way in — and decided from the
      // domain alone, so saying so reveals nothing about the account.
      if (err instanceof SsoRequiredError) {
        setSsoRequired({ connection: err.connection, href: err.href, start: err.start })
        return
      }
      const message = err instanceof AccountError ? err.message : 'Something went wrong.'
      setError(
        message === 'invalid credentials'
          ? 'That email and password combination did not work.'
          : message
      )
      // The server will not say *why* a login failed — that is the
      // enumeration guard working. An unconfirmed account is the one common,
      // recoverable cause, so offer the fix without claiming it is the cause.
      if (err instanceof AccountError && err.status === 401) setUnverified(true)
    } finally {
      setPending(false)
    }
  }

  async function resend() {
    setError(null)
    try {
      await account.resendVerify(email)
      // Always answers 200, whether or not the address has an account —
      // this really is "sent" from the caller's point of view.
      setResent(true)
    } catch (err) {
      // Replaces whatever error was showing (e.g. the failed-login message
      // that prompted this click) — the resend attempt is the one the user
      // just took, so its outcome is what belongs in the box now.
      setError(err instanceof AccountError ? err.message : 'Something went wrong. Try again.')
    }
  }

  return (
    <AccountShell
      title="Sign in"
      subtitle="Use your email and password."
      footer={
        <>
          No account yet? <TextLink href="/account/sign-up">Create one</TextLink>
        </>
      }
    >
      <form onSubmit={onSubmit} className="space-y-4">
        {error ? <Notice kind="error">{error}</Notice> : null}
        {ssoRequired ? (
          <SsoRequiredNotice
            connection={ssoRequired.connection}
            href={ssoRequired.href}
            start={ssoRequired.start}
            loginHint={email || undefined}
            redirectTo={redirectTo}
          />
        ) : null}

        <Field
          label="Email"
          name="email"
          type="email"
          autoComplete="username"
          required
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          disabled={pending}
        />
        <Field
          label="Password"
          name="password"
          type="password"
          autoComplete="current-password"
          required
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          disabled={pending}
        />

        <div className="text-right text-sm">
          <TextLink href="/account/forgot">Forgot your password?</TextLink>
        </div>

        <SubmitButton pending={pending}>Sign in</SubmitButton>

        {unverified && email ? (
          <p className="text-center text-xs text-muted-foreground">
            Never confirmed your email?{' '}
            {resent ? (
              <span>Check your inbox — we have sent the link again.</span>
            ) : (
              <button type="button" onClick={resend} className="text-primary underline-offset-4 hover:underline">
                Resend the confirmation link
              </button>
            )}
          </p>
        ) : null}
      </form>

      <OauthButtons redirectTo={redirectTo} />
    </AccountShell>
  )
}

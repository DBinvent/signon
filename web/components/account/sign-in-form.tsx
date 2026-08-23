// Sign in.
//
// Generated file — the source of truth is
// ../../user_mgmt/web/components/account/sign-in-form.tsx. Edit it there and
// re-run `user_mgmt/web/sync.sh <this-app>`.

'use client'

import { useState } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import { account, AccountError } from '@/lib/account-client'
import { AccountShell, Field, Notice, SubmitButton, TextLink } from './ui'
import { OauthButtons } from './oauth-buttons'

export function SignInForm({ redirectTo = '/' }: { redirectTo?: string }) {
  const router = useRouter()
  const params = useSearchParams()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(
    // The OAuth callback cannot return a JSON body — it is a browser redirect —
    // so it signals failure with this marker instead.
    params.get('error') === 'oauth' ? 'That sign-in did not complete. Try again.' : null
  )
  const [unverified, setUnverified] = useState(false)
  const [resent, setResent] = useState(false)

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault()
    setPending(true)
    setError(null)
    setUnverified(false)
    try {
      await account.login(email, password)
      router.push(redirectTo)
    } catch (err) {
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

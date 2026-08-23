// Password reset, step one: ask for the link.
//
// Generated file — the source of truth is
// ../../user_mgmt/web/components/account/forgot-form.tsx. Edit it there and
// re-run `user_mgmt/web/sync.sh <this-app>`.

'use client'

import { useState } from 'react'
import { account, AccountError } from '@/lib/account-client'
import { AccountShell, Field, Notice, SubmitButton, TextLink } from './ui'

export function ForgotForm() {
  const [email, setEmail] = useState('')
  const [pending, setPending] = useState(false)
  const [sent, setSent] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault()
    setPending(true)
    setError(null)
    try {
      await account.requestReset(email)
      setSent(true)
    } catch (err) {
      // The endpoint answers 200 for any address, so the only thing that can
      // land here is a transport failure or the rate limit.
      setError(err instanceof AccountError ? err.message : 'Something went wrong.')
    } finally {
      setPending(false)
    }
  }

  if (sent) {
    return (
      <AccountShell
        title="Check your email"
        subtitle={
          <>
            If <strong>{email}</strong> has an account, a reset link is on its way. The link works
            once and expires in an hour.
          </>
        }
        footer={<TextLink href="/account/sign-in">Back to sign in</TextLink>}
      >
        <Notice kind="info">
          Nothing arriving? Check the spam folder, then try again in a few minutes.
        </Notice>
      </AccountShell>
    )
  }

  return (
    <AccountShell
      title="Reset your password"
      subtitle="Enter your email and we will send you a link."
      footer={<TextLink href="/account/sign-in">Back to sign in</TextLink>}
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
        <SubmitButton pending={pending}>Send reset link</SubmitButton>
      </form>
    </AccountShell>
  )
}

// Password reset, step two: choose the new password.
//
// Generated file — the source of truth is
// ../../user_mgmt/web/components/account/reset-form.tsx. Edit it there and
// re-run `user_mgmt/web/sync.sh <this-app>`.

'use client'

import { useState } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import { account, AccountError, passwordProblem, PASSWORD_MIN_LEN } from '@/lib/account-client'
import { AccountShell, Field, Notice, SubmitButton, TextLink } from './ui'

export function ResetForm() {
  const router = useRouter()
  const token = useSearchParams().get('token') ?? ''
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [done, setDone] = useState(false)

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    if (password !== confirm) {
      setError('Those two passwords do not match.')
      return
    }
    // The email is not known on this page — the token identifies the account
    // server side — so the "not your own address" rule can only be checked
    // there. Length is checked here to save a round trip.
    const problem = passwordProblem(password, '')
    if (problem) {
      setError(problem)
      return
    }

    setPending(true)
    try {
      await account.confirmReset(token, password)
      setDone(true)
    } catch (err) {
      setError(
        err instanceof AccountError && err.status === 401
          ? 'That reset link is no longer valid. Ask for a new one.'
          : err instanceof AccountError
            ? err.message
            : 'Something went wrong.'
      )
    } finally {
      setPending(false)
    }
  }

  if (!token) {
    return (
      <AccountShell
        title="Reset your password"
        footer={<TextLink href="/account/forgot">Ask for a new link</TextLink>}
      >
        <Notice kind="error">This page needs the link from your reset email.</Notice>
      </AccountShell>
    )
  }

  if (done) {
    return (
      <AccountShell
        title="Password changed"
        subtitle="Every other session has been signed out."
        footer={<TextLink href="/account/sign-in">Sign in</TextLink>}
      >
        <Notice kind="success">You can sign in with your new password now.</Notice>
        <div className="mt-4">
          <SubmitButton type="button" onClick={() => router.push('/account/sign-in')}>
            Go to sign in
          </SubmitButton>
        </div>
      </AccountShell>
    )
  }

  return (
    <AccountShell
      title="Choose a new password"
      subtitle="Signing in everywhere else will be required again afterwards."
      footer={<TextLink href="/account/sign-in">Back to sign in</TextLink>}
    >
      <form onSubmit={onSubmit} className="space-y-4">
        {error ? <Notice kind="error">{error}</Notice> : null}
        <Field
          label="New password"
          name="password"
          type="password"
          autoComplete="new-password"
          required
          minLength={PASSWORD_MIN_LEN}
          hint={`At least ${PASSWORD_MIN_LEN} characters.`}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          disabled={pending}
        />
        <Field
          label="Repeat new password"
          name="confirm"
          type="password"
          autoComplete="new-password"
          required
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          disabled={pending}
        />
        <SubmitButton pending={pending}>Set new password</SubmitButton>
      </form>
    </AccountShell>
  )
}

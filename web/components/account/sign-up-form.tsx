// Registration, step one of two.
//
// Generated file — the source of truth is
// ../../user_mgmt/web/components/account/sign-up-form.tsx. Edit it there and
// re-run `user_mgmt/web/sync.sh <this-app>`.
//
// The two-step shape (details, then confirm the address) is the one the 2021
// user-cabinet used; what is gone is its company/DBA/address block, which
// belongs to a product's own onboarding rather than to creating a login.

'use client'

import { useState } from 'react'
import { useRouter } from 'next/navigation'
import { account, AccountError, passwordProblem, PASSWORD_MIN_LEN } from '@/lib/account-client'
import { AccountShell, Field, Notice, Steps, SubmitButton, TextLink } from './ui'
import { OauthButtons } from './oauth-buttons'

export function SignUpForm() {
  const router = useRouter()
  const [displayName, setDisplayName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)

    // Checked here only to save a round trip; the server enforces the same
    // policy and is the one that decides.
    if (password !== confirm) {
      setError('Those two passwords do not match.')
      return
    }
    const problem = passwordProblem(password, email)
    if (problem) {
      setError(problem)
      return
    }

    setPending(true)
    try {
      await account.register(email, password, displayName)
      // Deliberately the same next step whether or not the address was already
      // registered — the server answers identically, and so must the UI, or
      // the page becomes the account-existence oracle the API refuses to be.
      router.push(`/account/verify?email=${encodeURIComponent(email)}`)
    } catch (err) {
      setError(err instanceof AccountError ? err.message : 'Something went wrong.')
    } finally {
      setPending(false)
    }
  }

  return (
    <AccountShell
      title="Create your account"
      subtitle="We will email you a link to confirm the address."
      footer={
        <>
          Already have an account? <TextLink href="/account/sign-in">Sign in</TextLink>
        </>
      }
    >
      <Steps current={1} labels={['Your details', 'Confirm email']} />

      <form onSubmit={onSubmit} className="space-y-4">
        {error ? <Notice kind="error">{error}</Notice> : null}

        <Field
          label="Name"
          name="name"
          autoComplete="name"
          placeholder="Optional"
          value={displayName}
          onChange={(e) => setDisplayName(e.target.value)}
          disabled={pending}
        />
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
          autoComplete="new-password"
          required
          minLength={PASSWORD_MIN_LEN}
          hint={`At least ${PASSWORD_MIN_LEN} characters. Length is what matters — no symbol requirements.`}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          disabled={pending}
        />
        <Field
          label="Repeat password"
          name="confirm"
          type="password"
          autoComplete="new-password"
          required
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          disabled={pending}
        />

        <SubmitButton pending={pending}>Create account</SubmitButton>
      </form>

      <OauthButtons redirectTo="/" />
    </AccountShell>
  )
}

// Registration, step one of two.
//
// Generated file — the source of truth is
// ../../signon/web/components/account/sign-up-form.tsx. Edit it there and
// re-run `signon/web/sync.sh <this-app>`.
//
// The two-step shape (details, then confirm the address) is the one an older
// account service used; what is gone is its company/DBA/address block, which
// belongs to a product's own onboarding rather than to creating a login.

'use client'

import { useState } from 'react'
import { useRouter } from 'next/navigation'
import {
  account,
  AccountError,
  passwordProblem,
  PASSWORD_MIN_LEN,
  RegisteredHereError,
  SsoRequiredError,
} from '@/lib/account-client'
import {
  AccountShell,
  Checkbox,
  Field,
  Notice,
  RegisteredHereNotice,
  Steps,
  SubmitButton,
  TextLink,
} from './ui'
import { OauthButtons } from './oauth-buttons'
import { SsoRequiredNotice } from './sso-sign-in'

export function SignUpForm() {
  const router = useRouter()
  const [displayName, setDisplayName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [ssoRequired, setSsoRequired] = useState<SsoRequiredError | null>(null)
  // Pre-ticked: the welcome and occasional news, off with one click later.
  const [emails, setEmails] = useState(true)
  const [registeredHere, setRegisteredHere] = useState<RegisteredHereError | null>(null)

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault()
    await submit(false)
  }

  async function submit(another: boolean) {
    setError(null)
    setSsoRequired(null)
    setRegisteredHere(null)

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
      await account.register(email, password, displayName, { emails, another })
      // Deliberately the same next step whether or not the address was already
      // registered — the server answers identically, and so must the UI, or
      // the page becomes the account-existence oracle the API refuses to be.
      router.push(`/account/verify?email=${encodeURIComponent(email)}`)
    } catch (err) {
      // An account at a domain that enforces SSO is created by signing in
      // through it. Decided from the domain alone, before any account lookup,
      // so this does not break the same-answer rule above.
      if (err instanceof SsoRequiredError) setSsoRequired(err)
      // About this browser, not this address — see RegisteredHereError.
      else if (err instanceof RegisteredHereError) setRegisteredHere(err)
      else setError(err instanceof AccountError ? err.message : 'Something went wrong.')
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
        {registeredHere ? (
          <RegisteredHereNotice
            hint={registeredHere.hint}
            pending={pending}
            onAnother={() => submit(true)}
          />
        ) : null}
        {ssoRequired ? (
          <SsoRequiredNotice
            connection={ssoRequired.connection}
            href={ssoRequired.href}
            start={ssoRequired.start}
            loginHint={email || undefined}
          />
        ) : null}

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
        <Checkbox
          name="emails"
          label="Email me a welcome and occasional product news"
          hint="Unsubscribe from any of them, or from your profile."
          checked={emails}
          onChange={(e) => setEmails(e.target.checked)}
          disabled={pending}
        />

        <SubmitButton pending={pending}>Create account</SubmitButton>
      </form>

      <OauthButtons redirectTo="/" />
    </AccountShell>
  )
}

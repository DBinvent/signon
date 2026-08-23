// Registration, step two: confirm the address.
//
// Generated file — the source of truth is
// ../../user_mgmt/web/components/account/verify-panel.tsx. Edit it there and
// re-run `user_mgmt/web/sync.sh <this-app>`.
//
// Two ways in, both landing on this one page:
//
// * the mailed link, carrying ?id=&token= — confirmed automatically on load;
// * ?email=, from having just registered — the six-digit code form, for when
//   the link is awkward to click (a phone, a copy-pasted address).
//
// Confirming proves control of the inbox, which is what a login asks for too,
// so the server signs the user in on success and this page can go straight
// into the app.

'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import { account, AccountError } from '@/lib/account-client'
import { AccountShell, Field, Notice, Steps, SubmitButton, TextLink } from './ui'

const RESEND_COOLDOWN_SECONDS = 60

export function VerifyPanel({ redirectTo = '/' }: { redirectTo?: string }) {
  const router = useRouter()
  const params = useSearchParams()
  const id = params.get('id')
  const token = params.get('token')

  // Seeded from the query when arriving straight from sign-up, editable when
  // arriving cold (a link opened in a different browser, say).
  const [email, setEmail] = useState(params.get('email') ?? '')
  const [code, setCode] = useState('')
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [done, setDone] = useState(false)
  const [cooldown, setCooldown] = useState(0)
  // React 18 StrictMode mounts effects twice in development; without this the
  // link would be spent on the first pass and rejected on the second, which
  // looks exactly like a broken link.
  const consumed = useRef(false)

  const finish = useCallback(() => {
    setDone(true)
    // A beat so the confirmation is actually readable before the redirect.
    setTimeout(() => router.push(redirectTo), 1200)
  }, [router, redirectTo])

  useEffect(() => {
    if (!id || !token || consumed.current) return
    consumed.current = true
    setPending(true)
    account
      .verify(id, token)
      .then(finish)
      .catch((err) =>
        setError(
          err instanceof AccountError && err.status === 401
            ? 'That confirmation link is no longer valid. Ask for a new one below.'
            : 'Something went wrong. Try again.'
        )
      )
      .finally(() => setPending(false))
  }, [id, token, finish])

  useEffect(() => {
    if (cooldown <= 0) return
    const timer = setTimeout(() => setCooldown((c) => c - 1), 1000)
    return () => clearTimeout(timer)
  }, [cooldown])

  async function submitCode(e: React.FormEvent) {
    e.preventDefault()
    setPending(true)
    setError(null)
    try {
      await account.verifyCode(email, code.trim())
      finish()
    } catch {
      // The server will not distinguish "wrong code" from "no such account";
      // neither does this message.
      setError('That code did not work. Check it, or ask for a new one.')
    } finally {
      setPending(false)
    }
  }

  async function resend() {
    setError(null)
    try {
      await account.resendVerify(email)
      setCooldown(RESEND_COOLDOWN_SECONDS)
    } catch (err) {
      // Do not start the cooldown on a failed attempt — nothing was sent, so
      // nothing should block the user from immediately trying again.
      setError(err instanceof AccountError ? err.message : 'Something went wrong. Try again.')
    }
  }

  if (done) {
    return (
      <AccountShell title="Email confirmed" subtitle="Taking you to your dashboard…">
        <Notice kind="success">Your account is active and you are signed in.</Notice>
      </AccountShell>
    )
  }

  return (
    <AccountShell
      title="Confirm your email"
      subtitle={
        email ? (
          <>
            We sent a link and a six-digit code to <strong>{email}</strong>.
          </>
        ) : (
          'Open the link we emailed you, or enter the code from that message.'
        )
      }
      footer={<TextLink href="/account/sign-in">Back to sign in</TextLink>}
    >
      <Steps current={2} labels={['Your details', 'Confirm email']} />

      {error ? (
        <div className="mb-4">
          <Notice kind="error">{error}</Notice>
        </div>
      ) : null}

      {id && token && pending ? (
        <Notice kind="info">Confirming your email…</Notice>
      ) : (
        <form onSubmit={submitCode} className="space-y-4">
          {!params.get('email') ? (
            <Field
              label="Email"
              name="email"
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              disabled={pending}
            />
          ) : null}
          <Field
            label="Confirmation code"
            name="code"
            inputMode="numeric"
            autoComplete="one-time-code"
            pattern="[0-9]*"
            maxLength={6}
            placeholder="123456"
            required
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
            disabled={pending}
          />
          <SubmitButton pending={pending} disabled={code.length !== 6}>
            Confirm
          </SubmitButton>
        </form>
      )}

      <p className="mt-4 text-center text-xs text-muted-foreground">
        {cooldown > 0 ? (
          <>Sent. You can ask again in {cooldown}s.</>
        ) : (
          <button
            type="button"
            onClick={resend}
            disabled={!email}
            className="text-primary underline-offset-4 hover:underline disabled:opacity-60 disabled:no-underline"
          >
            Send it again
          </button>
        )}
      </p>
    </AccountShell>
  )
}

// Finishing a sign-in through a provider that does not vouch for the email:
// Amazon and Facebook.
//
// Generated file — the source of truth is
// ../../signon/web/components/account/oauth-confirm-panel.tsx. Edit it
// there and re-run `signon/web/sync.sh <this-app>`.
//
// Those providers prove who someone is to them, not that the address they
// report is that person's. Linking on their word would let anyone who puts
// your address on their own Amazon account sign in as you, so the callback
// parks the identity behind ?token= and lands here instead of starting a
// session. A six-digit code mailed to the address proves the inbox; only then
// does the server link the identity (or create the account) and sign the user
// in. Facebook can report no address at all — the "needs_email" branch. A site
// that asks before creating an account answers "no_profile" instead, and the
// page ends on the same "Create one?" prompt as /account/sso/finish.

'use client'

import { useEffect, useState } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import {
  account,
  AccountError,
  SsoRequiredError,
  type NoProfile,
  type PendingSignIn,
} from '@/lib/account-client'
import { AccountShell, Field, Notice, SubmitButton, TextLink } from './ui'
import { SsoRequiredNotice } from './sso-sign-in'
import { NoProfilePanel } from './sso-finish-panel'

const RESEND_COOLDOWN_SECONDS = 60
/**
 * The server's max_verify_attempts. Past it every code is refused until a new
 * one is sent, which resets the count — but the 401 reads the same as a plain
 * wrong code, so the page keeps its own tally to tell the user which.
 */
const MAX_CODE_ATTEMPTS = 5

type Stage = 'loading' | 'email' | 'code' | 'done' | 'offer' | 'expired' | 'broken'

export function OauthConfirmPanel() {
  const router = useRouter()
  const token = useSearchParams().get('token') ?? ''
  const [stage, setStage] = useState<Stage>('loading')
  const [info, setInfo] = useState<PendingSignIn | null>(null)
  const [email, setEmail] = useState('')
  const [code, setCode] = useState('')
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [ssoRequired, setSsoRequired] = useState<SsoRequiredError | null>(null)
  const [offer, setOffer] = useState<NoProfile | null>(null)
  const [misses, setMisses] = useState(0)
  const [cooldown, setCooldown] = useState(0)

  useEffect(() => {
    if (!token) return
    let cancelled = false
    account
      .pendingSignIn(token)
      .then((p) => {
        if (cancelled) return
        setInfo(p)
        setStage(p.needs_email ? 'email' : 'code')
        // The callback mailed the code moments before redirecting here;
        // asking again straight away would only hit the server's cooldown.
        if (p.code_sent) setCooldown(RESEND_COOLDOWN_SECONDS)
      })
      .catch((err) => {
        if (cancelled) return
        setStage(err instanceof AccountError && err.status === 401 ? 'expired' : 'broken')
      })
    return () => {
      cancelled = true
    }
  }, [token])

  useEffect(() => {
    if (cooldown <= 0) return
    const timer = setTimeout(() => setCooldown((c) => c - 1), 1000)
    return () => clearTimeout(timer)
  }, [cooldown])

  /** What any call here can answer: SSO enforced, a dead token, or a message. */
  function fail(err: unknown) {
    if (err instanceof SsoRequiredError) setSsoRequired(err)
    else if (err instanceof AccountError && err.status === 401) setStage('expired')
    else setError(err instanceof AccountError ? err.message : 'Something went wrong. Try again.')
  }

  /** A fresh code went out: the old one, and its misses, no longer count. */
  function codeSent(to?: string) {
    setInfo((p) => (p ? { ...p, email: to ?? p.email, needs_email: false, code_sent: true } : p))
    setCode('')
    setMisses(0)
    setCooldown(RESEND_COOLDOWN_SECONDS)
  }

  async function submitEmail(e: React.FormEvent) {
    e.preventDefault()
    setPending(true)
    setError(null)
    setSsoRequired(null)
    try {
      await account.pendingEmail(token, email)
      codeSent(email.trim())
      setStage('code')
    } catch (err) {
      if (err instanceof AccountError && err.status === 400) setError('Enter a valid email address.')
      else fail(err)
    } finally {
      setPending(false)
    }
  }

  async function submitCode(e: React.FormEvent) {
    e.preventDefault()
    setPending(true)
    setError(null)
    setSsoRequired(null)
    try {
      const result = await account.pendingConfirm(token, code.trim())
      if (result.status === 'no_profile') {
        // The address is proven, but this site asks before creating a profile.
        setOffer(result)
        setStage('offer')
        return
      }
      setStage('done')
      // A full load rather than router.push: the session cookie has just been
      // set, and the destination should read the signed-in user fresh.
      window.location.assign(result.redirect_to || '/')
    } catch (err) {
      if (err instanceof AccountError && err.status === 401) {
        // A wrong code and a dead link answer alike; ask which this was.
        const alive = await account.pendingSignIn(token).then(
          () => true,
          (probe) => !(probe instanceof AccountError && probe.status === 401)
        )
        if (!alive) {
          setStage('expired')
          return
        }
        const next = misses + 1
        setMisses(next)
        setError(
          next >= MAX_CODE_ATTEMPTS
            ? 'That code has been tried too many times. Send a new one, or start the sign-in again.'
            : 'That code did not work. Check it, or ask for a new one.'
        )
      } else {
        fail(err)
      }
    } finally {
      setPending(false)
    }
  }

  async function resend() {
    setPending(true)
    setError(null)
    setSsoRequired(null)
    try {
      await account.pendingResend(token)
      codeSent()
    } catch (err) {
      // No cooldown on a failed attempt — nothing was sent, so nothing should
      // stop the user trying again straight away.
      fail(err)
    } finally {
      setPending(false)
    }
  }

  function changeAddress() {
    setError(null)
    setSsoRequired(null)
    setEmail('')
    setStage('email')
  }

  if (!token) {
    return (
      <AccountShell
        title="Finish signing in"
        footer={<TextLink href="/account/sign-in">Back to sign in</TextLink>}
      >
        <Notice kind="error">This page is only reached from a sign-in. Start again from the sign-in page.</Notice>
      </AccountShell>
    )
  }

  if (stage === 'expired') {
    return (
      <AccountShell title="Sign-in link expired">
        <Notice kind="error">This sign-in link has expired. Start again from the sign-in page.</Notice>
        <div className="mt-4">
          <SubmitButton type="button" onClick={() => router.push('/account/sign-in')}>
            Start again
          </SubmitButton>
        </div>
      </AccountShell>
    )
  }

  if (stage === 'loading' || stage === 'broken') {
    return (
      <AccountShell
        title="Finish signing in"
        footer={<TextLink href="/account/sign-in">Back to sign in</TextLink>}
      >
        {stage === 'loading' ? (
          <Notice kind="info">Loading…</Notice>
        ) : (
          <Notice kind="error">Something went wrong. Reload the page to try again.</Notice>
        )}
      </AccountShell>
    )
  }

  if (stage === 'offer' && offer) return <NoProfilePanel offer={offer} />

  if (stage === 'done') {
    return (
      <AccountShell title="Signed in" subtitle="Taking you on…">
        <Notice kind="success">Your email is confirmed and you are signed in.</Notice>
      </AccountShell>
    )
  }

  // 'email' and 'code' are only reached once `info` has loaded.
  const provider = info?.provider_name ?? 'That provider'
  const address = info?.email ?? null
  const spent = misses >= MAX_CODE_ATTEMPTS

  return (
    <AccountShell
      title="Confirm your email"
      subtitle={
        stage === 'email' ? (
          address ? (
            'Enter the address to use instead, and we will send it a code.'
          ) : (
            `${provider} did not share an email address. Enter the one to use for your account, and we will send it a code.`
          )
        ) : info?.code_sent ? (
          <>
            We sent a six-digit code to <strong>{address}</strong>. Enter it to finish signing in with{' '}
            {provider}.
          </>
        ) : (
          <>
            To finish signing in with {provider}, we need to send a code to <strong>{address}</strong>.
          </>
        )
      }
      footer={<TextLink href="/account/sign-in">Back to sign in</TextLink>}
    >
      <p className="mb-4 text-xs text-muted-foreground">
        {provider} does not confirm email addresses for us, so we check the address is yours before
        signing you in.
      </p>

      {error || ssoRequired ? (
        <div className="mb-4 space-y-4">
          {error ? <Notice kind="error">{error}</Notice> : null}
          {ssoRequired ? (
            <SsoRequiredNotice
              connection={ssoRequired.connection}
              href={ssoRequired.href}
              start={ssoRequired.start}
              loginHint={(stage === 'email' ? email : address) || undefined}
            />
          ) : null}
        </div>
      ) : null}

      {stage === 'email' ? (
        <form onSubmit={submitEmail} className="space-y-4">
          <Field
            label="Email"
            name="email"
            type="email"
            autoComplete="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            disabled={pending}
          />
          <SubmitButton pending={pending}>Send the code</SubmitButton>
          {address ? (
            <p className="text-center text-xs text-muted-foreground">
              <button
                type="button"
                onClick={() => {
                  setError(null)
                  setSsoRequired(null)
                  setStage('code')
                }}
                className="text-primary underline-offset-4 hover:underline"
              >
                Keep {address}
              </button>
            </p>
          ) : null}
        </form>
      ) : info?.code_sent ? (
        <form onSubmit={submitCode} className="space-y-4">
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
            disabled={pending || spent}
          />
          <SubmitButton pending={pending} disabled={code.length !== 6 || spent}>
            Confirm and sign in
          </SubmitButton>
        </form>
      ) : (
        // The callback could not mail it (rate limit, or mail briefly down).
        <SubmitButton type="button" pending={pending} onClick={resend}>
          Send the code
        </SubmitButton>
      )}

      {stage === 'code' ? (
        <p className="mt-4 text-center text-xs text-muted-foreground">
          {info?.code_sent ? (
            <>
              {cooldown > 0 ? (
                <>Sent. You can ask again in {cooldown}s.</>
              ) : (
                <button
                  type="button"
                  onClick={resend}
                  disabled={pending}
                  className="text-primary underline-offset-4 hover:underline disabled:opacity-60 disabled:no-underline"
                >
                  Send it again
                </button>
              )}
              {' · '}
            </>
          ) : null}
          <button
            type="button"
            onClick={changeAddress}
            className="text-primary underline-offset-4 hover:underline"
          >
            Use a different address
          </button>
        </p>
      ) : null}
    </AccountShell>
  )
}

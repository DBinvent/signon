// Where a sign-in through the SSO service comes back to, and the "Create
// one?" prompt for someone it proved but this site has no profile for.
//
// Generated file — the source of truth is
// ../../signon/web/components/account/sso-finish-panel.tsx. Edit it there
// and re-run `signon/web/sync.sh <this-app>`.
//
// The SSO service does the provider or IdP round trip, then sends the browser
// here with a one-time ?ticket=. Redeeming it is this site's backend's job —
// it checks the ticket was minted for this site and this browser — and the
// answer is signed in, or no profile yet. The latter never creates an account
// by itself: nobody gets a profile they did not ask for, and someone who
// signed in to the wrong service by mistake sees it here. A profile made from
// a sign-in with no address the provider vouches for (Amazon, Facebook, Microsoft, a
// private GitHub email, an IdP that sends none) has no email at all.
//
// One more answer, a 409: the address typed on a customer connection's button
// already has an account. A typed address is never a way into an account that
// exists, so the person signs in to it some other way.

'use client'

import { useEffect, useRef, useState } from 'react'
import Link from 'next/link'
import { useSearchParams } from 'next/navigation'
import {
  account,
  AccountError,
  RegisteredHereError,
  SsoRequiredError,
  type NoProfile,
} from '@/lib/account-client'
import { AccountShell, Checkbox, Notice, RegisteredHereNotice, SubmitButton, TextLink } from './ui'
import { SsoRequiredNotice } from './sso-sign-in'

type Stage = 'loading' | 'done' | 'offer' | 'sso' | 'taken' | 'expired'

export function SsoFinishPanel() {
  const ticket = useSearchParams().get('ticket') ?? ''
  const [stage, setStage] = useState<Stage>(ticket ? 'loading' : 'expired')
  const [offer, setOffer] = useState<NoProfile | null>(null)
  const [ssoRequired, setSsoRequired] = useState<SsoRequiredError | null>(null)
  // A ticket is single use. React 18 StrictMode mounts effects twice in
  // development; without this the second pass would be refused and the page
  // would read as an expired link. No cancelled flag either, for the same
  // reason: the first pass is the one whose answer counts.
  const redeemed = useRef(false)

  useEffect(() => {
    if (!ticket || redeemed.current) return
    redeemed.current = true
    account
      .ssoFinish(ticket)
      .then((result) => {
        switch (result.status) {
          case 'ok':
            setStage('done')
            // A full load rather than router.push: the session cookie has just
            // been set, and the destination should read the signed-in user fresh.
            window.location.assign(result.redirect_to || '/')
            break
          case 'no_profile':
            setOffer(result)
            setStage('offer')
            break
          default:
            setStage('expired')
        }
      })
      .catch((err) => {
        // Not a broken link but a different way in, decided from the domain.
        if (err instanceof SsoRequiredError) {
          setSsoRequired(err)
          setStage('sso')
        } else if (err instanceof AccountError && err.status === 409) {
          setStage('taken')
        } else {
          // A spent, expired or foreign ticket all answer 401 alike, and none
          // of them can be retried — so every failure reads the same.
          setStage('expired')
        }
      })
  }, [ticket])

  if (stage === 'offer' && offer) return <NoProfilePanel offer={offer} />

  if (stage === 'sso' && ssoRequired) {
    return (
      <AccountShell
        title="Single sign-on required"
        footer={<TextLink href="/account/sign-in">Back to sign in</TextLink>}
      >
        <SsoRequiredNotice
          connection={ssoRequired.connection}
          href={ssoRequired.href}
          start={ssoRequired.start}
        />
      </AccountShell>
    )
  }

  if (stage === 'taken') return <TakenPanel />

  if (stage === 'expired') return <ExpiredPanel />

  if (stage === 'done') {
    return (
      <AccountShell title="Signed in" subtitle="Taking you on…">
        <Notice kind="success">You are signed in.</Notice>
      </AccountShell>
    )
  }

  return (
    <AccountShell title="Finishing sign-in">
      <Notice kind="info">Signing you in…</Notice>
    </AccountShell>
  )
}

/**
 * "Logged in successfully as … using …. No profile exists yet. Create one?"
 * Shared with the emailed-code step, which can end the same way. Cancel
 * creates nothing: the token simply lapses.
 */
export function NoProfilePanel({ offer }: { offer: NoProfile }) {
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [ssoRequired, setSsoRequired] = useState<SsoRequiredError | null>(null)
  const [expired, setExpired] = useState(false)
  const [taken, setTaken] = useState(false)
  const [done, setDone] = useState(false)
  const [emails, setEmails] = useState(true)
  const [registeredHere, setRegisteredHere] = useState<RegisteredHereError | null>(null)

  async function create(another = false) {
    setPending(true)
    setError(null)
    setSsoRequired(null)
    setRegisteredHere(null)
    try {
      const { redirect_to } = await account.createProfile(offer.token, { emails, another })
      setDone(true)
      window.location.assign(redirect_to || '/')
    } catch (err) {
      if (err instanceof SsoRequiredError) setSsoRequired(err)
      // Also a 409, so before the "address taken" one below; the token is not
      // spent by it, so "create another" retries with the same one.
      else if (err instanceof RegisteredHereError) setRegisteredHere(err)
      else if (err instanceof AccountError && err.status === 401) setExpired(true)
      else if (err instanceof AccountError && err.status === 409) setTaken(true)
      else setError(err instanceof AccountError ? err.message : 'Something went wrong. Try again.')
    } finally {
      setPending(false)
    }
  }

  if (expired) return <ExpiredPanel message="This sign-in has expired. Start again from the sign-in page." />

  if (taken) return <TakenPanel />

  if (done) {
    return (
      <AccountShell title="Profile created" subtitle="Taking you on…">
        <Notice kind="success">Your profile is ready and you are signed in.</Notice>
      </AccountShell>
    )
  }

  const via = offer.provider_name || offer.connection_name || 'single sign-on'
  // Who signed in, as best this site knows: the address the profile will
  // have, else the name the provider gave, else nothing at all.
  const who = offer.email ? (
    <>
      {' '}as <strong>{offer.email}</strong>
      {offer.name ? <> ({offer.name})</> : null}
    </>
  ) : offer.name ? (
    <>
      {' '}as <strong>{offer.name}</strong>
    </>
  ) : null

  return (
    <AccountShell title="Create your profile?">
      <p className="text-sm">
        Logged in successfully{who} using {via}. No profile exists yet. Create one?
      </p>
      {offer.email ? null : (
        <p className="mt-2 text-sm text-muted-foreground">
          The profile will have no email address — {via} did not share one this site can rely on.
          You will sign in to it with {via}.
        </p>
      )}

      {offer.email ? (
        <div className="mt-4">
          <Checkbox
            name="emails"
            label="Email me a welcome and occasional product news"
            hint="Unsubscribe from any of them, or from your profile."
            checked={emails}
            onChange={(e) => setEmails(e.target.checked)}
            disabled={pending}
          />
        </div>
      ) : null}

      {error || ssoRequired || registeredHere ? (
        <div className="mt-4 space-y-4">
          {error ? <Notice kind="error">{error}</Notice> : null}
          {registeredHere ? (
            <RegisteredHereNotice
              hint={registeredHere.hint}
              pending={pending}
              onAnother={() => create(true)}
            />
          ) : null}
          {ssoRequired ? (
            <SsoRequiredNotice
              connection={ssoRequired.connection}
              href={ssoRequired.href}
              start={ssoRequired.start}
              loginHint={offer.email ?? undefined}
            />
          ) : null}
        </div>
      ) : null}

      <div className="mt-6 space-y-2">
        {/* Retrying would only be refused again; the notice above is the way in. */}
        {ssoRequired ? null : (
          <SubmitButton type="button" pending={pending} onClick={() => create()}>
            Create profile
          </SubmitButton>
        )}
        <Link
          href="/account/sign-in"
          aria-disabled={pending}
          className={`block w-full rounded-md border border-border px-4 py-2 text-center text-sm font-medium
                      transition hover:bg-accent hover:text-accent-foreground ${
                        pending ? 'pointer-events-none opacity-60' : ''
                      }`}
        >
          Cancel
        </Link>
      </div>
    </AccountShell>
  )
}

/** The 409 — its only meaning: a typed address that already has an account here. */
function TakenPanel() {
  return (
    <AccountShell title="This address already has an account">
      <Notice kind="error">An account with this address already exists — sign in to it another way.</Notice>
      <Link
        href="/account/sign-in"
        className="mt-4 block w-full rounded-md bg-primary px-4 py-2 text-center text-sm font-medium
                   text-primary-foreground transition hover:opacity-90"
      >
        Go to sign in
      </Link>
    </AccountShell>
  )
}

function ExpiredPanel({
  message = 'This sign-in link has expired or was already used.',
}: {
  message?: string
}) {
  return (
    <AccountShell title="Sign-in link expired">
      <Notice kind="error">{message}</Notice>
      <Link
        href="/account/sign-in"
        className="mt-4 block w-full rounded-md bg-primary px-4 py-2 text-center text-sm font-medium
                   text-primary-foreground transition hover:opacity-90"
      >
        Start again
      </Link>
    </AccountShell>
  )
}

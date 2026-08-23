// The one piece of account UI that belongs on a site's own landing page:
// "sign in / create account" when signed out, "you are signed in" when not.
//
// Generated file — the source of truth is
// ../../user_mgmt/web/components/account/account-cta.tsx. Edit it there and
// re-run `user_mgmt/web/sync.sh <this-app>`.

'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { account, type Account } from '@/lib/account-client'

export function AccountCta() {
  // `undefined` is "still asking", distinct from `null` for "signed out" —
  // without the distinction the page flashes the signed-out buttons on every
  // load for a user who is in fact signed in.
  const [me, setMe] = useState<Account | null | undefined>(undefined)

  useEffect(() => {
    let cancelled = false
    account
      .me()
      .then((who) => {
        if (!cancelled) setMe(who)
      })
      .catch(() => {
        if (!cancelled) setMe(null)
      })
    return () => {
      cancelled = true
    }
  }, [])

  if (me === undefined) {
    return <div className="h-10" aria-hidden />
  }

  if (me) {
    return (
      <div className="flex flex-col items-center gap-2">
        <p className="text-sm text-muted-foreground">
          Signed in as <span className="text-foreground">{me.display_name ?? me.email}</span>
        </p>
        <Link
          href="/account/profile"
          className="rounded-md border border-border px-4 py-2 text-sm font-medium transition
                     hover:bg-accent hover:text-accent-foreground"
        >
          Your account
        </Link>
      </div>
    )
  }

  return (
    <div className="flex flex-wrap items-center justify-center gap-3">
      <Link
        href="/account/sign-up"
        className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground
                   transition hover:opacity-90"
      >
        Create an account
      </Link>
      <Link
        href="/account/sign-in"
        className="rounded-md border border-border px-4 py-2 text-sm font-medium transition
                   hover:bg-accent hover:text-accent-foreground"
      >
        Sign in
      </Link>
    </div>
  )
}

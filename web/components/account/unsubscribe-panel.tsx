// Where the unsubscribe link in mail to an account lands.
//
// Generated file — the source of truth is
// ../../signon/web/components/account/unsubscribe-panel.tsx. Edit it there
// and re-run `signon/web/sync.sh <this-app>`.
//
// Acts on load, like the mailing list's page (components/news/token-panel.tsx):
// the click in the mail was the request. An undo is right there, because a
// link scanner or a stray click can land here too, and the same link turns the
// mail back on.

'use client'

import { useEffect, useRef, useState } from 'react'
import { useSearchParams } from 'next/navigation'
import { account } from '@/lib/account-client'
import { AccountShell, Notice, TextLink } from './ui'

type State = 'working' | 'off' | 'on' | 'failed'

export function UnsubscribePanel() {
  const token = useSearchParams().get('token') ?? ''
  const [state, setState] = useState<State>('working')
  const [pending, setPending] = useState(false)
  // StrictMode double-mounts effects in development; one call is enough.
  const started = useRef(false)

  useEffect(() => {
    if (!token || started.current) return
    started.current = true
    account
      .unsubscribe(token)
      .then(() => setState('off'))
      .catch(() => setState('failed'))
  }, [token])

  async function set(enabled: boolean) {
    setPending(true)
    try {
      await account.unsubscribe(token, enabled)
      setState(enabled ? 'on' : 'off')
    } catch {
      setState('failed')
    } finally {
      setPending(false)
    }
  }

  const footer = <TextLink href="/account/profile">Email settings in your profile</TextLink>

  if (!token) {
    return (
      <AccountShell title="Unsubscribe" footer={footer}>
        <Notice kind="error">This page needs the link from the email we sent you.</Notice>
      </AccountShell>
    )
  }

  return (
    <AccountShell title="Unsubscribe" footer={footer}>
      {state === 'working' ? <Notice kind="info">Turning these emails off…</Notice> : null}
      {state === 'off' ? (
        <div className="space-y-3">
          <Notice kind="success">
            Done — no more welcome or news emails. Account emails (address confirmations, password
            resets) still arrive.
          </Notice>
          <button
            type="button"
            onClick={() => set(true)}
            disabled={pending}
            className="text-sm text-muted-foreground underline-offset-4 hover:underline disabled:opacity-60"
          >
            Undo — keep sending them
          </button>
        </div>
      ) : null}
      {state === 'on' ? (
        <div className="space-y-3">
          <Notice kind="success">You are subscribed again.</Notice>
          <button
            type="button"
            onClick={() => set(false)}
            disabled={pending}
            className="text-sm text-muted-foreground underline-offset-4 hover:underline disabled:opacity-60"
          >
            Unsubscribe after all
          </button>
        </div>
      ) : null}
      {state === 'failed' ? (
        <Notice kind="error">
          That unsubscribe link is not valid. Sign in and turn emails off in your profile instead.
        </Notice>
      ) : null}
    </AccountShell>
  )
}

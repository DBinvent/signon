// The two pages a mailing-list link lands on: confirm and unsubscribe.
//
// Generated file — the source of truth is
// ../../signon/web/components/news/token-panel.tsx. Edit it there and
// re-run `signon/web/sync.sh <this-app>`.
//
// One component for both because they differ only in which call they make and
// what they say afterwards. Both act on load — a link from an email should do
// the thing, not present a button that repeats the request the person already
// made by clicking.

'use client'

import { useEffect, useRef, useState } from 'react'
import { useSearchParams } from 'next/navigation'
import { news } from '@/lib/news-client'
import { AccountShell, Notice, TextLink } from '@/components/account/ui'

type Mode = 'confirm' | 'unsubscribe'

const COPY: Record<Mode, { title: string; working: string; done: string; failed: string }> = {
  confirm: {
    title: 'Confirm your subscription',
    working: 'Confirming…',
    done: 'You are subscribed. We will send updates and news to this address.',
    // Deliberately actionable: the usual cause is a link that was already
    // used, and telling someone to "try again" on a spent token is useless.
    failed:
      'That confirmation link is no longer valid — it may already have been used. Subscribe again to get a fresh one.',
  },
  unsubscribe: {
    title: 'Unsubscribe',
    working: 'Removing your address…',
    done: 'Done — this address will not receive any more updates.',
    failed: 'That unsubscribe link is not valid. If you keep getting mail, reply to it and we will remove you by hand.',
  },
}

export function TokenPanel({ mode }: { mode: Mode }) {
  const token = useSearchParams().get('token') ?? ''
  const [state, setState] = useState<'working' | 'done' | 'failed'>('working')
  // StrictMode double-mounts effects in development. The confirm token is
  // single use, so without this the second pass reports failure on a link
  // that in fact just worked.
  const started = useRef(false)
  const copy = COPY[mode]

  useEffect(() => {
    if (!token || started.current) return
    started.current = true
    const call = mode === 'confirm' ? news.confirm(token) : news.unsubscribe(token)
    call.then(() => setState('done')).catch(() => setState('failed'))
  }, [token, mode])

  if (!token) {
    return (
      <AccountShell title={copy.title} footer={<TextLink href="/">Back to the site</TextLink>}>
        <Notice kind="error">This page needs the link from the email we sent you.</Notice>
      </AccountShell>
    )
  }

  return (
    <AccountShell title={copy.title} footer={<TextLink href="/">Back to the site</TextLink>}>
      {state === 'working' ? (
        <Notice kind="info">{copy.working}</Notice>
      ) : state === 'done' ? (
        <Notice kind="success">{copy.done}</Notice>
      ) : (
        <Notice kind="error">{copy.failed}</Notice>
      )}
    </AccountShell>
  )
}

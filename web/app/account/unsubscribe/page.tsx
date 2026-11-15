// Generated file — the source of truth is
// ../../../../signon/web/app/account/unsubscribe/page.tsx. Edit it there and
// re-run `signon/web/sync.sh <this-app>`.
//
// The unsubscribe link in mail to an account (the welcome, news) — not the
// mailing list's, which is /news/unsubscribe. A Suspense boundary is required:
// the panel reads ?token= with useSearchParams under `output: 'export'`.

import { Suspense } from 'react'
import type { Metadata } from 'next'
import { UnsubscribePanel } from '@/components/account/unsubscribe-panel'

export const metadata: Metadata = { title: 'Unsubscribe' }

export default function Page() {
  return (
    <Suspense fallback={<p className="p-6 text-sm text-muted-foreground">Loading…</p>}>
      <UnsubscribePanel />
    </Suspense>
  )
}

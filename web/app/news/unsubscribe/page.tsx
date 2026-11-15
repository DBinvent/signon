// Generated file — the source of truth is
// ../../../../signon/web/app/news/unsubscribe/page.tsx. Edit it there and
// re-run `signon/web/sync.sh <this-app>`.
//
// A Suspense boundary is not optional: TokenPanel reads the query string with
// useSearchParams, and `output: 'export'` refuses to prerender a page that
// does so outside one.

import { Suspense } from 'react'
import type { Metadata } from 'next'
import { TokenPanel } from '@/components/news/token-panel'

export const metadata: Metadata = { title: 'Unsubscribe' }

export default function Page() {
  return (
    <Suspense fallback={<p className="p-6 text-sm text-muted-foreground">Loading…</p>}>
      <TokenPanel mode="unsubscribe" />
    </Suspense>
  )
}

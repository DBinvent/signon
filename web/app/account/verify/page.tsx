// Generated file — the source of truth is
// ../../../../signon/web/app/account/verify/page.tsx. Edit it there and
// re-run `signon/web/sync.sh <this-app>`.
//
// A Suspense boundary is not optional here: these screens read the query
// string with useSearchParams, and `output: 'export'` refuses to prerender a
// page that does so outside one.

import { Suspense } from 'react'
import type { Metadata } from 'next'
import { VerifyPanel } from '@/components/account/verify-panel'

export const metadata: Metadata = { title: 'Confirm your email' }

export default function Page() {
  return (
    <Suspense fallback={<p className="p-6 text-sm text-muted-foreground">Loading…</p>}>
      <VerifyPanel />
    </Suspense>
  )
}

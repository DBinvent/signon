// Generated file — the source of truth is
// ../../../../../signon/web/app/account/sso/test/page.tsx. Edit it there
// and re-run `signon/web/sync.sh <this-app>`.
//
// A Suspense boundary is not optional here: these screens read the query
// string with useSearchParams, and `output: 'export'` refuses to prerender a
// page that does so outside one.

import { Suspense } from 'react'
import type { Metadata } from 'next'
import { SsoTestPanel } from '@/components/account/sso-test-panel'

export const metadata: Metadata = { title: 'SSO connection test' }

export default function Page() {
  return (
    <Suspense fallback={<p className="p-6 text-sm text-muted-foreground">Loading…</p>}>
      <SsoTestPanel />
    </Suspense>
  )
}

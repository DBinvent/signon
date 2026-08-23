// Generated file — the source of truth is
// ../../../../user_mgmt/web/app/account/forgot/page.tsx. Edit it there and
// re-run `user_mgmt/web/sync.sh <this-app>`.
//
// A Suspense boundary is not optional here: these screens read the query
// string with useSearchParams, and `output: 'export'` refuses to prerender a
// page that does so outside one.

import { Suspense } from 'react'
import type { Metadata } from 'next'
import { ForgotForm } from '@/components/account/forgot-form'

export const metadata: Metadata = { title: 'Reset your password' }

export default function Page() {
  return (
    <Suspense fallback={<p className="p-6 text-sm text-muted-foreground">Loading…</p>}>
      <ForgotForm />
    </Suspense>
  )
}

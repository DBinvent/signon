// SSO buttons.
//
// Generated file — the source of truth is
// ../../user_mgmt/web/components/account/oauth-buttons.tsx. Edit it there and
// re-run `user_mgmt/web/sync.sh <this-app>`.
//
// Renders nothing at all when the deployment has no provider credentials
// configured: GET /account/oauth answers with an empty list, so a site that
// does not want SSO gets no dead buttons and no separator.

'use client'

import { useEffect, useState } from 'react'
import { account, type Provider } from '@/lib/account-client'

export function OauthButtons({ redirectTo = '/' }: { redirectTo?: string }) {
  const [providers, setProviders] = useState<Provider[]>([])

  useEffect(() => {
    let cancelled = false
    account
      .providers()
      .then((r) => {
        if (!cancelled) setProviders(r.providers)
      })
      // A failure here is not worth an error banner on a sign-in form — the
      // email and password path still works.
      .catch(() => {})
    return () => {
      cancelled = true
    }
  }, [])

  if (providers.length === 0) return null

  return (
    <div className="mt-6">
      <div className="flex items-center gap-3">
        <span className="h-px flex-1 bg-border" />
        <span className="text-xs uppercase tracking-wide text-muted-foreground">or</span>
        <span className="h-px flex-1 bg-border" />
      </div>
      <div className="mt-4 space-y-2">
        {providers.map((provider) => (
          <button
            key={provider.key}
            type="button"
            onClick={() => account.startOauth(provider, redirectTo)}
            className="w-full rounded-md border border-border bg-background px-4 py-2 text-sm font-medium
                       transition hover:bg-accent hover:text-accent-foreground"
          >
            Continue with {provider.name}
          </button>
        ))}
      </div>
    </div>
  )
}

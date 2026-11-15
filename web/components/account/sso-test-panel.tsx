// The last page of a "Test connection" run from the dashboard's SSO settings.
//
// Generated file — the source of truth is
// ../../signon/web/components/account/sso-test-panel.tsx. Edit it there
// and re-run `signon/web/sync.sh <this-app>`.
//
// The test runs in a popup the dashboard opened, and the IdP round trip ends
// here with ?ok=1 or ?ok=0 and nothing else. What went wrong is reported to
// the dashboard, never put in this URL, so this page only says which way it
// went and gets out of the way.

'use client'

import { useSearchParams } from 'next/navigation'
import { AccountShell, Notice, SubmitButton } from './ui'

export function SsoTestPanel() {
  // Anything but an explicit pass reads as a failure: this page is no proof
  // of success on its own.
  const ok = useSearchParams().get('ok') === '1'

  return (
    <AccountShell title={ok ? 'Connection test passed' : 'Connection test failed'}>
      <Notice kind={ok ? 'success' : 'error'}>
        {ok
          ? 'Connection test passed. Return to the dashboard - you can close this window.'
          : 'Connection test failed. The dashboard shows what went wrong — you can close this window.'}
      </Notice>
      <div className="mt-4">
        {/* A script may only close a window a script opened — the popup case.
            Reached any other way the click does nothing, which is why the
            message above says the window can be closed by hand. */}
        <SubmitButton type="button" onClick={() => window.close()}>
          Close this window
        </SubmitButton>
      </div>
    </AccountShell>
  )
}

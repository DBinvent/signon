// SSO buttons: one per configured social provider, then "Sign in with SSO"
// where some customer has connected their own identity provider.
//
// Generated file — the source of truth is
// ../../signon/web/components/account/oauth-buttons.tsx. Edit it there and
// re-run `signon/web/sync.sh <this-app>`.
//
// Renders nothing at all when the deployment has neither: GET /account/oauth
// answers with an empty list and custom_sso false, so a site that does not
// want SSO gets no dead buttons and no separator.
//
// Brand marks are inline SVG — lucide has no brand icons, and six logos do
// not justify an icon dependency in every app. Paths are Simple Icons' (CC0),
// except Google's four-colour G, which is Google's own button asset. Apple and
// Google are drawn to their own rules (Apple's HIG, Google's sign-in branding
// guidelines), which fix the colours, the mark and the wording; the other
// four share the site's outline style.

'use client'

import { useEffect, useState } from 'react'
import { account, type Provider } from '@/lib/account-client'
import { SsoSignIn } from './sso-sign-in'

export function OauthButtons({ redirectTo = '/' }: { redirectTo?: string }) {
  const [providers, setProviders] = useState<Provider[]>([])
  const [customSso, setCustomSso] = useState(false)

  useEffect(() => {
    let cancelled = false
    account
      .providers()
      .then((r) => {
        if (cancelled) return
        setProviders(r.providers)
        // Strictly true: a backend older than the field leaves it undefined.
        setCustomSso(r.custom_sso === true)
      })
      // A failure here is not worth an error banner on a sign-in form — the
      // email and password path still works.
      .catch(() => {})
    return () => {
      cancelled = true
    }
  }, [])

  if (providers.length === 0 && !customSso) return null

  return (
    <div className="mt-6">
      <div className="flex items-center gap-3">
        <span className="h-px flex-1 bg-border" />
        <span className="text-xs uppercase tracking-wide text-muted-foreground">or</span>
        <span className="h-px flex-1 bg-border" />
      </div>
      <div className="mt-4 space-y-2">
        {providers.map((provider) => (
          <ProviderButton
            key={provider.key}
            provider={provider}
            onClick={() => account.startOauth(provider, redirectTo)}
          />
        ))}
        {customSso ? <SsoSignIn redirectTo={redirectTo} /> : null}
      </div>
    </div>
  )
}

function ProviderButton({ provider, onClick }: { provider: Provider; onClick: () => void }) {
  if (provider.key === 'apple') {
    // Apple's HIG: logo and "Sign in with Apple" in one colour, in the
    // system font with the title at about 43% of the button's height. Black
    // on a light page; the black style is not for dark backgrounds, so a dark
    // theme gets Apple's white style instead.
    return (
      <button
        type="button"
        onClick={onClick}
        style={{ fontFamily: '-apple-system, BlinkMacSystemFont, system-ui, sans-serif' }}
        className="flex h-10 w-full items-center justify-center gap-1.5 rounded-md bg-black px-4 text-[17px]
                   font-medium text-white transition hover:opacity-90 dark:bg-white dark:text-black"
      >
        <AppleLogo className="-mt-0.5 size-4" />
        Sign in with Apple
      </button>
    )
  }

  if (provider.key === 'google') {
    // Google's sign-in branding, light theme: white fill, #747775 border,
    // #1F1F1F label in Roboto Medium 14px, the full-colour G at 20px with
    // 10px to the label.
    return (
      <button
        type="button"
        onClick={onClick}
        style={{ fontFamily: 'Roboto, Arial, sans-serif' }}
        className="flex h-10 w-full items-center justify-center gap-2.5 rounded-md border border-[#747775]
                   bg-white px-3 text-sm font-medium tracking-[0.25px] text-[#1f1f1f] transition
                   hover:bg-[#f2f2f2]"
      >
        <GoogleLogo className="size-5" />
        Sign in with Google
      </button>
    )
  }

  if (provider.key === 'microsoft') {
    // Microsoft's sign-in branding, light theme: white fill, #8C8C8C border,
    // #5E5E5E label in Segoe UI Semibold, the four-square logo, "Sign in
    // with Microsoft".
    return (
      <button
        type="button"
        onClick={onClick}
        style={{ fontFamily: '"Segoe UI", system-ui, sans-serif' }}
        className="flex h-10 w-full items-center justify-center gap-3 rounded-md border border-[#8c8c8c]
                   bg-white px-3 text-[15px] font-semibold text-[#5e5e5e] transition hover:bg-[#f3f3f3]"
      >
        <MicrosoftLogo className="size-[21px]" />
        Sign in with Microsoft
      </button>
    )
  }

  const Logo = LOGOS[provider.key]
  return (
    <button
      type="button"
      onClick={onClick}
      className="flex h-10 w-full items-center justify-center gap-2.5 rounded-md border border-border
                 bg-background px-4 text-sm font-medium transition hover:bg-accent hover:text-accent-foreground"
    >
      {/* A provider enabled server side before it has a mark here still works, just without one. */}
      {Logo ? <Logo className="size-[18px]" /> : null}
      Continue with {provider.name}
    </button>
  )
}

type LogoProps = { className?: string }

const LOGOS: Record<string, (props: LogoProps) => React.ReactElement> = {
  amazon: AmazonLogo,
  facebook: FacebookLogo,
  linkedin: LinkedInLogo,
  github: GitHubLogo,
}

function MicrosoftLogo({ className }: LogoProps) {
  return (
    <svg viewBox="0 0 21 21" aria-hidden className={className}>
      <rect x="1" y="1" width="9" height="9" fill="#f25022" />
      <rect x="11" y="1" width="9" height="9" fill="#7fba00" />
      <rect x="1" y="11" width="9" height="9" fill="#00a4ef" />
      <rect x="11" y="11" width="9" height="9" fill="#ffb900" />
    </svg>
  )
}

function AppleLogo({ className }: LogoProps) {
  return (
    <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden className={className}>
      <path d="M12.152 6.896c-.948 0-2.415-1.078-3.96-1.04-2.04.027-3.91 1.183-4.961 3.014-2.117 3.675-.546 9.103 1.519 12.09 1.013 1.454 2.208 3.09 3.792 3.039 1.52-.065 2.09-.987 3.935-.987 1.831 0 2.35.987 3.96.948 1.637-.026 2.676-1.48 3.676-2.948 1.156-1.688 1.636-3.325 1.662-3.415-.039-.013-3.182-1.221-3.22-4.857-.026-3.04 2.48-4.494 2.597-4.559-1.429-2.09-3.623-2.324-4.39-2.376-2-.156-3.675 1.09-4.61 1.09zM15.53 3.83c.843-1.012 1.4-2.427 1.245-3.83-1.207.052-2.662.805-3.532 1.818-.78.896-1.454 2.338-1.273 3.714 1.338.104 2.715-.688 3.559-1.701" />
    </svg>
  )
}

function GoogleLogo({ className }: LogoProps) {
  return (
    <svg viewBox="0 0 48 48" aria-hidden className={className}>
      <path
        fill="#EA4335"
        d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"
      />
      <path
        fill="#4285F4"
        d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"
      />
      <path
        fill="#FBBC05"
        d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"
      />
      <path
        fill="#34A853"
        d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"
      />
    </svg>
  )
}

/** Single-colour, so it follows the theme like GitHub's. */
function AmazonLogo({ className }: LogoProps) {
  return (
    <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden className={className}>
      <path d="M.045 18.02c.072-.116.187-.124.348-.022 3.636 2.11 7.594 3.166 11.87 3.166 2.852 0 5.668-.533 8.447-1.595l.315-.14c.138-.06.234-.1.293-.13.226-.088.39-.046.525.13.12.174.09.336-.12.48-.256.19-.6.41-1.006.654-1.244.743-2.64 1.316-4.185 1.726a17.617 17.617 0 01-10.951-.577 17.88 17.88 0 01-5.43-3.35c-.1-.074-.151-.15-.151-.22 0-.047.021-.09.051-.13zm6.565-6.218c0-1.005.247-1.863.743-2.577.495-.71 1.17-1.25 2.04-1.615.796-.335 1.756-.575 2.912-.72.39-.046 1.033-.103 1.92-.174v-.37c0-.93-.105-1.558-.3-1.875-.302-.43-.78-.65-1.44-.65h-.182c-.48.046-.896.196-1.246.46-.35.27-.575.63-.675 1.096-.06.3-.206.465-.435.51l-2.52-.315c-.248-.06-.372-.18-.372-.39 0-.046.007-.09.022-.15.247-1.29.855-2.25 1.82-2.88.976-.616 2.1-.975 3.39-1.05h.54c1.65 0 2.957.434 3.888 1.29.135.15.27.3.405.48.12.165.224.314.283.45.075.134.15.33.195.57.06.254.105.42.135.51.03.104.062.3.076.615.01.313.02.493.02.553v5.28c0 .376.06.72.165 1.036.105.313.21.54.315.674l.51.674c.09.136.136.256.136.36 0 .12-.06.226-.18.314-1.2 1.05-1.86 1.62-1.963 1.71-.165.135-.375.15-.63.045a6.062 6.062 0 01-.526-.496l-.31-.347a9.391 9.391 0 01-.317-.42l-.3-.435c-.81.886-1.603 1.44-2.4 1.665-.494.15-1.093.227-1.83.227-1.11 0-2.04-.343-2.76-1.034-.72-.69-1.08-1.665-1.08-2.94l-.05-.076zm3.753-.438c0 .566.14 1.02.425 1.364.285.34.675.512 1.155.512.045 0 .106-.007.195-.02.09-.016.134-.023.166-.023.614-.16 1.08-.553 1.424-1.178.165-.28.285-.58.36-.91.09-.32.12-.59.135-.8.015-.195.015-.54.015-1.005v-.54c-.84 0-1.484.06-1.92.18-1.275.36-1.92 1.17-1.92 2.43l-.035-.02zm9.162 7.027c.03-.06.075-.11.132-.17.362-.243.714-.41 1.05-.5a8.094 8.094 0 011.612-.24c.14-.012.28 0 .41.03.65.06 1.05.168 1.172.33.063.09.099.228.099.39v.15c0 .51-.149 1.11-.424 1.8-.278.69-.664 1.248-1.156 1.68-.073.06-.14.09-.197.09-.03 0-.06 0-.09-.012-.09-.044-.107-.12-.064-.24.54-1.26.806-2.143.806-2.64 0-.15-.03-.27-.087-.344-.145-.166-.55-.257-1.224-.257-.243 0-.533.016-.87.046-.363.045-.7.09-1 .135-.09 0-.148-.014-.18-.044-.03-.03-.036-.047-.02-.077 0-.017.006-.03.02-.063v-.06z" />
    </svg>
  )
}

function FacebookLogo({ className }: LogoProps) {
  return (
    <svg viewBox="0 0 24 24" aria-hidden className={className}>
      {/* The f is a cut-out; white behind it keeps it white on a dark card. */}
      <circle cx="12" cy="12" r="11" fill="#fff" />
      <path
        fill="#0866FF"
        d="M9.101 23.691v-7.98H6.627v-3.667h2.474v-1.58c0-4.085 1.848-5.978 5.858-5.978.401 0 .955.042 1.468.103a8.68 8.68 0 0 1 1.141.195v3.325a8.623 8.623 0 0 0-.653-.036 26.805 26.805 0 0 0-.733-.009c-.707 0-1.259.096-1.675.309a1.686 1.686 0 0 0-.679.622c-.258.42-.374.995-.374 1.752v1.297h3.919l-.386 2.103-.287 1.564h-3.246v8.245C19.396 23.238 24 18.179 24 12.044c0-6.627-5.373-12-12-12s-12 5.373-12 12c0 5.628 3.874 10.35 9.101 11.647Z"
      />
    </svg>
  )
}

function LinkedInLogo({ className }: LogoProps) {
  return (
    <svg viewBox="0 0 24 24" aria-hidden className={className}>
      {/* Same as Facebook's: "in" is a cut-out, so white behind it. */}
      <rect x="2" y="2" width="20" height="20" fill="#fff" />
      <path
        fill="#0A66C2"
        d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433c-1.144 0-2.063-.926-2.063-2.065 0-1.138.92-2.063 2.063-2.063 1.14 0 2.064.925 2.064 2.063 0 1.139-.925 2.065-2.064 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z"
      />
    </svg>
  )
}

/** Single-colour, as GitHub's logo guidelines have it, so it follows the theme. */
function GitHubLogo({ className }: LogoProps) {
  return (
    <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden className={className}>
      <path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12" />
    </svg>
  )
}

# signon/web — the shared account UI

The frontend half of `signon`: a typed client for the `/account` API and the
screens the four Next.js apps mount.

```
lib/account-client.ts            typed fetch client + password policy mirror
lib/news-client.ts               typed client for the mailing list
components/account/ui.tsx        shell, field, checkbox, button, notice, step indicator, "already has an account here" notice
components/account/sign-in-form.tsx
components/account/sign-up-form.tsx
components/account/verify-panel.tsx     link and six-digit-code confirmation
components/account/forgot-form.tsx
components/account/reset-form.tsx
components/account/account-panel.tsx    profile, password, providers, sessions
components/account/oauth-buttons.tsx    provider buttons with brand marks
components/account/sso-sign-in.tsx      "Sign in with SSO" + the SSO-required notice
components/account/oauth-confirm-panel.tsx  emailed-code step for Amazon / Facebook / Microsoft
components/account/sso-test-panel.tsx   end of a dash "Test connection" popup
components/account/sso-finish-panel.tsx where an SSO-service sign-in lands, + the "Create one?" prompt
components/account/unsubscribe-panel.tsx the unsubscribe link in mail to an account (welcome, news), with an undo
components/news/subscribe-form.tsx       updates-and-news signup
components/news/token-panel.tsx          confirm / unsubscribe landing pages
app/account/{sign-in,sign-up,verify,forgot,reset,profile,unsubscribe}/page.tsx
app/account/oauth/confirm/page.tsx
app/account/sso/{finish,test}/page.tsx
app/news/{confirm,unsubscribe}/page.tsx
```

## Routes it expects

| path | screen |
|---|---|
| `/account/sign-in` | email + password, the configured provider buttons, and "Sign in with SSO" where `custom_sso` is on; reads the `?error=oauth`, `sso` and `sso_required&sso=<slug>` markers the callbacks redirect with |
| `/account/sign-up` | step 1 of registration, with the pre-ticked "Email me a welcome and occasional product news" box; a browser that already has an account here is asked first (sign in, or "Create another account anyway") |
| `/account/verify` | step 2 — `?id=&token=` from the mail link, or `?email=` for the code form |
| `/account/forgot` | request a reset link |
| `/account/reset` | `?token=` from the reset mail |
| `/account/profile` | signed-in account management, including the "Emails" switch (welcome and news on or off) |
| `/account/unsubscribe` | `?token=` — the unsubscribe link in mail to an account; acts on load, offers an undo; like `/news/unsubscribe`, it has to keep working in old mail |
| `/account/oauth/confirm` | `?token=` — the emailed-code step for providers that do not vouch for the address (Amazon, Facebook, Microsoft), in-process sign-in only |
| `/account/sso/finish` | `?ticket=` — where every sign-in through the SSO service ends: redeems the one-time ticket, then signs in or asks "No profile exists yet. Create one?" (a profile with no email when the provider vouched for none); a 409 when an address typed on a customer connection's button already has an account |
| `/account/sso/test` | `?ok=1\|0` — where a dash "Test connection" popup ends up |
| `/news/confirm` | `?token=` — double opt-in confirmation from the subscribe mail |
| `/news/unsubscribe` | `?token=` — must keep working in mail sent months ago |

`/account/verify`, `/account/reset`, `/news/confirm` and `/news/unsubscribe`
are the paths the server builds its mail links against (`Config::verify_path`,
`reset_path`, `subscribe_confirm_path`, `unsubscribe_path`), so renaming one
means changing both ends. The same holds for the browser redirects it ends
flows with: `/account/unsubscribe` (`account_unsubscribe_path`),
`/account/sign-in` (`sign_in_path`), `/account/oauth/confirm`
(`oauth_confirm_path`), and `/account/sso/finish` and `/account/sso/test`,
which the SSO service redirects to.
`/news/unsubscribe` and `/account/unsubscribe` are the ones to leave alone:
links to them are out in mail nobody can edit.

`SubscribeForm` is not routed - drop it wherever a site wants the signup box
(a dash site's home page, for example).

## Installing it into an app

```sh
./sync.sh ../../my-site/dash             # everything
./sync.sh --news-only ../../my-site/landing   # just the signup box + its client
```

`--news-only` is for a marketing site with no login: it copies
`components/news/subscribe-form.tsx` and `lib/news-client.ts` and nothing
else. `subscribe-form.tsx` imports only the client, which is what makes that
two-file subset work; `token-panel.tsx` depends on `components/account/ui.tsx`
and is deliberately left out, because the confirm and unsubscribe pages live
on the dash site — the backend builds its mail links against one
`APP_BASE_URL`.

It copies, rather than being imported as a package, because the sites are
separate GitHub repositories built by Cloudflare Workers Builds - a
`file:` dependency pointing outside the cloned repo works locally and fails in
CI, and nothing here is published to a registry. Every copied file carries a
header naming this directory as the source; edit here, then re-run `sync.sh`.

## What an app has to provide

* **Tailwind v4 and the design tokens** in `app/globals.css` — `--background`,
  `--card`, `--border`, `--input`, `--primary`, `--muted-foreground`,
  `--destructive`, `--success`, `--ring`. An app with shadcn's tokens defines these
  (the first site's set was the original). The components use those tokens and
  nothing else, so each site's palette applies with no per-app styling.
* **The `@/*` path alias** to the app root — in every app's `tsconfig.json`
  already.
* **A Worker that forwards `/api/*` to the backend and strips the prefix**, so
  a relative `fetch('/api/account/login')` from the browser reaches
  `/account/login` on the service. `NEXT_PUBLIC_ACCOUNT_API` overrides the
  `/api/account` default if a site ever needs a different prefix.
* **Where sign-in runs through an SSO service**, a Worker that
  also forwards `/sso/*` there. The backend then hands out `href` paths on the
  site's own origin (`/sso/start/google`, discovery's and the SSO-required
  notice's `/sso/org/…/start`), and the buttons navigate to those. A site that
  runs the flows in-process gets no `href`, and the buttons go to
  `/api/account/…/start` as before — the same files serve both.

No shadcn components, no form library, no state manager — six forms did not
justify adding three dependencies to every app.

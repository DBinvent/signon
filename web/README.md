# user_mgmt/web — the shared account UI

The frontend half of `user_mgmt`: a typed client for the `/account` API and the
screens the four Next.js apps mount.

```
lib/account-client.ts            typed fetch client + password policy mirror
lib/news-client.ts               typed client for the mailing list
components/account/ui.tsx        shell, field, button, notice, step indicator
components/account/sign-in-form.tsx
components/account/sign-up-form.tsx
components/account/verify-panel.tsx     link and six-digit-code confirmation
components/account/forgot-form.tsx
components/account/reset-form.tsx
components/account/account-panel.tsx    profile, password, providers, sessions
components/account/oauth-buttons.tsx
components/news/subscribe-form.tsx       updates-and-news signup
components/news/token-panel.tsx          confirm / unsubscribe landing pages
app/account/{sign-in,sign-up,verify,forgot,reset,profile}/page.tsx
app/news/{confirm,unsubscribe}/page.tsx
```

## Routes it expects

| path | screen |
|---|---|
| `/account/sign-in` | email + password, plus any configured SSO buttons |
| `/account/sign-up` | step 1 of registration |
| `/account/verify` | step 2 — `?id=&token=` from the mail link, or `?email=` for the code form |
| `/account/forgot` | request a reset link |
| `/account/reset` | `?token=` from the reset mail |
| `/account/profile` | signed-in account management |
| `/news/confirm` | `?token=` — double opt-in confirmation from the subscribe mail |
| `/news/unsubscribe` | `?token=` — must keep working in mail sent months ago |

`/account/verify`, `/account/reset`, `/news/confirm` and `/news/unsubscribe`
are the paths the server builds its mail links against (`Config::verify_path`,
`reset_path`, `subscribe_confirm_path`, `unsubscribe_path`), so renaming one
means changing both ends. `/news/unsubscribe` is the one to leave alone:
links to it are already out in mail nobody can edit.

`SubscribeForm` is not routed — drop it wherever a site wants the signup box
(both `qw-bo/dash` and `dbinvent-bo/dash` put it on the home page).

## Installing it into an app

```sh
./sync.sh ../../qw-bo/dash          # everything
./sync.sh --news-only ../../qw/landing   # just the signup box + its client
```

`--news-only` is for a marketing site with no login: it copies
`components/news/subscribe-form.tsx` and `lib/news-client.ts` and nothing
else. `subscribe-form.tsx` imports only the client, which is what makes that
two-file subset work; `token-panel.tsx` depends on `components/account/ui.tsx`
and is deliberately left out, because the confirm and unsubscribe pages live
on the dash site — the backend builds its mail links against one
`APP_BASE_URL`.

It copies, rather than being imported as a package, because the four sites are
four separate GitHub repositories built by Cloudflare Workers Builds — a
`file:` dependency pointing outside the cloned repo works locally and fails in
CI, and nothing here is published to a registry. Every copied file carries a
header naming this directory as the source; edit here, then re-run `sync.sh`.

## What an app has to provide

* **Tailwind v4 and the design tokens** in `app/globals.css` — `--background`,
  `--card`, `--border`, `--input`, `--primary`, `--muted-foreground`,
  `--destructive`, `--success`, `--ring`. All four apps already define these
  (dash-ta's set was the original). The components use those tokens and
  nothing else, so each site's palette applies with no per-app styling.
* **The `@/*` path alias** to the app root — in every app's `tsconfig.json`
  already.
* **A Worker that forwards `/api/*` to the backend and strips the prefix**, so
  a relative `fetch('/api/account/login')` from the browser reaches
  `/account/login` on the service. `NEXT_PUBLIC_ACCOUNT_API` overrides the
  `/api/account` default if a site ever needs a different prefix.

No shadcn components, no form library, no state manager — six forms did not
justify adding three dependencies to four apps.

#!/usr/bin/env bash
# Copies the shared account UI into a Next.js app.
#
#   ./sync.sh ../../my-site/dash
#
# Why a copy rather than a package dependency: the sites live in separate
# GitHub repositories and deploy through Cloudflare Workers Builds,
# which clones one repo and runs `npm install` inside it. A `file:` dependency
# pointing outside that clone resolves locally and fails in CI, and nothing is
# published to a registry. So each app carries real files that its own build
# can see, every one of them stamped with a header pointing back here, and this
# script is what keeps them identical.
#
# Re-run it after editing anything under web/. It overwrites; it never merges.

set -euo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)"
TARGET="${1:?usage: sync.sh [--news-only] <path-to-nextjs-app>}"
NEWS_ONLY=""

if [[ "$TARGET" == "--news-only" ]]; then
  # For a marketing site that has no login: the signup box and its client,
  # nothing else. The confirm/unsubscribe *pages* stay on the dash site,
  # because the backend builds mail links against one APP_BASE_URL and that
  # is the dash origin — a landing site does not need its own copies.
  NEWS_ONLY=1
  TARGET="${2:?usage: sync.sh [--news-only] <path-to-nextjs-app>}"
fi

if [[ ! -f "$TARGET/package.json" ]]; then
  echo "error: $TARGET does not look like a Next.js app (no package.json)" >&2
  exit 1
fi

if [[ -n "$NEWS_ONLY" ]]; then
  mkdir -p "$TARGET/components/news" "$TARGET/lib"
  # subscribe-form.tsx imports nothing but lib/news-client.ts, which is what
  # makes this two-file subset possible; token-panel.tsx does depend on
  # components/account/ui.tsx and is deliberately not copied here.
  rsync -r "$SRC/components/news/subscribe-form.tsx" "$TARGET/components/news/subscribe-form.tsx"
  rsync -r "$SRC/lib/news-client.ts" "$TARGET/lib/news-client.ts"
  echo "synced the signup box into $TARGET"
  echo "  components/news/subscribe-form.tsx"
  echo "  lib/news-client.ts"
  exit 0
fi

mkdir -p "$TARGET/app/account" "$TARGET/app/news" \
         "$TARGET/components/account" "$TARGET/components/news" "$TARGET/lib"

# -a would carry ownership and timestamps that mean nothing across repos;
# --delete on app/account and components/account so a screen removed here also
# disappears there, rather than lingering as a stale copy.
rsync -r --delete "$SRC/app/account/" "$TARGET/app/account/"
rsync -r --delete "$SRC/app/news/" "$TARGET/app/news/"
rsync -r --delete "$SRC/components/account/" "$TARGET/components/account/"
rsync -r --delete "$SRC/components/news/" "$TARGET/components/news/"
rsync -r "$SRC/lib/account-client.ts" "$TARGET/lib/account-client.ts"
rsync -r "$SRC/lib/news-client.ts" "$TARGET/lib/news-client.ts"

echo "synced account UI into $TARGET"
echo "  app/account/{sign-in,sign-up,verify,forgot,reset,profile,oauth/confirm,sso/finish,sso/test}"
echo "  app/news/{confirm,unsubscribe}"
echo "  components/account/  components/news/"
echo "  lib/account-client.ts  lib/news-client.ts"

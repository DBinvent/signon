// Shared primitives for the account screens.
//
// Generated file — the source of truth is
// ../../user_mgmt/web/components/account/ui.tsx. Edit it there and re-run
// `user_mgmt/web/sync.sh <this-app>`; a local edit will be overwritten.
//
// Plain Tailwind against the design tokens each app already defines in
// app/globals.css (--background, --card, --primary, --muted-foreground …), so
// the same markup takes on each site's palette with nothing imported. No
// shadcn component imports on purpose: none of the four apps has
// components/ui/ generated, and adding that dependency to all four to render
// six forms would not pay for itself.

'use client'

import Link from 'next/link'
import type { ReactNode } from 'react'

export function AccountShell({
  title,
  subtitle,
  children,
  footer,
}: {
  title: string
  subtitle?: ReactNode
  children: ReactNode
  footer?: ReactNode
}) {
  return (
    <main className="flex min-h-screen flex-col items-center justify-center px-6 py-12">
      <div className="w-full max-w-md">
        <div className="rounded-xl border border-border bg-card p-6 shadow-sm sm:p-8">
          <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
          {subtitle ? (
            <p className="mt-1.5 text-sm text-muted-foreground">{subtitle}</p>
          ) : null}
          <div className="mt-6">{children}</div>
        </div>
        {footer ? (
          <div className="mt-4 text-center text-sm text-muted-foreground">{footer}</div>
        ) : null}
      </div>
    </main>
  )
}

export function Field({
  label,
  hint,
  ...props
}: {
  label: string
  hint?: ReactNode
} & React.InputHTMLAttributes<HTMLInputElement>) {
  const id = props.id ?? props.name ?? label.toLowerCase().replace(/\s+/g, '-')
  return (
    <div className="space-y-1.5">
      <label htmlFor={id} className="block text-sm font-medium">
        {label}
      </label>
      <input
        {...props}
        id={id}
        className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm outline-none transition
                   placeholder:text-muted-foreground focus-visible:border-ring focus-visible:ring-2
                   focus-visible:ring-ring/40 disabled:cursor-not-allowed disabled:opacity-60"
      />
      {hint ? <p className="text-xs text-muted-foreground">{hint}</p> : null}
    </div>
  )
}

export function SubmitButton({
  children,
  pending,
  ...props
}: { pending?: boolean } & React.ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      {...props}
      type={props.type ?? 'submit'}
      disabled={pending || props.disabled}
      className="w-full rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground
                 transition hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-60"
    >
      {pending ? 'Working…' : children}
    </button>
  )
}

/**
 * `role="alert"` matters: these carry the result of a submit, and a screen
 * reader that never announces "that password was rejected" leaves the user
 * staring at an unchanged form.
 */
export function Notice({ kind, children }: { kind: 'error' | 'success' | 'info'; children: ReactNode }) {
  const tone =
    kind === 'error'
      ? 'border-destructive/40 bg-destructive/10 text-destructive'
      : kind === 'success'
        ? 'border-success/40 bg-success/10 text-success'
        : 'border-border bg-muted text-muted-foreground'
  return (
    <div role="alert" className={`rounded-md border px-3 py-2 text-sm ${tone}`}>
      {children}
    </div>
  )
}

export function TextLink({ href, children }: { href: string; children: ReactNode }) {
  return (
    <Link href={href} className="font-medium text-primary underline-offset-4 hover:underline">
      {children}
    </Link>
  )
}

/** The signup progress indicator, matching the two-step flow. */
export function Steps({ current, labels }: { current: number; labels: string[] }) {
  return (
    <ol className="mb-6 flex items-center gap-2 text-xs">
      {labels.map((label, i) => {
        const step = i + 1
        const done = step < current
        const active = step === current
        return (
          <li key={label} className="flex flex-1 items-center gap-2">
            <span
              aria-current={active ? 'step' : undefined}
              className={`flex size-5 shrink-0 items-center justify-center rounded-full border text-[10px] font-medium ${
                active
                  ? 'border-primary bg-primary text-primary-foreground'
                  : done
                    ? 'border-success text-success'
                    : 'border-border text-muted-foreground'
              }`}
            >
              {done ? '✓' : step}
            </span>
            <span className={active ? 'font-medium' : 'text-muted-foreground'}>{label}</span>
            {step < labels.length ? <span className="h-px flex-1 bg-border" /> : null}
          </li>
        )
      })}
    </ol>
  )
}

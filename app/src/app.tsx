// Worker entry for the Runner Credential Vault.
//
//   /login, /logout        GitHub sign-in (owner only; see db.ts)
//   /vault/*               owner pages: registry, registration, detail, audit, settings
//   /api/runner/*          runner API (runner-api.ts): OIDC session, registry, use
//   /api/auth/*            BetterAuth

import './globals.css'
import { env } from 'cloudflare:workers'
import { Spiceflow } from 'spiceflow'
import { Head } from 'spiceflow/react'
import { getDb, getAuth, getSession, getRequestOrigin, requirePageSession } from './db.ts'
import { ensureSchema } from './lib/schema.ts'
import { loadRunnerPolicyInput } from './lib/runner-policy.ts'
import { presetForService } from './lib/presets.ts'
import { serviceAdapterFor, serviceAdapterFromDocument } from './lib/service-adapter.ts'
import {
  SETUP_STATE_COOKIE, SETUP_STATE_MAX_AGE_SECONDS, buildManifest, convertManifest, isConfigured, loadOwnerId, loadOwnerLogin, loadVaultKeys,
  newSetupState, saveGithubApp, setupStateMatches, type VaultEnv,
} from './lib/vault-config.ts'
import { Button } from './components/ui/button'
import { runnerApp } from './runner-api.ts'
import { cn } from './lib/utils'
import { Badge } from './components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './components/ui/table'
import { TimeAgo } from './components/ui/time-ago'
import { availability } from './lib/credential-policy.ts'
import { getCredentialForOwner, listAudit, listCredentialsForOwner } from './lib/credential-service.ts'
import { peekEnrollmentLink } from './lib/enrollment.ts'
import { linkHost, readStoredDoc, type CredentialDoc } from './lib/credential-docs.ts'
import { KeyRound, LayoutDashboard, Plus, ChartNoAxesCombined, ShieldCheck, Settings as SettingsIcon, ClipboardList, Workflow, LogOut, Activity, Clock3, CheckCircle2, AlertTriangle, ChevronRight, LockKeyhole, ArrowUpRight, Fingerprint, Search } from 'lucide-react'
import { getUsageAnalytics, listCredentialIntegrationMetadata, listNotifications, listCredentialValidationHistory, loadVaultPreferences, runScheduledCredentialValidation, unreadNotificationCount } from './lib/vault-observability.ts'
import { SectionCard } from './components/ui/section-card.tsx'
import { NotificationBell } from './components/notification-actions.tsx'
import { RunCredentialValidationButton } from './components/validation-actions.tsx'

const themeScript = `(function(){var d=document.documentElement;var m=document.cookie.match(/(?:^|;\\s*)color-theme=(light|dark)(?:;|$)/);var t=m?m[1]:null;if(!t)t=window.matchMedia('(prefers-color-scheme:dark)').matches?'dark':'light';if(t==='dark')d.classList.add('dark');else d.classList.remove('dark')})()`

// Only allow local vault paths for post-login redirects.
function safeRedirectPath(value: string | null): string {
  if (!value || !value.startsWith('/') || value.startsWith('//')) return '/vault'
  if (value === '/vault' || value.startsWith('/vault/')) return value
  return '/vault'
}

async function Shell({ request, children, signedIn }: { request: Request; children: React.ReactNode; signedIn?: boolean }) {
  const dark = /(?:^|;\s*)color-theme=dark(?:;|$)/.test(request.headers.get('cookie') ?? '')
  const current = new URL(request.url).pathname
  const unread = signedIn ? await unreadNotificationCount(getDb()) : 0
  const notifications = signedIn ? await listNotifications(getDb(), 8) : []
  const navGroups = [
    {
      label: 'Workspace',
      items: [
        { href: '/vault', label: 'Overview', icon: LayoutDashboard },
        { href: '/vault/services', label: 'Provider catalog', icon: Plus },
        { href: '/vault/integrations', label: 'Integrations', icon: Workflow },
      ],
    },
    {
      label: 'Security & insights',
      items: [
        { href: '/vault/validation', label: 'Credential health', icon: ShieldCheck },
        { href: '/vault/analytics', label: 'Usage analytics', icon: ChartNoAxesCombined },
        { href: '/vault/audit', label: 'Audit log', icon: ClipboardList },
      ],
    },
  ]
  const mobileItems = [
    { href: '/vault', label: 'Overview', icon: LayoutDashboard },
    { href: '/vault/services', label: 'Add', icon: Plus },
    { href: '/vault/validation', label: 'Health', icon: ShieldCheck },
    { href: '/vault/analytics', label: 'Usage', icon: ChartNoAxesCombined },
    { href: '/vault/settings', label: 'Settings', icon: SettingsIcon },
  ]
  const isActive = (href: string) => href === '/vault'
    ? current === href || current.startsWith('/vault/credentials/')
    : href === '/vault/services'
      ? current === href || current.startsWith('/vault/new') || current.startsWith('/vault/register/')
      : current === href || current.startsWith(href + '/')
  const currentItem = [...navGroups.flatMap((group) => group.items), { href: '/vault/settings', label: 'Settings', icon: SettingsIcon }]
    .find((item) => isActive(item.href))
  const pageTitle = current.startsWith('/vault/new') ? 'Add credential' : current.startsWith('/vault/register/') ? 'Registration' : currentItem?.label ?? 'Vault'

  return (
    <html lang="en" className={cn('h-dvh', dark ? 'dark' : undefined)} suppressHydrationWarning>
      <Head>
        <Head.Meta charSet="UTF-8" />
        <Head.Meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover" />
        <Head.Meta name="robots" content="noindex, nofollow" />
        <Head.Title>Runner Credential Vault</Head.Title>
      </Head>
      <body className="h-dvh overflow-hidden bg-background font-sans antialiased">
        <script dangerouslySetInnerHTML={{ __html: themeScript }} />
        <a href="#main-content" className="sr-only z-[100] rounded-lg bg-primary px-3 py-2 text-sm font-semibold text-primary-foreground focus:not-sr-only focus:fixed focus:left-3 focus:top-3">Skip to main content</a>
        {signedIn ? (
          <div className="flex h-full min-h-0 w-full">
            <aside className="relative hidden h-full w-[258px] shrink-0 flex-col border-r border-white/[0.07] bg-[#111a16] text-slate-100 lg:flex">
              <div className="flex h-[4.5rem] shrink-0 items-center gap-3 border-b border-white/[0.07] px-5">
                <span className="grid size-10 place-items-center rounded-[13px] bg-emerald-400 text-[#102018] shadow-lg shadow-emerald-950/20">
                  <KeyRound className="size-[19px]" strokeWidth={2.5} aria-hidden />
                </span>
                <span className="min-w-0">
                  <span className="block text-[15px] font-semibold tracking-tight">Runner Vault</span>
                  <span className="mt-0.5 block text-[9px] font-semibold tracking-[0.19em] text-emerald-300/75">CREDENTIAL CONTROL</span>
                </span>
              </div>

              <div className="px-4 pt-5">
                <a href="/vault/services" className="group flex min-h-11 w-full items-center justify-center gap-2 rounded-xl bg-emerald-400 px-3 text-sm font-semibold text-[#102018] shadow-lg shadow-emerald-950/20 transition hover:bg-emerald-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-200">
                  <Plus className="size-4 transition-transform group-hover:rotate-90" />
                  Add credential
                </a>
              </div>

              <nav aria-label="Main navigation" className="min-h-0 flex-1 space-y-7 overflow-y-auto px-3 pb-5 pt-7">
                {navGroups.map((group) => (
                  <div key={group.label}>
                    <p className="mb-2 px-3 text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-500">{group.label}</p>
                    <div className="space-y-1">
                      {group.items.map((item) => {
                        const Icon = item.icon
                        const active = isActive(item.href)
                        return (
                          <a
                            key={item.href}
                            href={item.href}
                            aria-current={active ? 'page' : undefined}
                            className={cn(
                              'group flex min-h-10 items-center gap-3 rounded-lg px-3 text-[13px] font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-300/70',
                              active
                                ? 'bg-emerald-400/[0.13] text-emerald-200 ring-1 ring-inset ring-emerald-300/15'
                                : 'text-slate-400 hover:bg-white/[0.055] hover:text-slate-100',
                            )}
                          >
                            <Icon className={cn('size-[17px] shrink-0', active ? 'text-emerald-300' : 'text-slate-500 group-hover:text-slate-300')} aria-hidden />
                            <span className="flex-1">{item.label}</span>
                            {active && <span className="size-1.5 rounded-full bg-emerald-300" />}
                          </a>
                        )
                      })}
                    </div>
                  </div>
                ))}
              </nav>

              <div className="shrink-0 border-t border-white/[0.07] p-3">
                <div className="rounded-xl border border-white/[0.08] bg-white/[0.035] p-3">
                  <div className="flex items-center gap-2">
                    <span className="grid size-7 place-items-center rounded-lg bg-emerald-400/10 text-emerald-300"><LockKeyhole className="size-3.5" /></span>
                    <span className="text-xs font-semibold text-slate-200">Protected workspace</span>
                    <span className="ml-auto size-1.5 rounded-full bg-emerald-400 shadow-[0_0_0_3px_rgba(52,211,153,.12)]" />
                  </div>
                  <p className="mt-2 text-[11px] leading-relaxed text-slate-500">Secrets stay encrypted and masked. Access is mediated by the Vault runtime.</p>
                </div>
                <a href="/vault/settings" aria-current={isActive('/vault/settings') ? 'page' : undefined} className={cn('mt-2 flex min-h-10 items-center gap-3 rounded-lg px-3 text-[13px] font-medium transition-colors', isActive('/vault/settings') ? 'bg-white/[0.08] text-white' : 'text-slate-400 hover:bg-white/[0.055] hover:text-slate-100')}>
                  <SettingsIcon className="size-[17px] text-slate-500" />
                  Workspace settings
                </a>
              </div>
            </aside>

            <div className="flex min-h-0 min-w-0 flex-1 flex-col">
              <header className="sticky top-0 z-30 flex h-[4.25rem] shrink-0 items-center border-b border-border/80 bg-background/90 backdrop-blur-xl">
                <div className="mx-auto flex w-full max-w-[1480px] items-center justify-between gap-3 px-4 sm:px-6 lg:px-8">
                  <div className="flex min-w-0 items-center gap-3">
                    <a href="/vault" className="flex shrink-0 items-center gap-2 lg:hidden">
                      <span className="grid size-8 place-items-center rounded-[10px] bg-emerald-500 text-white"><KeyRound className="size-4" /></span>
                      <span className="text-sm font-semibold tracking-tight">Runner Vault</span>
                    </a>
                    <div className="hidden min-w-0 items-center gap-2 text-sm lg:flex">
                      <span className="text-muted-foreground">Workspace</span>
                      <ChevronRight className="size-3.5 text-muted-foreground/60" />
                      <span className="truncate font-semibold text-foreground">{pageTitle}</span>
                    </div>
                    <div className="min-w-0 lg:hidden">
                      <p className="truncate text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">{pageTitle}</p>
                    </div>
                  </div>
                  <div className="flex shrink-0 items-center gap-2">
                    <NotificationBell unread={unread} notifications={notifications} />
                    <span className="mx-0.5 hidden h-6 w-px bg-border sm:block" />
                    <a href="/vault/settings" aria-label="Settings" title="Settings" className="grid size-9 place-items-center rounded-xl border border-border bg-card text-muted-foreground transition-colors hover:bg-muted hover:text-foreground">
                      <SettingsIcon className="size-[17px]" aria-hidden />
                    </a>
                    <a href="/logout" aria-label="Sign out" title="Sign out" className="grid size-9 place-items-center rounded-xl border border-border bg-card text-muted-foreground transition-colors hover:border-destructive/30 hover:bg-destructive/5 hover:text-destructive">
                      <LogOut className="size-[17px]" aria-hidden />
                    </a>
                  </div>
                </div>
              </header>

              <div className="min-h-0 flex-1 overflow-y-auto">
                <main id="main-content" className="mx-auto min-h-full w-full max-w-[1480px] px-4 pb-28 pt-6 sm:px-6 sm:pt-7 sm:pb-10 lg:px-8 lg:pt-8">
                  {children}
                </main>
              </div>

              <nav aria-label="Mobile navigation" className="fixed inset-x-0 bottom-0 z-30 border-t border-border/80 bg-background/95 pb-[env(safe-area-inset-bottom)] shadow-[0_-10px_30px_-22px_rgba(0,0,0,.35)] backdrop-blur-xl lg:hidden">
                <div className="mx-auto grid max-w-xl grid-cols-5 gap-1 px-2 pt-1.5">
                  {mobileItems.map((item) => {
                    const Icon = item.icon
                    const active = isActive(item.href)
                    return (
                      <a key={item.href} href={item.href} aria-current={active ? 'page' : undefined} className={cn('flex min-h-[3.35rem] flex-col items-center justify-center gap-1 rounded-xl px-1 text-[10px] font-semibold transition-colors', active ? 'text-emerald-700 dark:text-emerald-300' : 'text-muted-foreground hover:bg-muted')}>
                        <span className={cn('grid size-7 place-items-center rounded-lg transition-colors', active ? 'bg-emerald-500/10' : '')}><Icon className="size-[18px]" aria-hidden /></span>
                        <span>{item.label}</span>
                      </a>
                    )
                  })}
                </div>
              </nav>
            </div>
          </div>
        ) : (
          <div className="flex h-full min-h-0 flex-col overflow-y-auto">
            <header className="flex h-16 shrink-0 items-center border-b border-border/70 px-5 sm:px-8">
              <a href="/" className="flex items-center gap-2.5">
                <span className="grid size-9 place-items-center rounded-xl bg-emerald-500 text-white"><KeyRound className="size-[18px]" /></span>
                <span className="text-sm font-semibold tracking-tight">Runner Vault</span>
              </a>
            </header>
            <main id="main-content" className="mx-auto flex w-full max-w-5xl flex-1 items-start justify-center px-4 py-10 sm:px-6 sm:py-16">{children}</main>
          </div>
        )}
      </body>
    </html>
  )
}
function CredentialValidationSummary({ value }: { value: string | null }) {
  if (!value) return null
  let report: {
    status?: string
    identity?: string
    tokenType?: string
    message?: string
    permissionsComplete?: boolean
    permissions?: Array<{ name?: string; access?: string; scope?: string; resources?: string[] }>
  }
  try { report = JSON.parse(value) as typeof report } catch { return null }
  if (!report || typeof report !== 'object') return null
  return (
    <section className="space-y-3 rounded-xl border border-border p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-sm font-semibold">Token verification & permissions</h2>
        <Badge variant={report.status === 'valid' ? 'secondary' : 'outline'}>{report.status ?? 'Not verified'}</Badge>
      </div>
      <p className="text-sm text-muted-foreground">{report.message ?? 'No validation message available.'}</p>
      <div className="flex flex-wrap gap-2 text-xs">
        {report.identity && <span className="rounded-full border border-border px-2.5 py-1">{report.identity}</span>}
        {report.tokenType && <span className="rounded-full border border-border px-2.5 py-1">{report.tokenType}</span>}
        {report.permissionsComplete && <span className="rounded-full border border-border px-2.5 py-1">Complete permission list</span>}
      </div>
      {report.permissions?.length ? (
        <div className="space-y-2">
          <p className="text-xs font-medium text-muted-foreground">{report.permissions.length} permissions detected · showing the first 8</p>
          <ul className="grid gap-2 sm:grid-cols-2">
            {report.permissions.slice(0, 8).map((item, index) => (
              <li key={index} className="min-w-0 rounded-lg border border-border px-3 py-2">
                <p className="break-words text-sm font-medium">{item.name ?? 'Permission'}</p>
                <p className="break-words text-xs text-muted-foreground">{item.access ?? 'unknown'}{item.scope ? ` · ${item.scope}` : ''}</p>
              </li>
            ))}
          </ul>
          {report.permissions.length > 8 && (
            <details className="rounded-lg border border-border">
              <summary className="cursor-pointer px-3 py-2.5 text-sm font-medium">Show all {report.permissions.length} permissions</summary>
              <ul className="grid max-h-64 gap-2 overflow-y-auto border-t border-border p-2 sm:grid-cols-2">
                {report.permissions.slice(8).map((item, index) => (
                  <li key={index + 8} className="min-w-0 rounded-lg border border-border px-3 py-2">
                    <p className="break-words text-sm font-medium">{item.name ?? 'Permission'}</p>
                    <p className="break-words text-xs text-muted-foreground">{item.access ?? 'unknown'}{item.scope ? ` · ${item.scope}` : ''}</p>
                    {item.resources?.length ? <p className="mt-1 break-all text-xs text-muted-foreground">{item.resources.slice(0, 8).join(', ')}</p> : null}
                  </li>
                ))}
              </ul>
            </details>
          )}
        </div>
      ) : null}
    </section>
  )
}

function validationBadge(status: string | null | undefined) {
  const value = status || 'not_tested'
  const labels: Record<string, string> = {
    valid: 'Verified', invalid: 'Invalid', expired: 'Expired',
    unavailable: 'Unreachable', insufficient_permissions: 'Limited access',
    unsupported: 'Unsupported', not_tested: 'Not checked',
  }
  const variant = value === 'invalid' || value === 'expired' ? 'destructive'
    : value === 'valid' ? 'secondary' : 'outline'
  const tone = value === 'valid' ? 'border-emerald-500/20 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300'
    : value === 'unsupported' || value === 'not_tested' ? 'text-muted-foreground' : ''
  return <Badge variant={variant} className={cn('font-medium', tone)}>{labels[value] ?? value.replaceAll('_', ' ')}</Badge>
}

function statusBadge(c: { status: 'active' | 'disabled' | 'pending'; visible: boolean; expiresAt: number | null; externallyManaged: boolean; hasValue: boolean }, now: number) {
  const state = availability(c, now)
  if (state.available) return <Badge variant="secondary">Active</Badge>
  const label: Record<string, string> = { pending: 'Pending', disabled: 'Disabled', hidden: 'Hidden', expired: 'Expired', no_value: 'No value' }
  return <Badge variant="outline">{label[state.reason] ?? state.reason}</Badge>
}

function DocView({ doc }: { doc: CredentialDoc }) {
  const List = ({ items }: { items: string[] }) => (
    <ul className="list-disc pl-5 space-y-1 text-sm">{items.map((item, i) => <li key={i}>{item}</li>)}</ul>
  )
  const Links = ({ links }: { links: { title: string; url: string }[] }) => (
    <ul className="space-y-1 text-sm">
      {links.map((l, i) => (
        <li key={i}>
          <a href={l.url} target="_blank" rel="noopener noreferrer nofollow" className="underline">{l.title}</a>
          <span className="text-muted-foreground"> — {linkHost(l.url)}</span>
        </li>
      ))}
    </ul>
  )
  return (
    <div className="rounded-lg border border-border p-4 space-y-4">
      <div className="flex items-center gap-2">
        <h2 className="text-sm font-semibold">Setup notes written by the requesting model</h2>
        <Badge variant={doc.verification === 'verified' ? 'secondary' : 'outline'}>{doc.verification === 'verified' ? 'Checked against official docs' : 'Unverified'}</Badge>
      </div>
      {doc.verification === 'unverified' && <p className="text-sm text-muted-foreground">{doc.unverified_note}</p>}
      <p className="text-sm">{doc.overview}</p>
      <dl className="text-sm grid gap-1 sm:grid-cols-[10rem_1fr]">
        <dt className="text-muted-foreground">Task</dt><dd>{doc.task}</dd>
        <dt className="text-muted-foreground">Token type</dt><dd>{doc.token_type}</dd>
      </dl>
      {doc.creation_link && <p className="text-sm">Create it here: <a href={doc.creation_link.url} target="_blank" rel="noopener noreferrer nofollow" className="underline">{doc.creation_link.title}</a> <span className="text-muted-foreground">({linkHost(doc.creation_link.url)})</span></p>}
      {doc.creation_steps.length > 0 && <div><h3 className="text-xs font-medium uppercase text-muted-foreground mb-1">Steps</h3><ol className="list-decimal pl-5 space-y-1 text-sm">{doc.creation_steps.map((s, i) => <li key={i}>{s}</li>)}</ol></div>}
      {doc.required_permissions.length > 0 && (
        <div><h3 className="text-xs font-medium uppercase text-muted-foreground mb-1">Required permissions</h3>
          <ul className="space-y-1 text-sm">{doc.required_permissions.map((p, i) => <li key={i}><span className="font-medium">{p.name}</span> — {p.level}. <span className="text-muted-foreground">{p.why}</span></li>)}</ul></div>
      )}
      {doc.unnecessary_permissions.length > 0 && <div><h3 className="text-xs font-medium uppercase text-muted-foreground mb-1">Do not grant</h3><List items={doc.unnecessary_permissions} /></div>}
      {doc.security_notes.length > 0 && <div><h3 className="text-xs font-medium uppercase text-muted-foreground mb-1">Security notes</h3><List items={doc.security_notes} /></div>}
      {doc.expiration_guidance.length > 0 && <div><h3 className="text-xs font-medium uppercase text-muted-foreground mb-1">Expiration</h3><List items={doc.expiration_guidance} /></div>}
      {doc.service_adapter && (
        <section className="rounded-xl border border-border bg-muted/25 p-3.5">
          <div className="flex items-center gap-2 text-sm font-semibold"><ShieldCheck className="size-4 text-success"/> Verified service adapter</div>
          <p className="mt-2 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">API destination · Read only</p>
          <p className="mt-1 break-all font-mono text-xs sm:text-sm">{doc.service_adapter.api_base_url}</p>
          <p className="mt-1.5 text-xs leading-relaxed text-muted-foreground">The vault derives the exact allowed host and authentication header from this reviewed adapter. The token is never shown to the model.</p>
          {doc.service_adapter.cli_tools.length > 0 && <div className="mt-3 flex flex-wrap gap-2">{doc.service_adapter.cli_tools.map((tool) => <span key={tool.id} className="rounded-lg border border-border bg-background px-2.5 py-1.5 text-xs"><span className="font-semibold">{tool.label}</span><span className="ml-2 font-mono text-muted-foreground">{tool.binary}</span></span>)}</div>}
        </section>
      )}
      {doc.official_documentation_links.length > 0 && <div><h3 className="text-xs font-medium uppercase text-muted-foreground mb-1">Documentation</h3><Links links={doc.official_documentation_links} /></div>}
      <p className="text-xs text-muted-foreground">This text came from a model, not from the vault. Check it against the provider's own page before creating a token.</p>
    </div>
  )
}

function Message({ title, text }: { title: string; text: string }) {
  return (
    <div className="max-w-md mx-auto py-16 text-center space-y-2">
      <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
      <p className="text-sm text-muted-foreground">{text}</p>
    </div>
  )
}

const vaultEnv = () => env as unknown as VaultEnv

export const app = new Spiceflow()
  // The vault creates its own tables on first request (no migration step).
  .use(async (_ctx, next) => {
    await ensureSchema(env.DB)
    return next()
  })
  .use(async ({ request }, next) => {
    const url = new URL(request.url)
    if (url.pathname.startsWith('/api/auth')) {
      const auth = await getAuth(request)
      const res = await auth.handler(request)
      if (res.ok || res.status !== 404) return res
    }
    return next()
  })

  .layout('/login', async ({ children, request }) => <Shell request={request}>{children}</Shell>)
  .layout('/setup', async ({ children, request }) => <Shell request={request}>{children}</Shell>)
  .layout('/vault/*', async ({ children, request }) => <Shell request={request} signedIn>{children}</Shell>)

  .get('/', ({ request }) => Response.redirect(new URL('/vault', request.url).toString(), 302))

  .get('/logout', async ({ request }) => {
    const origin = getRequestOrigin(request)
    const res = new Response(null, { status: 302, headers: { Location: new URL('/login', origin).toString() } })
    if (await getSession(request)) {
      const auth = await getAuth(request)
      const { headers } = await auth.api.signOut({ headers: request.headers, returnHeaders: true })
      for (const cookie of headers.getSetCookie()) res.headers.append('Set-Cookie', cookie)
    }
    return res
  })

  .page('/login', async ({ request, redirect }) => {
    const session = await getSession(request)
    const redirectTo = safeRedirectPath(new URL(request.url).searchParams.get('redirect'))
    if (session) throw redirect(redirectTo)
    const { LoginButton } = await import('./components/login-button')
    const keys = await loadVaultKeys(getDb(), vaultEnv())
    const githubOAuthConfigured = await isConfigured(getDb(), vaultEnv(), keys)
    const ownerLogin = githubOAuthConfigured ? await loadOwnerLogin(getDb()) : null
    return (
      <div className="flex justify-center py-24">
        <div className="text-center max-w-sm space-y-4">
          <h1 className="text-xl font-semibold tracking-tight">Runner Credential Vault</h1>
          <p className="text-sm text-muted-foreground">Sign in with the owner's GitHub account.</p>
          {githubOAuthConfigured ? (
            <>
              <LoginButton callbackURL={redirectTo} />
              {ownerLogin && <p className="text-xs text-muted-foreground">This vault belongs to @{ownerLogin}.</p>}
            </>
          ) : (
            <div role="status" className="rounded-lg border border-border bg-muted/40 p-4 text-left space-y-2">
              <p className="text-sm font-medium">This vault is not set up yet.</p>
              <p className="text-sm text-muted-foreground">
                The person who deployed it finishes setup once on the <a className="underline" href="/setup">setup page</a>.
                Until then the vault stays locked.
              </p>
            </div>
          )}
        </div>
      </div>
    )
  })

  // ── Deployment-bound owner setup ──────────────────────────────────
  // Workers Builds derives OWNER_GITHUB_ID from the checked-out GitHub repository before this flow is enabled.
  .page('/setup', async ({ request }) => {
    const db = getDb()
    const e = vaultEnv()
    const keys = await loadVaultKeys(db, e)
    const expectedOwnerId = await loadOwnerId(db, e)
    if (!expectedOwnerId) {
      return <Message title="Setup is locked" text={lockedReason(e)} />
    }
    if (await isConfigured(db, e, keys)) {
      const owner = await loadOwnerLogin(db)
      return (
        <Message
          title="Already set up"
          text={owner ? `This vault belongs to GitHub user @${owner}. If that is not you, delete this deployment and deploy again.` : 'Sign-in is configured. Use the login page to open the vault.'}
        />
      )
    }
    const failed = new URL(request.url).searchParams.get('error')
    return (
      <div className="max-w-md mx-auto py-16 space-y-4">
        <h1 className="text-xl font-semibold tracking-tight">Connect your GitHub account</h1>
        <p className="text-sm text-muted-foreground">
          This deployment is permanently bound to GitHub account ID <code>{expectedOwnerId}</code>
          {typeof e.DEPLOY_OWNER_LOGIN === 'string' && e.DEPLOY_OWNER_LOGIN ? <> (<strong>@{e.DEPLOY_OWNER_LOGIN}</strong>{typeof e.DEPLOY_OWNER_REPO === 'string' && e.DEPLOY_OWNER_REPO ? <>, from repository <code>{e.DEPLOY_OWNER_REPO}</code></> : null})</> : null}.
          If that is not you, you deployed someone else's copy: delete this deployment and deploy again from your own repository. Otherwise create the private sign-in app with that same GitHub account; any other account is rejected.
        </p>
        {failed === 'github' && <p role="alert" className="text-sm text-destructive">GitHub setup did not complete. Try again.</p>}
        {failed === 'owner_mismatch' && <p role="alert" className="text-sm text-destructive">This is not the GitHub account that owns the deployment repository. Switch accounts and try again.</p>}
        {failed === 'provisioning' && <p role="status" className="text-sm text-muted-foreground">Owner verification is still being provisioned. Reload shortly.</p>}
        <form method="post" action="/setup/start">
          <Button type="submit">Create the GitHub App</Button>
        </form>
      </div>
    )
  })

  .post('/setup/start', async ({ request }) => {
    const db = getDb()
    const e = vaultEnv()
    const keys = await loadVaultKeys(db, e)
    const origin = getRequestOrigin(request)
    if (await isConfigured(db, e, keys)) return new Response(null, { status: 303, headers: { Location: new URL('/setup', origin).toString() } })
    if (!await loadOwnerId(db, e)) return new Response(null, { status: 303, headers: { Location: new URL('/setup?error=provisioning', origin).toString(), 'Cache-Control': 'no-store' } })
    const state = newSetupState()
    const manifest = buildManifest(origin, crypto.randomUUID().slice(0, 6))
    const attr = (v: string) => v.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    // GitHub needs the manifest as a form POST from the browser, so hand the browser a
    // tiny page that submits it. The state also goes in an HttpOnly cookie so the
    // callback can prove it comes back to the same browser.
    const page = `<!doctype html><meta charset="utf-8"><meta name="robots" content="noindex"><title>Redirecting to GitHub</title>
<form id="f" method="post" action="https://github.com/settings/apps/new?state=${state}"><input type="hidden" name="manifest" value="${attr(JSON.stringify(manifest))}"><noscript><button>Continue to GitHub</button></noscript></form>
<script>document.getElementById('f').submit()</script>`
    return new Response(page, {
      status: 200,
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store',
        'Set-Cookie': `${SETUP_STATE_COOKIE}=${state}; Path=/; Max-Age=${SETUP_STATE_MAX_AGE_SECONDS}; HttpOnly; Secure; SameSite=Lax`,
      },
    })
  })

  .get('/setup/github/callback', async ({ request }) => {
    const db = getDb()
    const e = vaultEnv()
    const keys = await loadVaultKeys(db, e)
    const origin = getRequestOrigin(request)
    const to = (q: string) => new Response(null, { status: 303, headers: { Location: new URL(q, origin).toString() } })
    if (await isConfigured(db, e, keys)) return to('/login')
    const expectedOwnerId = await loadOwnerId(db, e)
    if (!expectedOwnerId) return to('/setup?error=provisioning')
    const params = new URL(request.url).searchParams
    if (!setupStateMatches(request.headers.get('cookie'), params.get('state'))) return to('/setup?error=github')
    const converted = await convertManifest(params.get('code') ?? '')
    if (!converted) return to('/setup?error=github')
    if (converted.ownerId !== expectedOwnerId) return to('/setup?error=owner_mismatch')
    try {
      await saveGithubApp(db, keys, converted, expectedOwnerId)
    } catch {
      return to('/setup')
    }
    const res = to('/login')
    res.headers.append('Set-Cookie', `${SETUP_STATE_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`)
    return res
  })

  // ── Registry ──────────────────────────────────────────────────────
  .page('/vault', async ({ request }) => {
    await requirePageSession(request)
    const db = getDb()
    const rows = await listCredentialsForOwner(db)
    const searchQuery = new URL(request.url).searchParams.get('q')?.trim().slice(0, 100) ?? ''
    const healthFilter = new URL(request.url).searchParams.get('health') ?? 'all'
    const registryRows = rows.filter((row) => {
      const query = searchQuery.toLowerCase()
      const matchesQuery = !query || row.name.toLowerCase().includes(query) || row.service.toLowerCase().includes(query)
      const matchesHealth = healthFilter === 'all'
        || (healthFilter === 'verified' && row.validationStatus === 'valid')
        || (healthFilter === 'attention' && ['invalid', 'expired', 'insufficient_permissions'].includes(row.validationStatus ?? ''))
        || (healthFilter === 'review' && row.validationStatus !== 'valid' && !['invalid', 'expired', 'insufficient_permissions'].includes(row.validationStatus ?? ''))
      return matchesQuery && matchesHealth
    })
    const now = Date.now()
    const runnerPolicy = await loadRunnerPolicyInput(db)
    const runnerConfigured = runnerPolicy !== null || Boolean((env as unknown as VaultEnv).RUNNER_REPOSITORY)
    const runnerOwnerReady = Boolean(await loadOwnerId(db, vaultEnv()))
    const validCount = rows.filter((row) => row.validationStatus === 'valid').length
    const attentionCount = rows.filter((row) => ['invalid', 'expired', 'insufficient_permissions'].includes(row.validationStatus ?? '')).length
    const reviewCount = Math.max(0, rows.length - validCount - attentionCount)
    const preferences = await loadVaultPreferences(db)
    const recentChecks = await listCredentialValidationHistory(db, 6)
    const percent = (count: number) => rows.length ? Math.round(count / rows.length * 100) : 0
    const segmentPercent = (count: number) => rows.length ? count / rows.length * 100 : 0

    return (
      <div className="mx-auto w-full min-w-0 max-w-[1360px] space-y-7 sm:space-y-8">
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div className="min-w-0">
            <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-primary">Control center <span className="mx-1.5 text-muted-foreground/50">/</span> Overview</p>
            <h1 className="mt-2 text-2xl font-semibold tracking-tight sm:text-[2rem]">Workspace overview</h1>
            <p className="mt-1.5 max-w-2xl text-sm leading-relaxed text-muted-foreground">A live view of your credentials, verification health and connected runtime.</p>
          </div>
          <div className="flex w-full flex-wrap gap-2 sm:w-auto">
            <a href="/vault/validation" className="inline-flex min-h-10 flex-1 items-center justify-center gap-2 rounded-xl border border-border bg-card px-3.5 text-sm font-medium text-foreground transition-colors hover:bg-muted sm:flex-none">
              <ShieldCheck className="size-4 text-muted-foreground" /> Health center
            </a>
            <a href="/vault/services" className="inline-flex min-h-10 flex-1 items-center justify-center gap-2 rounded-xl bg-primary px-4 text-sm font-semibold text-primary-foreground shadow-sm transition hover:bg-primary/90 sm:flex-none">
              <Plus className="size-4" /> Add credential
            </a>
          </div>
        </div>

        <section aria-label="Credential summary" className="grid grid-cols-2 gap-3 xl:grid-cols-4">
          {[
            { label: 'Total credentials', value: rows.length, note: rows.filter((row) => row.status === 'active').length + ' active', icon: KeyRound, tone: 'bg-slate-500/10 text-slate-600 dark:text-slate-300' },
            { label: 'Verified', value: validCount, note: rows.length ? percent(validCount) + '% of your registry' : 'No credentials yet', icon: CheckCircle2, tone: 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-300' },
            { label: 'Needs attention', value: attentionCount, note: attentionCount ? 'Review required' : 'No blocking issues', icon: AlertTriangle, tone: attentionCount ? 'bg-rose-500/10 text-rose-700 dark:text-rose-300' : 'bg-slate-500/10 text-slate-500 dark:text-slate-300' },
            { label: 'To review', value: reviewCount, note: 'Unverified or inconclusive', icon: Clock3, tone: 'bg-amber-500/10 text-amber-700 dark:text-amber-300' },
          ].map((metric) => {
            const Icon = metric.icon
            return (
              <article key={metric.label} className="group relative min-w-0 overflow-hidden rounded-2xl border border-border bg-card p-4 transition-colors hover:border-border/80 sm:p-5">
                <div className="flex items-center justify-between gap-2">
                  <p className="text-xs font-medium text-muted-foreground sm:text-[13px]">{metric.label}</p>
                  <span className={cn('grid size-9 shrink-0 place-items-center rounded-xl', metric.tone)}><Icon className="size-[17px]" /></span>
                </div>
                <p className="mt-3 text-[1.85rem] font-semibold leading-none tracking-tight tabular-nums sm:text-3xl">{metric.value}</p>
                <p className="mt-2 text-[11px] text-muted-foreground sm:text-xs">{metric.note}</p>
              </article>
            )
          })}
        </section>

        <div className="grid gap-4 xl:grid-cols-[1.15fr_0.85fr]">
          <SectionCard
            title="Credential health"
            description="Current verification state across the registry."
            icon={<ShieldCheck className="size-[18px]" />}
            action={<a href="/vault/validation" className="inline-flex min-h-8 items-center gap-1.5 rounded-lg px-2 text-xs font-semibold text-primary transition hover:bg-primary/5">View details <ArrowUpRight className="size-3.5" /></a>}
          >
            <div className="space-y-5">
              <div className="flex items-end justify-between gap-3">
                <div><p className="text-3xl font-semibold tracking-tight tabular-nums">{percent(validCount)}<span className="ml-0.5 text-base font-medium text-muted-foreground">%</span></p><p className="mt-1 text-xs text-muted-foreground">Verified credentials</p></div>
                <p className="text-xs text-muted-foreground">{validCount} of {rows.length}</p>
              </div>
              <div className="flex h-2.5 overflow-hidden rounded-full bg-muted" role="img" aria-label={validCount + ' verified, ' + attentionCount + ' need attention, ' + reviewCount + ' to review'}>
                {validCount > 0 && <span className="h-full bg-emerald-500 transition-all" style={{ width: segmentPercent(validCount) + '%' }} />}
                {attentionCount > 0 && <span className="h-full bg-rose-500 transition-all" style={{ width: segmentPercent(attentionCount) + '%' }} />}
                {reviewCount > 0 && <span className="h-full bg-amber-400 transition-all" style={{ width: segmentPercent(reviewCount) + '%' }} />}
              </div>
              <div className="grid grid-cols-3 gap-3">
                <div className="min-w-0"><div className="flex items-center gap-1.5"><span className="size-2 rounded-full bg-emerald-500" /><span className="truncate text-[11px] text-muted-foreground">Verified</span></div><p className="mt-1.5 text-lg font-semibold tabular-nums">{validCount}</p></div>
                <div className="min-w-0"><div className="flex items-center gap-1.5"><span className="size-2 rounded-full bg-rose-500" /><span className="truncate text-[11px] text-muted-foreground">Attention</span></div><p className="mt-1.5 text-lg font-semibold tabular-nums">{attentionCount}</p></div>
                <div className="min-w-0"><div className="flex items-center gap-1.5"><span className="size-2 rounded-full bg-amber-400" /><span className="truncate text-[11px] text-muted-foreground">To review</span></div><p className="mt-1.5 text-lg font-semibold tabular-nums">{reviewCount}</p></div>
              </div>
              <div className="flex items-start gap-2.5 rounded-xl border border-border/70 bg-muted/30 p-3">
                <Clock3 className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
                <p className="text-xs leading-relaxed text-muted-foreground">Scheduled validation runs every <strong className="font-semibold text-foreground">{preferences.validationIntervalHours} hours</strong>. Repeated failures back off automatically; temporary network errors never invalidate a token.</p>
              </div>
            </div>
          </SectionCard>

          <SectionCard
            title="Runner connection"
            description="Trust relationship and runtime readiness."
            icon={<Workflow className="size-[18px]" />}
            action={<Badge variant={runnerConfigured ? 'secondary' : 'outline'}>{runnerConfigured ? 'Configured' : 'Pending'}</Badge>}
          >
            <div className="flex items-start gap-3">
              <span className={cn('grid size-11 shrink-0 place-items-center rounded-xl', runnerConfigured ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-300' : 'bg-amber-500/10 text-amber-700 dark:text-amber-300')}>
                {runnerConfigured ? <Fingerprint className="size-5" /> : <Clock3 className="size-5" />}
              </span>
              <div className="min-w-0 flex-1">
                <p className="text-sm font-semibold">{runnerConfigured ? 'Runner trust policy is configured' : runnerOwnerReady ? 'Waiting for the first trusted run' : 'Owner identity is not configured'}</p>
                <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
                  {runnerConfigured
                    ? 'The Vault has a runner trust policy and can issue short-lived sessions to approved workflows.'
                    : runnerOwnerReady
                      ? 'The first valid workflow from the owner’s main branch will bind its immutable repository and owner IDs automatically.'
                      : 'OIDC bootstrap stays locked until this deployment has a pinned GitHub owner identity.'}
                </p>
              </div>
            </div>
            <div className="mt-4 space-y-2 rounded-xl border border-border/70 bg-muted/25 p-3.5">
              <div className="flex items-center justify-between gap-3 text-xs"><span className="text-muted-foreground">Owner identity</span><span className="inline-flex items-center gap-1.5 font-medium">{runnerOwnerReady ? <><CheckCircle2 className="size-3.5 text-success" /> Verified</> : <><AlertTriangle className="size-3.5 text-warning" /> Pending</>}</span></div>
              <div className="flex items-center justify-between gap-3 text-xs"><span className="text-muted-foreground">Credential delivery</span><span className="font-medium">Vault proxy</span></div>
              {runnerPolicy?.repository && <div className="border-t border-border/70 pt-2"><p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Trusted repository</p><p className="mt-1 break-all font-mono text-xs">{runnerPolicy.repository}</p></div>}
            </div>
            <a href="/vault/integrations" className="mt-3 inline-flex min-h-9 w-full items-center justify-center gap-2 rounded-lg border border-border bg-background px-3 text-xs font-semibold transition-colors hover:bg-muted">View integrations <ArrowUpRight className="size-3.5" /></a>
          </SectionCard>
        </div>

        <SectionCard
          title="Credential registry"
          description="Encrypted values stay write-only. Runners receive access through the Vault proxy."
          icon={<KeyRound className="size-[18px]" />}
          action={<a href="/vault/services" className="inline-flex min-h-8 items-center gap-1.5 rounded-lg px-2 text-xs font-semibold text-primary transition hover:bg-primary/5"><Plus className="size-3.5" /> Add new</a>}
        >
          {rows.length > 0 && (
            <form method="get" action="/vault" className="mb-4 flex flex-col gap-2 sm:flex-row">
              <label className="flex min-h-10 min-w-0 flex-1 items-center gap-2 rounded-xl border border-input bg-background px-3">
                <Search className="size-4 shrink-0 text-muted-foreground" />
                <input type="search" name="q" value={searchQuery} placeholder="Search credentials or providers…" defaultValue={searchQuery} className="h-10 min-w-0 flex-1 bg-transparent text-sm outline-none placeholder:text-muted-foreground/70" />
              </label>
              <div className="flex gap-2">
                <select name="health" defaultValue={healthFilter} aria-label="Filter credentials by verification state" className="h-10 min-w-0 flex-1 rounded-xl border border-input bg-background px-3 text-xs sm:w-44 sm:flex-none">
                  <option value="all">All states</option>
                  <option value="verified">Verified</option>
                  <option value="attention">Needs attention</option>
                  <option value="review">To review</option>
                </select>
                <Button type="submit" variant="outline" size="lg">Filter</Button>
                {(searchQuery || healthFilter !== 'all') && <a href="/vault" className="inline-flex min-h-10 items-center rounded-xl px-3 text-xs font-medium text-muted-foreground hover:bg-muted hover:text-foreground">Clear</a>}
              </div>
            </form>
          )}
          {rows.length === 0 ? (
            <div className="grid justify-items-center rounded-xl border border-dashed border-border bg-muted/15 px-5 py-10 text-center">
              <span className="grid size-12 place-items-center rounded-2xl bg-primary/10 text-primary"><KeyRound className="size-5" /></span>
              <h3 className="mt-4 text-sm font-semibold">Your credential registry is empty</h3>
              <p className="mt-1.5 max-w-sm text-xs leading-relaxed text-muted-foreground">Add your first provider credential, or approve a one-time registration request from a trusted Runner.</p>
              <a href="/vault/services" className="mt-4 inline-flex min-h-10 items-center gap-2 rounded-xl bg-primary px-4 text-xs font-semibold text-primary-foreground transition hover:bg-primary/90"><Plus className="size-3.5" /> Add your first credential</a>
            </div>
          ) : registryRows.length === 0 ? (
            <div className="grid justify-items-center rounded-xl border border-dashed border-border bg-muted/15 px-5 py-10 text-center">
              <span className="grid size-10 place-items-center rounded-xl bg-muted text-muted-foreground"><Search className="size-4" /></span>
              <p className="mt-3 text-sm font-semibold">No matching credentials</p>
              <p className="mt-1 text-xs text-muted-foreground">Try a different name, provider or verification filter.</p>
              <a href="/vault" className="mt-3 inline-flex min-h-8 items-center gap-1 rounded-lg px-3 text-xs font-semibold text-primary hover:bg-primary/5">Clear filters <ChevronRight className="size-3" /></a>
            </div>
          ) : (
            <>
              <div className="mb-3 text-[11px] text-muted-foreground">{registryRows.length} of {rows.length} credentials</div>
              <div className="hidden overflow-x-auto sm:block">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Credential</TableHead><TableHead>Provider</TableHead><TableHead>Availability</TableHead><TableHead>Verification</TableHead><TableHead>Expires</TableHead><TableHead>Last used</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {registryRows.map((credential) => (
                      <TableRow key={credential.id}>
                        <TableCell><a className="font-mono text-xs font-semibold text-foreground decoration-border underline-offset-4 hover:text-primary hover:underline" href={'/vault/credentials/' + credential.id}>{credential.name}</a></TableCell>
                        <TableCell className="text-sm">{credential.service}</TableCell>
                        <TableCell>{statusBadge(credential, now)}</TableCell>
                        <TableCell>{validationBadge(credential.validationStatus)}</TableCell>
                        <TableCell className="text-xs text-muted-foreground">{credential.expiresAt ? <TimeAgo ts={credential.expiresAt} /> : credential.lifetime === 'permanent' ? 'Never' : '—'}</TableCell>
                        <TableCell className="text-xs text-muted-foreground">{credential.lastUsedAt ? <TimeAgo ts={credential.lastUsedAt} /> : 'Never'}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
              <div className="grid gap-2.5 sm:hidden">
                {registryRows.map((credential) => (
                  <a key={credential.id} href={'/vault/credentials/' + credential.id} className="block min-w-0 rounded-xl border border-border bg-background p-3.5 transition-colors active:bg-muted/50">
                    <div className="flex min-w-0 items-start justify-between gap-3">
                      <div className="min-w-0"><p className="break-all font-mono text-xs font-semibold">{credential.name}</p><p className="mt-1 text-xs text-muted-foreground">{credential.service}</p></div>
                      {validationBadge(credential.validationStatus)}
                    </div>
                    <div className="mt-3 flex flex-wrap items-center justify-between gap-2 border-t border-border/70 pt-3">
                      {statusBadge(credential, now)}
                      <span className="text-[11px] text-muted-foreground">{credential.lastUsedAt ? <>Last used <TimeAgo ts={credential.lastUsedAt} /></> : 'Not used yet'}</span>
                    </div>
                  </a>
                ))}
              </div>
            </>
          )}
        </SectionCard>

        <SectionCard
          title="Recent validation activity"
          description="The latest scheduled and manual checks across your credentials."
          icon={<Activity className="size-[18px]" />}
          action={<a href="/vault/validation" className="inline-flex min-h-8 items-center gap-1.5 rounded-lg px-2 text-xs font-semibold text-primary transition hover:bg-primary/5">Full history <ArrowUpRight className="size-3.5" /></a>}
        >
          {recentChecks.length === 0 ? (
            <div className="flex items-center gap-3 rounded-xl bg-muted/25 px-4 py-5">
              <span className="grid size-9 shrink-0 place-items-center rounded-xl bg-background text-muted-foreground"><Activity className="size-4" /></span>
              <div><p className="text-xs font-semibold">No validation events yet</p><p className="mt-1 text-xs text-muted-foreground">Checks will appear here after a credential is added and verified.</p></div>
            </div>
          ) : (
            <div className="divide-y divide-border/70">
              {recentChecks.map((item) => (
                <a key={item.id} href={'/vault/credentials/' + item.credentialId} className="flex min-w-0 items-center gap-3 py-3 first:pt-0 last:pb-0 hover:bg-muted/20">
                  <span className={cn('grid size-8 shrink-0 place-items-center rounded-lg', item.status === 'valid' ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-300' : item.status === 'invalid' || item.status === 'expired' ? 'bg-rose-500/10 text-rose-600 dark:text-rose-300' : 'bg-amber-500/10 text-amber-700 dark:text-amber-300')}>
                    {item.status === 'valid' ? <CheckCircle2 className="size-4" /> : item.status === 'invalid' || item.status === 'expired' ? <AlertTriangle className="size-4" /> : <Clock3 className="size-4" />}
                  </span>
                  <span className="min-w-0 flex-1"><span className="block truncate text-xs font-semibold">{item.credentialName}</span><span className="mt-1 block truncate text-[11px] text-muted-foreground">{item.provider} · {item.source === 'manual' ? 'Manual check' : 'Scheduled check'} · {item.durationMs} ms</span></span>
                  <span className="flex shrink-0 flex-col items-end gap-1">{validationBadge(item.status)}<TimeAgo ts={item.checkedAt} className="text-[10px] text-muted-foreground" /></span>
                </a>
              ))}
            </div>
          )}
        </SectionCard>
      </div>
    )
  })

  // ── Owner-facing provider catalog and direct registration ─────────
  .page('/vault/services', async ({ request }) => {
    await requirePageSession(request)
    const { ServiceCatalog } = await import('./components/service-catalog.tsx')
    return <div className="mx-auto w-full min-w-0 max-w-[1180px] space-y-6"><div><p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-primary">Credential setup</p><h1 className="mt-2 text-2xl font-semibold tracking-tight sm:text-[2rem]">Choose a provider</h1><p className="mt-1.5 max-w-2xl text-sm leading-relaxed text-muted-foreground">Start with a curated provider preset. The Vault derives the API destination and authentication rules where a reviewed adapter is available; you only supply the secret.</p></div><ServiceCatalog /></div>
  })

  .page('/vault/new', async ({ request }) => {
    await requirePageSession(request)
    const serviceId = new URL(request.url).searchParams.get('service') ?? ''
    const preset = presetForService(serviceId)
    const preferences = await loadVaultPreferences(getDb())
    const { CredentialForm } = await import('./components/credential-form.tsx')
    if (!preset) return <div className="mx-auto w-full max-w-2xl"><SectionCard title="Custom service registration" description="Custom providers are registered from the Runner using their official API documentation. The request includes a verified Service Adapter, so network and authentication rules can be derived safely."><p className="text-sm text-muted-foreground">Ask the model on your Runner to request a one-time credential link for this service. You will be able to add the secret here without entering hosts, scopes or authentication settings.</p><a href="/vault" className="mt-4 inline-flex min-h-11 items-center gap-2 rounded-xl bg-primary px-4 text-sm font-medium text-primary-foreground">Back to overview <ChevronRight className="size-4"/></a></SectionCard></div>
    return <div className="mx-auto w-full min-w-0 max-w-3xl space-y-5"><div><a href="/vault/services" className="inline-flex min-h-11 items-center gap-2 text-sm text-muted-foreground hover:text-foreground"><ChevronRight className="size-4 rotate-180"/> Provider catalog</a><h1 className="mt-2 text-2xl font-bold tracking-tight">{`Add ${preset.label} credential`}</h1><p className="mt-1 text-sm text-muted-foreground">Enter the token. Vault derives the verified API host, authentication style and validation behavior.</p></div><CredentialForm mode="create" preset={{ label: preset.label, docsUrl: preset.docsUrl }} apiBaseUrl={serviceAdapterFor(serviceId)?.apiBaseUrl} defaults={{ visible: preferences.defaultVisible, lifetime: preferences.defaultLifetime }} /></div>
  })

  // ── One-time registration link ──────────────────────────────────
  .page('/vault/register/:token', async ({ params, request }) => {
    await requirePageSession(request)
    const db = getDb()
    const link = await peekEnrollmentLink(db, params.token, Date.now())
    if (!link || link.kind !== 'register') return <Message title="Link not valid" text="This link is unknown, expired, or has already been used. Ask the model for a new one." />
    const credential = await getCredentialForOwner(db, link.credentialId)
    if (!credential) return <Message title="Link not valid" text="The credential for this link no longer exists." />
    if (credential.status !== 'pending' || credential.externallyManaged) {
      return <Message title="Registration closed" text="This credential is no longer accepting a value. Ask the runner for a fresh registration request." />
    }
    const { CredentialForm } = await import('./components/credential-form.tsx')
    const preset = presetForService(credential.service)
    const preferences = await loadVaultPreferences(db)
    return (
      <div className="mx-auto w-full min-w-0 max-w-3xl space-y-5 sm:space-y-6">
        <div>
          <h1 className="break-all text-base font-semibold tracking-tight font-mono sm:text-lg">{credential.name}</h1>
          <p className="mt-1 text-sm text-muted-foreground">{credential.service}</p>
          <p className="text-xs text-muted-foreground mt-1">Link expires in about {Math.max(1, Math.round((link.expiresAt - Date.now()) / 60_000))} min and works once.</p>
        </div>
        {credential.doc && <DocView doc={credential.doc} />}
        <CredentialForm mode="register" token={params.token} credentialId={credential.id} serviceName={credential.service} preset={preset ? { label: preset.label } : null} apiBaseUrl={serviceAdapterFromDocument(credential.doc)?.apiBaseUrl ?? serviceAdapterFor(credential.service)?.apiBaseUrl} defaults={{ visible: preferences.defaultVisible, lifetime: preferences.defaultLifetime }} />
      </div>
    )
  })

  // ── Credential detail ───────────────────────────────────────────
  .page('/vault/credentials/:id', async ({ params, request }) => {
    await requirePageSession(request)
    const db = getDb()
    const c = await getCredentialForOwner(db, params.id)
    if (!c) return <Message title="Not found" text="No such credential." />
    const now = Date.now()
    const log = await listAudit(db, { credentialName: c.name, limit: 20 })
    const { CredentialControls } = await import('./components/credential-actions.tsx')
    const { CredentialForm } = await import('./components/credential-form.tsx')
    return (
      <div className="mx-auto w-full min-w-0 max-w-[1120px] space-y-6">
        <div className="space-y-4">
          <a href="/vault" className="inline-flex min-h-9 items-center gap-2 rounded-lg px-2 text-xs font-medium text-muted-foreground transition hover:bg-muted hover:text-foreground">
            <ChevronRight className="size-3.5 rotate-180" /> Back to overview
          </a>
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0">
              <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-primary">Credential details</p>
              <h1 className="mt-2 break-all font-mono text-xl font-semibold tracking-tight sm:text-2xl">{c.name}</h1>
              <p className="mt-1.5 text-sm text-muted-foreground">{c.service} <span className="mx-1.5 text-muted-foreground/50">·</span> Updated <TimeAgo ts={c.updatedAt} /></p>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              {statusBadge(c, now)}
              {validationBadge(c.validationStatus)}
            </div>
          </div>
        </div>

        <div className="grid min-w-0 gap-4 xl:grid-cols-[0.95fr_1.05fr]">
          <SectionCard title="Configuration" description="Read-only security and delivery metadata." icon={<KeyRound className="size-[18px]" />}>
            <dl className="grid min-w-0 grid-cols-[7.25rem_minmax(0,1fr)] gap-x-3 text-xs sm:grid-cols-[9rem_minmax(0,1fr)]">
              <dt className="border-b border-border/70 py-2.5 text-muted-foreground">Delivery</dt><dd className="min-w-0 border-b border-border/70 py-2.5 font-medium">{c.externallyManaged ? 'Managed elsewhere' : c.delivery}</dd>
              <dt className="border-b border-border/70 py-2.5 text-muted-foreground">Allowed hosts</dt><dd className="min-w-0 break-all border-b border-border/70 py-2.5 font-mono text-[11px]">{c.allowedHosts.join(', ') || '—'}</dd>
              <dt className="border-b border-border/70 py-2.5 text-muted-foreground">Authentication</dt><dd className="min-w-0 break-words border-b border-border/70 py-2.5 font-mono text-[11px]">{c.authHeader}: {c.authScheme}</dd>
              <dt className="border-b border-border/70 py-2.5 text-muted-foreground">Lifetime</dt><dd className="min-w-0 border-b border-border/70 py-2.5">{c.lifetime}{c.expiresAt ? <> · <TimeAgo ts={c.expiresAt} /></> : null}</dd>
              <dt className="border-b border-border/70 py-2.5 text-muted-foreground">Secret value</dt><dd className="min-w-0 border-b border-border/70 py-2.5 font-medium">{c.hasValue ? 'Stored · write only' : 'Not stored'}</dd>
              <dt className="border-b border-border/70 py-2.5 text-muted-foreground">Visibility</dt><dd className="min-w-0 border-b border-border/70 py-2.5">{c.visible ? 'Available to approved runners' : 'Hidden from runners'}</dd>
              <dt className="border-b border-border/70 py-2.5 text-muted-foreground">Last checked</dt><dd className="min-w-0 border-b border-border/70 py-2.5">{c.lastValidatedAt ? <TimeAgo ts={c.lastValidatedAt}/> : 'Never'}</dd>
              <dt className="border-b border-border/70 py-2.5 text-muted-foreground">Next check</dt><dd className="min-w-0 border-b border-border/70 py-2.5">{c.nextValidationAt ? <TimeAgo ts={c.nextValidationAt}/> : 'Not scheduled'}</dd>
              {c.firstValidationFailureAt && <><dt className="py-2.5 text-muted-foreground">First failure</dt><dd className="min-w-0 py-2.5 text-destructive"><TimeAgo ts={c.firstValidationFailureAt}/> · {c.validationFailureCount} consecutive failures</dd></>}
            </dl>
          </SectionCard>
          <div className="min-w-0 space-y-3">
            <div className="flex items-center justify-between gap-3 px-1">
              <div><h2 className="text-sm font-semibold">Verification & permissions</h2><p className="mt-0.5 text-xs text-muted-foreground">Provider-reported identity and granted access.</p></div>
              <Badge variant="outline">Secret masked</Badge>
            </div>
            <CredentialValidationSummary value={c.validationDetails} />
          </div>
        </div>

        <SectionCard title="Access controls" description="Enable or disable availability and control whether approved Runners can discover this credential." icon={<ShieldCheck className="size-[18px]" />}>
          <CredentialControls id={c.id} name={c.name} enabled={c.status === 'active'} visible={c.visible} canEnable={c.hasValue || c.externallyManaged} />
        </SectionCard>

        {c.doc && <SectionCard title="Provider setup notes" description="Original registration guidance and reviewed service-adapter details." icon={<Workflow className="size-[18px]" />}><DocView doc={c.doc} /></SectionCard>}

        {!c.externallyManaged && (
          <SectionCard title="Replace secret value" description="Submit a replacement token. The previous value is not displayed and cannot be recovered from the dashboard." icon={<LockKeyhole className="size-[18px]" />}>
            <CredentialForm mode="replace" id={c.id} credentialId={c.id} serviceName={c.service} apiBaseUrl={serviceAdapterFromDocument(c.doc)?.apiBaseUrl ?? serviceAdapterFor(c.service)?.apiBaseUrl} defaults={{ visible: c.visible, lifetime: c.lifetime }} />
          </SectionCard>
        )}

        <SectionCard title="Recent activity" description="Owner and Runner actions associated with this credential." icon={<Activity className="size-[18px]" />}>
          <AuditTable rows={log} />
        </SectionCard>
      </div>
    )
  })



  .page('/vault/validation', async ({ request }) => {
    await requirePageSession(request)
    const db = getDb()
    const rows = await listCredentialsForOwner(db)
    const history = await listCredentialValidationHistory(db, 80)
    const statuses = ['valid', 'invalid', 'expired', 'unavailable', 'insufficient_permissions', 'unsupported', 'not_tested']
    const counts = Object.fromEntries(statuses.map((status) => [status, rows.filter((row) => row.validationStatus === status).length]))
    const labels: Record<string, string> = { valid: 'Valid', invalid: 'Invalid', expired: 'Expired', unavailable: 'Unreachable', insufficient_permissions: 'Insufficient access', unsupported: 'Unsupported', not_tested: 'Not tested' }
    const badge = (status: string) => <Badge variant={status === 'valid' ? 'secondary' : status === 'invalid' || status === 'expired' ? 'destructive' : 'outline'}>{labels[status] ?? status}</Badge>
    return <div className="mx-auto w-full max-w-5xl space-y-6">
      <div><p className="text-xs font-semibold uppercase tracking-[0.16em] text-primary">Credential health</p><h1 className="mt-1 text-2xl font-bold tracking-tight">Validation</h1><p className="mt-1 text-sm text-muted-foreground">Scheduled checks run every 15 minutes. Repeated failures use exponential backoff; manual checks are available per credential.</p></div>
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-7">{statuses.map((status) => <div key={status} className="rounded-2xl border border-border bg-card p-3 shadow-sm"><p className="text-2xl font-bold tabular-nums">{counts[status]}</p><p className="mt-1 text-xs text-muted-foreground">{labels[status]}</p></div>)}</div>
      <SectionCard title="Credential checks" description="A timeout or rate limit never turns a token into Invalid. Consecutive failures are tracked separately from provider status.">
        {rows.length === 0 ? <p className="text-sm text-muted-foreground">No credentials have been registered yet.</p> : <div className="divide-y divide-border">{rows.map((row) => {
          const status = row.validationStatus || 'not_tested'
          return <div key={row.id} className="flex flex-wrap items-center justify-between gap-3 py-3 first:pt-0 last:pb-0">
            <a href={`/vault/credentials/${row.id}`} className="min-w-0 flex-1 rounded-lg py-1 hover:text-primary">
              <span className="block break-all font-mono text-sm font-semibold">{row.name}</span>
              <span className="mt-1 block text-xs text-muted-foreground">{row.service}</span>
            </a>
            <div className="flex min-w-[11rem] flex-col items-end gap-1.5">
              <div className="flex items-center gap-2">{badge(status)}{row.validationFailureCount > 0 && <Badge variant="outline">{row.validationFailureCount} failed</Badge>}</div>
              <span className="text-right text-xs text-muted-foreground">{row.lastValidatedAt ? <>Last checked <TimeAgo ts={row.lastValidatedAt}/></> : 'Never checked'}</span>
              <span className="text-right text-xs text-muted-foreground">{row.nextValidationAt ? <>Next check <TimeAgo ts={row.nextValidationAt}/></> : 'No next check scheduled'}</span>
              {row.firstValidationFailureAt && <span className="text-right text-xs text-destructive">First failure <TimeAgo ts={row.firstValidationFailureAt}/></span>}
              {row.status === 'active' && row.hasValue && <RunCredentialValidationButton id={row.id}/>}
            </div>
          </div>
        })}</div>}
      </SectionCard>
      <SectionCard title="Recent validation history" description="Each scheduled or manual attempt is recorded with status, permissions metadata and duration. Secret values are never included.">
        {history.length === 0 ? <p className="text-sm text-muted-foreground">No validation attempts have been recorded yet.</p> : <div className="divide-y divide-border">
          {history.map((item) => <article key={item.id} className="flex flex-wrap items-start justify-between gap-3 py-3 first:pt-0 last:pb-0">
            <div className="min-w-0 flex-1">
              <a href={`/vault/credentials/${item.credentialId}`} className="break-all font-mono text-sm font-semibold hover:text-primary">{item.credentialName}</a>
              <p className="mt-1 text-xs text-muted-foreground">{item.provider} · {item.source === 'manual' ? 'Manual check' : 'Scheduled check'} · {item.durationMs} ms</p>
              <p className="mt-1 text-xs leading-relaxed text-muted-foreground">{item.message}</p>
            </div>
            <div className="flex shrink-0 flex-col items-end gap-1">{badge(item.status)}<TimeAgo ts={item.checkedAt}/></div>
          </article>)}
        </div>}
      </SectionCard>
    </div>
  })

  .page('/vault/analytics', async ({ request }) => {
    await requirePageSession(request)
    const analytics = await getUsageAnalytics(getDb())
    const maxHourly = Math.max(1, ...analytics.series.map((row) => row.requests))
    const successRate = analytics.totals.requests ? Math.round(analytics.totals.successes / analytics.totals.requests * 100) : 0
    const consumerRate = (successes: number, requests: number) => requests ? Math.round(successes / requests * 100) : 0
    const number = new Intl.NumberFormat('en-GB')
    return <div className="mx-auto w-full max-w-5xl space-y-6">
      <div><p className="text-xs font-semibold uppercase tracking-[0.16em] text-primary">Runtime insights</p><h1 className="mt-1 text-2xl font-bold tracking-tight">Usage analytics</h1><p className="mt-1 text-sm text-muted-foreground">Aggregated proxy activity over the last 30 days. Request headers, bodies and token values are never recorded.</p></div>
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        {[
          { label: 'Requests', value: number.format(analytics.totals.requests), icon: Activity },
          { label: 'Success rate', value: `${successRate}%`, icon: CheckCircle2 },
          { label: 'Average latency', value: analytics.totals.requests ? `${analytics.totals.averageLatencyMs} ms` : '—', icon: Clock3 },
          { label: 'Failed requests', value: number.format(analytics.totals.errors), icon: AlertTriangle },
          { label: 'Peak latency', value: analytics.totals.requests ? String(analytics.totals.maxLatencyMs) + ' ms' : '—', icon: Clock3 },
        ].map((metric) => { const Icon = metric.icon; return <div key={metric.label} className="rounded-2xl border border-border bg-card p-4 shadow-sm"><span className="grid size-9 place-items-center rounded-xl bg-primary/10 text-primary"><Icon className="size-4"/></span><p className="mt-4 text-2xl font-bold tabular-nums">{metric.value}</p><p className="mt-1 text-xs text-muted-foreground">{metric.label}</p></div>})}
      </div>
      <SectionCard title="Request volume" description="Hourly usage during the last 24 hours">
        {analytics.series.length === 0 ? <div className="grid min-h-36 place-items-center text-center"><div><ChartNoAxesCombined className="mx-auto size-8 text-muted-foreground"/><p className="mt-2 text-sm font-medium">No usage recorded yet</p><p className="mt-1 text-xs text-muted-foreground">The chart fills as the Runner and supported CLI tools make requests.</p></div></div> :
          <div className="space-y-2">{analytics.series.map((row) => <div key={row.windowStart} className="grid grid-cols-[4.5rem_minmax(0,1fr)_3rem] items-center gap-3 text-xs"><span className="text-muted-foreground">{new Date(row.windowStart).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', timeZone: 'UTC' })}</span><div className="h-2.5 overflow-hidden rounded-full bg-muted"><div className="h-full rounded-full bg-primary" style={{ width: `${Math.max(2, row.requests / maxHourly * 100)}%` }} /></div><span className="text-right tabular-nums text-muted-foreground">{row.requests}</span></div>)}</div>}
      </SectionCard>
      <SectionCard title="Usage by tool" description="Requests are attributed to the Runner or the CLI integration that initiated them. No request payloads or secrets are retained.">
        {analytics.consumers.length === 0 ? <p className="text-sm text-muted-foreground">No consumer usage recorded yet. CLI attribution appears after a tool makes its first proxy request.</p> : <div className="grid gap-3 sm:grid-cols-2">
          {analytics.consumers.map((row) => <article key={row.consumer} className="rounded-xl border border-border p-3">
            <div className="flex items-start justify-between gap-2"><div className="min-w-0"><p className="break-all font-mono text-sm font-semibold">{row.consumer === 'runner' ? 'Runner' : row.consumer.replace(/^cli:/, '')}</p><p className="mt-1 text-xs text-muted-foreground">{row.consumer === 'runner' ? 'Direct Runner proxy use' : 'CLI integration'}</p></div><Badge variant="outline">{consumerRate(row.successes, row.requests)}% success</Badge></div>
            <div className="mt-3 grid grid-cols-3 gap-2 border-t border-border pt-3">
              <div><p className="text-lg font-semibold tabular-nums">{number.format(row.requests)}</p><p className="text-[11px] text-muted-foreground">Requests</p></div>
              <div><p className="text-lg font-semibold tabular-nums">{number.format(row.errors)}</p><p className="text-[11px] text-muted-foreground">Errors</p></div>
              <div><p className="text-lg font-semibold tabular-nums">{row.averageLatencyMs} ms</p><p className="text-[11px] text-muted-foreground">Avg. latency</p></div>
            </div>
          </article>)}
        </div>}
      </SectionCard>
      <SectionCard title="Top credentials" description="Ranked by proxy request count over the last 30 days">
        {analytics.credentials.length === 0 ? <p className="text-sm text-muted-foreground">No credential usage to report.</p> : <div className="overflow-x-auto"><Table><TableHeader><TableRow><TableHead>Credential</TableHead><TableHead>Service</TableHead><TableHead>Requests</TableHead><TableHead>Success</TableHead><TableHead>Errors</TableHead><TableHead>Avg. latency</TableHead></TableRow></TableHeader><TableBody>{analytics.credentials.map((row) => <TableRow key={row.credentialId}><TableCell><a href={'/vault/credentials/' + row.credentialId} className="font-mono text-xs underline">{row.credentialName}</a></TableCell><TableCell>{row.service}</TableCell><TableCell className="tabular-nums">{number.format(row.requests)}</TableCell><TableCell className="tabular-nums">{consumerRate(row.successes, row.requests)}%</TableCell><TableCell className="tabular-nums">{number.format(row.errors)}</TableCell><TableCell className="tabular-nums">{row.averageLatencyMs} ms</TableCell></TableRow>)}</TableBody></Table></div>}
      </SectionCard>
    </div>
  })

  .page('/vault/integrations', async ({ request }) => {
    await requirePageSession(request)
    const rows = await listCredentialIntegrationMetadata(getDb())
    return <div className="mx-auto w-full max-w-4xl space-y-6">
      <div><p className="text-xs font-semibold uppercase tracking-[0.16em] text-primary">Tool connectivity</p><h1 className="mt-1 text-2xl font-bold tracking-tight">Integrations</h1><p className="mt-1 text-sm text-muted-foreground">See which command-line tools can consume each credential through the Vault proxy. Raw tokens are never passed to CLI arguments or environment variables.</p></div>
      {rows.length === 0 ? <SectionCard title="No integrations yet" description="Add a credential or register one from your Runner."/> : <div className="grid gap-3 lg:grid-cols-2">{rows.map((row) => <article key={row.id} className="min-w-0 rounded-2xl border border-border bg-card p-4 shadow-sm"><div className="flex items-start justify-between gap-3"><div className="min-w-0"><p className="break-all font-mono text-sm font-semibold">{row.name}</p><p className="mt-1 text-sm text-muted-foreground">{row.service}</p></div><Badge variant={row.status === 'active' ? 'secondary' : 'outline'}>{row.status}</Badge></div><div className="mt-3 rounded-xl bg-muted/60 p-3"><p className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">API host</p><p className="mt-1 break-all font-mono text-xs">{row.host ?? 'Not detected'}</p></div><div className="mt-3 space-y-2">{row.tools.length ? row.tools.map((tool) => <div key={tool.id} className="rounded-xl border border-border p-3"><div className="flex items-center gap-2"><Workflow className="size-4 text-primary"/><p className="text-sm font-semibold">{tool.label}</p><code className="ml-auto rounded-md bg-muted px-2 py-1 text-xs">{tool.binary}</code></div><p className="mt-2 text-xs leading-relaxed text-muted-foreground">{tool.setupHint}</p></div>) : <p className="text-xs text-muted-foreground">No CLI consumer has been verified for this service yet. It remains available through the Runner proxy API.</p>}</div></article>)}</div>}
    </div>
  })

  .page('/vault/audit', async ({ request }) => {
    await requirePageSession(request)
    const rows = await listAudit(getDb(), { limit: 200 })
    return (
      <div className="mx-auto w-full min-w-0 max-w-4xl space-y-4">
        <h1 className="text-xl font-semibold tracking-tight">Audit log</h1>
        <p className="text-sm text-muted-foreground">Append-only. Results are what the vault observed; no secret values are ever recorded.</p>
        <AuditTable rows={rows} />
      </div>
    )
  })

  .page('/vault/settings', async ({ request }) => {
    await requirePageSession(request)
    const { RevokeSessionsButton, AddExternalForm } = await import('./components/credential-actions.tsx')
    const { VaultSettingsForm } = await import('./components/vault-settings-form.tsx')
    const db = getDb()
    const preferences = await loadVaultPreferences(db)
    const policy = await loadRunnerPolicyInput(db)
    const fixedByEnv = Boolean((env as unknown as VaultEnv).RUNNER_REPOSITORY)
    const pinnedOwner = await loadOwnerId(db, vaultEnv())
    const buildOwner = String((env as unknown as VaultEnv).OWNER_GITHUB_ID ?? '')
    const ownerDiffers = Boolean(buildOwner && pinnedOwner && buildOwner !== pinnedOwner)
    return (
      <div className="mx-auto w-full max-w-4xl space-y-6">
        <div><p className="text-xs font-semibold uppercase tracking-[0.16em] text-primary">Vault preferences</p><h1 className="mt-1 text-2xl font-bold tracking-tight">Settings</h1><p className="mt-1 text-sm text-muted-foreground">Control validation, runtime behavior, notifications and retention. Provider security rules remain automatic.</p></div>
        {ownerDiffers && <p role="alert" className="rounded-xl border border-warning/30 bg-warning/5 p-4 text-sm">The deployment reports GitHub account ID {buildOwner}, but this vault remains bound to {pinnedOwner}. That change is ignored.</p>}
        <VaultSettingsForm initial={preferences} />
        <SectionCard title="Runner connection" description="OIDC trust is pinned to the first valid workflow from the owner’s main branch." icon={<Workflow className="size-5"/>}>
          {fixedByEnv ? <p className="text-sm text-muted-foreground">This deployment uses an explicit RUNNER_* trust policy.</p> : policy ? <dl className="grid grid-cols-[7.5rem_minmax(0,1fr)] gap-x-3 gap-y-2 text-sm"><dt className="text-muted-foreground">Repository</dt><dd className="break-all font-mono">{policy.repository}</dd><dt className="text-muted-foreground">Repository ID</dt><dd className="font-mono">{policy.repositoryId}</dd><dt className="text-muted-foreground">Owner ID</dt><dd className="font-mono">{policy.repositoryOwnerId ?? 'legacy policy'}</dd><dt className="text-muted-foreground">Branch</dt><dd className="font-mono">{policy.branch}</dd><dt className="text-muted-foreground">Workflow</dt><dd className="break-all font-mono">{policy.workflowFile}</dd></dl> : <p className="rounded-xl bg-muted/50 p-3 text-sm text-muted-foreground">Waiting for the first valid owner-owned workflow run. Pull-request events are rejected.</p>}
        </SectionCard>
        <SectionCard title="Runner sessions" description="Sessions last 30 minutes. Revoking invalidates every session issued so far." icon={<ShieldCheck className="size-5"/>}>
          <RevokeSessionsButton />
        </SectionCard>
        <SectionCard title="Entries managed elsewhere" description="Metadata-only entries such as GITHUB_TOKEN. Vault stores no value and never proxies these credentials." icon={<KeyRound className="size-5"/>}>
          <AddExternalForm />
        </SectionCard>
      </div>
    )
  })

  .use(runnerApp)

function lockedReason(e: VaultEnv): string {
  switch (e.DEPLOY_OWNER_ERROR) {
    case 'organization':
      return 'The repository this was deployed from belongs to an organization, and a personal GitHub account must own the vault. Set the build variable RUNNER_VAULT_OWNER_GITHUB_ID to your numeric GitHub user ID (github.com/settings/profile shows your login; api.github.com/users/<login> shows the id) and redeploy.'
    case 'lookup_failed':
      return 'GitHub could not be reached while building, so the owner could not be verified. Redeploy, or set the build variable RUNNER_VAULT_OWNER_GITHUB_ID to your numeric GitHub user ID.'
    case 'no_identity':
      return 'No GitHub identity was available while building. Deploy from your own GitHub repository, or set the build variable RUNNER_VAULT_OWNER_GITHUB_ID to your numeric GitHub user ID, then redeploy.'
    default:
      return 'This vault stays locked until the deployment build verifies the GitHub owner. Reload after the build finishes.'
  }
}

function AuditTable({ rows }: { rows: Awaited<ReturnType<typeof listAudit>> }) {
  if (rows.length === 0) return <p className="text-sm text-muted-foreground">No activity yet.</p>
  return (
    <>
      <div className="hidden overflow-x-auto sm:block">
        <Table>
          <TableHeader><TableRow><TableHead>When</TableHead><TableHead>Action</TableHead><TableHead>Credential</TableHead><TableHead>Result</TableHead><TableHead>Actor</TableHead><TableHead>Request detail</TableHead></TableRow></TableHeader>
          <TableBody>
            {rows.map((r) => (
              <TableRow key={r.id}>
                <TableCell><TimeAgo ts={r.at} /></TableCell>
                <TableCell>{r.action}</TableCell>
                <TableCell className="font-mono">{r.credentialName || '—'}</TableCell>
                <TableCell>{r.result || '—'}</TableCell>
                <TableCell className="max-w-48 truncate" title={r.actor}>{r.actor}</TableCell>
                <TableCell className="max-w-72 truncate" title={r.detail}>{r.detail || '—'}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
      <div className="grid gap-3 sm:hidden">
        {rows.map((r) => (
          <article key={r.id} className="min-w-0 space-y-3 rounded-xl border border-border bg-card p-3">
            <div className="flex min-w-0 items-start justify-between gap-3">
              <div className="min-w-0">
                <p className="break-words text-sm font-semibold">{r.action}</p>
                <p className="mt-1 break-all font-mono text-xs text-muted-foreground">{r.credentialName || '—'}</p>
              </div>
              <span className="shrink-0 rounded-full border border-border px-2 py-1 text-xs">{r.result || '—'}</span>
            </div>
            <div className="grid grid-cols-2 gap-3 border-t border-border pt-3 text-xs">
              <div><p className="text-muted-foreground">When</p><p className="mt-1"><TimeAgo ts={r.at} /></p></div>
              <div className="min-w-0"><p className="text-muted-foreground">Actor</p><p className="mt-1 break-all">{r.actor}</p></div>
            </div>
            {r.detail ? <p className="break-words border-t border-border pt-3 text-xs text-muted-foreground">{r.detail}</p> : null}
          </article>
        ))}
      </div>
    </>
  )
}

export type App = typeof app

export default {
  fetch: (request: Request) => app.handle(request),
  scheduled: (_controller, _environment, context) => {
    context.waitUntil((async () => {
      await ensureSchema(env.DB)
      const db = getDb()
      const keys = await loadVaultKeys(db, vaultEnv())
      await runScheduledCredentialValidation(db, keys.encryptionKey)
    })())
  },
} satisfies ExportedHandler<Env>

declare module 'spiceflow/react' {
  interface SpiceflowRegister { app: typeof app }
}

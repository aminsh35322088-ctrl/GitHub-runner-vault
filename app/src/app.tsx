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
import { KeyRound, LayoutDashboard, Plus, ChartNoAxesCombined, ShieldCheck, Settings as SettingsIcon, ClipboardList, Workflow, LogOut, Activity, Clock3, CheckCircle2, AlertTriangle, ChevronRight } from 'lucide-react'
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
  const navItems = [
    { href: '/vault', label: 'Overview', icon: LayoutDashboard },
    { href: '/vault/services', label: 'Add', icon: Plus },
    { href: '/vault/validation', label: 'Health', icon: ShieldCheck },
    { href: '/vault/analytics', label: 'Analytics', icon: ChartNoAxesCombined },
    { href: '/vault/settings', label: 'Settings', icon: SettingsIcon },
  ]
  const isActive = (href: string) => href === '/vault' ? current === href : current === href || current.startsWith(href + '/')
  return (
    <html lang="en" className={cn('h-dvh', dark ? 'dark' : undefined)} suppressHydrationWarning>
      <Head>
        <Head.Meta charSet="UTF-8" />
        <Head.Meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover" />
        <Head.Meta name="robots" content="noindex, nofollow" />
        <Head.Title>Runner Credential Vault</Head.Title>
      </Head>
      <body className="flex h-dvh flex-col bg-background font-sans antialiased">
        <script dangerouslySetInnerHTML={{ __html: themeScript }} />
        <header className="sticky top-0 z-30 shrink-0 border-b border-border/80 bg-background/90 backdrop-blur-xl">
          <div className="mx-auto flex h-[4.25rem] max-w-(--content-max-width) items-center justify-between gap-4 px-3 sm:px-6">
            <a href="/vault" className="group flex min-w-0 items-center gap-3">
              <span className="grid size-10 shrink-0 place-items-center rounded-2xl bg-gradient-to-br from-emerald-500 to-teal-700 text-white shadow-lg shadow-emerald-900/15 transition-transform group-hover:rotate-[-4deg]">
                <KeyRound className="size-5" aria-hidden />
              </span>
              <span className="min-w-0">
                <span className="block truncate text-sm font-bold tracking-tight sm:text-base">Runner Vault</span>
                <span className="hidden text-[11px] font-medium tracking-[0.12em] text-muted-foreground sm:block">CREDENTIAL CONTROL PLANE</span>
              </span>
            </a>
            {signedIn && (
              <>
                <nav aria-label="Primary navigation" className="hidden items-center gap-1 lg:flex">
                  {navItems.map((item) => {
                    const Icon = item.icon
                    const active = isActive(item.href)
                    return <a key={item.href} href={item.href} aria-current={active ? 'page' : undefined} className={cn('inline-flex min-h-10 items-center gap-2 rounded-xl px-3 text-sm font-medium transition-colors', active ? 'bg-primary/10 text-primary' : 'text-muted-foreground hover:bg-muted hover:text-foreground')}>
                      <Icon className="size-4" aria-hidden />{item.label}
                    </a>
                  })}
                  <a href="/vault/audit" className={cn('inline-flex min-h-10 items-center gap-2 rounded-xl px-3 text-sm font-medium transition-colors', isActive('/vault/audit') ? 'bg-primary/10 text-primary' : 'text-muted-foreground hover:bg-muted hover:text-foreground')}>
                    <ClipboardList className="size-4" aria-hidden />Audit
                  </a>
                </nav>
                <div className="flex shrink-0 items-center gap-2">
<NotificationBell unread={unread} notifications={notifications} />
                  <a href="/vault/settings" aria-label="Settings" className="hidden size-10 place-items-center rounded-xl border border-border bg-card text-muted-foreground transition-colors hover:bg-muted hover:text-foreground sm:grid lg:hidden">
                    <SettingsIcon className="size-[18px]" aria-hidden />
                  </a>
                  <a href="/logout" aria-label="Sign out" className="grid size-10 place-items-center rounded-xl border border-border text-muted-foreground transition-colors hover:bg-muted hover:text-foreground">
                    <LogOut className="size-[18px]" aria-hidden />
                  </a>
                </div>
              </>
            )}
          </div>
        </header>
        <div className="min-h-0 grow overflow-y-auto">
          <main className="mx-auto min-h-full max-w-(--content-max-width) px-3 pb-28 pt-5 sm:border-x sm:px-6 sm:pb-10 sm:pt-7">{children}</main>
        </div>
        {signedIn && (
          <nav aria-label="Mobile navigation" className="fixed inset-x-0 bottom-0 z-30 border-t border-border/80 bg-background/90 pb-[env(safe-area-inset-bottom)] shadow-[0_-8px_28px_-18px_rgba(0,0,0,.45)] backdrop-blur-xl lg:hidden">
            <div className="mx-auto grid max-w-xl grid-cols-5 gap-1 px-2 pt-2">
              {navItems.map((item) => {
                const Icon = item.icon
                const active = isActive(item.href)
                return <a key={item.href} href={item.href} aria-current={active ? 'page' : undefined} className={cn('flex min-h-14 flex-col items-center justify-center gap-1 rounded-xl px-1 text-[10px] font-semibold transition-colors', active ? 'bg-primary/10 text-primary' : 'text-muted-foreground hover:bg-muted')}>
                  <Icon className={cn('size-[19px]', active && 'stroke-[2.4]')} aria-hidden />
                  <span>{item.label}</span>
                </a>
              })}
            </div>
          </nav>
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
    const rows = await listCredentialsForOwner(getDb())
    const now = Date.now()
    const runnerPolicy = await loadRunnerPolicyInput(getDb())
    const runnerConfigured = runnerPolicy !== null || Boolean((env as unknown as VaultEnv).RUNNER_REPOSITORY)
    const runnerOwnerReady = Boolean(await loadOwnerId(getDb(), vaultEnv()))
    const validCount = rows.filter((row) => row.validationStatus === 'valid').length
    const invalidCount = rows.filter((row) => row.validationStatus === 'invalid' || row.validationStatus === 'expired').length
    const pendingCount = rows.filter((row) => !row.lastValidatedAt || row.validationStatus === 'unavailable' || row.validationStatus === 'unsupported').length
    const preferences = await loadVaultPreferences(getDb())
    return (
      <div className="mx-auto w-full min-w-0 max-w-5xl space-y-6">
        <section className="relative isolate overflow-hidden rounded-[1.75rem] bg-gradient-to-br from-slate-950 via-emerald-950 to-teal-900 px-5 py-6 text-white shadow-xl shadow-emerald-950/10 sm:px-7 sm:py-8">
          <div className="pointer-events-none absolute -right-12 -top-20 -z-10 size-72 rounded-full bg-emerald-400/15 blur-3xl"/>
          <div className="pointer-events-none absolute -bottom-24 left-1/3 -z-10 size-60 rounded-full bg-cyan-400/10 blur-3xl"/>
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div className="max-w-2xl"><p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-emerald-200">Credential control plane</p><h1 className="mt-2 text-2xl font-bold tracking-tight sm:text-3xl">Your secrets, under control.</h1><p className="mt-2 max-w-xl text-sm leading-relaxed text-slate-200/80">One secure access layer for runners, integrations and every API credential your infrastructure depends on.</p></div>
            <a href="/vault/services" className="inline-flex min-h-11 items-center gap-2 rounded-xl bg-white px-4 text-sm font-semibold text-slate-950 shadow-lg transition-transform hover:-translate-y-0.5"><Plus className="size-4"/> Add credential</a>
          </div>
          <div className="mt-7 flex flex-wrap items-center gap-3 text-xs text-slate-200/80">
            <span className="inline-flex items-center gap-2 rounded-full border border-white/15 bg-white/10 px-3 py-1.5"><span className={cn('size-1.5 rounded-full', runnerOwnerReady ? 'bg-emerald-300' : 'bg-amber-300')}/>{runnerOwnerReady ? 'Owner identity verified' : 'Runner identity pending'}</span>
            <span className="rounded-full border border-white/15 bg-white/10 px-3 py-1.5">Scheduled checks · every {preferences.validationIntervalHours}h</span>
            <a href="/vault/integrations" className="inline-flex items-center gap-1 underline underline-offset-4">View integrations <ChevronRight className="size-3"/></a>
          </div>
        </section>
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
          {[
            { label: 'Total credentials', value: rows.length, icon: KeyRound, tone: 'bg-slate-500/10 text-slate-600 dark:text-slate-300' },
            { label: 'Verified', value: validCount, icon: CheckCircle2, tone: 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-300' },
            { label: 'Need attention', value: invalidCount, icon: AlertTriangle, tone: 'bg-rose-500/10 text-rose-700 dark:text-rose-300' },
            { label: 'Not yet confirmed', value: pendingCount, icon: Clock3, tone: 'bg-amber-500/10 text-amber-700 dark:text-amber-300' },
          ].map((metric) => { const Icon = metric.icon; return <div key={metric.label} className="rounded-2xl border border-border bg-card p-4 shadow-sm"><span className={cn('grid size-9 place-items-center rounded-xl', metric.tone)}><Icon className="size-[18px]"/></span><p className="mt-4 text-2xl font-bold tabular-nums tracking-tight">{metric.value}</p><p className="mt-1 text-xs text-muted-foreground">{metric.label}</p></div> })}
        </div>
        <div className="flex flex-wrap items-center justify-between gap-2"><div><h2 className="text-lg font-semibold tracking-tight">Credential registry</h2><p className="mt-1 text-sm text-muted-foreground">Encrypted values stay write-only. Runners receive access through the proxy.</p></div><div className="flex gap-2"><a href="/vault/validation" className="inline-flex min-h-10 items-center gap-2 rounded-xl border border-border bg-card px-3 text-sm font-medium hover:bg-muted"><ShieldCheck className="size-4"/> Health</a><a href="/vault/analytics" className="inline-flex min-h-10 items-center gap-2 rounded-xl border border-border bg-card px-3 text-sm font-medium hover:bg-muted"><ChartNoAxesCombined className="size-4"/> Analytics</a></div></div>
        {!runnerConfigured && runnerOwnerReady && (
          <div role="status" className="rounded-lg border border-border bg-muted/40 p-4 space-y-1">
            <p className="text-sm font-medium">Automatic runner connection is ready</p>
            <p className="text-sm text-muted-foreground">
              The first valid run of the owner’s main/.github/workflows/rdc-lab.yml workflow
              will bind its immutable repository and owner IDs automatically. No repository ID or manual policy setup is needed.
            </p>
          </div>
        )}
        {!runnerConfigured && !runnerOwnerReady && (
          <div role="alert" className="rounded-lg border border-border bg-muted/40 p-4 space-y-1">
            <p className="text-sm font-medium">Runner auto-connection is unavailable</p>
            <p className="text-sm text-muted-foreground">This deployment has no pinned GitHub owner identity, so OIDC bootstrap fails closed.</p>
          </div>
        )}
        {rows.length === 0 ? (
          <p className="text-sm text-muted-foreground">Nothing registered yet. Add a credential here, or let a model on the runner request one.</p>
        ) : (
          <>
            <div className="hidden overflow-x-auto sm:block">
              <Table>
                <TableHeader>
                  <TableRow><TableHead>Name</TableHead><TableHead>Service</TableHead><TableHead>Status</TableHead><TableHead>Use</TableHead><TableHead>Expires</TableHead><TableHead>Last used</TableHead></TableRow>
                </TableHeader>
                <TableBody>
                  {rows.map((c) => (
                    <TableRow key={c.id}>
                      <TableCell><a className="font-mono underline" href={`/vault/credentials/${c.id}`}>{c.name}</a></TableCell>
                      <TableCell>{c.service}</TableCell>
                      <TableCell>{statusBadge(c, now)}</TableCell>
                      <TableCell>{c.externallyManaged ? 'external' : c.delivery}</TableCell>
                      <TableCell>{c.expiresAt ? <TimeAgo ts={c.expiresAt} /> : c.lifetime === 'permanent' ? 'never' : '—'}</TableCell>
                      <TableCell>{c.lastUsedAt ? <TimeAgo ts={c.lastUsedAt} /> : '—'}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
            <div className="grid gap-3 sm:hidden">
              {rows.map((c) => (
                <a key={c.id} href={`/vault/credentials/${c.id}`} className="block min-w-0 rounded-xl border border-border bg-card p-4 active:bg-muted/50">
                  <div className="flex min-w-0 items-start justify-between gap-3">
                    <div className="min-w-0">
                      <p className="break-all font-mono text-sm font-semibold">{c.name}</p>
                      <p className="mt-1 text-sm text-muted-foreground">{c.service}</p>
                    </div>
                    {statusBadge(c, now)}
                  </div>
                  <div className="mt-3 grid grid-cols-2 gap-3 border-t border-border pt-3 text-sm">
                    <div><p className="text-xs text-muted-foreground">Delivery</p><p>{c.externallyManaged ? 'External' : c.delivery}</p></div>
                    <div><p className="text-xs text-muted-foreground">Expires</p><p>{c.expiresAt ? <TimeAgo ts={c.expiresAt} /> : c.lifetime === 'permanent' ? 'Never' : '—'}</p></div>
                    <div className="col-span-2"><p className="text-xs text-muted-foreground">Last used</p><p>{c.lastUsedAt ? <TimeAgo ts={c.lastUsedAt} /> : 'Never'}</p></div>
                  </div>
                </a>
              ))}
            </div>
          </>
        )}
      </div>
    )
  })

  // ── Owner-facing provider catalog and direct registration ─────────
  .page('/vault/services', async ({ request }) => {
    await requirePageSession(request)
    const { ServiceCatalog } = await import('./components/service-catalog.tsx')
    return <div className="mx-auto w-full min-w-0 max-w-4xl space-y-5"><div><h1 className="text-xl font-semibold tracking-tight">Add a credential</h1><p className="mt-1 text-sm text-muted-foreground">Choose a provider to prefill its API host and authentication style, or configure a custom service.</p></div><ServiceCatalog /></div>
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
      <div className="mx-auto w-full min-w-0 max-w-3xl space-y-5 sm:space-y-6">
        <div className="space-y-2">
          <div className="flex min-w-0 flex-wrap items-start gap-2"><h1 className="min-w-0 break-all font-mono text-base font-semibold tracking-tight sm:text-lg">{c.name}</h1>{statusBadge(c, now)}</div>
          <p className="break-words text-sm text-muted-foreground">{c.service}</p>
        </div>
        <dl className="grid min-w-0 grid-cols-[7.5rem_minmax(0,1fr)] gap-x-3 gap-y-2 rounded-xl border border-border p-3 text-sm sm:grid-cols-[10rem_minmax(0,1fr)] sm:p-4">
          <dt className="text-muted-foreground">Delivery</dt><dd className="break-words">{c.externallyManaged ? 'managed elsewhere (metadata only)' : c.delivery}</dd>
          <dt className="text-muted-foreground">Allowed hosts</dt><dd className="break-all font-mono">{c.allowedHosts.join(', ') || '—'}</dd>
          <dt className="text-muted-foreground">Auth header</dt><dd className="break-words font-mono">{c.authHeader}: {c.authScheme}</dd>
          <dt className="text-muted-foreground">Lifetime</dt><dd className="break-words">{c.lifetime}{c.expiresAt ? <> · expires <TimeAgo ts={c.expiresAt} /></> : null}</dd>
          <dt className="text-muted-foreground">Value stored</dt><dd>{c.hasValue ? 'yes (write-only)' : 'no'}</dd>
          <dt className="text-muted-foreground">Last checked</dt><dd>{c.lastValidatedAt ? <TimeAgo ts={c.lastValidatedAt}/> : 'Never'}</dd>
          <dt className="text-muted-foreground">Next check</dt><dd>{c.nextValidationAt ? <TimeAgo ts={c.nextValidationAt}/> : 'Not scheduled'}</dd>
          {c.firstValidationFailureAt && <><dt className="text-muted-foreground">First failure</dt><dd><TimeAgo ts={c.firstValidationFailureAt}/> · {c.validationFailureCount} consecutive failures</dd></>}
        </dl>
        <CredentialValidationSummary value={c.validationDetails} />
        <section className="rounded-xl border border-border p-4 sm:p-5">
          <CredentialControls id={c.id} name={c.name} enabled={c.status === 'active'} visible={c.visible} canEnable={c.hasValue || c.externallyManaged} />
        </section>
        {c.doc && <DocView doc={c.doc} />}
        {!c.externallyManaged && (
          <section className="space-y-3 rounded-xl border border-border p-4 sm:p-5">
            <h2 className="text-base font-semibold">Replace value or change rules</h2>
            <CredentialForm mode="replace" id={c.id} credentialId={c.id} serviceName={c.service} apiBaseUrl={serviceAdapterFromDocument(c.doc)?.apiBaseUrl ?? serviceAdapterFor(c.service)?.apiBaseUrl} defaults={{ visible: c.visible, lifetime: c.lifetime }} />
          </section>
        )}
        <section className="space-y-3 rounded-xl border border-border p-4 sm:p-5">
          <h2 className="text-sm font-semibold">Recent activity</h2>
          <AuditTable rows={log} />
        </section>
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

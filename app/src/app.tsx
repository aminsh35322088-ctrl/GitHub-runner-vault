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
import { formatAllowedHosts, presetForService } from './lib/presets.ts'
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

const themeScript = `(function(){var d=document.documentElement;var m=document.cookie.match(/(?:^|;\\s*)color-theme=(light|dark)(?:;|$)/);var t=m?m[1]:null;if(!t)t=window.matchMedia('(prefers-color-scheme:dark)').matches?'dark':'light';if(t==='dark')d.classList.add('dark');else d.classList.remove('dark')})()`

// Only allow local vault paths for post-login redirects.
function safeRedirectPath(value: string | null): string {
  if (!value || !value.startsWith('/') || value.startsWith('//')) return '/vault'
  if (value === '/vault' || value.startsWith('/vault/')) return value
  return '/vault'
}

function Shell({ request, children, signedIn }: { request: Request; children: React.ReactNode; signedIn?: boolean }) {
  const dark = /(?:^|;\s*)color-theme=dark(?:;|$)/.test(request.headers.get('cookie') ?? '')
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
        <nav className="z-20 shrink-0 border-b border-border bg-background">
          <div className="mx-auto flex h-14 max-w-(--content-max-width) items-center justify-between px-3 sm:border-x sm:px-6">
            <a href="/vault" className="font-semibold tracking-tight">Runner Credential Vault</a>
            {signedIn && (
              <>
                <div className="hidden items-center gap-5 text-sm text-muted-foreground sm:flex">
                  <a href="/vault" className="hover:text-foreground">Credentials</a>
                  <a href="/vault/services" className="hover:text-foreground">Add credential</a>
                  <a href="/vault/audit" className="hover:text-foreground">Audit</a>
                  <a href="/vault/settings" className="hover:text-foreground">Settings</a>
                  <a href="/logout" className="hover:text-foreground">Sign out</a>
                </div>
                <a href="/logout" className="rounded-lg border border-border px-3 py-2 text-sm sm:hidden">Sign out</a>
              </>
            )}
          </div>
        </nav>
        <div className="min-h-0 grow overflow-y-auto">
          <main className="mx-auto min-h-full max-w-(--content-max-width) px-3 pb-24 pt-4 sm:border-x sm:px-6 sm:pb-8 sm:pt-6">{children}</main>
        </div>
        {signedIn && (
          <nav aria-label="Mobile navigation" className="fixed inset-x-0 bottom-0 z-30 border-t border-border bg-background/95 pb-[env(safe-area-inset-bottom)] shadow-[0_-6px_24px_-16px_rgba(0,0,0,.35)] backdrop-blur sm:hidden">
            <div className="mx-auto grid max-w-md grid-cols-4 gap-1 px-2 pt-2">
              {[
                { href: '/vault', label: 'Credentials' },
                { href: '/vault/services', label: 'Add' },
                { href: '/vault/audit', label: 'Audit' },
                { href: '/vault/settings', label: 'Settings' },
              ].map((item) => {
                const current = new URL(request.url).pathname
                const active = item.href === '/vault' ? current === '/vault' : current === item.href || current.startsWith(item.href + '/')
                return <a key={item.href} href={item.href} aria-current={active ? 'page' : undefined} className={cn('flex min-h-11 items-center justify-center rounded-lg px-1 text-center text-xs font-medium', active ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:bg-muted')}>{item.label}</a>
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
        <ul className="grid gap-2 sm:grid-cols-2">
          {report.permissions.map((item, index) => (
            <li key={index} className="min-w-0 rounded-lg border border-border px-3 py-2">
              <p className="break-words text-sm font-medium">{item.name ?? 'Permission'}</p>
              <p className="break-words text-xs text-muted-foreground">{item.access ?? 'unknown'}{item.scope ? ` · ${item.scope}` : ''}</p>
              {item.resources?.length ? <p className="mt-1 break-all text-xs text-muted-foreground">{item.resources.join(', ')}</p> : null}
            </li>
          ))}
        </ul>
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
    const runnerConfigured = (await loadRunnerPolicyInput(getDb())) !== null || Boolean((env as unknown as VaultEnv).RUNNER_REPOSITORY)
    return (
      <div className="mx-auto w-full min-w-0 max-w-4xl space-y-4">
        <div className="flex min-w-0 flex-wrap items-center justify-between gap-3"><h1 className="text-xl font-semibold tracking-tight">Credentials</h1><a href="/vault/services" className="inline-flex min-h-11 flex-1 items-center justify-center rounded-lg bg-primary px-3 py-2 text-sm font-medium text-primary-foreground sm:flex-none">+ Add credential</a></div>
        {!runnerConfigured && (
          <div role="status" className="rounded-lg border border-border bg-muted/40 p-4 space-y-1">
            <p className="text-sm font-medium">Next step: connect your runner repository</p>
            <p className="text-sm text-muted-foreground">
              Runners cannot reach the vault until you say which repository and workflow may.{' '}
              <a className="underline" href="/vault/settings">Open settings</a>.
            </p>
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
    const { CredentialForm } = await import('./components/credential-form.tsx')
    return <div className="mx-auto w-full min-w-0 max-w-3xl space-y-5"><div><a href="/vault/services" className="inline-flex min-h-11 items-center text-sm underline underline-offset-4">← Provider catalog</a><h1 className="mt-2 text-xl font-semibold tracking-tight">{preset ? `Configure ${preset.label}` : 'Configure a custom service'}</h1><p className="mt-1 text-sm text-muted-foreground">Review the provider settings, enter the secret, and explicitly create the credential. The secret is write-only.</p></div><CredentialForm mode="create" preset={preset ? { label: preset.label, docsUrl: preset.docsUrl } : null} defaults={{ delivery: 'proxy', allowedHosts: preset ? formatAllowedHosts(preset.hosts) : '', authHeader: preset?.authHeader ?? 'Authorization', authScheme: preset?.authScheme ?? 'Bearer', visible: true, lifetime: 'permanent' }} /></div>
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
    return (
      <div className="mx-auto w-full min-w-0 max-w-3xl space-y-5 sm:space-y-6">
        <div>
          <h1 className="break-all text-base font-semibold tracking-tight font-mono sm:text-lg">{credential.name}</h1>
          <p className="mt-1 text-sm text-muted-foreground">{credential.service}</p>
          <p className="text-xs text-muted-foreground mt-1">Link expires in about {Math.max(1, Math.round((link.expiresAt - Date.now()) / 60_000))} min and works once.</p>
        </div>
        {credential.doc && <DocView doc={credential.doc} />}
        <CredentialForm mode="register" token={params.token} serviceName={credential.service} preset={preset ? { label: preset.label } : null} defaults={{ delivery: 'proxy', allowedHosts: preset ? formatAllowedHosts(preset.hosts) : '', authHeader: preset?.authHeader ?? 'Authorization', authScheme: preset?.authScheme ?? 'Bearer', visible: true, lifetime: 'permanent' }} />
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
        </dl>
        <CredentialValidationSummary value={c.validationDetails} />
        <section className="rounded-xl border border-border p-4 sm:p-5">
          <CredentialControls id={c.id} name={c.name} enabled={c.status === 'active'} visible={c.visible} canEnable={c.hasValue || c.externallyManaged} />
        </section>
        {c.doc && <DocView doc={c.doc} />}
        {!c.externallyManaged && (
          <section className="space-y-3 rounded-xl border border-border p-4 sm:p-5">
            <h2 className="text-base font-semibold">Replace value or change rules</h2>
            <CredentialForm mode="replace" id={c.id} serviceName={c.service} defaults={{ delivery: c.delivery, allowedHosts: c.allowedHosts.join('\n'), authHeader: c.authHeader, authScheme: c.authScheme, visible: c.visible, lifetime: c.lifetime }} />
          </section>
        )}
        <section className="space-y-3 rounded-xl border border-border p-4 sm:p-5">
          <h2 className="text-sm font-semibold">Recent activity</h2>
          <AuditTable rows={log} />
        </section>
      </div>
    )
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
    const { RevokeSessionsButton, AddExternalForm, RunnerPolicyForm } = await import('./components/credential-actions.tsx')
    const policy = await loadRunnerPolicyInput(getDb())
    const fixedByEnv = Boolean((env as unknown as VaultEnv).RUNNER_REPOSITORY)
    const pinnedOwner = await loadOwnerId(getDb(), vaultEnv())
    const buildOwner = String((env as unknown as VaultEnv).OWNER_GITHUB_ID ?? '')
    const ownerDiffers = Boolean(buildOwner && pinnedOwner && buildOwner !== pinnedOwner)
    return (
      <div className="mx-auto w-full max-w-3xl space-y-5 sm:space-y-8">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Settings</h1>
          <p className="mt-1 text-sm text-muted-foreground">Manage runner access and credential security.</p>
        </div>
        {ownerDiffers && (
          <p role="alert" className="rounded-lg border border-border bg-muted/40 p-4 text-sm">
            The deployment now reports GitHub account ID {buildOwner}, but this vault stays bound to {pinnedOwner}, set when it was first deployed. The change is ignored. To bind a different account, delete the <code>owner_github_id</code> row from the <code>vault_setting</code> table (only possible before a sign-in app is registered) or deploy a fresh vault.
          </p>
        )}
        <section className="space-y-3 rounded-xl border border-border p-4 sm:p-5">
          <h2 className="text-base font-semibold">Runner repository</h2>
          <p className="text-sm text-muted-foreground">
            Only this repository's workflow, on this branch, can sign in as a runner. Pull-request runs are never accepted.
          </p>
          {fixedByEnv ? (
            <p className="text-sm text-muted-foreground">This is fixed by the Worker's RUNNER_* variables and cannot be changed here.</p>
          ) : (
            <RunnerPolicyForm defaults={{ repository: policy?.repository ?? '', branch: policy?.branch ?? 'main', workflowFile: policy?.workflowFile ?? 'rdc-lab.yml', repositoryId: policy?.repositoryId ?? '' }} />
          )}
        </section>
        <section className="space-y-3 rounded-xl border border-border p-4 sm:p-5">
          <h2 className="text-base font-semibold">Runner sessions</h2>
          <p className="text-sm text-muted-foreground">Sessions last 30 minutes. Revoking invalidates every session issued so far, for example after a runner reset.</p>
          <RevokeSessionsButton />
        </section>
        <section id="advanced-credential-settings" className="space-y-3 rounded-xl border border-border p-4 sm:p-5">
          <div>
            <h2 className="text-base font-semibold">Advanced settings</h2>
            <p className="mt-1 text-sm text-muted-foreground">These settings are configured per credential, so one token cannot inherit another token's network access.</p>
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="rounded-lg bg-muted/40 p-3"><p className="text-sm font-medium">Network restrictions</p><p className="mt-1 text-sm text-muted-foreground">Exact allowed hostnames; the proxy refuses every other destination.</p></div>
            <div className="rounded-lg bg-muted/40 p-3"><p className="text-sm font-medium">Authentication mapping</p><p className="mt-1 text-sm text-muted-foreground">Header name and Bearer, Token or Raw scheme for each provider.</p></div>
            <div className="rounded-lg bg-muted/40 p-3"><p className="text-sm font-medium">Lifetime & visibility</p><p className="mt-1 text-sm text-muted-foreground">Expiry, permanent or temporary storage, and runner visibility.</p></div>
            <div className="rounded-lg bg-muted/40 p-3"><p className="text-sm font-medium">Token inspection</p><p className="mt-1 text-sm text-muted-foreground">Provider identity and available permissions are recorded without storing the token in reports.</p></div>
          </div>
          <a href="/vault" className="inline-flex min-h-11 items-center rounded-lg border border-border px-3 py-2 text-sm font-medium underline underline-offset-4">Open credentials to edit advanced settings</a>
        </section>
        <section className="space-y-3 rounded-xl border border-border p-4 sm:p-5">
          <h2 className="text-base font-semibold">Entries managed elsewhere</h2>
          <p className="text-sm text-muted-foreground">Lists a credential (such as GITHUB_TOKEN) so runners know it exists. The vault stores no value for it and never proxies it.</p>
          <AddExternalForm />
        </section>
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
  fetch: (request: Request) => {
    return app.handle(request)
  },
} satisfies ExportedHandler<Env>

declare module 'spiceflow/react' {
  interface SpiceflowRegister { app: typeof app }
}

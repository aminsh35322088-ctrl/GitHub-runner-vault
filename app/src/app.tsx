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
import {
  SETUP_STATE_COOKIE, SETUP_STATE_MAX_AGE_SECONDS, buildManifest, convertManifest, isConfigured, loadOwnerLogin, loadVaultKeys,
  newSetupState, saveGithubApp, setupStateMatches, type VaultEnv,
} from './lib/vault-config.ts'
import { Button } from './components/ui/button'
import { runnerApp } from './runner-api.ts'
import { normalizeOwnerId } from './lib/owner.ts'
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
        <Head.Meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <Head.Meta name="robots" content="noindex, nofollow" />
        <Head.Title>Runner Credential Vault</Head.Title>
      </Head>
      <body className="flex h-dvh flex-col bg-background font-sans antialiased">
        <script dangerouslySetInnerHTML={{ __html: themeScript }} />
        <nav className="shrink-0 border-b border-border">
          <div className="max-w-(--content-max-width) mx-auto border-x border-border flex h-14 items-center justify-between px-4 sm:px-6">
            <a href="/vault" className="font-semibold tracking-tight">Runner Credential Vault</a>
            {signedIn && (
              <div className="flex items-center gap-4 text-sm text-muted-foreground">
                <a href="/vault" className="hover:text-foreground">Credentials</a>
                <a href="/vault/services" className="hover:text-foreground">Add credential</a>
                <a href="/vault/audit" className="hover:text-foreground">Audit</a>
                <a href="/vault/settings" className="hover:text-foreground">Settings</a>
                <a href="/logout" className="hover:text-foreground">Sign out</a>
              </div>
            )}
          </div>
        </nav>
        <div className="min-h-0 grow overflow-y-auto">
          <main className="max-w-(--content-max-width) mx-auto border-x border-border min-h-full p-4 sm:p-6">{children}</main>
        </div>
      </body>
    </html>
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

  // ── First-time setup ──────────────────────────────────────────────
  // No password: the first person to finish GitHub's manifest flow owns the vault.
  .page('/setup', async ({ request }) => {
    const db = getDb()
    const e = vaultEnv()
    const keys = await loadVaultKeys(db, e)
    const expectedOwnerId = normalizeOwnerId(e.OWNER_GITHUB_ID)
    if (!expectedOwnerId) {
      return <Message title="Waiting for deployment verification" text="This vault stays locked until the Deploy to Cloudflare workflow verifies and provisions its GitHub owner. Reload this page after deployment finishes." />
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
          This deployment is permanently bound to GitHub account ID <code>{expectedOwnerId}</code>. Create the private sign-in app with that same GitHub account. GitHub confirms the creator's numeric account ID; any other account is rejected.
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
    if (!normalizeOwnerId(e.OWNER_GITHUB_ID)) return new Response(null, { status: 303, headers: { Location: new URL('/setup?error=provisioning', origin).toString(), 'Cache-Control': 'no-store' } })
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
    const expectedOwnerId = normalizeOwnerId(e.OWNER_GITHUB_ID)
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
      <div className="space-y-4">
        <div className="flex items-center justify-between gap-3"><h1 className="text-lg font-semibold tracking-tight">Credentials</h1><a href="/vault/services" className="rounded-md bg-primary px-3 py-2 text-sm font-medium text-primary-foreground">+ Add credential</a></div>
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
        )}
      </div>
    )
  })

  // ── Owner-facing provider catalog and direct registration ─────────
  .page('/vault/services', async ({ request }) => {
    await requirePageSession(request)
    const { ServiceCatalog } = await import('./components/service-catalog.tsx')
    return <div className="space-y-5"><div><h1 className="text-lg font-semibold tracking-tight">Add a credential</h1><p className="text-sm text-muted-foreground mt-1">Choose a provider to prefill its API host and authentication style, or configure a custom service.</p></div><ServiceCatalog /></div>
  })

  .page('/vault/new', async ({ request }) => {
    await requirePageSession(request)
    const serviceId = new URL(request.url).searchParams.get('service') ?? ''
    const preset = presetForService(serviceId)
    const { CredentialForm } = await import('./components/credential-form.tsx')
    return <div className="space-y-5 max-w-2xl"><div><a href="/vault/services" className="text-sm underline">← Provider catalog</a><h1 className="text-lg font-semibold tracking-tight mt-2">{preset ? `Configure ${preset.label}` : 'Configure a custom service'}</h1><p className="text-sm text-muted-foreground mt-1">Review the provider settings, enter the secret, and explicitly create the credential. The secret is write-only.</p></div><CredentialForm mode="create" preset={preset ? { label: preset.label, docsUrl: preset.docsUrl } : null} defaults={{ delivery: 'proxy', allowedHosts: preset?.hosts.join('\\n') ?? '', authHeader: preset?.authHeader ?? 'Authorization', authScheme: preset?.authScheme ?? 'Bearer', visible: true, lifetime: 'permanent' }} /></div>
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
      <div className="space-y-6 max-w-2xl">
        <div>
          <h1 className="text-lg font-semibold tracking-tight font-mono">{credential.name}</h1>
          <p className="text-sm text-muted-foreground">{credential.service} — {credential.purpose}</p>
          <p className="text-xs text-muted-foreground mt-1">Link expires in about {Math.max(1, Math.round((link.expiresAt - Date.now()) / 60_000))} min and works once.</p>
        </div>
        {credential.doc && <DocView doc={credential.doc} />}
        <CredentialForm mode="register" token={params.token} preset={preset ? { label: preset.label } : null} defaults={{ delivery: 'proxy', allowedHosts: preset ? preset.hosts.join('\n') : '', authHeader: preset?.authHeader ?? 'Authorization', authScheme: preset?.authScheme ?? 'Bearer', visible: true, lifetime: 'permanent' }} />
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
      <div className="space-y-6 max-w-2xl">
        <div className="space-y-1">
          <div className="flex items-center gap-2"><h1 className="text-lg font-semibold tracking-tight font-mono">{c.name}</h1>{statusBadge(c, now)}</div>
          <p className="text-sm text-muted-foreground">{c.service} — {c.purpose}</p>
        </div>
        <dl className="text-sm grid gap-1 sm:grid-cols-[10rem_1fr]">
          <dt className="text-muted-foreground">Delivery</dt><dd>{c.externallyManaged ? 'managed elsewhere (metadata only)' : c.delivery}</dd>
          <dt className="text-muted-foreground">Allowed hosts</dt><dd className="font-mono">{c.allowedHosts.join(', ') || '—'}</dd>
          <dt className="text-muted-foreground">Auth header</dt><dd className="font-mono">{c.authHeader}: {c.authScheme}</dd>
          <dt className="text-muted-foreground">Lifetime</dt><dd>{c.lifetime}{c.expiresAt ? <> · expires <TimeAgo ts={c.expiresAt} /></> : null}</dd>
          <dt className="text-muted-foreground">Value stored</dt><dd>{c.hasValue ? 'yes (write-only)' : 'no'}</dd>
        </dl>
        <CredentialControls id={c.id} name={c.name} enabled={c.status === 'active'} visible={c.visible} canEnable={c.hasValue || c.externallyManaged} />
        {c.doc && <DocView doc={c.doc} />}
        {!c.externallyManaged && (
          <div className="space-y-3">
            <h2 className="text-sm font-semibold">Replace value or change rules</h2>
            <CredentialForm mode="replace" id={c.id} defaults={{ delivery: c.delivery, allowedHosts: c.allowedHosts.join('\n'), authHeader: c.authHeader, authScheme: c.authScheme, visible: c.visible, lifetime: c.lifetime }} />
          </div>
        )}
        <div className="space-y-2">
          <h2 className="text-sm font-semibold">Recent activity</h2>
          <AuditTable rows={log} />
        </div>
      </div>
    )
  })

  .page('/vault/audit', async ({ request }) => {
    await requirePageSession(request)
    const rows = await listAudit(getDb(), { limit: 200 })
    return (
      <div className="space-y-4">
        <h1 className="text-lg font-semibold tracking-tight">Audit log</h1>
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
    return (
      <div className="space-y-8 max-w-2xl">
        <h1 className="text-lg font-semibold tracking-tight">Settings</h1>
        <section className="space-y-2">
          <h2 className="text-sm font-semibold">Runner repository</h2>
          <p className="text-sm text-muted-foreground">
            Only this repository's workflow, on this branch, can sign in as a runner. Pull-request runs are never accepted.
          </p>
          {fixedByEnv ? (
            <p className="text-sm text-muted-foreground">This is fixed by the Worker's RUNNER_* variables and cannot be changed here.</p>
          ) : (
            <RunnerPolicyForm defaults={{ repository: policy?.repository ?? '', branch: policy?.branch ?? 'main', workflowFile: policy?.workflowFile ?? 'rdc-lab.yml', repositoryId: policy?.repositoryId ?? '' }} />
          )}
        </section>
        <section className="space-y-2">
          <h2 className="text-sm font-semibold">Runner sessions</h2>
          <p className="text-sm text-muted-foreground">Sessions last 30 minutes. Revoking invalidates every session issued so far, for example after a runner reset.</p>
          <RevokeSessionsButton />
        </section>
        <section className="space-y-2">
          <h2 className="text-sm font-semibold">Entries managed elsewhere</h2>
          <p className="text-sm text-muted-foreground">Lists a credential (such as GITHUB_TOKEN) so runners know it exists. The vault stores no value for it and never proxies it.</p>
          <AddExternalForm />
        </section>
      </div>
    )
  })

  .use(runnerApp)

function AuditTable({ rows }: { rows: Awaited<ReturnType<typeof listAudit>> }) {
  if (rows.length === 0) return <p className="text-sm text-muted-foreground">No activity yet.</p>
  return (
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

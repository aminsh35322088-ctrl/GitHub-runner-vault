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
import { hasGithubOAuthConfig } from './lib/auth-config.ts'
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

export const app = new Spiceflow()
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
    const githubOAuthConfigured = hasGithubOAuthConfig(env as unknown as {
      GITHUB_CLIENT_ID?: string
      GITHUB_CLIENT_SECRET?: string
    })
    return (
      <div className="flex justify-center py-24">
        <div className="text-center max-w-sm space-y-4">
          <h1 className="text-xl font-semibold tracking-tight">Runner Credential Vault</h1>
          <p className="text-sm text-muted-foreground">Sign in with the owner's GitHub account.</p>
          {githubOAuthConfigured ? (
            <LoginButton callbackURL={redirectTo} />
          ) : (
            <div role="status" className="rounded-lg border border-border bg-muted/40 p-4 text-left space-y-2">
              <p className="text-sm font-medium">GitHub sign-in is not configured yet.</p>
              <p className="text-sm text-muted-foreground">
                Add both <code>GITHUB_CLIENT_ID</code> and <code>GITHUB_CLIENT_SECRET</code> as encrypted
                Worker secrets, then redeploy. The vault remains locked until OAuth is configured.
              </p>
            </div>
          )}
        </div>
      </div>
    )
  })

  // ── Registry ──────────────────────────────────────────────────────
  .page('/vault', async ({ request }) => {
    await requirePageSession(request)
    const rows = await listCredentialsForOwner(getDb())
    const now = Date.now()
    return (
      <div className="space-y-4">
        <h1 className="text-lg font-semibold tracking-tight">Credentials</h1>
        {rows.length === 0 ? (
          <p className="text-sm text-muted-foreground">Nothing registered yet. A model on the runner asks for a credential and gives you a one-time link.</p>
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
    return (
      <div className="space-y-6 max-w-2xl">
        <div>
          <h1 className="text-lg font-semibold tracking-tight font-mono">{credential.name}</h1>
          <p className="text-sm text-muted-foreground">{credential.service} — {credential.purpose}</p>
          <p className="text-xs text-muted-foreground mt-1">Link expires in about {Math.max(1, Math.round((link.expiresAt - Date.now()) / 60_000))} min and works once.</p>
        </div>
        {credential.doc && <DocView doc={credential.doc} />}
        <CredentialForm mode="register" token={params.token} defaults={{ delivery: 'proxy', allowedHosts: '', authHeader: 'Authorization', authScheme: 'Bearer', visible: true, lifetime: 'permanent' }} />
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
    const { RevokeSessionsButton, AddExternalForm } = await import('./components/credential-actions.tsx')
    return (
      <div className="space-y-8 max-w-2xl">
        <h1 className="text-lg font-semibold tracking-tight">Settings</h1>
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

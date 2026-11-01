// Owner form for storing a credential value and its rules.
// Used on the one-time registration page and on the credential detail page.
// The value field is write-only: nothing in the UI ever displays a stored value.

'use client'

import { useState } from 'react'
import { ErrorBoundary } from 'spiceflow/react'
import { Button } from './ui/button'
import { Input } from './ui/input'
import { NativeSelect } from './ui/native-select'
import { createCredentialAction, submitRegistrationAction, replaceCredentialAction, type StoreForm } from '../vault-actions.ts'

export type FormDefaults = {
  delivery: 'proxy'
  allowedHosts: string
  authHeader: string
  authScheme: 'Bearer' | 'Token' | 'Raw'
  visible: boolean
  lifetime: 'permanent' | 'temporary'
}

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="text-sm font-medium mb-1.5 block">{label}</span>
      {children}
      {hint && <span className="block text-xs text-muted-foreground mt-1">{hint}</span>}
    </label>
  )
}

export function CredentialForm({ mode, token, id, defaults, preset = null }: { mode: 'create' | 'register' | 'replace'; token?: string; id?: string; defaults: FormDefaults; preset?: { label: string; docsUrl?: string } | null }) {
  const [lifetime, setLifetime] = useState(defaults.lifetime)
  const [errorMessage, setErrorMessage] = useState('')
  const [saving, setSaving] = useState(false)

  return (
    <ErrorBoundary
      fallback={
        <div className="rounded-lg border border-destructive/40 bg-destructive/5 p-4 flex flex-col gap-2">
          <ErrorBoundary.ErrorMessage className="text-sm text-destructive" />
          <ErrorBoundary.ResetButton className="text-sm text-destructive underline cursor-pointer self-start">
            Try again
          </ErrorBoundary.ResetButton>
        </div>
      }
    >
      <form
        className="flex flex-col gap-4"
        autoComplete="off"
        action={async (formData: FormData) => {
          setErrorMessage('')
          setSaving(true)
          try {
            const hours = String(formData.get('hours') ?? '').trim()
            const form: StoreForm = {
              value: String(formData.get('value') ?? ''),
              lifetime,
              expiresInHours: lifetime === 'temporary' ? Number(hours || 24) : hours ? Number(hours) : null,
              visible: formData.get('visible') === 'on',
              delivery: 'proxy',
              allowedHosts: String(formData.get('hosts') ?? ''),
              authHeader: String(formData.get('authHeader') ?? 'Authorization'),
              authScheme: String(formData.get('authScheme') ?? 'Bearer') as StoreForm['authScheme'],
            }
            if (mode === 'create') {
              const created = await createCredentialAction({
                name: String(formData.get('name') ?? ''),
                service: String(formData.get('service') ?? ''),
                purpose: String(formData.get('purpose') ?? ''),
                form,
              })
              window.location.assign(`/vault/credentials/${created.id}`)
            } else if (mode === 'register') await submitRegistrationAction(token!, form)
            else await replaceCredentialAction(id!, form)
            if (mode !== 'create') window.location.assign('/vault')
          } catch {
            setErrorMessage('The credential could not be saved. Check the values and link status, then try again.')
          } finally {
            setSaving(false)
          }
        }}
      >
        {mode === 'create' && (
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Credential name" hint="Unique name exposed to authorized runners.">
              <Input name="name" required maxLength={80} placeholder="e.g. production-cloudflare" className="w-full font-mono" />
            </Field>
            <Field label="Service / provider">
              <Input name="service" required maxLength={80} defaultValue={preset?.label ?? ''} placeholder="e.g. My API" className="w-full" />
            </Field>
            <div className="sm:col-span-2">
              <Field label="Purpose" hint="What should this credential be used for?">
                <Input name="purpose" required maxLength={500} placeholder="e.g. Manage DNS records for the production zone" className="w-full" />
              </Field>
            </div>
          </div>
        )}
        <Field label="Secret value" hint="Write-only. It is encrypted immediately and cannot be shown again.">
          <Input name="value" type="password" required autoComplete="new-password" spellCheck={false} className="w-full font-mono" />
        </Field>

        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Lifetime">
            <NativeSelect className="w-full" value={lifetime} onChange={(e) => setLifetime(e.target.value as 'permanent' | 'temporary')}>
                <option value="permanent">Permanent</option>
                <option value="temporary">Temporary (max 24 h)</option>
              </NativeSelect>
          </Field>
          <Field label={lifetime === 'temporary' ? 'Expires in (hours, max 24)' : 'Expires in (hours, optional)'}>
            <Input name="hours" type="number" step="any" min="0.1" max={lifetime === 'temporary' ? 24 : undefined} required={lifetime === 'temporary'} className="w-full" />
          </Field>
        </div>

        {/* Known services come pre-filled; anything unfamiliar opens for the owner to decide. */}
        <details open={!preset && (mode === 'register' || mode === 'create')} className="rounded-md border border-border p-3 space-y-4">
          <summary className="cursor-pointer text-sm font-medium">
            {preset ? `${preset.label}: ${defaults.allowedHosts.split('\n')[0]} (${defaults.authHeader}: ${defaults.authScheme}) — change` : 'Where this token may be used'}
          </summary>
          <Field label="Allowed hosts" hint="One exact hostname per line. You decide this, not the model.">
            <textarea name="hosts" rows={3} defaultValue={defaults.allowedHosts} required spellCheck={false}
              className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm font-mono focus:outline-none focus:ring-1 focus:ring-ring" />
          </Field>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Auth header">
              <Input name="authHeader" defaultValue={defaults.authHeader} className="w-full font-mono" />
            </Field>
            <Field label="Auth scheme">
              <NativeSelect className="w-full" name="authScheme" defaultValue={defaults.authScheme}>
                <option value="Bearer">Bearer</option>
                <option value="Token">Token</option>
                <option value="Raw">Raw (value only)</option>
              </NativeSelect>
            </Field>
          </div>
        </details>

        <label className="flex items-start gap-2.5 cursor-pointer">
          <input type="checkbox" name="visible" defaultChecked={defaults.visible} className="mt-0.5 size-4 rounded border-border accent-primary" />
          <span className="text-sm">
            <span className="font-medium">Visible to runners</span>
            <span className="block text-muted-foreground mt-0.5">Hidden credentials stay in the vault but cannot be listed or used.</span>
          </span>
        </label>

        {errorMessage && <p role="alert" aria-live="polite" className="text-sm text-destructive">{errorMessage}</p>}
        {preset?.docsUrl && <p className="text-xs text-muted-foreground">Provider reference: <a className="underline" href={preset.docsUrl} target="_blank" rel="noopener noreferrer nofollow">official API documentation</a>. Review the settings before saving.</p>}
        <Button type="submit" disabled={saving}>{saving ? 'Saving…' : mode === 'create' ? 'Review and create credential' : mode === 'register' ? 'Save and activate' : 'Replace value'}</Button>
      </form>
    </ErrorBoundary>
  )
}

// Owner form for storing a credential value and its rules.
// Used on the one-time registration page and on the credential detail page.
// The value field is write-only: nothing in the UI ever displays a stored value.

'use client'

import { useState } from 'react'
import { ErrorBoundary } from 'spiceflow/react'
import { Button } from './ui/button'
import { Input } from './ui/input'
import { NativeSelect } from './ui/native-select'
import { submitRegistrationAction, replaceCredentialAction, type StoreForm } from '../vault-actions.ts'

export type FormDefaults = {
  delivery: 'proxy' | 'inject'
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

export function CredentialForm({ mode, token, id, defaults }: { mode: 'register' | 'replace'; token?: string; id?: string; defaults: FormDefaults }) {
  const [lifetime, setLifetime] = useState(defaults.lifetime)
  const [delivery, setDelivery] = useState(defaults.delivery)

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
          const hours = String(formData.get('hours') ?? '').trim()
          const form: StoreForm = {
            value: String(formData.get('value') ?? ''),
            lifetime,
            expiresInHours: lifetime === 'temporary' ? Number(hours || 24) : hours ? Number(hours) : null,
            visible: formData.get('visible') === 'on',
            delivery,
            allowedHosts: String(formData.get('hosts') ?? ''),
            authHeader: String(formData.get('authHeader') ?? 'Authorization'),
            authScheme: String(formData.get('authScheme') ?? 'Bearer') as StoreForm['authScheme'],
          }
          if (mode === 'register') await submitRegistrationAction(token!, form)
          else await replaceCredentialAction(id!, form)
          window.location.assign('/vault')
        }}
      >
        <Field label="Secret value" hint="Write-only. It is encrypted immediately and cannot be shown again.">
          <Input name="value" type="password" required autoComplete="new-password" spellCheck={false} className="w-full font-mono" />
        </Field>

        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Lifetime">
            <NativeSelect className="w-full">
              <select value={lifetime} onChange={(e) => setLifetime(e.target.value as 'permanent' | 'temporary')}>
                <option value="permanent">Permanent</option>
                <option value="temporary">Temporary (max 24 h)</option>
              </select>
            </NativeSelect>
          </Field>
          <Field label={lifetime === 'temporary' ? 'Expires in (hours, max 24)' : 'Expires in (hours, optional)'}>
            <Input name="hours" type="number" step="any" min="0.1" max={lifetime === 'temporary' ? 24 : undefined} required={lifetime === 'temporary'} className="w-full" />
          </Field>
        </div>

        <Field label="How the runner uses it" hint="Proxy: the vault makes the call and never returns the token (recommended). Inject: only for low-privilege or short-lived tokens.">
          <NativeSelect className="w-full">
            <select value={delivery} onChange={(e) => setDelivery(e.target.value as 'proxy' | 'inject')}>
              <option value="proxy">Proxy (recommended)</option>
              <option value="inject">Inject</option>
            </select>
          </NativeSelect>
        </Field>

        <Field label="Allowed hosts" hint="One exact hostname per line, e.g. api.cloudflare.com. You decide this, not the model.">
          <textarea name="hosts" rows={3} defaultValue={defaults.allowedHosts} required={delivery === 'proxy'} spellCheck={false}
            className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm font-mono focus:outline-none focus:ring-1 focus:ring-ring" />
        </Field>

        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Auth header">
            <Input name="authHeader" defaultValue={defaults.authHeader} className="w-full font-mono" />
          </Field>
          <Field label="Auth scheme">
            <NativeSelect className="w-full">
              <select name="authScheme" defaultValue={defaults.authScheme}>
                <option value="Bearer">Bearer</option>
                <option value="Token">Token</option>
                <option value="Raw">Raw (value only)</option>
              </select>
            </NativeSelect>
          </Field>
        </div>

        <label className="flex items-start gap-2.5 cursor-pointer">
          <input type="checkbox" name="visible" defaultChecked={defaults.visible} className="mt-0.5 size-4 rounded border-border accent-primary" />
          <span className="text-sm">
            <span className="font-medium">Visible to runners</span>
            <span className="block text-muted-foreground mt-0.5">Hidden credentials stay in the vault but cannot be listed or used.</span>
          </span>
        </label>

        <Button type="submit">{mode === 'register' ? 'Save and activate' : 'Replace value'}</Button>
      </form>
    </ErrorBoundary>
  )
}

// Owner form for storing and validating a credential.
// The owner only controls the secret, lifetime and visibility. Network and auth
// policy are derived from a reviewed provider preset or a verified Service Adapter.

'use client'

import { useState } from 'react'
import { ErrorBoundary } from 'spiceflow/react'
import { Button } from './ui/button'
import { Input } from './ui/input'
import { NativeSelect } from './ui/native-select'
import {
  createCredentialAction, submitRegistrationAction, replaceCredentialAction,
  validateCredentialTokenAction, type StoreForm,
} from '../vault-actions.ts'
import type { CredentialValidationReport } from '../lib/credential-validation.ts'

export type FormDefaults = {
  visible: boolean
  lifetime: 'permanent' | 'temporary'
}

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <label className="block min-w-0">
      <span className="mb-1.5 block text-sm font-medium">{label}</span>
      {children}
      {hint && <span className="mt-1 block text-sm text-muted-foreground">{hint}</span>}
    </label>
  )
}

function ValidationResult({ report }: { report: CredentialValidationReport }) {
  const tone = report.status === 'valid'
    ? 'border-success/30 bg-success/5'
    : report.status === 'invalid' || report.status === 'expired'
      ? 'border-destructive/30 bg-destructive/5'
      : report.status === 'insufficient_permissions'
        ? 'border-warning/30 bg-warning/5'
        : 'border-border bg-muted/30'
  const title = report.status === 'valid'
    ? 'Token verified'
    : report.status === 'invalid'
      ? 'Token rejected by provider'
      : report.status === 'insufficient_permissions'
        ? 'Token lacks access to the verification endpoint'
        : report.status === 'unsupported'
          ? 'Automatic verification is not available'
          : report.status === 'expired'
            ? 'Token expired'
            : 'Verification could not be completed'
  const visiblePermissions = report.permissions.slice(0, 8)
  const remaining = Math.max(0, report.permissions.length - visiblePermissions.length)
  return (
    <section role="status" aria-live="polite" className={`space-y-3 rounded-xl border p-3 sm:p-4 ${tone}`}>
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0 space-y-1">
          <p className="text-sm font-semibold">{title}</p>
          <p className="text-sm text-muted-foreground">{report.message}</p>
        </div>
        <span className="shrink-0 rounded-full border border-border bg-background/80 px-2.5 py-1 text-xs font-medium">{report.status}</span>
      </div>
      {(report.identity || report.tokenType || report.permissions.length > 0) && (
        <div className="flex flex-wrap gap-2 text-xs">
          {report.identity && <span className="rounded-full border border-border px-2.5 py-1">{report.identity}</span>}
          {report.tokenType && <span className="rounded-full border border-border px-2.5 py-1">{report.tokenType}</span>}
          {report.permissionsComplete && <span className="rounded-full border border-border px-2.5 py-1">Complete permission list</span>}
          {report.permissions.length > 0 && <span className="rounded-full border border-border px-2.5 py-1">{report.permissions.length} permissions detected</span>}
        </div>
      )}
      {visiblePermissions.length > 0 && (
        <ul className="grid gap-2 sm:grid-cols-2">
          {visiblePermissions.map((permission, index) => (
            <li key={`${permission.name}-${index}`} className="min-w-0 rounded-lg border border-border/70 bg-background/70 px-3 py-2">
              <span className="block break-words text-sm font-medium">{permission.name}</span>
              <span className="block break-words text-xs text-muted-foreground">
                {permission.access}{permission.scope ? ` · ${permission.scope}` : ''}
              </span>
            </li>
          ))}
        </ul>
      )}
      {remaining > 0 && (
        <details className="rounded-lg border border-border bg-background/70">
          <summary className="cursor-pointer px-3 py-2.5 text-sm font-medium">
            Show all permissions ({report.permissions.length})
          </summary>
          <div className="max-h-64 overflow-y-auto border-t border-border p-2">
            <ul className="grid gap-1.5 sm:grid-cols-2">
              {report.permissions.slice(8).map((permission, index) => (
                <li key={`${permission.name}-${index + 8}`} className="min-w-0 rounded-md border border-border/70 px-3 py-2">
                  <span className="block break-words text-sm font-medium">{permission.name}</span>
                  <span className="block break-words text-xs text-muted-foreground">{permission.access}{permission.scope ? ` · ${permission.scope}` : ''}</span>
                </li>
              ))}
            </ul>
          </div>
        </details>
      )}
      <p className="text-xs text-muted-foreground">Token content is never shown or included in this report.</p>
    </section>
  )
}

function safeErrorMessage(error: unknown): string {
  const message = error instanceof Error ? error.message : ''
  const messages: Record<string, string> = {
    invalid_name: 'Credential name is not valid.',
    reserved_name: 'This name is reserved for the runtime.',
    exists: 'A credential with this name already exists.',
    invalid_hosts: 'The provider adapter contains an invalid host.',
    hosts_required: 'No verified API host is available for this service.',
    invalid_auth_style: 'The provider authentication policy is invalid.',
    invalid_expiry: 'Choose a valid token lifetime.',
    invalid_value: 'The token is empty or has an invalid format.',
    internal_error: 'Vault storage failed. Check the database or Worker security log.',
    unauthorized: 'Your sign-in session expired. Sign in again.',
    invalid_form: 'Review the highlighted form fields.',
    service_adapter_required: 'This custom service needs a verified Service Adapter. Ask the runner model to create a new one-time credential request with official API documentation.',
  }
  const code = message.split(':', 1)[0] ?? ''
  if (messages[code]) return messages[code]
  if (message.startsWith('This link is invalid')) return 'This registration link is invalid, expired or already used.'
  if (message.startsWith('This registration is no longer available')) return 'This credential is no longer accepting a value. Request a new link from the runner.'
  if (message && message.length <= 360 && !/SQLITE|D1_ERROR|stack|node_modules|\/home\//i.test(message)) return message
  return 'Could not save the credential. Check the form and try again; the token value is never displayed.'
}

export function CredentialForm({
  mode, token, id, defaults, preset = null, serviceName, credentialId, apiBaseUrl,
}: {
  mode: 'create' | 'register' | 'replace'
  token?: string
  id?: string
  defaults: FormDefaults
  preset?: { label: string; docsUrl?: string } | null
  serviceName?: string
  credentialId?: string
  apiBaseUrl?: string
}) {
  const [lifetime, setLifetime] = useState(defaults.lifetime)
  const [service, setService] = useState(preset?.label ?? serviceName ?? '')
  const [secretValue, setSecretValue] = useState('')
  const [validation, setValidation] = useState<CredentialValidationReport | null>(null)
  const [lastChecked, setLastChecked] = useState('')
  const [validating, setValidating] = useState(false)
  const [validationError, setValidationError] = useState('')
  const [errorMessage, setErrorMessage] = useState('')
  const [saving, setSaving] = useState(false)

  async function checkToken(value = secretValue) {
    const candidate = value.trim()
    if (!candidate || !service.trim() || candidate === lastChecked) return
    setValidating(true)
    setValidationError('')
    setValidation(null)
    try {
      const result = await validateCredentialTokenAction(service, candidate, credentialId)
      if (!result.ok) {
        setValidationError(safeErrorMessage(new Error(result.error)))
        return
      }
      setValidation(result.value)
      if (result.value.status !== 'unavailable') setLastChecked(candidate)
    } catch (error) {
      setValidationError(safeErrorMessage(error))
    } finally {
      setValidating(false)
    }
  }

  return (
    <ErrorBoundary
      fallback={
        <div className="flex flex-col gap-2 rounded-lg border border-destructive/40 bg-destructive/5 p-4">
          <ErrorBoundary.ErrorMessage className="text-sm text-destructive" />
          <ErrorBoundary.ResetButton className="cursor-pointer self-start text-sm text-destructive underline">Try again</ErrorBoundary.ResetButton>
        </div>
      }
    >
      <form
        className="flex min-w-0 flex-col gap-5"
        autoComplete="off"
        action={async (formData: FormData) => {
          setErrorMessage('')
          setSaving(true)
          try {
            const hours = String(formData.get('hours') ?? '').trim()
            const form: StoreForm = {
              value: String(formData.get('value') ?? ''),
              lifetime,
              expiresInHours: hours ? Number(hours) : null,
              visible: formData.get('visible') === 'on',
            }
            if (mode === 'create') {
              const created = await createCredentialAction({
                name: String(formData.get('name') ?? ''),
                service,
                form,
              })
              if (!created.ok) {
                setErrorMessage(safeErrorMessage(new Error(created.error)))
                return
              }
              window.location.assign(`/vault/credentials/${created.value.id}`)
            } else if (mode === 'register') {
              const registered = await submitRegistrationAction(token!, form)
              if (!registered.ok) {
                setErrorMessage(safeErrorMessage(new Error(registered.error)))
                return
              }
              window.location.assign('/vault')
            } else {
              const replaced = await replaceCredentialAction(id!, form)
              if (!replaced.ok) {
                setErrorMessage(safeErrorMessage(new Error(replaced.error)))
                return
              }
              window.location.assign('/vault')
            }
          } catch (error) {
            setErrorMessage(safeErrorMessage(error))
          } finally {
            setSaving(false)
          }
        }}
      >
        {mode === 'create' && (
          <div className="grid min-w-0 gap-4 sm:grid-cols-2">
            <Field label="Credential name" hint="Use a unique uppercase name. This is the identifier shown to your Runner.">
              <Input name="name" required maxLength={64} defaultValue={preset?.label ? preset.label.toUpperCase().replace(/[^A-Z0-9]+/g, '_').replace(/^_+|_+$/g, '') + '_API_TOKEN' : ''} placeholder="CLOUDFLARE_API_TOKEN" className="w-full font-mono" />
            </Field>
            <Field label="Service / provider">
              <Input name="service" required maxLength={80} value={service} onChange={(event) => {
                setService(event.target.value)
                setValidation(null)
                setLastChecked('')
              }} placeholder="e.g. My API" className="w-full" />
            </Field>
          </div>
        )}

        {apiBaseUrl && (
          <section className="rounded-xl border border-border bg-muted/25 p-3.5 sm:p-4">
            <div className="flex items-center gap-2 text-sm font-semibold">
              <span className="grid size-7 place-items-center rounded-lg bg-success/10 text-success">✓</span>
              Verified API destination
              <span className="ml-auto rounded-full border border-border bg-background px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide text-muted-foreground">Read only</span>
            </div>
            <p className="mt-2 break-all font-mono text-xs text-foreground sm:text-sm">{apiBaseUrl}</p>
            <p className="mt-1.5 text-xs leading-relaxed text-muted-foreground">The vault sends this credential only to this provider API origin. Host and authentication rules are controlled by the reviewed service adapter, not by this form.</p>
          </section>
        )}
        <Field label="Secret token" hint="Sent only to the provider for verification, then encrypted by the vault. It is write-only.">
          <Input
            name="value" type="password" required autoComplete="new-password" spellCheck={false}
            value={secretValue} onChange={(event) => {
              setSecretValue(event.target.value)
              setValidation(null)
              setLastChecked('')
              setValidationError('')
            }}
            onBlur={() => void checkToken()}
            className="w-full font-mono"
            inputMode="text"
          />
        </Field>
        <div className="grid min-w-0 gap-4 sm:grid-cols-2">
          <Field label="Token lifetime">
            <NativeSelect className="w-full" value={lifetime} onChange={(event) => setLifetime(event.target.value as 'permanent' | 'temporary')}>
              <option value="permanent">Permanent (until revoked)</option>
              <option value="temporary">Temporary (maximum 24 hours)</option>
            </NativeSelect>
          </Field>
          <Field label={lifetime === 'temporary' ? 'Expires in (hours)' : 'Optional expiry (hours)'}>
            <Input name="hours" type="number" step="any" min="0.1" max={lifetime === 'temporary' ? 24 : 24 * 365 * 3}
              required={lifetime === 'temporary'} className="w-full" placeholder={lifetime === 'temporary' ? '24' : 'No expiry'} />
          </Field>
        </div>
        <label className="flex min-h-11 cursor-pointer items-start gap-3 rounded-xl border border-border p-3">
          <input type="checkbox" name="visible" defaultChecked={defaults.visible} className="mt-1 size-5 shrink-0 rounded border-border accent-primary" />
          <span className="text-sm">
            <span className="font-medium">Visible to runners</span>
            <span className="mt-0.5 block text-muted-foreground">Hidden credentials remain stored but cannot be listed or used by runners.</span>
          </span>
        </label>
        <p className="text-xs text-muted-foreground">API host, authentication header and verification method are derived automatically from the provider's reviewed Service Adapter. No manual network or scope settings are required.</p>
        <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
          <Button type="button" variant="outline" disabled={!secretValue.trim() || !service.trim() || validating} onClick={() => void checkToken(secretValue)}>
            {validating ? 'Checking token…' : 'Test access & inspect permissions'}
          </Button>
          {validation?.status === 'valid' && <span className="text-sm text-success">Verified</span>}
          {validationError && <span className="text-sm text-destructive" role="alert">{validationError}</span>}
        </div>
        {validation && <ValidationResult report={validation} />}

        {errorMessage && <p role="alert" aria-live="polite" className="rounded-lg border border-destructive/30 bg-destructive/5 p-3 text-sm text-destructive">{errorMessage}</p>}
        <div className="sticky bottom-0 -mx-3 border-t border-border bg-background/95 px-3 py-3 backdrop-blur sm:static sm:mx-0 sm:border-0 sm:bg-transparent sm:p-0">
          <Button type="submit" disabled={saving || validating} className="min-h-12 w-full">
            {saving ? 'Saving…' : mode === 'create' ? 'Verify and save credential' : mode === 'register' ? 'Verify, save and activate' : 'Verify and replace token'}
          </Button>
        </div>
      </form>
    </ErrorBoundary>
  )
}

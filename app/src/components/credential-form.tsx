// Owner form for storing and validating a credential.
// The owner only controls the secret, lifetime and visibility. Network and auth
// policy are derived from a reviewed provider preset or a verified Service Adapter.

'use client'

import { useState, type FormEvent } from 'react'
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

const STEP_META = [
  { title: 'Service', description: 'Confirm what this credential belongs to.' },
  { title: 'Secret', description: 'Enter the token and optionally inspect its access.' },
  { title: 'Access', description: 'Choose its lifetime and runner visibility.' },
] as const

export function CredentialForm({
  mode, token, id, defaults, preset = null, serviceName, credentialName, credentialPurpose, credentialId, apiBaseUrl, credentialFields = [], connectionLabel: initialConnectionLabel = '', providerAccountId: initialProviderAccountId = '',
}: {
  mode: 'create' | 'register' | 'replace'
  token?: string
  id?: string
  defaults: FormDefaults
  preset?: { label: string; docsUrl?: string } | null
  serviceName?: string
  credentialName?: string
  credentialPurpose?: string
  credentialId?: string
  apiBaseUrl?: string
  credentialFields?: Array<{ id: string; label: string; required: boolean; secret: boolean }>
  connectionLabel?: string
  providerAccountId?: string
}) {
  const [step, setStep] = useState(1)
  const [name, setName] = useState(
    preset?.label
      ? preset.label.toUpperCase().replace(/[^A-Z0-9]+/g, '_').replace(/^_+|_+$/g, '') + '_API_TOKEN'
      : '',
  )
  const [lifetime, setLifetime] = useState(defaults.lifetime)
  const [service] = useState(preset?.label ?? serviceName ?? '')
  const [secretValue, setSecretValue] = useState('')
  const [authFieldValues, setAuthFieldValues] = useState<Record<string, string>>({})
  const [connectionLabel, setConnectionLabel] = useState(initialConnectionLabel)
  const [providerAccountId, setProviderAccountId] = useState(initialProviderAccountId)
  const [hours, setHours] = useState('')
  const [visible, setVisible] = useState(defaults.visible)
  const [validation, setValidation] = useState<CredentialValidationReport | null>(null)
  const [testRequested, setTestRequested] = useState(false)
  const [lastChecked, setLastChecked] = useState('')
  const [validating, setValidating] = useState(false)
  const [validationError, setValidationError] = useState('')
  const [stepError, setStepError] = useState('')
  const [errorMessage, setErrorMessage] = useState('')
  const [saving, setSaving] = useState(false)

  async function checkToken(value = secretValue) {
    const candidate = value.trim()
    if (!candidate || !service.trim() || candidate === lastChecked || validating) return
    setValidating(true)
    setValidationError('')
    setValidation(null)
    setTestRequested(true)
    try {
      const result = await validateCredentialTokenAction(service, candidate, credentialId, authFieldValues)
      if (!result.ok) {
        setValidationError(safeErrorMessage(new Error(result.error)))
        return
      }
      setValidation(result.value)
      if (result.value.providerAccountId) setProviderAccountId(result.value.providerAccountId)
      if (result.value.identity?.startsWith('@') && result.value.status === 'valid') setConnectionLabel(result.value.identity)
      if (result.value.status !== 'unavailable') setLastChecked(candidate)
    } catch (error) {
      setValidationError(safeErrorMessage(error))
    } finally {
      setValidating(false)
    }
  }

  function continueToNextStep() {
    setStepError('')
    if (step === 1 && mode === 'create') {
      if (!name.trim()) {
        setStepError('Add a credential name to continue.')
        return
      }
      if (!service.trim()) {
        setStepError('Choose or enter a service name to continue.')
        return
      }
    }
    if (step === 2) {
      if (!secretValue.trim()) {
        setStepError('Enter the secret token before continuing.')
        return
      }
      const missingField = mode === 'replace'
        ? undefined
        : credentialFields.slice(1).find((field) => field.required && !authFieldValues[field.id]?.trim())
      if (missingField) {
        setStepError('Enter the required ' + missingField.label + ' field before continuing.')
        return
      }
    }
    setStep(Math.min(3, step + 1))
  }

  async function saveCredential(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (step < 3) {
      continueToNextStep()
      return
    }
    setErrorMessage('')
    setStepError('')
    if (!secretValue.trim()) {
      setStep(2)
      setStepError('Enter the secret token before saving.')
      return
    }
    if (lifetime === 'temporary' && (!hours.trim() || !Number.isFinite(Number(hours)) || Number(hours) <= 0 || Number(hours) > 24)) {
      setStepError('Temporary credentials must expire within 24 hours.')
      return
    }
    if (hours.trim() && (!Number.isFinite(Number(hours)) || Number(hours) <= 0 || Number(hours) > 24 * 365 * 3)) {
      setStepError('Enter an expiry greater than zero and no longer than three years.')
      return
    }
    setSaving(true)
    try {
      const form: StoreForm = {
        value: secretValue,
        lifetime,
        expiresInHours: hours.trim() ? Number(hours) : null,
        visible,
        connectionLabel,
        providerAccountId,
        authFields: authFieldValues,
        validationRequested: testRequested,
      }
      if (mode === 'create') {
        const created = await createCredentialAction({ name, service, form })
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
  }

  const steps = [
    { title: mode === 'create' ? 'Service' : 'Request', description: STEP_META[0].description },
    STEP_META[1],
    STEP_META[2],
  ]
  const actionLabel = mode === 'create' ? 'Save credential' : mode === 'register' ? 'Save and activate' : 'Replace token'

  return (
    <ErrorBoundary
      fallback={
        <div className="flex flex-col gap-2 rounded-lg border border-destructive/40 bg-destructive/5 p-4">
          <ErrorBoundary.ErrorMessage className="text-sm text-destructive" />
          <ErrorBoundary.ResetButton className="cursor-pointer self-start text-sm text-destructive underline">Try again</ErrorBoundary.ResetButton>
        </div>
      }
    >
      <form className="flex min-w-0 flex-col gap-5" autoComplete="off" onSubmit={saveCredential}>
        <nav aria-label="Credential setup progress" className="rounded-2xl border border-border bg-card p-3 sm:p-4">
          <ol className="grid grid-cols-3 gap-2">
            {steps.map((item, index) => {
              const itemStep = index + 1
              const complete = step > itemStep
              const current = step === itemStep
              return (
                <li key={item.title} className="min-w-0">
                  <div className={`flex items-center gap-2 ${current ? 'text-foreground' : complete ? 'text-success' : 'text-muted-foreground'}`}>
                    <span className={`grid size-7 shrink-0 place-items-center rounded-full border text-xs font-semibold ${current ? 'border-primary bg-primary text-primary-foreground' : complete ? 'border-success/40 bg-success/10' : 'border-border bg-background'}`}>
                      {complete ? '✓' : itemStep}
                    </span>
                    <span className="truncate text-xs font-semibold sm:text-sm">{item.title}</span>
                  </div>
                  <div className={`mt-2 h-1 rounded-full ${complete || current ? 'bg-primary' : 'bg-muted'}`} />
                </li>
              )
            })}
          </ol>
          <div className="mt-3 flex flex-wrap items-baseline justify-between gap-2">
            <p className="text-sm font-semibold">{steps[step - 1]?.title}</p>
            <p className="text-xs text-muted-foreground">Step {step} of 3</p>
          </div>
          <p className="mt-1 text-sm text-muted-foreground">{steps[step - 1]?.description}</p>
        </nav>

        {step === 1 && (
          <section className="space-y-4 rounded-2xl border border-border bg-card p-4 sm:p-5">
            {mode === 'create' ? (
              <>
                <div>
                  <h2 className="text-base font-semibold">Identify this credential</h2>
                  <p className="mt-1 text-sm text-muted-foreground">Give it a stable name and select the provider that owns the token.</p>
                </div>
                <div className="grid min-w-0 gap-4 sm:grid-cols-2">
                  <Field label="Credential name" hint="Unique uppercase identifier shown to your Runner.">
                    <Input name="name" value={name} onChange={(event) => setName(event.target.value)} maxLength={64} placeholder="CLOUDFLARE_API_TOKEN" className="w-full font-mono" />
                  </Field>
                  <Field label="Selected provider" hint="The provider is fixed by the reviewed catalog preset. Choose another service from the catalog to change it.">
                    <Input value={service} readOnly aria-readonly="true" className="w-full bg-muted/40 text-muted-foreground" />
                  </Field>
                </div>
              </>
            ) : (
              <>
                <div>
                  <h2 className="text-base font-semibold">{mode === 'register' ? 'Review the Runner request' : 'Review the credential'}</h2>
                  <p className="mt-1 text-sm text-muted-foreground">
                    {mode === 'register'
                      ? 'The Runner supplied the service metadata and a reviewed adapter. You only need to provide the secret.'
                      : 'You are replacing the stored token. The credential identity and provider policy remain owner-controlled.'}
                  </p>
                </div>
                <dl className="grid gap-3 rounded-xl border border-border bg-muted/20 p-3 sm:grid-cols-2">
                  <div className="min-w-0">
                    <dt className="text-xs text-muted-foreground">Credential</dt>
                    <dd className="mt-1 break-all font-mono text-sm font-medium">{credentialName ?? 'Existing credential'}</dd>
                  </div>
                  <div className="min-w-0">
                    <dt className="text-xs text-muted-foreground">Service</dt>
                    <dd className="mt-1 break-words text-sm font-medium">{service || 'Provider not specified'}</dd>
                  </div>
                  {credentialPurpose && (
                    <div className="sm:col-span-2">
                      <dt className="text-xs text-muted-foreground">Requested purpose</dt>
                      <dd className="mt-1 break-words text-sm">{credentialPurpose}</dd>
                    </div>
                  )}
                </dl>
              </>
            )}

            {apiBaseUrl && (
              <div className="rounded-xl border border-success/25 bg-success/5 p-3.5 sm:p-4">
                <div className="flex flex-wrap items-center gap-2 text-sm font-semibold">
                  <span className="grid size-7 place-items-center rounded-lg bg-success/10 text-success">✓</span>
                  Verified API destination
                  <span className="ml-auto rounded-full border border-border bg-background px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide text-muted-foreground">Read only</span>
                </div>
                <p className="mt-2 break-all font-mono text-xs text-foreground sm:text-sm">{apiBaseUrl}</p>
                <p className="mt-1.5 text-xs leading-relaxed text-muted-foreground">The Vault sends this credential only to this provider API origin. Host and authentication rules come from the reviewed Service Adapter; they cannot be changed here.</p>
              </div>
            )}
            {!apiBaseUrl && mode === 'create' && (
              <p className="rounded-xl border border-warning/30 bg-warning/5 p-3 text-sm text-muted-foreground">
                A reviewed Service Adapter must exist before a custom provider can receive a credential. For custom services, request a one-time setup link from the Runner with official API documentation.
              </p>
            )}
          </section>
        )}

        {step === 2 && (
          <section className="space-y-4 rounded-2xl border border-border bg-card p-4 sm:p-5">
            <div>
              <h2 className="text-base font-semibold">Add the secret token</h2>
              <p className="mt-1 text-sm text-muted-foreground">Paste the token exactly as issued by the provider. It stays masked and is never returned by the Vault.</p>
            </div>
            <Field label="Secret token" hint="Used for verification, then encrypted by the Vault. It is write-only.">
              <Input
                name="value" type="password" autoComplete="new-password" spellCheck={false}
                value={secretValue} onChange={(event) => {
                  setSecretValue(event.target.value)
                  setValidation(null)
                  setTestRequested(false)
                  setLastChecked('')
                  setValidationError('')
                  setStepError('')
                }}
                className="w-full font-mono"
                inputMode="text"
                aria-required="true"
              />
            </Field>
            {credentialFields.slice(1).map((field) => (
              <Field key={field.id} label={field.label} hint={field.secret ? 'Encrypted with the primary credential. Leave empty during replacement to keep the existing stored value.' : 'Stored as connection metadata; never used as a secret unless the adapter explicitly maps it.'}>
                <Input
                  name={'auth_' + field.id}
                  type={field.secret ? 'password' : 'text'}
                  autoComplete="off"
                  spellCheck={false}
                  value={authFieldValues[field.id] ?? ''}
                  onChange={(event) => {
                    setAuthFieldValues((current) => ({ ...current, [field.id]: event.target.value }))
                    setValidation(null)
                    setTestRequested(false)
                    setLastChecked('')
                  }}
                  className="w-full font-mono"
                  aria-required={field.required && mode !== 'replace'}
                />
              </Field>
            ))}
            <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
              <Button type="button" variant="outline" disabled={!secretValue.trim() || !service.trim() || validating || saving} onClick={() => void checkToken(secretValue)}>
                {validating ? 'Checking token…' : 'Test access & inspect permissions'}
              </Button>
              {validation?.status === 'valid' && <span className="text-sm font-medium text-success">✓ Token verified</span>}
            </div>
            {validationError && <p className="rounded-lg border border-destructive/30 bg-destructive/5 p-3 text-sm text-destructive" role="alert">{validationError}</p>}
            {validation && <ValidationResult report={validation} />}
            <p className="text-xs leading-relaxed text-muted-foreground">Test is optional. When requested, Save rechecks on the server and records the result. Invalid tokens, unsupported checks, and network failures never block storage.</p>
          </section>
        )}

        {step === 3 && (
          <section className="space-y-4 rounded-2xl border border-border bg-card p-4 sm:p-5">
            <div>
              <h2 className="text-base font-semibold">Set access and lifetime</h2>
              <p className="mt-1 text-sm text-muted-foreground">Choose how long this token should remain stored and whether approved Runners can discover it.</p>
            </div>
            <div className="rounded-xl border border-border p-3.5 space-y-3">
              <div>
                <h3 className="text-sm font-semibold">Provider connection identity</h3>
                <p className="mt-1 text-xs text-muted-foreground">Use a label to distinguish accounts under the same provider. IDs are public metadata, never secrets.</p>
              </div>
              <div className="grid min-w-0 gap-3 sm:grid-cols-2">
                <Field label="Connection label" hint="Examples: Personal, Production, Work, or a bot username.">
                  <Input value={connectionLabel} onChange={(event) => setConnectionLabel(event.target.value)} maxLength={120} className="w-full" placeholder="Personal / Production" />
                </Field>
                <Field label="Provider account ID" hint="Optional public account, tenant, workspace, or bot identifier.">
                  <Input value={providerAccountId} onChange={(event) => setProviderAccountId(event.target.value)} maxLength={160} className="w-full font-mono" placeholder="Public account ID" />
                </Field>
              </div>
            </div>
            <div className="grid min-w-0 gap-4 sm:grid-cols-2">
              <Field label="Token lifetime">
                <NativeSelect className="w-full" value={lifetime} onChange={(event) => setLifetime(event.target.value as 'permanent' | 'temporary')}>
                  <option value="permanent">Permanent (until revoked)</option>
                  <option value="temporary">Temporary (maximum 24 hours)</option>
                </NativeSelect>
              </Field>
              <Field label={lifetime === 'temporary' ? 'Expires in (hours)' : 'Optional expiry (hours)'} hint={lifetime === 'temporary' ? 'Required. Maximum 24 hours.' : 'Leave empty for no expiry.'}>
                <Input name="hours" type="number" step="any" min="0.1" max={lifetime === 'temporary' ? 24 : 24 * 365 * 3}
                  value={hours} onChange={(event) => setHours(event.target.value)} className="w-full" placeholder={lifetime === 'temporary' ? '24' : 'No expiry'} />
              </Field>
            </div>
            <label className="flex min-h-11 cursor-pointer items-start gap-3 rounded-xl border border-border p-3">
              <input type="checkbox" name="visible" checked={visible} onChange={(event) => setVisible(event.target.checked)} className="mt-1 size-5 shrink-0 rounded border-border accent-primary" />
              <span className="text-sm">
                <span className="font-medium">Visible to approved Runners</span>
                <span className="mt-0.5 block text-muted-foreground">When hidden, the credential stays stored but cannot be discovered or used by Runners.</span>
              </span>
            </label>
            <div className="rounded-xl border border-border bg-muted/25 p-3.5">
              <h3 className="text-sm font-semibold">Review before saving</h3>
              <dl className="mt-3 grid gap-3 text-sm sm:grid-cols-2">
                <div className="min-w-0">
                  <dt className="text-xs text-muted-foreground">Provider</dt>
                  <dd className="mt-1 break-words font-medium">{service || 'Not specified'}</dd>
                </div>
                <div className="min-w-0">
                  <dt className="text-xs text-muted-foreground">Secret</dt>
                  <dd className="mt-1 font-medium">{secretValue.trim() ? 'Provided · concealed' : 'Missing'}</dd>
                </div>
                <div className="min-w-0">
                  <dt className="text-xs text-muted-foreground">Lifetime</dt>
                  <dd className="mt-1 font-medium">{lifetime === 'temporary' ? `Expires after ${hours || '—'} hour(s)` : hours ? `Expires after ${hours} hour(s)` : 'Until revoked'}</dd>
                </div>
                <div className="min-w-0">
                  <dt className="text-xs text-muted-foreground">Runner visibility</dt>
                  <dd className="mt-1 font-medium">{visible ? 'Visible to approved Runners' : 'Hidden from Runners'}</dd>
                </div>
              </dl>
              {validation && (
                <p className="mt-3 border-t border-border pt-3 text-xs text-muted-foreground">
                  Latest check: <span className="font-medium text-foreground">{validation.status.replaceAll('_', ' ')}</span>. The save operation will verify the token again.
                </p>
              )}
            </div>
            <p className="text-xs leading-relaxed text-muted-foreground">The Vault sends the token only to the provider's reviewed HTTPS destination, then encrypts it at rest. The token is not included in logs, URLs, notifications or the response.</p>
          </section>
        )}

        {stepError && <p role="alert" aria-live="polite" className="rounded-lg border border-destructive/30 bg-destructive/5 p-3 text-sm text-destructive">{stepError}</p>}
        {errorMessage && <p role="alert" aria-live="polite" className="rounded-lg border border-destructive/30 bg-destructive/5 p-3 text-sm text-destructive">{errorMessage}</p>}

        <div className="sticky bottom-[calc(4.25rem+env(safe-area-inset-bottom))] z-20 -mx-3 flex flex-col-reverse gap-2 border-t border-border bg-background/95 px-3 py-3 backdrop-blur sm:static sm:mx-0 sm:flex-row sm:items-center sm:justify-between sm:border-0 sm:bg-transparent sm:p-0">
          <div>
            {step > 1 && (
              <Button type="button" variant="outline" className="w-full sm:w-auto" disabled={saving || validating} onClick={() => {
                setStepError('')
                setStep(step - 1)
              }}>
                Back
              </Button>
            )}
          </div>
          {step < 3 ? (
            <Button type="button" className="min-h-12 w-full sm:w-auto" disabled={saving || validating} onClick={continueToNextStep}>
              Continue
              <span aria-hidden="true">→</span>
            </Button>
          ) : (
            <Button type="submit" loading={saving} disabled={saving || validating} className="min-h-12 w-full sm:w-auto">
              {saving ? 'Saving securely…' : actionLabel}
            </Button>
          )}
        </div>
      </form>
    </ErrorBoundary>
  )
}

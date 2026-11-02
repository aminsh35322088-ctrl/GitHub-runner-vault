// Owner form for storing and validating a credential.
// The token is write-only: validation summaries contain metadata only.

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
  delivery: 'proxy'
  allowedHosts: string
  authHeader: string
  authScheme: 'Bearer' | 'Token' | 'Raw'
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
    : report.status === 'invalid'
      ? 'border-destructive/30 bg-destructive/5'
      : 'border-border bg-muted/30'
  const title = report.status === 'valid'
    ? 'توکن تأیید شد'
    : report.status === 'invalid'
      ? 'توکن معتبر نیست'
      : report.status === 'unsupported'
        ? 'بررسی خودکار در دسترس نیست'
        : 'اعتبارسنجی کامل نشد'
  return (
    <section role="status" aria-live="polite" className={`space-y-3 rounded-xl border p-3 sm:p-4 ${tone}`}>
      <div className="space-y-1">
        <p className="text-sm font-semibold">{title}</p>
        <p className="text-sm text-muted-foreground">{report.message}</p>
      </div>
      {(report.identity || report.tokenType) && (
        <div className="flex flex-wrap gap-2 text-xs">
          {report.identity && <span className="rounded-full border border-border px-2.5 py-1">{report.identity}</span>}
          {report.tokenType && <span className="rounded-full border border-border px-2.5 py-1">{report.tokenType}</span>}
          {report.permissionsComplete && <span className="rounded-full border border-border px-2.5 py-1">Permission list complete</span>}
        </div>
      )}
      {report.permissions.length > 0 && (
        <div className="space-y-2">
          <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Access detected</p>
          <ul className="grid gap-2 sm:grid-cols-2">
            {report.permissions.map((permission, index) => (
              <li key={`${permission.name}-${index}`} className="min-w-0 rounded-lg border border-border/70 bg-background/70 px-3 py-2">
                <span className="block break-words text-sm font-medium">{permission.name}</span>
                <span className="block break-words text-xs text-muted-foreground">
                  {permission.access}{permission.scope ? ` · ${permission.scope}` : ''}
                </span>
                {permission.resources?.length ? <span className="mt-1 block break-all text-xs text-muted-foreground">{permission.resources.join(', ')}</span> : null}
              </li>
            ))}
          </ul>
        </div>
      )}
      <p className="text-xs text-muted-foreground">Token content is never shown or included in this report.</p>
    </section>
  )
}

function safeErrorMessage(error: unknown): string {
  const message = error instanceof Error ? error.message : ''
  const messages: Record<string, string> = {
    invalid_name: 'نام Credential قابل‌استفاده نیست؛ یک نام حداقل دوحرفی انتخاب کن.',
    reserved_name: 'این نام برای متغیر سیستمی رزرو شده است.',
    exists: 'این نام قبلاً ثبت شده است. نام دیگری انتخاب کن.',
    invalid_hosts: 'یکی از Hostها معتبر نیست. فقط hostname دقیق وارد کن؛ بدون پروتکل، پورت یا wildcard.',
    hosts_required: 'حداقل یک Host مجاز لازم است.',
    invalid_auth_style: 'نام Auth header یا روش ارسال توکن معتبر نیست.',
    invalid_expiry: 'زمان انقضا معتبر نیست.',
    invalid_value: 'مقدار توکن خالی یا دارای قالب نامعتبر است.',
    'شناسه Account Cloudflare باید دقیقاً ۳۲ کاراکتر هگزادسیمال باشد.': 'شناسه حساب Cloudflare را دقیقاً با ۳۲ کاراکتر هگزادسیمال وارد کن.',
  }
  const code = message.split(':', 1)[0] ?? ''
  if (messages[code]) return messages[code]
  if (code === 'internal_error') return 'ذخیره در Vault انجام نشد. اتصال دیتابیس یا گزارش امنیتی Worker را بررسی می‌کنیم.'
  if (code === 'unauthorized') return 'نشست ورود منقضی شده است؛ دوباره با GitHub وارد شو.'
  if (code === 'invalid_form') return 'اطلاعات فرم معتبر نیست؛ فیلدهای مشخص‌شده را بررسی کن.'
  if (message.startsWith('This link is invalid')) return 'این لینک نامعتبر، منقضی یا قبلاً استفاده شده است.'
  if (message.startsWith('This registration is no longer available')) return 'این درخواست ثبت دیگر فعال نیست. از رانر یک لینک جدید بساز.'
  if (message && message.length <= 360 && !/SQLITE|D1_ERROR|stack|node_modules|\/home\//i.test(message)) return message
  return 'ذخیره انجام نشد. اطلاعات فرم و اتصال دیتابیس را بررسی کن؛ مقدار توکن نمایش داده نمی‌شود.'
}

export function CredentialForm({
  mode, token, id, defaults, preset = null, serviceName,
}: {
  mode: 'create' | 'register' | 'replace'
  token?: string
  id?: string
  defaults: FormDefaults
  preset?: { label: string; docsUrl?: string } | null
  serviceName?: string
}) {
  const [lifetime, setLifetime] = useState(defaults.lifetime)
  const [service, setService] = useState(preset?.label ?? serviceName ?? '')
  const [cloudflareAccountId, setCloudflareAccountId] = useState('')
  const [secretValue, setSecretValue] = useState('')
  const isCloudflare = service.trim().toLowerCase().replace(/[^a-z0-9]/g, '') === 'cloudflare'
  const isCloudflareAccountToken = isCloudflare && secretValue.trim().toLowerCase().startsWith('cfat_')
  const [validation, setValidation] = useState<CredentialValidationReport | null>(null)
  const [lastChecked, setLastChecked] = useState('')
  const [validating, setValidating] = useState(false)
  const [validationError, setValidationError] = useState('')
  const [errorMessage, setErrorMessage] = useState('')
  const [saving, setSaving] = useState(false)

  async function checkToken(value = secretValue, accountId = cloudflareAccountId) {
    const candidate = value.trim()
    if (!candidate || !service.trim() || candidate === lastChecked) return
    if (service.trim().toLowerCase().replace(/[^a-z0-9]/g, '') === 'cloudflare' && accountId && !/^[a-f0-9]{32}$/i.test(accountId)) {
      setValidationError('شناسه حساب Cloudflare را دقیقاً با ۳۲ کاراکتر هگزادسیمال وارد کن.')
      return
    }
    setValidating(true)
    setValidationError('')
    setValidation(null)
    try {
      const result = await validateCredentialTokenAction(service, candidate, accountId || undefined)
      if (!result.ok) {
        setValidationError(safeErrorMessage(new Error(result.error)))
        return
      }
      const report = result.value
      setValidation(report)
      if (report.status !== 'unavailable') setLastChecked(candidate)
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
              expiresInHours: lifetime === 'temporary' ? Number(hours || 24) : hours ? Number(hours) : null,
              visible: formData.get('visible') === 'on',
              delivery: 'proxy',
              allowedHosts: String(formData.get('hosts') ?? ''),
              authHeader: String(formData.get('authHeader') ?? 'Authorization'),
              authScheme: String(formData.get('authScheme') ?? 'Bearer') as StoreForm['authScheme'],
              cloudflareAccountId: String(formData.get('cloudflareAccountId') ?? ''),
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
            <Field label="Credential name" hint="Spaces and lowercase letters are converted to a safe environment-variable name.">
              <Input name="name" required maxLength={120} defaultValue={preset?.label ? `${preset.label} API token` : ''} placeholder="e.g. PRODUCTION_CLOUDFLARE" className="w-full font-mono" />
            </Field>
            <Field label="Service / provider">
              <Input name="service" required maxLength={80} value={service} onChange={(event) => {
                setService(event.target.value)
                setCloudflareAccountId('')
                setValidation(null)
                setLastChecked('')
              }} placeholder="e.g. My API" className="w-full" />
            </Field>
          </div>
        )}

        <Field label="API token" hint="Only sent to the provider for verification, then encrypted by the vault. The token is write-only.">
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
        {isCloudflareAccountToken && (
          <Field label="Cloudflare Account ID" hint="This is an Account API Token (cfat_). Enter the 32-character ID of the account that owns it; it is required for verification.">
            <Input name="cloudflareAccountId" value={cloudflareAccountId} onChange={(event) => {
              setCloudflareAccountId(event.target.value)
              setValidation(null)
              setLastChecked('')
            }} placeholder="32-character Account ID" maxLength={32} pattern="[a-fA-F0-9]{32}" title="Enter exactly 32 hexadecimal characters." autoCapitalize="none" spellCheck={false} className="w-full font-mono" />
          </Field>
        )}
        <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
          <Button type="button" variant="outline" disabled={!secretValue.trim() || !service.trim() || validating} onClick={() => void checkToken(secretValue)}>
            {validating ? 'Checking token…' : 'Verify token & inspect permissions'}
          </Button>
          {validation?.status === 'valid' && <span className="text-sm text-success">Verified</span>}
          {validationError && <span className="text-sm text-destructive" role="alert">{validationError}</span>}
        </div>
        {validation && <ValidationResult report={validation} />}

        <details open className="overflow-hidden rounded-xl border border-border bg-card">
          <summary className="cursor-pointer list-none px-4 py-3.5 text-base font-semibold marker:content-none">
            <span className="flex items-center justify-between gap-3">
              <span>Advanced settings</span>
              <span className="text-xs font-normal text-muted-foreground">Network, authentication & expiry</span>
            </span>
          </summary>
          <div className="space-y-5 border-t border-border p-4">
            {isCloudflare && !isCloudflareAccountToken && (
              <Field label="Cloudflare Account ID (optional)" hint="For legacy Account API tokens when Cloudflare cannot list your accounts. New cfat_ tokens show this field above the verification button.">
                <Input name="cloudflareAccountId" value={cloudflareAccountId} onChange={(event) => {
                  setCloudflareAccountId(event.target.value)
                  setValidation(null)
                  setLastChecked('')
                }} placeholder="32-character Account ID" maxLength={32} pattern="[a-fA-F0-9]{32}" title="Enter exactly 32 hexadecimal characters." autoCapitalize="none" spellCheck={false} className="w-full font-mono" />
              </Field>
            )}
            <div className="grid min-w-0 gap-4 sm:grid-cols-2">
              <Field label="Allowed hosts" hint="Exact hostnames only. The proxy cannot call hosts outside this list.">
                <textarea name="hosts" rows={3} defaultValue={defaults.allowedHosts} required spellCheck={false}
                  className="min-h-28 w-full rounded-lg border border-input bg-background px-3 py-3 font-mono text-base focus:outline-none focus:ring-2 focus:ring-ring" />
              </Field>
              <div className="space-y-4">
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
            </div>
            <div className="grid min-w-0 gap-4 sm:grid-cols-2">
              <Field label="Lifetime">
                <NativeSelect className="w-full" value={lifetime} onChange={(event) => setLifetime(event.target.value as 'permanent' | 'temporary')}>
                  <option value="permanent">Permanent</option>
                  <option value="temporary">Temporary (max 24 h)</option>
                </NativeSelect>
              </Field>
              <Field label={lifetime === 'temporary' ? 'Expires in (hours, max 24)' : 'Expires in (hours, optional)'}>
                <Input name="hours" type="number" step="any" min="0.1" max={lifetime === 'temporary' ? 24 : undefined} required={lifetime === 'temporary'} className="w-full" />
              </Field>
            </div>
            <label className="flex min-h-11 cursor-pointer items-start gap-3">
              <input type="checkbox" name="visible" defaultChecked={defaults.visible} className="mt-1 size-5 shrink-0 rounded border-border accent-primary" />
              <span className="text-sm">
                <span className="font-medium">Visible to runners</span>
                <span className="mt-0.5 block text-muted-foreground">Hidden credentials stay in the vault but cannot be listed or used.</span>
              </span>
            </label>
            {preset?.docsUrl && <p className="text-sm text-muted-foreground">Provider reference: <a className="underline" href={preset.docsUrl} target="_blank" rel="noopener noreferrer nofollow">official API documentation</a>.</p>}
          </div>
        </details>

        {errorMessage && <p role="alert" aria-live="polite" className="rounded-lg border border-destructive/30 bg-destructive/5 p-3 text-sm text-destructive">{errorMessage}</p>}
        <Button type="submit" disabled={saving || validating} className="min-h-12 w-full sm:w-auto">
          {saving ? 'Saving…' : mode === 'create' ? 'Verify and save credential' : mode === 'register' ? 'Verify, save and activate' : 'Verify and replace token'}
        </Button>
      </form>
    </ErrorBoundary>
  )
}

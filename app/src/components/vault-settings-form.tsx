'use client'

import { useState } from 'react'
import {
  CheckCircle2, Clock3, Database, Gauge, RotateCcw, Save, Settings2, ShieldCheck, Zap,
} from 'lucide-react'
import { Button } from './ui/button'
import { NativeSelect } from './ui/native-select'
import { saveVaultPreferencesAction } from '../vault-actions.ts'
import type { VaultPreferences } from '../lib/vault-observability.ts'

function Section({
  title,
  description,
  children,
  icon,
}: {
  title: string
  description: string
  children: React.ReactNode
  icon: React.ReactNode
}) {
  return (
    <section className="overflow-hidden rounded-2xl border border-border bg-card">
      <div className="flex items-start gap-3 border-b border-border/70 px-4 py-4 sm:px-5">
        <span className="grid size-10 shrink-0 place-items-center rounded-xl bg-primary/10 text-primary">{icon}</span>
        <div className="min-w-0">
          <h2 className="text-sm font-semibold tracking-tight">{title}</h2>
          <p className="mt-1 max-w-2xl text-xs leading-relaxed text-muted-foreground">{description}</p>
        </div>
      </div>
      <div className="grid gap-x-5 gap-y-5 p-4 sm:grid-cols-2 sm:p-5">{children}</div>
    </section>
  )
}

function Field({
  label,
  hint,
  children,
}: {
  label: string
  hint: string
  children: React.ReactNode
}) {
  return (
    <label className="block min-w-0 space-y-2">
      <span className="block text-xs font-semibold">{label}</span>
      {children}
      <span className="block text-[11px] leading-relaxed text-muted-foreground">{hint}</span>
    </label>
  )
}

export function VaultSettingsForm({ initial }: { initial: VaultPreferences }) {
  const [value, setValue] = useState(initial)
  const [savedValue, setSavedValue] = useState(initial)
  const [saving, setSaving] = useState(false)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  const dirty = JSON.stringify(value) !== JSON.stringify(savedValue)

  function update<K extends keyof VaultPreferences>(key: K, next: VaultPreferences[K]) {
    setValue((current) => ({ ...current, [key]: next }))
    setMessage('')
    setError('')
  }

  async function save() {
    setSaving(true)
    setMessage('')
    setError('')
    const next = { ...value }
    try {
      const result = await saveVaultPreferencesAction(next)
      if (!result.ok) throw new Error('Could not save preferences')
      setValue(next)
      setSavedValue(next)
      setMessage('All preference changes have been saved.')
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Save failed')
    } finally {
      setSaving(false)
    }
  }

  function reset() {
    setValue({ ...savedValue })
    setMessage('')
    setError('')
  }

  return (
    <div className="space-y-4">
      <Section
        title="Credential defaults"
        description="These defaults are applied to new credentials only. Existing credentials keep their current access rules."
        icon={<Settings2 className="size-[18px]" />}
      >
        <Field label="Default visibility" hint="Hidden credentials stay stored but are not discoverable by approved runners.">
          <NativeSelect className="w-full" value={value.defaultVisible ? 'visible' : 'hidden'} onChange={(event) => update('defaultVisible', event.target.value === 'visible')}>
            <option value="visible">Visible to approved runners</option>
            <option value="hidden">Hidden by default</option>
          </NativeSelect>
        </Field>
        <Field label="Default token lifetime" hint="Temporary credentials expire after the selected registration lifetime.">
          <NativeSelect className="w-full" value={value.defaultLifetime} onChange={(event) => update('defaultLifetime', event.target.value as VaultPreferences['defaultLifetime'])}>
            <option value="permanent">Permanent until revoked</option>
            <option value="temporary">Temporary · up to 24 hours</option>
          </NativeSelect>
        </Field>
      </Section>

      <Section
        title="Validation schedule"
        description="Due credentials are checked by the scheduled Worker in bounded batches. Repeated failures use exponential backoff."
        icon={<ShieldCheck className="size-[18px]" />}
      >
        <Field label="Validation interval" hint="This controls how often each credential becomes due; the Worker wakes every 15 minutes to process due checks.">
          <NativeSelect className="w-full" value={String(value.validationIntervalHours)} onChange={(event) => update('validationIntervalHours', Number(event.target.value))}>
            {[1, 2, 3, 4, 6, 8, 12, 24].map((hours) => <option value={hours} key={hours}>Every {hours} hour{hours === 1 ? '' : 's'}</option>)}
          </NativeSelect>
        </Field>
        <div className="flex items-start gap-2.5 rounded-xl border border-border/70 bg-muted/25 p-3">
          <Clock3 className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
          <div><p className="text-xs font-semibold">Failure handling is automatic</p><p className="mt-1 text-[11px] leading-relaxed text-muted-foreground">Network errors stay inconclusive. Invalid, expired and permission-limited states remain distinct; repeated failures back off without losing the first-failure timestamp.</p></div>
        </div>
      </Section>

      <Section
        title="Runtime performance"
        description="Bounded request timeouts help prevent stalled upstream APIs from holding Worker resources."
        icon={<Gauge className="size-[18px]" />}
      >
        <Field label="Upstream request timeout" hint="Applies to proxied provider calls. Credential validation uses its own bounded timeout.">
          <NativeSelect className="w-full" value={String(value.proxyTimeoutMs)} onChange={(event) => update('proxyTimeoutMs', Number(event.target.value))}>
            {[5_000, 10_000, 15_000, 20_000, 25_000, 30_000].map((ms) => <option value={ms} key={ms}>{ms / 1000} seconds</option>)}
          </NativeSelect>
        </Field>
        <div className="flex items-start gap-2.5 rounded-xl border border-border/70 bg-muted/25 p-3">
          <Zap className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
          <div><p className="text-xs font-semibold">No unbounded proxy waits</p><p className="mt-1 text-[11px] leading-relaxed text-muted-foreground">The selected value is clamped by the Vault runtime and does not change the provider host allow-list or authentication policy.</p></div>
        </div>
      </Section>

      <Section
        title="Runner traffic limits"
        description="Tune throughput per credential and the total OIDC/session and registration rates. Limits remain bounded to protect the Vault from accidental or abusive bursts."
        icon={<ShieldCheck className="size-[18px]" />}
      >
        <Field label="Requests per credential / minute" hint="Applies independently to each credential across all active Runner sessions.">
          <NativeSelect className="w-full" value={String(value.proxyRequestsPerMinute)} onChange={(event) => update('proxyRequestsPerMinute', Number(event.target.value))}>
            {[30, 60, 120, 240, 480, 600].map((limit) => <option value={limit} key={limit}>{limit} requests / minute</option>)}
          </NativeSelect>
        </Field>
        <Field label="New Runner sessions / hour" hint="Limits OIDC-to-session exchanges across the trusted Runner policy.">
          <NativeSelect className="w-full" value={String(value.runnerSessionsPerHour)} onChange={(event) => update('runnerSessionsPerHour', Number(event.target.value))}>
            {[10, 20, 40, 60, 80, 120].map((limit) => <option value={limit} key={limit}>{limit} sessions / hour</option>)}
          </NativeSelect>
        </Field>
        <Field label="Credential registrations / hour" hint="Limits owner-inbox requests from trusted Runner workflows.">
          <NativeSelect className="w-full" value={String(value.runnerRegistrationsPerHour)} onChange={(event) => update('runnerRegistrationsPerHour', Number(event.target.value))}>
            {[5, 10, 20, 30, 40, 60].map((limit) => <option value={limit} key={limit}>{limit} requests / hour</option>)}
          </NativeSelect>
        </Field>
        <div className="flex items-start gap-2.5 rounded-xl border border-border/70 bg-muted/25 p-3">
          <Gauge className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
          <div><p className="text-xs font-semibold">Per-credential isolation</p><p className="mt-1 text-[11px] leading-relaxed text-muted-foreground">A busy credential does not consume another credential’s proxy allowance. Raising a limit never exposes the stored token to a Runner.</p></div>
        </div>
      </Section>

      <Section
        title="Data retention"
        description="Retention limits apply to aggregate usage records, validation history and in-panel notifications. Secret values and request payloads are not analytics data."
        icon={<Database className="size-[18px]" />}
      >
        <Field label="Usage & validation history" hint="Hourly usage aggregates and validation history older than this window are removed automatically.">
          <NativeSelect className="w-full" value={String(value.analyticsRetentionDays)} onChange={(event) => update('analyticsRetentionDays', Number(event.target.value))}>
            {[7, 30, 60, 90, 180, 365].map((days) => <option value={days} key={days}>{days} days</option>)}
          </NativeSelect>
        </Field>
        <Field label="Notification history" hint="Older in-panel events are removed automatically. Unread counts are recalculated from retained events.">
          <NativeSelect className="w-full" value={String(value.notificationRetentionDays)} onChange={(event) => update('notificationRetentionDays', Number(event.target.value))}>
            {[7, 30, 60, 90, 180, 365].map((days) => <option value={days} key={days}>{days} days</option>)}
          </NativeSelect>
        </Field>
      </Section>

      <div className="sticky bottom-[calc(4.25rem+env(safe-area-inset-bottom))] z-20 -mx-4 border-t border-border bg-background/95 px-4 py-3 backdrop-blur sm:static sm:mx-0 sm:border-0 sm:bg-transparent sm:px-0 sm:py-0">
        <div className="flex flex-col gap-3 rounded-2xl border border-border bg-card p-3 sm:flex-row sm:items-center sm:justify-between sm:px-4">
          <div className="flex min-w-0 items-start gap-2.5">
            <span className={dirty ? 'mt-1 size-2 shrink-0 rounded-full bg-amber-500' : 'mt-1 size-2 shrink-0 rounded-full bg-emerald-500'} />
            <div className="min-w-0" aria-live="polite">
              <p className="text-xs font-semibold">{dirty ? 'Unsaved changes' : 'All settings saved'}</p>
              <p className="mt-0.5 text-[11px] text-muted-foreground">{message || (dirty ? 'Save to apply these preferences to the Vault.' : 'Your preferences are up to date.')}</p>
              {error && <p role="alert" className="mt-1 text-xs text-destructive">{error}</p>}
            </div>
          </div>
          <div className="flex shrink-0 gap-2">
            {dirty && <Button variant="outline" onClick={reset} disabled={saving} className="min-h-10 flex-1 sm:flex-none"><RotateCcw className="mr-1.5 size-3.5" /> Reset</Button>}
            <Button onClick={save} disabled={saving || !dirty} className="min-h-10 flex-1 sm:flex-none"><Save className="mr-1.5 size-3.5" />{saving ? 'Saving…' : 'Save changes'}</Button>
          </div>
        </div>
      </div>
    </div>
  )
}
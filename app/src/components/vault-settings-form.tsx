'use client'

import { useState } from 'react'
import { Button } from './ui/button'
import { Input } from './ui/input'
import { NativeSelect } from './ui/native-select'
import { saveVaultPreferencesAction } from '../vault-actions.ts'
import type { VaultPreferences } from '../lib/vault-observability.ts'

function Section({ title, description, children, icon }: { title: string; description: string; children: React.ReactNode; icon: React.ReactNode }) {
  return <section className="overflow-hidden rounded-2xl border border-border bg-card shadow-sm">
    <div className="flex items-start gap-3 border-b border-border/70 px-4 py-4 sm:px-5">
      <span className="grid size-10 shrink-0 place-items-center rounded-xl bg-primary/10 text-primary">{icon}</span>
      <div className="min-w-0"><h2 className="font-semibold tracking-tight">{title}</h2><p className="mt-1 text-sm text-muted-foreground">{description}</p></div>
    </div>
    <div className="grid gap-4 p-4 sm:grid-cols-2 sm:p-5">{children}</div>
  </section>
}

function Field({ label, hint, children }: { label: string; hint: string; children: React.ReactNode }) {
  return <label className="block min-w-0 space-y-1.5"><span className="text-sm font-medium">{label}</span>{children}<span className="block text-xs leading-relaxed text-muted-foreground">{hint}</span></label>
}

export function VaultSettingsForm({ initial }: { initial: VaultPreferences }) {
  const [value, setValue] = useState(initial)
  const [saving, setSaving] = useState(false)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  function update<K extends keyof VaultPreferences>(key: K, next: VaultPreferences[K]) {
    setValue((current) => ({ ...current, [key]: next }))
  }
  async function save() {
    setSaving(true); setMessage(''); setError('')
    try {
      const result = await saveVaultPreferencesAction(value)
      if (!result.ok) throw new Error('Could not save preferences')
      setMessage('Preferences saved.')
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Save failed')
    } finally { setSaving(false) }
  }
  return <div className="space-y-4">
    <Section title="General defaults" description="Applied to new credentials. Existing credentials are not changed." icon={<span aria-hidden>✦</span>}>
      <Field label="Default visibility" hint="Hidden credentials are stored but never listed or used by runners.">
        <NativeSelect className="w-full" value={value.defaultVisible ? 'visible' : 'hidden'} onChange={(event) => update('defaultVisible', event.target.value === 'visible')}>
          <option value="visible">Visible to runners</option><option value="hidden">Hidden by default</option>
        </NativeSelect>
      </Field>
      <Field label="Default token lifetime" hint="A temporary credential expires after the selected duration on its registration form.">
        <NativeSelect className="w-full" value={value.defaultLifetime} onChange={(event) => update('defaultLifetime', event.target.value as VaultPreferences['defaultLifetime'])}>
          <option value="permanent">Permanent until revoked</option><option value="temporary">Temporary (24 hours maximum)</option>
        </NativeSelect>
      </Field>
    </Section>
    <Section title="Validation schedule" description="Provider checks run in bounded batches. Network and permission errors are never reported as an invalid token." icon={<span aria-hidden>◷</span>}>
      <Field label="Validation interval" hint="The Worker wakes every 15 minutes and only checks credentials whose due time has arrived.">
        <NativeSelect className="w-full" value={String(value.validationIntervalHours)} onChange={(event) => update('validationIntervalHours', Number(event.target.value))}>
          {[1,2,3,4,6,8,12,24].map((hours) => <option value={hours} key={hours}>Every {hours} hour{hours === 1 ? '' : 's'}</option>)}
        </NativeSelect>
      </Field>
    </Section>
    <Section title="Runtime performance" description="Safe bounds protect the Worker from stalled upstream APIs and unbounded request concurrency." icon={<span aria-hidden>⚡</span>}>
      <Field label="Upstream timeout" hint="Applies to proxied API calls. Validation uses a separate short timeout.">
        <NativeSelect className="w-full" value={String(value.proxyTimeoutMs)} onChange={(event) => update('proxyTimeoutMs', Number(event.target.value))}>
          {[5_000,10_000,15_000,20_000,25_000,30_000].map((ms) => <option value={ms} key={ms}>{ms / 1000} seconds</option>)}
        </NativeSelect>
      </Field>
    </Section>
    <Section title="Data retention" description="Only aggregate counts and metadata are retained. Request headers, bodies and secret values are never stored in analytics." icon={<span aria-hidden>▤</span>}>
      <Field label="Usage analytics" hint="Hourly aggregate data is automatically removed after this period.">
        <NativeSelect className="w-full" value={String(value.analyticsRetentionDays)} onChange={(event) => update('analyticsRetentionDays', Number(event.target.value))}>
          {[7,30,60,90,180,365].map((days) => <option value={days} key={days}>{days} days</option>)}
        </NativeSelect>
      </Field>
      <Field label="Notification history" hint="Older in-panel notifications are automatically removed.">
        <NativeSelect className="w-full" value={String(value.notificationRetentionDays)} onChange={(event) => update('notificationRetentionDays', Number(event.target.value))}>
          {[7,30,60,90,180,365].map((days) => <option value={days} key={days}>{days} days</option>)}
        </NativeSelect>
      </Field>
    </Section>
    <div className="sticky bottom-0 flex flex-col gap-2 border-t border-border bg-background/95 py-3 backdrop-blur sm:static sm:flex-row sm:items-center sm:border-0 sm:bg-transparent sm:py-0">
      <Button onClick={save} disabled={saving} className="min-h-11 w-full sm:w-auto">{saving ? 'Saving…' : 'Save preferences'}</Button>
      {message && <p role="status" className="text-sm text-success">{message}</p>}
      {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
    </div>
  </div>
}

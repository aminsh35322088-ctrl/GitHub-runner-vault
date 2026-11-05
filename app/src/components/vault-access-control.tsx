'use client'

import { useState } from 'react'
import { ShieldCheck, ShieldOff } from 'lucide-react'
import { setVaultAccessEnabledAction } from '../vault-actions.ts'
import { Button } from './ui/button'

export function VaultAccessControl({ initialEnabled }: { initialEnabled: boolean }) {
  const [enabled, setEnabled] = useState(initialEnabled)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')

  async function changeAccess(next: boolean) {
    setSaving(true)
    setError('')
    setMessage('')
    try {
      const result = await setVaultAccessEnabledAction(next)
      if (!result.ok || result.enabled !== next) throw new Error('Vault access state could not be confirmed')
      setEnabled(result.enabled)
      setMessage(next
        ? 'Vault access enabled. Runners must obtain a fresh Session.'
        : 'Vault access disabled. All existing Runner Sessions have been revoked.')
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not update Vault access')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
      <div className="min-w-0">
        <div className="flex items-center gap-2">
          {enabled
            ? <ShieldCheck className="size-4 text-success" aria-hidden="true" />
            : <ShieldOff className="size-4 text-destructive" aria-hidden="true" />}
          <span className="text-sm font-semibold">{enabled ? 'Runner access is enabled' : 'Runner access is disabled'}</span>
        </div>
        <p className="mt-1 max-w-2xl text-xs leading-relaxed text-muted-foreground">
          {enabled
            ? 'Authenticated Runners can create Sessions and use stored credentials through the proxy.'
            : 'All Runner API requests are blocked. Owner settings remain available so access can be restored.'}
        </p>
        {!enabled && <p className="mt-2 text-xs text-muted-foreground">Re-enabling does not restore previous Sessions; the Runner must authenticate again.</p>}
        {message && <p role="status" className="mt-2 text-xs text-muted-foreground">{message}</p>}
        {error && <p role="alert" className="mt-2 text-xs text-destructive">{error}</p>}
      </div>
      <Button
        variant={enabled ? 'destructive' : 'default'}
        disabled={saving}
        loading={saving}
        onClick={() => changeAccess(!enabled)}
        aria-label={enabled ? 'Disable Vault access' : 'Enable Vault access'}
      >
        {enabled ? 'Disable Vault Access' : 'Enable Vault Access'}
      </Button>
    </div>
  )
}

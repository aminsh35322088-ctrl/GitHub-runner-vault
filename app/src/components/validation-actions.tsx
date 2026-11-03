'use client'

import { useState } from 'react'
import { RefreshCw } from 'lucide-react'
import { Button } from './ui/button'
import { validateStoredCredentialAction } from '../vault-actions.ts'

export function RunCredentialValidationButton({ id }: { id: string }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  async function run() {
    setBusy(true)
    setError('')
    try {
      const result = await validateStoredCredentialAction(id)
      if (!result.ok) throw new Error(result.error)
      window.location.reload()
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Validation failed')
    } finally {
      setBusy(false)
    }
  }

  return <div className="flex flex-col items-end gap-1">
    <Button size="sm" variant="outline" disabled={busy} onClick={() => void run()}>
      <RefreshCw className={busy ? 'size-3.5 animate-spin' : 'size-3.5'} />
      {busy ? 'Checking…' : 'Run check'}
    </Button>
    {error && <span role="alert" className="max-w-48 text-right text-xs text-destructive">{error}</span>}
  </div>
}

// Small owner controls: enable/disable, show/hide, delete, revoke sessions, add external entry.

'use client'

import { useState } from 'react'
import { Button } from './ui/button'
import { Input } from './ui/input'
import {
  addExternalAction, deleteCredentialAction, dismissRegistrationRequestAction, renewRegistrationLinkAction, revokeRunnerSessionsAction, saveRunnerPolicyAction, setEnabledAction, setVisibleAction,
} from '../vault-actions.ts'

function useRun() {
  const [error, setError] = useState('')
  const run = async (fn: () => Promise<unknown>, after: () => void = () => window.location.reload()) => {
    setError('')
    try {
      await fn()
      after()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed')
    }
  }
  return { error, run }
}

export function RenewRegistrationLinkButton({ id, hasActiveLink }: { id: string; hasActiveLink: boolean }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  async function openFreshLink() {
    setBusy(true)
    setError('')
    try {
      const result = await renewRegistrationLinkAction(id)
      window.location.assign(result.url)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not create a new registration link.')
      setBusy(false)
    }
  }
  return (
    <div className="space-y-2">
      <Button type="button" disabled={busy} loading={busy} onClick={() => void openFreshLink()}>
        {busy ? 'Preparing secure form…' : hasActiveLink ? 'Open a fresh owner form' : 'Generate a new owner form'}
      </Button>
      <p className="text-xs leading-relaxed text-muted-foreground">
        Creates a new 15-minute, single-use link and invalidates any earlier unused link.
      </p>
      {error && <p role="alert" className="text-xs text-destructive">{error}</p>}
    </div>
  )
}

export function DismissRunnerRequestButton({ id, name }: { id: string; name: string }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  async function dismiss() {
    if (!window.confirm(`Dismiss the pending request for ${name}? This permanently removes its metadata and invalidates every registration link. This cannot be undone.`)) return
    setBusy(true)
    setError('')
    try {
      await dismissRegistrationRequestAction(id)
      window.location.assign('/vault/requests')
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not dismiss this request.')
      setBusy(false)
    }
  }
  return (
    <div className="space-y-2">
      <Button type="button" size="sm" variant="destructive" disabled={busy} loading={busy} onClick={() => void dismiss()}>
        {busy ? 'Dismissing…' : 'Dismiss request'}
      </Button>
      {error && <p role="alert" className="text-xs text-destructive">{error}</p>}
    </div>
  )
}

export function CredentialControls({ id, name, enabled, visible, canEnable }: { id: string; name: string; enabled: boolean; visible: boolean; canEnable: boolean }) {
  const { error, run } = useRun()
  return (
    <div className="flex flex-wrap items-center gap-2">
      <Button size="sm" variant="outline" disabled={!enabled && !canEnable} onClick={() => run(() => setEnabledAction(id, !enabled))}>
        {enabled ? 'Disable' : 'Enable'}
      </Button>
      <Button size="sm" variant="outline" onClick={() => run(() => setVisibleAction(id, !visible))}>
        {visible ? 'Hide' : 'Show'}
      </Button>
      <Button size="sm" variant="destructive"
        onClick={() => { if (window.confirm(`Delete ${name}? The stored value is destroyed.`)) run(() => deleteCredentialAction(id), () => window.location.assign('/vault')) }}>
        Delete
      </Button>
      {error && <span className="text-xs text-destructive">{error}</span>}
    </div>
  )
}

export function RevokeSessionsButton() {
  const { error, run } = useRun()
  const [done, setDone] = useState(false)
  return (
    <div className="flex items-center gap-3">
      <Button variant="outline" onClick={() => run(() => revokeRunnerSessionsAction(), () => setDone(true))}>Revoke all runner sessions</Button>
      {done && <span className="text-sm text-muted-foreground">Done. Runners must authenticate again.</span>}
      {error && <span className="text-xs text-destructive">{error}</span>}
    </div>
  )
}

export function AddExternalForm() {
  const { error, run } = useRun()
  return (
    <form className="flex flex-col gap-3 max-w-md" action={async (fd: FormData) => {
      await run(() => addExternalAction({ name: String(fd.get('name') ?? ''), service: String(fd.get('service') ?? '') }))
    }}>
      <Input name="name" placeholder="GITHUB_TOKEN" required className="font-mono" />
      <Input name="service" placeholder="Service (GitHub)" required />
      <p className="text-sm text-muted-foreground">Purpose is generated automatically from the selected service.</p>
      <Button type="submit" variant="outline" className="min-h-11">Add metadata-only entry</Button>
      {error && <span className="text-xs text-destructive">{error}</span>}
    </form>
  )
}

export function RunnerPolicyForm({ defaults }: { defaults: { repository: string; branch: string; workflowFile: string; repositoryId: string } }) {
  const { error, run } = useRun()
  const [needsId, setNeedsId] = useState(false)
  return (
    <form className="flex flex-col gap-3 max-w-md" action={async (fd: FormData) => {
      await run(async () => {
        try {
          await saveRunnerPolicyAction({
            repository: String(fd.get('repository') ?? ''),
            branch: String(fd.get('branch') ?? ''),
            workflowFile: String(fd.get('workflowFile') ?? ''),
            repositoryId: String(fd.get('repositoryId') ?? ''),
          })
        } catch (e) {
          setNeedsId(true)
          throw e
        }
      })
    }}>
      <label className="text-xs text-muted-foreground">Repository (owner/name)
        <Input name="repository" defaultValue={defaults.repository} placeholder="you/your-runner-repo" required className="font-mono mt-1" />
      </label>
      <label className="text-xs text-muted-foreground">Branch
        <Input name="branch" defaultValue={defaults.branch} required className="font-mono mt-1" />
      </label>
      <label className="text-xs text-muted-foreground">Workflow file
        <Input name="workflowFile" defaultValue={defaults.workflowFile} required className="font-mono mt-1" />
      </label>
      {(needsId || defaults.repositoryId) && (
        <label className="text-xs text-muted-foreground">Repository id (only for private repositories)
          <Input name="repositoryId" defaultValue={defaults.repositoryId} inputMode="numeric" className="font-mono mt-1" />
        </label>
      )}
      <Button type="submit">Save runner repository</Button>
      {error && <span className="text-xs text-destructive">{error}</span>}
    </form>
  )
}

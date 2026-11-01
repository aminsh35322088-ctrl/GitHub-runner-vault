// Small owner controls: enable/disable, show/hide, delete, revoke sessions, add external entry.

'use client'

import { useState } from 'react'
import { Button } from './ui/button'
import { Input } from './ui/input'
import {
  addExternalAction, deleteCredentialAction, revokeRunnerSessionsAction, saveRunnerPolicyAction, setEnabledAction, setVisibleAction,
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
      await run(() => addExternalAction({ name: String(fd.get('name') ?? ''), service: String(fd.get('service') ?? ''), purpose: String(fd.get('purpose') ?? '') }))
    }}>
      <Input name="name" placeholder="GITHUB_TOKEN" required className="font-mono" />
      <Input name="service" placeholder="Service (GitHub)" required />
      <Input name="purpose" placeholder="What is it for" required />
      <Button type="submit" variant="outline">Add metadata-only entry</Button>
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

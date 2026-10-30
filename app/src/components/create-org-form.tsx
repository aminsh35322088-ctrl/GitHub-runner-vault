// Client component form for creating a new organization.
// Uses server action, navigates on success.
// Shows an auto-join checkbox for users with a non-public email domain.

'use client'

import { useState } from 'react'
import { z } from 'zod'
import { parseFormData } from 'spiceflow'
import { ErrorBoundary, useLoaderData } from 'spiceflow/react'
import { Button } from 'sigillo-app/src/components/ui/button'
import { Input } from 'sigillo-app/src/components/ui/input'
import { createOrgAction } from '../actions.ts'
import { COMMON_EMAIL_DOMAINS, getEmailDomain } from '../lib/utils.ts'

const orgSchema = z.object({ name: z.string().min(1, 'Name is required') })
const fields = orgSchema.keyof().enum

export function CreateOrgForm() {
  const { user } = useLoaderData('/dash/*')
  const [autoJoin, setAutoJoin] = useState(false)

  const domain = getEmailDomain(user.email)
  const showAutoJoin = !!domain && !COMMON_EMAIL_DOMAINS.has(domain)

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
        action={async (formData: FormData) => {
          const { name } = parseFormData(orgSchema, formData)
          await createOrgAction({ name, enableAutoJoin: autoJoin })
        }}
      >
        <div>
          <label htmlFor="org-name" className="text-sm font-medium mb-1.5 block">Name</label>
          <Input
            id="org-name"
            name={fields.name}
            placeholder="My Organization"
            required
            autoFocus
            className="w-full"
          />
        </div>
        {showAutoJoin && (
          <label className="flex items-start gap-2.5 cursor-pointer">
            <input
              type="checkbox"
              checked={autoJoin}
              onChange={(e) => setAutoJoin(e.target.checked)}
              className="mt-0.5 size-4 rounded border-border accent-primary"
            />
            <span className="text-sm">
              <span className="font-medium">Auto-join by email domain</span>
              <span className="block text-muted-foreground mt-0.5">
                Anyone with an <span className="font-mono text-foreground">@{domain}</span> email will automatically join this organization.
              </span>
            </span>
          </label>
        )}
        <Button type="submit">Create Organization</Button>
      </form>
    </ErrorBoundary>
  )
}

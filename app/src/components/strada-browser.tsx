// Side-effect client component that boots Strada browser telemetry
// (pageview spans, uncaught errors, React render errors).
//
// The project id comes from a server prop at request time instead of a
// build-time public env var on purpose: the same vite build output is
// packaged into the self-host bundle (`npx sigillo self-host`), so a
// build-time inlined id would send telemetry from customers' self-hosted
// instances to our Strada project. Self-hosted workers have no
// STRADA_PROJECT_ID binding, AppShell renders nothing, and no telemetry
// is ever initialized in their browsers.
/// <reference types="vite/client" />
'use client'

import { useEffect } from 'react'
import { initStrada, captureException } from '@strada.sh/sdk'
import { setReactErrorHandlers } from 'spiceflow/react'

let started = false

export function StradaBrowser({ projectId, environment }: { projectId: string; environment?: string }) {
  useEffect(() => {
    if (started) return
    started = true
    initStrada({
      projectId,
      service: 'sigillo-app-browser',
      environment,
      // keep OTel local during dev/HMR
      enabled: !import.meta.hot,
    })
    // Capture React render errors globally, even when an ErrorBoundary
    // swallows them.
    setReactErrorHandlers({
      onCaughtError: (error) => captureException(error, { tags: { reactHandler: 'onCaughtError' } }),
      onUncaughtError: (error) => captureException(error, { tags: { reactHandler: 'onUncaughtError' } }),
      onRecoverableError: (error) => captureException(error, { tags: { reactHandler: 'onRecoverableError' } }),
    })
  }, [projectId, environment])
  return null
}

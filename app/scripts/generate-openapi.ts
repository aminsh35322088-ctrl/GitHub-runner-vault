// Generate OpenAPI spec and write to src/openapi.json for holocron.
// Run: pnpm openapi
//
// Uses app.handle() to generate the spec without starting a server.
// Stubs cloudflare:workers since it's not available outside workerd.

import { writeFile } from 'node:fs/promises'
import { resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { register } from 'node:module'

// Stub cloudflare:workers so the import doesn't blow up outside workerd
register('data:text/javascript,' + encodeURIComponent(`
  export function resolve(specifier, context, next) {
    if (specifier === 'cloudflare:workers') {
      return { url: 'data:text/javascript,export const env = {};export function waitUntil() {}', shortCircuit: true }
    }
    return next(specifier, context)
  }
`))

const { apiApp } = await import('../src/api.ts')

const res = await apiApp.handle(new Request('http://localhost/api/v0/openapi.json'))
if (!res.ok) throw new Error(`${res.status} ${await res.text()}`)
const spec = (await res.json()) as any

spec.info = {
  title: 'Sigillo API',
  description: 'REST API for the Sigillo secrets manager. Used by the CLI, SDKs, and agents.',
  version: '0.1.0',
}

// Only keep /api/v0/ routes, drop page routes and the openapi endpoint itself
spec.paths = Object.fromEntries(
  Object.entries(spec.paths as Record<string, unknown>).filter(
    ([p]) => p.startsWith('/api/v0/') && p !== '/api/v0/openapi.json',
  ),
)

const outPath = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'src', 'openapi.json')
await writeFile(outPath, JSON.stringify(spec, null, 2) + '\n')
console.log(`Wrote ${outPath}`)

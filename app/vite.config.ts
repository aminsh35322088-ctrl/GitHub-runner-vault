/// <reference types="vitest/config" />
// Read D1 migration SQL files so they can be applied in the workerd setup file
import { cloudflare } from '@cloudflare/vite-plugin'
import { cloudflareTest } from '@cloudflare/vitest-pool-workers'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { spiceflowPlugin } from 'spiceflow/vite'
import { defineConfig } from 'vite'

const port = parseInt(process.env.PORT || '5188', 10)

// Routes every outbound fetch made by the worker under test to this handler.
//
// The vault has no outbound dependencies during tests (GitHub login is not
// exercised there), so every outbound fetch fails loudly instead of reaching the
// internet.
//
// Anything unrecognized gets a 501 instead of reaching the internet, so tests
// stay hermetic and a new unmocked dependency fails loudly and instantly
// instead of hanging.
function testOutboundService(request: Request): Response {
  return Response.json(
    { error: 'unexpected_outbound_request', url: request.url },
    { status: 501 },
  )
}

export default defineConfig(async () => {
  return {
    server: { port, strictPort: true },
    clearScreen: false,
    plugins: [
      // cloudflareTest() runs tests inside workerd via @cloudflare/vitest-pool-workers.
      // cloudflare() handles dev/build/deploy but conflicts with the vitest pool
      // (both manage workerd), so only one is active at a time.
      process.env.VITEST
        ? cloudflareTest({
            wrangler: { configPath: './wrangler.test.jsonc' },
            miniflare: {
              bindings: {
              },
              outboundService: testOutboundService,
            },
          })
        : null,
      tailwindcss(),
      // Tests need the raw react + spiceflow plugins next to cloudflareTest().
      ...(process.env.VITEST
        ? [react(), spiceflowPlugin({ entry: './src/app.tsx' })]
        : [react(), spiceflowPlugin({ entry: './src/app.tsx' })]),
      // cloudflare() must come AFTER spiceflow — spiceflow sets ssr outDir to
      // dist/rsc/ssr (nested inside the worker root) so workerd can resolve the
      // cross-environment import. cloudflare's config hook unconditionally sets
      // outDir to dist/ssr (sibling), and Vite's config merge gives the first
      // setter priority. See https://github.com/cloudflare/workers-sdk/issues/13869
      !process.env.VITEST
        ? cloudflare({
            viteEnvironment: {
              name: 'rsc',
              childEnvironments: ['ssr'],
            },
          })
        : null,
    ],
    resolve: {
      dedupe: ['spiceflow', 'spiceflow/react', 'react', 'react-dom', 'react/jsx-runtime', 'react/jsx-dev-runtime'],
    },
    test: {
      setupFiles: ['./src/test-setup.ts'],
      // Better Auth uses jose for GitHub OAuth/JWT handling. Bundle both through
      // Vite's SSR optimizer so the Workers test runtime does not resolve jose's
      // package-internal ESM imports through the pool's module fallback.
      // See Cloudflare's Workers Vitest module-resolution guidance:
      // https://developers.cloudflare.com/workers/testing/vitest-integration/known-issues/#module-resolution
      deps: {
        optimizer: {
          ssr: {
            enabled: true,
            include: ['better-auth'],
          },
        },
      },
    },
  }
})

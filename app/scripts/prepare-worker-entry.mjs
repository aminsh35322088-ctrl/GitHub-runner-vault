import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { pathToFileURL } from 'node:url'

/**
 * Vite's RSC bundle exports helper values for its own chunk graph. Workerd
 * interprets every export from the service entry as an entrypoint binding and
 * rejects non-handler values. Keep index.js intact for RSC chunk imports, but
 * expose only its default Worker handler from a tiny Wrangler-bundled entry.
 */
export function prepareWorkerEntrypoint(outputDir = resolve(process.cwd(), 'dist/rsc')) {
  const configPath = resolve(outputDir, 'wrangler.json')
  if (!existsSync(configPath)) {
    throw new Error('Vite build did not create dist/rsc/wrangler.json')
  }

  const config = JSON.parse(readFileSync(configPath, 'utf8'))
  const workerEntryPath = resolve(outputDir, 'worker.js')
  const bundlePath = resolve(outputDir, 'index.js')

  if (config.main === 'worker.js' && existsSync(workerEntryPath) && !('no_bundle' in config)) {
    return config
  }
  if (config.main !== 'index.js') {
    throw new Error(`Expected the Vite RSC bundle at index.js, found ${String(config.main)}`)
  }
  if (!existsSync(bundlePath)) {
    throw new Error('Vite build did not create dist/rsc/index.js')
  }

  writeFileSync(workerEntryPath, "import worker from './index.js'\nexport default worker\n")
  config.main = 'worker.js'
  // Wrangler must bundle the wrapper and its imported Worker module. The RSC
  // assets still import named helpers from index.js; those remain in that
  // dependency module and are not exposed as service-entry bindings.
  delete config.no_bundle
  writeFileSync(configPath, JSON.stringify(config, null, 2) + '\n')
  return config
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const config = prepareWorkerEntrypoint()
    console.log(`[worker-entry] prepared ${config.main} (bundled Worker wrapper)`)
  } catch (error) {
    console.error('[worker-entry] ' + (error instanceof Error ? error.message : String(error)))
    process.exitCode = 1
  }
}

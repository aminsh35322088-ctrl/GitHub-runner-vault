// Regression guard for the served document <head>.
//
// The Vault's Shell used to declare its charset/viewport/robots/title tags
// through spiceflow's <Head> collector. In spiceflow 1.26.0-rsc.18 that
// component only collects tags for a <CollectedHead/> emission that never
// lands in the production document (CollectedHead is not even exported),
// so the served HTML shipped with no <meta name="viewport"> at all and
// every phone laid the app out at ~980px desktop width, silently nullifying
// the responsive layout. Vitest/spiceflow test mode cannot catch this: it
// returns the page JSX directly without the production document pipeline.
//
// This check therefore exercises the closest-to-production path available:
// it builds the app if the build output is missing or stale, boots the
// built Worker with `wrangler dev` against a throwaway local D1, fetches
// real pages over HTTP, and asserts on the served HTML.
import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import { existsSync, mkdtempSync, rmSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

const appRoot = resolve(fileURLToPath(new URL('..', import.meta.url)))
const workerEntry = join(appRoot, 'dist', 'rsc', 'worker.js')
const workerConfig = join(appRoot, 'dist', 'rsc', 'wrangler.json')
const shellSource = join(appRoot, 'src', 'app.tsx')
const viteBin = join(appRoot, 'node_modules', '.bin', 'vite')
const wranglerBin = join(appRoot, 'node_modules', '.bin', 'wrangler')

// Same throwaway key the vitest config uses (bytes 0..31); never a real one.
const TEST_MASTER_KEY = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8='

function run(command, args) {
  const result = spawnSync(command, args, { cwd: appRoot, stdio: 'inherit' })
  assert.equal(result.status, 0, `${command} ${args.join(' ')} failed`)
}

function ensureBuilt() {
  const stale =
    !existsSync(workerEntry) ||
    !existsSync(workerConfig) ||
    statSync(shellSource).mtimeMs > statSync(workerEntry).mtimeMs
  if (!stale) return
  // Mirror the app package.json "build" script without depending on pnpm.
  run(process.execPath, ['scripts/embed-schema.mjs', '--check'])
  run(viteBin, ['build'])
  run(process.execPath, ['scripts/prepare-worker-entry.mjs'])
}

async function fetchWhenReady(baseUrl, path, deadlineMs = 90_000) {
  const deadline = Date.now() + deadlineMs
  let lastError
  while (Date.now() < deadline) {
    try {
      const response = await fetch(baseUrl + path)
      if (response.ok) return await response.text()
      lastError = new Error(`HTTP ${response.status}`)
    } catch (error) {
      lastError = error
    }
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 500))
  }
  throw lastError ?? new Error('worker did not become ready')
}

async function bootBuiltWorker(persistDir) {
  const port = 20_000 + Math.floor(Math.random() * 20_000)
  const child = spawn(
    wranglerBin,
    [
      'dev',
      '--config', workerConfig,
      '--port', String(port),
      '--local',
      '--persist-to', persistDir,
      '--var', `VAULT_MASTER_KEY:${TEST_MASTER_KEY}`,
    ],
    { cwd: appRoot, detached: true, stdio: 'ignore' },
  )
  const baseUrl = `http://127.0.0.1:${port}`
  try {
    const html = await fetchWhenReady(baseUrl, '/login')
    return { child, baseUrl, html }
  } catch (error) {
    stop(child)
    throw error
  }
}

function stop(child) {
  if (!child || child.killed) return
  try {
    process.kill(-child.pid, 'SIGTERM')
  } catch {
    child.kill('SIGTERM')
  }
}

function assertHeadTags(html, path) {
  assert.equal(
    (html.match(/name="viewport"/g) ?? []).length,
    1,
    `${path}: served HTML must contain exactly one viewport meta`,
  )
  assert.match(
    html,
    /<meta name="viewport" content="width=device-width, initial-scale=1\.0, viewport-fit=cover"\/>/,
    `${path}: viewport meta must carry the exact mobile layout contract`,
  )
  assert.match(
    html,
    /<title>Runner Credential Vault<\/title>/,
    `${path}: served HTML must contain the document title`,
  )
  assert.match(
    html,
    /<meta name="robots" content="noindex, nofollow"\/>/,
    `${path}: served HTML must contain the robots meta`,
  )
}

test('production build serves viewport, title and robots head tags', { timeout: 300_000 }, async () => {
  ensureBuilt()
  const persistDir = mkdtempSync(join(tmpdir(), 'runner-vault-head-tags-'))
  let booted
  try {
    booted = await bootBuiltWorker(persistDir)
    assertHeadTags(booted.html, '/login')
    const setupHtml = await fetchWhenReady(booted.baseUrl, '/setup')
    assertHeadTags(setupHtml, '/setup')
  } finally {
    stop(booted?.child)
    rmSync(persistDir, { recursive: true, force: true })
  }
})

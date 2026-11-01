import { describe, expect, test } from 'vitest'
import { presetForService } from './presets.ts'
import { normalizeAllowedHosts, normalizeAuthStyle } from './credential-input.ts'

describe('service presets', () => {
  test('match the exact service name regardless of case and punctuation', () => {
    expect(presetForService('Cloudflare')?.hosts).toEqual(['api.cloudflare.com'])
    expect(presetForService(' cloud-flare ')?.id).toBe('cloudflare')
    expect(presetForService('Railway')?.authScheme).toBe('Bearer')
    expect(presetForService('Anthropic')).toMatchObject({ authHeader: 'x-api-key', authScheme: 'Raw' })
  })

  test('never match by substring, so a model cannot smuggle a preset in', () => {
    for (const name of ['Cloudflare evil.example', 'my-cloudflare-proxy', 'github.com.attacker.io', '', 'unknown']) {
      expect(presetForService(name)).toBeNull()
    }
  })

  test('every preset passes the same host and header rules as owner input', () => {
    for (const service of ['cloudflare', 'railway', 'github', 'vercel', 'netlify', 'digitalocean', 'openai', 'anthropic', 'stripe', 'sentry']) {
      const p = presetForService(service)!
      expect(normalizeAllowedHosts(p.hosts).ok, service).toBe(true)
      expect(normalizeAuthStyle(p.authHeader, p.authScheme).ok, service).toBe(true)
    }
  })
})

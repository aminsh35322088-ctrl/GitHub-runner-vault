import { describe, expect, test } from 'vitest'
import { formatAllowedHosts, presetForService, SERVICE_CATALOG } from './presets.ts'
import { normalizeAllowedHosts, normalizeAuthStyle } from './credential-input.ts'

describe('service presets', () => {
  test('catalog exposes categorized providers with official HTTPS documentation', () => {
    expect(SERVICE_CATALOG.length).toBeGreaterThanOrEqual(15)
    expect(new Set(SERVICE_CATALOG.map((p) => p.id)).size).toBe(SERVICE_CATALOG.length)
    for (const provider of SERVICE_CATALOG) {
      expect(provider.docsUrl).toMatch(/^https:\/\//)
      expect(normalizeAllowedHosts(provider.hosts).ok, provider.id).toBe(true)
      const formValue = formatAllowedHosts(provider.hosts)
      expect(formValue).not.toContain('\\n')
      expect(formValue.split(/\s+/).filter(Boolean)).toEqual(provider.hosts)
      expect(normalizeAllowedHosts(formValue.split(/[\s,]+/).filter(Boolean)).ok, provider.id).toBe(true)
      expect(normalizeAuthStyle(provider.authHeader, provider.authScheme).ok, provider.id).toBe(true)
    }
  })

  test('match the exact service name regardless of case and punctuation', () => {
    expect(presetForService('Cloudflare')?.hosts).toEqual(['api.cloudflare.com'])
    expect(presetForService(' cloud-flare ')?.id).toBe('cloudflare')
    expect(presetForService('Railway')?.authScheme).toBe('Bearer')
    expect(presetForService('Anthropic')).toMatchObject({ authHeader: 'Authorization', authScheme: 'Bearer' })
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

  test('uses a service-derived purpose instead of requiring an owner-entered purpose', async () => {
    const { defaultPurposeForService } = await import('./presets.ts')
    expect(defaultPurposeForService('Cloudflare')).toBe('Manage zones, DNS, Workers and account resources.')
    expect(defaultPurposeForService('GitHub')).toBe('Manage repositories, issues, pull requests and workflows.')
    expect(defaultPurposeForService('Custom API')).toBe('Use the Custom API credential through the vault proxy.')
  })
})

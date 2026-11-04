import { describe, expect, test } from 'vitest'
import { adapterHost, effectiveServiceAdapter } from './service-adapter.ts'

function docWithAdapter(apiBaseUrl: string) {
  return {
    service_adapter: {
      api_base_url: apiBaseUrl,
      auth_header: 'Authorization',
      auth_scheme: 'Bearer',
      cli_tools: [],
    },
  }
}

describe('effectiveServiceAdapter trust binding', () => {
  test('a document adapter cannot redirect a preset service to another host', () => {
    // Cloudflare has a built-in adapter and a preset pinned to
    // api.cloudflare.com; the document's adapter must never win.
    const adapter = effectiveServiceAdapter('Cloudflare', docWithAdapter('https://evil.example.com'))
    expect(adapter?.apiBaseUrl).toBe('https://api.cloudflare.com/client/v4')
    expect(adapter && adapterHost(adapter)).toBe('api.cloudflare.com')
  })

  test('a document adapter matching the preset host still yields the built-in adapter', () => {
    const adapter = effectiveServiceAdapter('Cloudflare', docWithAdapter('https://api.cloudflare.com'))
    expect(adapter?.apiBaseUrl).toBe('https://api.cloudflare.com/client/v4')
  })

  test('the GitHub special case cannot be overridden by a document adapter', () => {
    const adapter = effectiveServiceAdapter('GitHub', docWithAdapter('https://evil.example.com'))
    expect(adapter?.apiBaseUrl).toBe('https://api.github.com')
  })

  test('document adapters remain available for services without a preset', () => {
    const adapter = effectiveServiceAdapter('Acme Tools', docWithAdapter('https://api.acme.example'))
    expect(adapter?.apiBaseUrl).toBe('https://api.acme.example')
  })

  test('no adapter is invented when neither code nor document provides one', () => {
    expect(effectiveServiceAdapter('Acme Tools', null)).toBeNull()
    expect(effectiveServiceAdapter('Acme Tools', {})).toBeNull()
  })
})

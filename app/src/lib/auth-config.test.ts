import { describe, expect, test } from 'vitest'
import { CLOUDFLARE_IP_ADDRESS_HEADERS } from './auth-config.ts'

describe('auth config', () => {
  test('client IP comes only from the edge-controlled Cloudflare header', () => {
    expect([...CLOUDFLARE_IP_ADDRESS_HEADERS]).toEqual(['cf-connecting-ip'])
  })
})

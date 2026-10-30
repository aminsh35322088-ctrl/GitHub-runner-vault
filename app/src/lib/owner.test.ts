import { describe, expect, test } from 'vitest'
import { isOwnerAccount, normalizeOwnerId, userHasOwnerAccount } from './owner.ts'

describe('normalizeOwnerId', () => {
  test('accepts a positive integer string and trims it', () => {
    expect(normalizeOwnerId('318252513')).toBe('318252513')
    expect(normalizeOwnerId(' 42 ')).toBe('42')
  })

  test.each([undefined, null, 42, '', '0', '-1', '01', 'abc', '12abc', '1.5', '1'.repeat(17)])(
    'rejects %s',
    (value) => {
      expect(normalizeOwnerId(value)).toBeNull()
    },
  )
})

describe('isOwnerAccount', () => {
  const owner = '318252513'

  test('matches the owner GitHub id exactly', () => {
    expect(isOwnerAccount({ providerId: 'github', accountId: owner }, owner)).toBe(true)
  })

  test('rejects another GitHub id, including a login name', () => {
    expect(isOwnerAccount({ providerId: 'github', accountId: '318252514' }, owner)).toBe(false)
    expect(isOwnerAccount({ providerId: 'github', accountId: 'aminsh35322088-ctrl' }, owner)).toBe(false)
  })

  test('rejects the owner id on a different provider', () => {
    expect(isOwnerAccount({ providerId: 'google', accountId: owner }, owner)).toBe(false)
    expect(isOwnerAccount({ providerId: 'credential', accountId: owner }, owner)).toBe(false)
  })

  test('fails closed when the owner id is missing or malformed', () => {
    for (const bad of [undefined, null, '', ' ', '0', 'abc']) {
      expect(isOwnerAccount({ providerId: 'github', accountId: owner }, bad)).toBe(false)
    }
  })
})

describe('userHasOwnerAccount', () => {
  test('true when any linked account is the owner', () => {
    expect(userHasOwnerAccount([
      { providerId: 'google', accountId: 'x' },
      { providerId: 'github', accountId: '7' },
    ], '7')).toBe(true)
  })

  test('false with no accounts or no owner match', () => {
    expect(userHasOwnerAccount([], '7')).toBe(false)
    expect(userHasOwnerAccount([{ providerId: 'github', accountId: '8' }], '7')).toBe(false)
  })
})

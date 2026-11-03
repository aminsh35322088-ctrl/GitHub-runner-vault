import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, test } from 'vitest'
import { MobileNavigation } from './mobile-navigation.tsx'

describe('Android bottom navigation', () => {
  test('keeps primary actions and secondary destinations available in five slots', () => {
    const html = renderToStaticMarkup(<MobileNavigation current="/vault" />)
    expect(html).toContain('aria-label="Mobile navigation"')
    expect(html).toContain('grid-cols-5')
    expect(html).toContain('lg:hidden')
    for (const href of [
      '/vault',
      '/vault/requests',
      '/vault/services',
      '/vault/validation',
      '/vault/integrations',
      '/vault/analytics',
      '/vault/audit',
      '/vault/settings',
    ]) expect(html).toContain('href="' + href + '"')
  })

  test('highlights a secondary destination in the More disclosure', () => {
    const html = renderToStaticMarkup(<MobileNavigation current="/vault/audit" />)
    expect(html).toContain('<details')
    expect(html).toContain('aria-label="More navigation links"')
    expect(html).toContain('href="/vault/audit" aria-current="page"')
  })

  test('keeps credential detail pages grouped under Home and service setup under Add', () => {
    const credential = renderToStaticMarkup(<MobileNavigation current="/vault/credentials/cred_123" />)
    const service = renderToStaticMarkup(<MobileNavigation current="/vault/new?service=github" />)
    expect(credential).toContain('href="/vault" aria-current="page"')
    expect(service).toContain('href="/vault/services" aria-current="page"')
  })
})

// Known services and how their APIs expect to be called, so the owner only has to
// paste a token. A preset is only ever a *default* shown to the owner (the form
// still posts hosts / header / scheme and the owner can change them). The model
// can influence nothing beyond choosing which curated entry matches its `service`
// text; it cannot add a host.

export interface ServicePreset {
  id: string
  label: string
  hosts: string[]
  authHeader: string
  authScheme: 'Bearer' | 'Token' | 'Raw'
}

const PRESETS: ServicePreset[] = [
  { id: 'cloudflare', label: 'Cloudflare', hosts: ['api.cloudflare.com'], authHeader: 'Authorization', authScheme: 'Bearer' },
  { id: 'railway', label: 'Railway', hosts: ['backboard.railway.com', 'backboard.railway.app'], authHeader: 'Authorization', authScheme: 'Bearer' },
  { id: 'github', label: 'GitHub', hosts: ['api.github.com'], authHeader: 'Authorization', authScheme: 'Bearer' },
  { id: 'vercel', label: 'Vercel', hosts: ['api.vercel.com'], authHeader: 'Authorization', authScheme: 'Bearer' },
  { id: 'netlify', label: 'Netlify', hosts: ['api.netlify.com'], authHeader: 'Authorization', authScheme: 'Bearer' },
  { id: 'digitalocean', label: 'DigitalOcean', hosts: ['api.digitalocean.com'], authHeader: 'Authorization', authScheme: 'Bearer' },
  { id: 'openai', label: 'OpenAI', hosts: ['api.openai.com'], authHeader: 'Authorization', authScheme: 'Bearer' },
  { id: 'anthropic', label: 'Anthropic', hosts: ['api.anthropic.com'], authHeader: 'x-api-key', authScheme: 'Raw' },
  { id: 'stripe', label: 'Stripe', hosts: ['api.stripe.com'], authHeader: 'Authorization', authScheme: 'Bearer' },
  { id: 'sentry', label: 'Sentry', hosts: ['sentry.io'], authHeader: 'Authorization', authScheme: 'Bearer' },
]

/** Exact (case- and punctuation-insensitive) match on the service name; no substring guessing. */
export function presetForService(service: string): ServicePreset | null {
  const key = service.toLowerCase().replace(/[^a-z0-9]/g, '')
  return PRESETS.find((p) => p.id === key || p.label.toLowerCase().replace(/[^a-z0-9]/g, '') === key) ?? null
}

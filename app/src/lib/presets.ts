// Curated provider catalog. Entries are safe starting points, not a substitute for
// reviewing the provider's current documentation and the exact permissions on a token.
// Unknown providers remain supported through the custom-service path.

export type ServiceCategory =
  | 'Cloud & Infrastructure'
  | 'Developer Platforms'
  | 'AI & LLM'
  | 'Payments'
  | 'Monitoring & Analytics'
  | 'Communication'
  | 'Data & Storage'

export interface ServicePreset {
  id: string
  label: string
  category: ServiceCategory
  description: string
  docsUrl: string
  hosts: string[]
  authHeader: string
  authScheme: 'Bearer' | 'Token' | 'Raw'
}

export const SERVICE_CATALOG: ServicePreset[] = [
  { id: 'cloudflare', label: 'Cloudflare', category: 'Cloud & Infrastructure', description: 'Manage zones, DNS, Workers and account resources.', docsUrl: 'https://developers.cloudflare.com/api/overview/', hosts: ['api.cloudflare.com'], authHeader: 'Authorization', authScheme: 'Bearer' },
  { id: 'railway', label: 'Railway', category: 'Cloud & Infrastructure', description: 'Manage projects, services, deployments and variables.', docsUrl: 'https://docs.railway.com/integrations/api', hosts: ['backboard.railway.com'], authHeader: 'Authorization', authScheme: 'Bearer' },
  { id: 'vercel', label: 'Vercel', category: 'Cloud & Infrastructure', description: 'Manage projects, deployments, domains and teams.', docsUrl: 'https://vercel.com/docs/rest-api', hosts: ['api.vercel.com'], authHeader: 'Authorization', authScheme: 'Bearer' },
  { id: 'netlify', label: 'Netlify', category: 'Cloud & Infrastructure', description: 'Manage sites, builds and deploys.', docsUrl: 'https://docs.netlify.com/api-and-cli-guides/api-guides/get-started-with-api/', hosts: ['api.netlify.com'], authHeader: 'Authorization', authScheme: 'Bearer' },
  { id: 'digitalocean', label: 'DigitalOcean', category: 'Cloud & Infrastructure', description: 'Manage Droplets, networking and platform resources.', docsUrl: 'https://docs.digitalocean.com/reference/api/', hosts: ['api.digitalocean.com'], authHeader: 'Authorization', authScheme: 'Bearer' },
  { id: 'github', label: 'GitHub', category: 'Developer Platforms', description: 'Manage repositories, issues, pull requests and workflows.', docsUrl: 'https://docs.github.com/en/rest/authentication/authenticating-to-the-rest-api', hosts: ['api.github.com'], authHeader: 'Authorization', authScheme: 'Bearer' },
  { id: 'openai', label: 'OpenAI', category: 'AI & LLM', description: 'Use the OpenAI API for models, responses and embeddings.', docsUrl: 'https://platform.openai.com/docs/api-reference/authentication', hosts: ['api.openai.com'], authHeader: 'Authorization', authScheme: 'Bearer' },
  { id: 'anthropic', label: 'Anthropic', category: 'AI & LLM', description: 'Use the Claude API and Messages endpoints.', docsUrl: 'https://platform.claude.com/docs/en/manage-claude/authentication', hosts: ['api.anthropic.com'], authHeader: 'Authorization', authScheme: 'Bearer' },
  { id: 'groq', label: 'Groq', category: 'AI & LLM', description: 'Access hosted inference and compatible chat completions.', docsUrl: 'https://console.groq.com/docs/quickstart', hosts: ['api.groq.com'], authHeader: 'Authorization', authScheme: 'Bearer' },
  { id: 'mistral', label: 'Mistral AI', category: 'AI & LLM', description: 'Access Mistral models and platform APIs.', docsUrl: 'https://docs.mistral.ai/api/', hosts: ['api.mistral.ai'], authHeader: 'Authorization', authScheme: 'Bearer' },
  { id: 'huggingface', label: 'Hugging Face', category: 'AI & LLM', description: 'Access inference APIs and Hugging Face Hub resources.', docsUrl: 'https://huggingface.co/docs/api-inference/quicktour', hosts: ['huggingface.co', 'router.huggingface.co'], authHeader: 'Authorization', authScheme: 'Bearer' },
  { id: 'stripe', label: 'Stripe', category: 'Payments', description: 'Manage payments, customers, subscriptions and billing.', docsUrl: 'https://docs.stripe.com/keys', hosts: ['api.stripe.com'], authHeader: 'Authorization', authScheme: 'Bearer' },
  { id: 'sentry', label: 'Sentry', category: 'Monitoring & Analytics', description: 'Access organizations, projects, issues and events.', docsUrl: 'https://docs.sentry.io/api/auth/', hosts: ['sentry.io'], authHeader: 'Authorization', authScheme: 'Bearer' },
  { id: 'supabase', label: 'Supabase', category: 'Data & Storage', description: 'Manage Supabase projects through the Management API.', docsUrl: 'https://supabase.com/docs/reference/api/introduction', hosts: ['api.supabase.com'], authHeader: 'Authorization', authScheme: 'Bearer' },
  { id: 'pinecone', label: 'Pinecone', category: 'Data & Storage', description: 'Manage vector index configuration through the control-plane API.', docsUrl: 'https://docs.pinecone.io/guides/operations/authentication', hosts: ['api.pinecone.io'], authHeader: 'Api-Key', authScheme: 'Raw' },
  { id: 'slack', label: 'Slack', category: 'Communication', description: 'Use Slack Web API methods and workspace integrations.', docsUrl: 'https://api.slack.com/authentication/token-types', hosts: ['slack.com'], authHeader: 'Authorization', authScheme: 'Bearer' },
]

export function presetForService(service: string): ServicePreset | null {
  const key = service.toLowerCase().replace(/[^a-z0-9]/g, '')
  return SERVICE_CATALOG.find((p) => p.id === key || p.label.toLowerCase().replace(/[^a-z0-9]/g, '') === key) ?? null
}

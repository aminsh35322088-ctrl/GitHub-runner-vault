import type { AuthScheme } from './credential-input.ts'

export type ServiceAdapterTool = {
  id: string
  label: string
  binary: string
  integration: 'base-url-env' | 'host-flag'
  variable?: string
  flag?: string
  setupHint: string
}

export type ServiceAdapter = {
  apiBaseUrl: string
  authHeader: string
  authScheme: AuthScheme
  validation?: {
    method: 'GET' | 'HEAD'
    path: string
    identityPointer?: string
    permissionsPointer?: string
    successPointer?: string
    successValue?: string | number | boolean
  }
  defaultHeaders?: Record<string, string>
  cliTools: ServiceAdapterTool[]
}

const northflank: ServiceAdapterTool = {
  id: 'northflank',
  label: 'Northflank CLI',
  binary: 'nf',
  integration: 'base-url-env',
  variable: 'NF_API_BASE_URL',
  setupHint: 'Set NF_API_BASE_URL to the local Vault proxy and NF_API_TOKEN to the non-secret placeholder shown by the CLI bridge. Northflank CLI documents both overrides for headless use.',
}

const adapters: Record<string, ServiceAdapter> = {
  cloudflare: {
    apiBaseUrl: 'https://api.cloudflare.com/client/v4',
    authHeader: 'Authorization',
    authScheme: 'Bearer',
    cliTools: [],
  },
  northflank: {
    apiBaseUrl: 'https://api.northflank.com/v1',
    authHeader: 'Authorization',
    authScheme: 'Bearer',
    validation: { method: 'GET', path: '/projects' },
    cliTools: [northflank],
  },
  railway: {
    apiBaseUrl: 'https://backboard.railway.com/graphql/v2',
    authHeader: 'Authorization',
    authScheme: 'Bearer',
    cliTools: [],
  },
  vercel: {
    apiBaseUrl: 'https://api.vercel.com',
    authHeader: 'Authorization',
    authScheme: 'Bearer',
    validation: { method: 'GET', path: '/v2/user' },
    cliTools: [],
  },
  netlify: {
    apiBaseUrl: 'https://api.netlify.com',
    authHeader: 'Authorization',
    authScheme: 'Bearer',
    validation: { method: 'GET', path: '/api/v1/user' },
    cliTools: [],
  },
  digitalocean: {
    apiBaseUrl: 'https://api.digitalocean.com',
    authHeader: 'Authorization',
    authScheme: 'Bearer',
    validation: { method: 'GET', path: '/v2/account' },
    cliTools: [],
  },
  openai: {
    apiBaseUrl: 'https://api.openai.com',
    authHeader: 'Authorization',
    authScheme: 'Bearer',
    validation: { method: 'GET', path: '/v1/models' },
    cliTools: [],
  },
  anthropic: {
    apiBaseUrl: 'https://api.anthropic.com',
    authHeader: 'x-api-key',
    authScheme: 'Raw',
    validation: { method: 'GET', path: '/v1/models' },
    defaultHeaders: { 'anthropic-version': '2023-06-01' },
    cliTools: [],
  },
  groq: {
    apiBaseUrl: 'https://api.groq.com',
    authHeader: 'Authorization',
    authScheme: 'Bearer',
    validation: { method: 'GET', path: '/openai/v1/models' },
    cliTools: [],
  },
  mistral: {
    apiBaseUrl: 'https://api.mistral.ai',
    authHeader: 'Authorization',
    authScheme: 'Bearer',
    validation: { method: 'GET', path: '/v1/models' },
    cliTools: [],
  },
  huggingface: {
    apiBaseUrl: 'https://huggingface.co',
    authHeader: 'Authorization',
    authScheme: 'Bearer',
    validation: { method: 'GET', path: '/api/whoami-v2' },
    cliTools: [],
  },
  stripe: {
    apiBaseUrl: 'https://api.stripe.com',
    authHeader: 'Authorization',
    authScheme: 'Bearer',
    validation: { method: 'GET', path: '/v1/account' },
    cliTools: [],
  },
  sentry: {
    apiBaseUrl: 'https://sentry.io',
    authHeader: 'Authorization',
    authScheme: 'Bearer',
    validation: { method: 'GET', path: '/api/0/' },
    cliTools: [],
  },
  supabase: {
    apiBaseUrl: 'https://api.supabase.com',
    authHeader: 'Authorization',
    authScheme: 'Bearer',
    validation: { method: 'GET', path: '/v1/projects' },
    cliTools: [],
  },
  pinecone: {
    apiBaseUrl: 'https://api.pinecone.io',
    authHeader: 'Api-Key',
    authScheme: 'Raw',
    validation: { method: 'GET', path: '/actions/whoami' },
    cliTools: [],
  },
  slack: {
    apiBaseUrl: 'https://slack.com',
    authHeader: 'Authorization',
    authScheme: 'Bearer',
    validation: { method: 'GET', path: '/api/auth.test', successPointer: '/ok', successValue: true },
    cliTools: [],
  },
}

export function serviceAdapterFromDocument(document: unknown): ServiceAdapter | null {
  if (!document || typeof document !== 'object' || Array.isArray(document)) return null
  const raw = (document as Record<string, unknown>).service_adapter
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null
  const adapter = raw as Record<string, unknown>
  const validation = adapter.validation && typeof adapter.validation === 'object'
    ? adapter.validation as Record<string, unknown> : null
  const tools = Array.isArray(adapter.cli_tools) ? adapter.cli_tools : []
  if (
    typeof adapter.api_base_url !== 'string' ||
    typeof adapter.auth_header !== 'string' ||
    !['Bearer', 'Token', 'Raw'].includes(String(adapter.auth_scheme)) ||
    (validation && (!['GET', 'HEAD'].includes(String(validation.method)) || typeof validation.path !== 'string'))
  ) return null
  const cliTools: ServiceAdapterTool[] = tools.flatMap((entry): ServiceAdapterTool[] => {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return []
    const tool = entry as Record<string, unknown>
    if (
      typeof tool.id !== 'string' || typeof tool.label !== 'string' ||
      typeof tool.binary !== 'string' || typeof tool.setup_hint !== 'string' ||
      !['base-url-env', 'host-flag'].includes(String(tool.integration))
    ) return []
    return [{
      id: tool.id, label: tool.label, binary: tool.binary,
      integration: tool.integration as ServiceAdapterTool['integration'],
      ...(typeof tool.variable === 'string' ? { variable: tool.variable } : {}),
      ...(typeof tool.flag === 'string' ? { flag: tool.flag } : {}),
      setupHint: tool.setup_hint,
    }]
  })
  const defaultHeaders = adapter.default_headers && typeof adapter.default_headers === 'object' && !Array.isArray(adapter.default_headers)
    ? adapter.default_headers as Record<string, string> : undefined
  return {
    apiBaseUrl: adapter.api_base_url,
    authHeader: adapter.auth_header,
    authScheme: adapter.auth_scheme as AuthScheme,
    ...(validation ? { validation: {
      method: validation.method as 'GET' | 'HEAD',
      path: validation.path as string,
      ...(typeof validation.identity_pointer === 'string' ? { identityPointer: validation.identity_pointer } : {}),
      ...(typeof validation.permissions_pointer === 'string' ? { permissionsPointer: validation.permissions_pointer } : {}),
      ...(typeof validation.success_pointer === 'string' ? { successPointer: validation.success_pointer } : {}),
      ...(['string', 'number', 'boolean'].includes(typeof validation.success_value) ? { successValue: validation.success_value as string | number | boolean } : {}),
    } } : {}),
    ...(defaultHeaders ? { defaultHeaders } : {}),
    cliTools,
  }
}

export function serviceAdapterFor(service: string, supplied?: ServiceAdapter | null): ServiceAdapter | null {
  if (supplied) return supplied
  const key = service.trim().toLowerCase().replace(/[^a-z0-9]/g, '')
  if (key === 'github') return {
    apiBaseUrl: 'https://api.github.com',
    authHeader: 'Authorization',
    authScheme: 'Bearer',
    cliTools: [],
  }
  return adapters[key] ?? null
}

export function adapterHost(adapter: ServiceAdapter): string | null {
  try {
    const url = new URL(adapter.apiBaseUrl)
    if (url.protocol !== 'https:' || url.username || url.password || (url.port && url.port !== '443') || url.search || url.hash) return null
    return url.hostname.toLowerCase()
  } catch {
    return null
  }
}

export function serviceAdapterCatalog(): Array<{ service: string; apiBaseUrl: string; cliTools: ServiceAdapterTool[] }> {
  return Object.entries(adapters).map(([service, adapter]) => ({
    service,
    apiBaseUrl: adapter.apiBaseUrl,
    cliTools: adapter.cliTools,
  }))
}

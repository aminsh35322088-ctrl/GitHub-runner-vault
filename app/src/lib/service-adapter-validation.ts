import { formatAuthValue } from './credential-input.ts'
import type { CredentialValidationReport, TokenPermission } from './credential-validation.ts'
import type { ServiceAdapter } from './service-adapter.ts'

const MAX_VALIDATION_RESPONSE_BYTES = 64 * 1024

function getPointer(value: unknown, pointer?: string): unknown {
  if (!pointer) return undefined
  if (pointer === '') return value
  if (!pointer.startsWith('/')) return undefined
  return pointer.slice(1).split('/').reduce<unknown>((current, part) => {
    if (current === null || typeof current !== 'object') return undefined
    const key = part.replace(/~1/g, '/').replace(/~0/g, '~')
    return (current as Record<string, unknown>)[key]
  }, value)
}

function permissionName(value: unknown): string {
  if (typeof value === 'string') return value.trim()
  if (!value || typeof value !== 'object' || Array.isArray(value)) return ''
  const row = value as Record<string, unknown>
  return typeof row.name === 'string' ? row.name
    : typeof row.permission === 'string' ? row.permission
      : typeof row.id === 'string' ? row.id : ''
}

function permissionsFrom(value: unknown): TokenPermission[] {
  if (typeof value === 'string') {
    return value.split(/[,\s]+/).map((name) => name.trim()).filter(Boolean).slice(0, 100)
      .map((name) => ({ name: name.slice(0, 120), access: 'granted' as const }))
  }

  if (Array.isArray(value)) {
    return value.slice(0, 100).flatMap((entry): TokenPermission[] => {
      if (typeof entry === 'string' && entry.trim()) return [{ name: entry.slice(0, 120), access: 'granted' }]
      if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return []
      const row = entry as Record<string, unknown>
      const name = permissionName(row)
      if (!name) return []
      const rawAccess = typeof row.access === 'string' ? row.access
        : typeof row.level === 'string' ? row.level
          : typeof row.status === 'string' ? row.status : 'granted'
      const access = /deny|revok|disable/i.test(rawAccess) ? 'deny' : 'granted'
      return [{ name: name.slice(0, 120), access }]
    })
  }

  // Many providers return grants as a JSON object rather than an array:
  // { "projects": { "read": true, "write": false } }. Flatten bounded leaves
  // into explicit capabilities without claiming that omitted keys are denied.
  if (!value || typeof value !== 'object') return []
  const permissions: TokenPermission[] = []
  const visit = (current: unknown, prefix: string, depth: number) => {
    if (permissions.length >= 100 || depth > 4) return
    if (typeof current === 'boolean') {
      if (!prefix) return
      permissions.push({ name: prefix.slice(0, 120), access: current ? 'granted' : 'unavailable' })
      return
    }
    if (typeof current === 'string') {
      if (!prefix || !current.trim()) return
      const access = /deny|revok|disable|false/i.test(current) ? 'deny' : 'granted'
      permissions.push({ name: prefix.slice(0, 120), access })
      return
    }
    if (Array.isArray(current)) {
      for (const entry of current.slice(0, 100 - permissions.length)) {
        if (typeof entry === 'string' && entry.trim()) {
          permissions.push({ name: entry.slice(0, 120), access: 'granted' })
        } else if (entry && typeof entry === 'object' && !Array.isArray(entry)) {
          const row = entry as Record<string, unknown>
          const name = permissionName(row)
          if (name) {
            const rawAccess = typeof row.access === 'string' ? row.access
              : typeof row.level === 'string' ? row.level
                : typeof row.status === 'string' ? row.status : 'granted'
            permissions.push({ name: name.slice(0, 120), access: /deny|revok|disable/i.test(rawAccess) ? 'deny' : 'granted' })
          }
        }
      }
      return
    }
    if (!current || typeof current !== 'object') return
    for (const [key, nested] of Object.entries(current as Record<string, unknown>).slice(0, 100 - permissions.length)) {
      if (!/^[a-zA-Z0-9_.:/ -]{1,100}$/.test(key)) continue
      const name = prefix ? prefix + "." + key : key
      if (nested && typeof nested === 'object' && !Array.isArray(nested)) {
        const row = nested as Record<string, unknown>
        if (permissionName(row)) {
          const itemName = permissionName(row)
          const rawAccess = typeof row.access === 'string' ? row.access
            : typeof row.level === 'string' ? row.level
              : typeof row.status === 'string' ? row.status : 'granted'
          permissions.push({ name: itemName.slice(0, 120), access: /deny|revok|disable/i.test(rawAccess) ? 'deny' : 'granted' })
        } else {
          visit(nested, name, depth + 1)
        }
      } else {
        visit(nested, name, depth + 1)
      }
      if (permissions.length >= 100) break
    }
  }
  visit(value, '', 0)
  return permissions
}

function hasPermissionRepresentation(value: unknown): boolean {
  return (typeof value === 'string' && Boolean(value.trim()))
    || Array.isArray(value)
    || Boolean(value && typeof value === 'object' && Object.keys(value).length > 0)
}

async function readBounded(response: Response): Promise<string | null> {
  if (!response.body) return ''
  const reader = response.body.getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      if (total + value.byteLength > MAX_VALIDATION_RESPONSE_BYTES) {
        await reader.cancel()
        return null
      }
      chunks.push(value)
      total += value.byteLength
    }
  } finally {
    reader.releaseLock()
  }
  const bytes = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    bytes.set(chunk, offset)
    offset += chunk.byteLength
  }
  return new TextDecoder().decode(bytes)
}

/**
 * Conservative generic verifier. Adapter metadata only describes a read-only
 * endpoint. The host is checked against the owner-approved allow-list and
 * redirects are never followed. A network/permission error is never called invalid.
 */
export async function validateWithServiceAdapter(
  provider: string,
  token: string,
  adapter: ServiceAdapter,
  allowedHosts: string[],
  fetchFn: typeof fetch = fetch,
  checkedAt = Date.now(),
): Promise<CredentialValidationReport> {
  const verification = adapter.validation
  if (!verification) {
    return {
      provider, status: 'unsupported', permissions: [], permissionsComplete: false,
      permissionSource: 'not-supported', checkedAt,
      message: 'این سرویس Adapter اعتبارسنجی مستند ندارد؛ اعتبار توکن قابل تأیید نیست.',
    }
  }

  let base: URL
  let target: URL
  try {
    base = new URL(adapter.apiBaseUrl)
    if (base.protocol !== 'https:' || base.username || base.password || (base.port && base.port !== '443')) throw new Error('unsafe base')
    const host = base.hostname.toLowerCase()
    if (!allowedHosts.includes(host)) throw new Error('host not approved')
    target = new URL(`${base.toString().replace(/\/$/, '')}/${verification.path.replace(/^\//, '')}`)
    if (target.hostname !== host || target.protocol !== 'https:' || target.username || target.password) throw new Error('unsafe target')
  } catch {
    return {
      provider, status: 'unsupported', permissions: [], permissionsComplete: false,
      permissionSource: 'not-supported', checkedAt,
      message: 'Service Adapter با Host مجاز یا URL امن Credential تطبیق ندارد؛ هیچ درخواست خارجی ارسال نشد.',
    }
  }

  const headers = new Headers(adapter.defaultHeaders ?? {})
  headers.set(adapter.authHeader, formatAuthValue(adapter.authScheme, token))
  headers.set('accept', 'application/json')
  headers.set('user-agent', 'runner-credential-vault/1')

  let response: Response
  try {
    response = await fetchFn(target.toString(), {
      method: verification.method,
      headers,
      redirect: 'manual',
      signal: AbortSignal.timeout(8_000),
    })
  } catch {
    return {
      provider, status: 'unavailable', permissions: [], permissionsComplete: false,
      permissionSource: 'service-adapter', checkedAt,
      message: 'سرویس برای اعتبارسنجی پاسخ نداد؛ توکن نامعتبر اعلام نشده است.',
    }
  }

  if (response.status === 401) {
    return {
      provider, status: 'invalid', permissions: [], permissionsComplete: false,
      permissionSource: 'service-adapter', checkedAt,
      message: 'سرویس اعتبارسنجی، توکن را رد کرد (HTTP 401).',
    }
  }
  if (response.status === 403) {
    return {
      provider, status: 'insufficient_permissions', permissions: [], permissionsComplete: false,
      permissionSource: 'service-adapter', checkedAt,
      message: 'توکن شناخته شد، اما برای endpoint اعتبارسنجی Permission کافی ندارد (HTTP 403).',
    }
  }
  if (response.status === 429 || response.status >= 500 || response.status >= 300 || !response.ok) {
    return {
      provider, status: 'unavailable', permissions: [], permissionsComplete: false,
      permissionSource: 'service-adapter', checkedAt,
      message: `پاسخ سرویس برای اعتبارسنجی قطعی نبود (HTTP ${response.status})؛ توکن نامعتبر اعلام نشده است.`,
    }
  }

  let body: unknown
  if (verification.method !== 'HEAD') {
    const raw = await readBounded(response)
    if (raw === null) {
      return {
        provider, status: verification.successPointer ? 'unavailable' : 'valid',
        permissions: [], permissionsComplete: false,
        permissionSource: 'service-adapter', checkedAt,
        message: verification.successPointer
          ? 'پاسخ سرویس برای اثبات معتبر بودن توکن بیش از حد بزرگ بود؛ وضعیت نامشخص باقی ماند.'
          : 'توکن با پاسخ موفق سرویس تأیید شد؛ پاسخ برای استخراج جزئیات مجوزها بیش از حد بزرگ بود.',
      }
    }
    try { body = JSON.parse(raw) } catch {
      return {
        provider, status: verification.successPointer ? 'unavailable' : 'valid',
        permissions: [], permissionsComplete: false,
        permissionSource: 'service-adapter', checkedAt,
        message: verification.successPointer
          ? 'پاسخ سرویس JSON قابل‌خواندن نبود؛ وضعیت توکن نامشخص باقی ماند.'
          : 'توکن با پاسخ موفق سرویس تأیید شد؛ اما پاسخ JSON برای استخراج Permissionها قابل‌خواندن نبود.',
      }
    }
  }
  if (verification.successPointer) {
    const observed = getPointer(body, verification.successPointer)
    if (observed !== verification.successValue) {
      const errorValue = body && typeof body === 'object' && !Array.isArray(body)
        ? (body as Record<string, unknown>).error : undefined
      const errorCode = typeof errorValue === 'string' ? errorValue : ''
      const denied = /missing_scope|not_allowed|insufficient_scope|permission_denied|scope_denied/i.test(errorCode)
      const rejected = /invalid_auth|invalid_token|token_invalid|token_revoked|token_expired|not_authed|account_inactive/i.test(errorCode)
      return {
        provider,
        status: denied ? 'insufficient_permissions' : rejected ? 'invalid' : 'unavailable',
        permissions: [], permissionsComplete: false,
        permissionSource: 'service-adapter', checkedAt,
        message: denied
          ? 'سرویس توکن را شناسایی کرد، اما دسترسی لازم را نداشت.'
          : rejected
            ? 'سرویس به‌صراحت اعلام کرد توکن نامعتبر یا منقضی است.'
            : 'پاسخ سرویس موفقیت اعتبارسنجی را تأیید نکرد؛ علت قطعی نیست و توکن نامعتبر اعلام نشد.',
      }
    }
  }
  const identityValue = getPointer(body, verification.identityPointer)
  const identity = typeof identityValue === 'string' && !identityValue.includes(token)
    ? identityValue.slice(0, 160) : undefined
  const permissionsValue = getPointer(body, verification.permissionsPointer)
  const permissions = permissionsFrom(permissionsValue).filter((permission) => !permission.name.includes(token))
  return {
    provider, status: 'valid', permissions,
    permissionsComplete: Boolean(verification.permissionsPointer && hasPermissionRepresentation(permissionsValue)),
    permissionSource: 'service-adapter', checkedAt,
    ...(identity ? { identity } : {}),
    message: permissions.length
      ? 'توکن با endpoint فقط‌خواندنی سرویس تأیید شد؛ Permissionهای قابل‌استخراج در ادامه آمده‌اند.'
      : 'توکن با endpoint فقط‌خواندنی سرویس تأیید شد؛ سرویس جزئیات Permissionها را از این endpoint افشا نکرد.',
  }
}

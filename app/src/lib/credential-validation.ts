export type TokenPermission = {
  name: string
  access: 'granted' | 'allow' | 'deny' | 'available' | 'unavailable'
  scope?: string
  resources?: string[]
}

export type CredentialValidationStatus = 'valid' | 'invalid' | 'insufficient_permissions' | 'unavailable' | 'unsupported' | 'expired'

export type CredentialValidationReport = {
  provider: string
  status: CredentialValidationStatus
  identity?: string
  providerAccountId?: string
  tokenType?: string
  permissions: TokenPermission[]
  permissionsComplete: boolean
  permissionSource: 'oauth-scopes' | 'cloudflare-token-policy' | 'capability-probe' | 'service-adapter' | 'not-readable' | 'not-exposed' | 'not-supported'
  message: string
  checkedAt: number
}

type Fetch = typeof fetch

import type { ServiceAdapter } from './service-adapter.ts'
import { validateWithServiceAdapter } from './service-adapter-validation.ts'

function report(
  provider: string,
  status: CredentialValidationStatus,
  permissionSource: CredentialValidationReport['permissionSource'],
  checkedAt: number,
  fields: Partial<CredentialValidationReport> & Pick<CredentialValidationReport, 'message'>,
): CredentialValidationReport {
  return {
    provider, status, permissions: [], permissionsComplete: false,
    permissionSource, checkedAt, ...fields,
  }
}

function scopesFromHeader(raw: string): TokenPermission[] {
  return raw.split(',').map((scope) => scope.trim()).filter(Boolean).map((name) => ({ name, access: 'granted' as const }))
}

async function validateGithubInstallationToken(
  headers: Headers,
  fetchFn: Fetch,
  checkedAt: number,
): Promise<CredentialValidationReport> {
  let response: Response
  try {
    response = await fetchFn('https://api.github.com/installation/repositories?per_page=50', {
      headers, signal: AbortSignal.timeout(8_000),
    })
  } catch {
    return report('GitHub', 'unavailable', 'capability-probe', checkedAt, {
      tokenType: 'GitHub App installation token',
      message: 'اتصال به GitHub برقرار نشد؛ اعتبار Installation Token قابل‌تأیید نیست.',
    })
  }
  if (response.status === 401) {
    return report('GitHub', 'invalid', 'capability-probe', checkedAt, {
      tokenType: 'GitHub App installation token',
      message: 'توکن GitHub App Installation نامعتبر یا منقضی است.',
    })
  }
  if (!response.ok) {
    return report('GitHub', 'unavailable', 'capability-probe', checkedAt, {
      tokenType: 'GitHub App installation token',
      message: `GitHub بررسی Installation Token را با HTTP ${response.status} رد کرد؛ توکن ذخیره نشد.`,
    })
  }
  try {
    const body = await response.json() as {
      total_count?: unknown
      repositories?: Array<{
        full_name?: unknown
        permissions?: Record<string, unknown>
      }>
    }
    const repositories = Array.isArray(body.repositories) ? body.repositories : []
    const permissions = new Map<string, TokenPermission>()
    for (const repository of repositories.slice(0, 50)) {
      if (typeof repository.full_name !== 'string') continue
      for (const [permission, granted] of Object.entries(repository.permissions ?? {})) {
        if (granted === true) permissions.set(permission, {
          name: `Repository ${permission}`,
          access: 'granted',
          scope: repository.full_name,
        })
      }
    }
    const total = typeof body.total_count === 'number' ? body.total_count : repositories.length
    return report('GitHub', 'valid', 'capability-probe', checkedAt, {
      identity: 'GitHub App installation',
      tokenType: 'GitHub App installation token',
      permissions: [...permissions.values()],
      permissionsComplete: false,
      message: `توکن Installation معتبر است و دسترسی به ${total} مخزن را تأیید کرد. Permissionهای نمایش‌داده‌شده از مخزن‌های در دسترس استخراج شده‌اند؛ این فهرست کامل تنظیمات App نیست.`,
    })
  } catch {
    return report('GitHub', 'valid', 'capability-probe', checkedAt, {
      identity: 'GitHub App installation',
      tokenType: 'GitHub App installation token',
      message: 'توکن Installation معتبر است؛ اما جزئیات مخزن‌های در دسترس قابل‌خواندن نبود.',
    })
  }
}

async function validateGithub(token: string, fetchFn: Fetch, checkedAt: number): Promise<CredentialValidationReport> {
  const headers = new Headers({
    Accept: 'application/vnd.github+json',
    Authorization: `Bearer ${token}`,
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'runner-credential-vault',
  })
  if (token.startsWith('ghs_')) return validateGithubInstallationToken(headers, fetchFn, checkedAt)

  let response: Response
  try {
    response = await fetchFn('https://api.github.com/user', { headers, signal: AbortSignal.timeout(8_000) })
  } catch {
    return report('GitHub', 'unavailable', 'not-exposed', checkedAt, {
      tokenType: 'unknown',
      message: 'اتصال به GitHub برقرار نشد؛ توکن ذخیره نشد. اتصال شبکه را بررسی و دوباره تلاش کن.',
    })
  }

  if (response.status === 401) {
    return report('GitHub', 'invalid', 'not-exposed', checkedAt, {
      message: 'توکن GitHub نامعتبر یا منقضی است.',
    })
  }
  if (response.status === 403 || response.status === 429) {
    const rateLimited = response.headers.get('x-ratelimit-remaining') === '0' || response.status === 429
    return report('GitHub', 'unavailable', 'not-exposed', checkedAt, {
      message: rateLimited
        ? 'GitHub درخواست اعتبارسنجی را به‌دلیل محدودیت نرخ موقتاً رد کرد؛ توکن هنوز نامعتبر تشخیص داده نشده است.'
        : 'GitHub درخواست بررسی هویت را رد کرد؛ ممکن است محدودیت سازمانی یا SSO فعال باشد. توکن ذخیره نشد.',
    })
  }
  if (!response.ok) {
    return report('GitHub', 'unavailable', 'not-exposed', checkedAt, {
      message: `GitHub بررسی توکن را با HTTP ${response.status} پاسخ داد؛ توکن ذخیره نشد.`,
    })
  }

  let identity: string | undefined
  try {
    const user = await response.json() as { login?: unknown }
    if (typeof user.login === 'string' && user.login.trim()) identity = `@${user.login}`
  } catch {
    return report('GitHub', 'unavailable', 'not-exposed', checkedAt, {
      message: 'پاسخ GitHub قابل‌خواندن نبود؛ توکن ذخیره نشد.',
    })
  }

  const rawScopes = response.headers.get('x-oauth-scopes')
  const tokenType = token.startsWith('github_pat_') ? 'fine-grained'
    : token.startsWith('ghp_') ? 'classic'
      : token.startsWith('gho_') ? 'OAuth App'
        : token.startsWith('ghu_') ? 'GitHub App user token'
          : token.startsWith('ghs_') ? 'GitHub App installation token'
            : rawScopes !== null ? 'classic / OAuth' : 'unknown'

  if (rawScopes !== null) {
    const permissions = scopesFromHeader(rawScopes)
    return report('GitHub', 'valid', 'oauth-scopes', checkedAt, {
      identity, tokenType, permissions, permissionsComplete: true,
      message: permissions.length
        ? 'توکن معتبر است. Scopeهای اعلام‌شده توسط GitHub در ادامه آمده‌اند.'
        : 'توکن معتبر است، اما GitHub هیچ OAuth Scopeای برای آن اعلام نکرده است.',
    })
  }

  if (tokenType === 'fine-grained') {
    try {
      const probe = await fetchFn('https://api.github.com/user/repos?per_page=1&visibility=all&affiliation=owner%2Ccollaborator%2Corganization_member', {
        headers, signal: AbortSignal.timeout(8_000),
      })
      const available = probe.ok
      const permissions: TokenPermission[] = [{
        name: 'Repository list',
        access: available ? 'available' : 'unavailable',
      }]
      return report('GitHub', 'valid', 'capability-probe', checkedAt, {
        identity, tokenType, permissions,
        message: available
          ? 'توکن Fine-grained معتبر است. دسترسی فهرست مخازن تأیید شد؛ GitHub فهرست کامل Permissionهای اعطاشده را از این API افشا نمی‌کند.'
          : 'توکن Fine-grained معتبر است، اما بررسی خواندن فهرست مخازن موفق نبود. Permissionهای کامل از API قابل استخراج نیستند.',
      })
    } catch {
      return report('GitHub', 'valid', 'not-exposed', checkedAt, {
        identity, tokenType,
        message: 'توکن معتبر است، اما بررسی تکمیلی Permissionها در دسترس نبود. GitHub فهرست کامل Permissionهای Fine-grained را از این API افشا نمی‌کند.',
      })
    }
  }

  return report('GitHub', 'valid', 'not-exposed', checkedAt, {
    identity, tokenType,
    message: 'توکن معتبر است. GitHub برای این نوع توکن فهرست Scope/Permission قابل‌خواندن برنگرداند.',
  })
}

type CloudflareTokenPolicy = {
  effect?: unknown
  permission_groups?: Array<{
    name?: unknown
    id?: unknown
    meta?: { scopes?: unknown }
  }>
  resources?: Record<string, unknown>
}

function permissionsFromPolicies(policies: CloudflareTokenPolicy[]): TokenPermission[] {
  return policies.flatMap((policy) =>
    (policy.permission_groups ?? []).map((group) => ({
      name: typeof group.name === 'string' ? group.name : typeof group.id === 'string' ? group.id : 'Permission group',
      access: (policy.effect === 'deny' ? 'deny' : 'allow') as 'allow' | 'deny',
      ...(typeof group.meta?.scopes === 'string' ? { scope: group.meta.scopes } : {}),
      ...(policy.resources ? { resources: Object.keys(policy.resources).slice(0, 12) } : {}),
    })),
  )
}

async function validateCloudflareAccountToken(
  headers: Headers,
  fetchFn: Fetch,
  checkedAt: number,
  accountId?: string,
): Promise<CredentialValidationReport> {
  let accounts: Array<{ id?: unknown; name?: unknown }>
  if (accountId) {
    accounts = [{ id: accountId }]
  } else {
    let accountsResponse: Response
    try {
      accountsResponse = await fetchFn('https://api.cloudflare.com/client/v4/accounts?page=1&per_page=50', {
        headers, signal: AbortSignal.timeout(8_000),
      })
    } catch {
      return report('Cloudflare', 'unavailable', 'not-readable', checkedAt, {
        tokenType: 'Account API Token',
        message: 'توکن از مسیر User Token تأیید نشد و اتصال برای بررسی Account Token برقرار نشد. هیچ مقداری ذخیره نشد.',
      })
    }
    if (!accountsResponse.ok) {
      return report('Cloudflare', 'unavailable', 'not-readable', checkedAt, {
        tokenType: 'Account API Token',
        message: 'توکن از مسیر User Token تأیید نشد و مجوز فهرست‌کردن حساب‌های Cloudflare کافی نیست. شناسه Account را در Advanced settings وارد کن.',
      })
    }

    try {
      const body = await accountsResponse.json() as { success?: unknown; result?: unknown }
      if (body.success !== true || !Array.isArray(body.result)) throw new Error('invalid account list')
      accounts = body.result as Array<{ id?: unknown; name?: unknown }>
    } catch {
      return report('Cloudflare', 'unavailable', 'not-readable', checkedAt, {
        tokenType: 'Account API Token',
        message: 'پاسخ فهرست حساب‌های Cloudflare قابل‌خواندن نبود؛ شناسه Account را در Advanced settings وارد کن.',
      })
    }
  }

  let inconclusive = false
  for (const account of accounts.slice(0, 20)) {
    if (typeof account.id !== 'string' || !/^[a-f0-9]{32}$/i.test(account.id)) continue
    let verification: Response
    try {
      verification = await fetchFn(
        `https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(account.id)}/tokens/verify`,
        { headers, signal: AbortSignal.timeout(8_000) },
      )
    } catch {
      inconclusive = true
      continue
    }
    if (!verification.ok) {
      if (verification.status !== 401 && verification.status !== 403 && verification.status !== 404) inconclusive = true
      continue
    }

    let verificationBody: { success?: unknown; result?: { id?: unknown; status?: unknown } }
    try { verificationBody = await verification.json() as typeof verificationBody } catch {
      inconclusive = true
      continue
    }
    if (verificationBody.success !== true || typeof verificationBody.result?.id !== 'string' || verificationBody.result.status !== 'active') continue

    const identity = typeof account.name === 'string' && account.name
      ? `Cloudflare Account · ${account.name}`
      : 'Cloudflare Account'
    let detail: Response
    try {
      detail = await fetchFn(
        `https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(account.id)}/tokens/${encodeURIComponent(verificationBody.result.id)}`,
        { headers, signal: AbortSignal.timeout(8_000) },
      )
    } catch {
      return report('Cloudflare', 'valid', 'not-readable', checkedAt, {
        identity, tokenType: 'Account API Token',
        message: 'توکن Account فعال است؛ اما اتصال برای خواندن Policyها برقرار نشد.',
      })
    }
    if (!detail.ok) {
      return report('Cloudflare', 'valid', 'not-readable', checkedAt, {
        identity, tokenType: 'Account API Token',
        message: 'توکن Account فعال است؛ اما جزئیات Policyها قابل‌خواندن نیست. برای نمایش Permissionها به دسترسی خواندن API Tokenها نیاز است.',
      })
    }

    try {
      const body = await detail.json() as { success?: unknown; result?: { name?: unknown; policies?: CloudflareTokenPolicy[] } }
      if (body.success !== true || !Array.isArray(body.result?.policies)) {
        return report('Cloudflare', 'valid', 'not-readable', checkedAt, {
          identity, tokenType: 'Account API Token',
          message: 'توکن Account فعال است؛ اما جزئیات Policyها در پاسخ Cloudflare موجود نبود.',
        })
      }
      const permissions = permissionsFromPolicies(body.result.policies)
      return report('Cloudflare', 'valid', 'cloudflare-token-policy', checkedAt, {
        identity: typeof body.result.name === 'string' ? `${body.result.name} · ${typeof account.name === 'string' ? account.name : 'Cloudflare Account'}` : identity,
        tokenType: 'Account API Token', permissions, permissionsComplete: true,
        message: permissions.length
          ? 'توکن Account فعال است؛ Policyها و Permissionهای ثبت‌شده توسط Cloudflare استخراج شدند.'
          : 'توکن Account فعال است، اما هیچ Permission group قابل‌نمایشی برای آن برنگشت.',
      })
    } catch {
      return report('Cloudflare', 'valid', 'not-readable', checkedAt, {
        identity, tokenType: 'Account API Token',
        message: 'توکن Account فعال است؛ اما پاسخ Permissionها قابل‌خواندن نبود.',
      })
    }
  }

  if (inconclusive || accounts.length > 20) {
    return report('Cloudflare', 'unavailable', 'not-readable', checkedAt, {
      tokenType: 'Account API Token',
      message: 'توکن از مسیر User Token تأیید نشد؛ بررسی Account Token کامل نشد. دسترسی فهرست حساب‌ها و API Tokenها را بررسی کن.',
    })
  }
  if (accountId) {
    return report('Cloudflare', 'invalid', 'not-readable', checkedAt, {
      tokenType: 'Account API Token',
      message: 'Cloudflare این توکن را برای Account ID واردشده فعال تشخیص نداد؛ شناسه و وضعیت توکن را بررسی کن.',
    })
  }
  return report('Cloudflare', 'unavailable', 'not-readable', checkedAt, {
    tokenType: 'Account API Token',
    message: 'توکن User Token تأیید نشد و حسابی برای بررسی خودکار پیدا نشد. شناسه ۳۲ کاراکتری Account را در Advanced settings وارد کن تا Account Token مستقیماً بررسی شود.',
  })
}

async function validateCloudflare(token: string, fetchFn: Fetch, checkedAt: number, accountId?: string): Promise<CredentialValidationReport> {
  const headers = new Headers({
    Authorization: `Bearer ${token}`,
    Accept: 'application/json',
    'User-Agent': 'runner-credential-vault',
  })

  // Cloudflare's current token format identifies Account API Tokens before a
  // request is made. Do not waste a User Token verification call on cfat_.
  if (token.startsWith('cfk_')) {
    return report('Cloudflare', 'invalid', 'not-readable', checkedAt, {
      tokenType: 'Global API Key',
      message: 'این مقدار Global API Key است، نه API Token. این Vault فقط API Tokenهای cfut_/cfat_ و قالب قدیمی API Token را می‌پذیرد.',
    })
  }
  if (token.startsWith('cfat_')) {
    return validateCloudflareAccountToken(headers, fetchFn, checkedAt, accountId)
  }

  let verified: Response
  try {
    verified = await fetchFn('https://api.cloudflare.com/client/v4/user/tokens/verify', {
      headers, signal: AbortSignal.timeout(8_000),
    })
  } catch {
    return report('Cloudflare', 'unavailable', 'not-readable', checkedAt, {
      tokenType: 'API Token',
      message: 'اتصال به Cloudflare برقرار نشد؛ توکن ذخیره نشد. اتصال شبکه را بررسی و دوباره تلاش کن.',
    })
  }
  if (verified.status === 401 && token.startsWith('cfut_')) {
    return report('Cloudflare', 'invalid', 'not-readable', checkedAt, {
      tokenType: 'User API Token', message: 'توکن User API Token در Cloudflare نامعتبر یا منقضی است.',
    })
  }
  if ([401, 403, 404].includes(verified.status)) {
    if (token.startsWith('cfut_')) {
      return report('Cloudflare', verified.status === 401 ? 'invalid' : 'unavailable', 'not-readable', checkedAt, {
        tokenType: 'User API Token',
        message: verified.status === 401
          ? 'توکن Cloudflare نامعتبر یا منقضی است.'
          : `Cloudflare توکن User را با HTTP ${verified.status} رد کرد؛ اعتبار آن قابل تأیید نشد. توکن ذخیره نشد.`,
      })
    }
    return validateCloudflareAccountToken(headers, fetchFn, checkedAt, accountId)
  }
  if (!verified.ok) {
    return report('Cloudflare', 'unavailable', 'not-readable', checkedAt, {
      tokenType: token.startsWith('cfut_') ? 'User API Token' : 'API Token', message: `Cloudflare اعتبارسنجی را با HTTP ${verified.status} رد کرد؛ اعتبار توکن قابل تأیید نشد و چیزی ذخیره نشد.`,
    })
  }

  let verifyBody: { success?: unknown; result?: { id?: unknown; status?: unknown } }
  try { verifyBody = await verified.json() as typeof verifyBody } catch {
    return report('Cloudflare', 'unavailable', 'not-readable', checkedAt, {
      tokenType: token.startsWith('cfut_') ? 'User API Token' : 'API Token', message: 'پاسخ اعتبارسنجی Cloudflare قابل‌خواندن نبود؛ توکن ذخیره نشد.',
    })
  }
  if (verifyBody.success !== true || typeof verifyBody.result?.id !== 'string') {
    return validateCloudflareAccountToken(headers, fetchFn, checkedAt, accountId)
  }
  if (verifyBody.result.status !== 'active') {
    return report('Cloudflare', 'invalid', 'not-readable', checkedAt, {
      tokenType: 'API Token', message: `توکن Cloudflare فعال نیست (وضعیت: ${String(verifyBody.result.status ?? 'نامشخص')}).`,
    })
  }

  let detail: Response
  try {
    detail = await fetchFn(`https://api.cloudflare.com/client/v4/user/tokens/${encodeURIComponent(verifyBody.result.id)}`, {
      headers, signal: AbortSignal.timeout(8_000),
    })
  } catch {
    return report('Cloudflare', 'valid', 'not-readable', checkedAt, {
      tokenType: 'API Token',
      message: 'توکن فعال است؛ اما اتصال برای خواندن جزئیات Permissionها برقرار نشد.',
    })
  }
  if (!detail.ok) {
    return report('Cloudflare', 'valid', 'not-readable', checkedAt, {
      tokenType: token.startsWith('cfut_') ? 'User API Token' : 'API Token',
      message: 'توکن فعال است؛ ولی جزئیات Permissionهای آن قابل‌خواندن نیست. برای مشاهدهٔ آن‌ها به API Tokens Read نیاز است.',
    })
  }

  try {
    const body = await detail.json() as {
      success?: unknown
      result?: { name?: unknown; policies?: CloudflareTokenPolicy[] }
    }
    if (body.success !== true || !Array.isArray(body.result?.policies)) {
      return report('Cloudflare', 'valid', 'not-readable', checkedAt, {
        tokenType: 'API Token', identity: typeof body.result?.name === 'string' ? body.result.name : undefined,
        message: 'توکن فعال است؛ اما Cloudflare جزئیات Policyها را در این پاسخ برنگرداند.',
      })
    }
    const permissions = permissionsFromPolicies(body.result.policies)
    return report('Cloudflare', 'valid', 'cloudflare-token-policy', checkedAt, {
      identity: typeof body.result.name === 'string' ? body.result.name : undefined,
      tokenType: token.startsWith('cfut_') ? 'User API Token' : 'API Token', permissions, permissionsComplete: true,
      message: permissions.length
        ? 'توکن فعال است؛ Policyها و Permissionهای ثبت‌شده توسط Cloudflare استخراج شدند.'
        : 'توکن فعال است، اما هیچ Permission group قابل‌نمایشی برای آن برنگشت.',
    })
  } catch {
    return report('Cloudflare', 'valid', 'not-readable', checkedAt, {
      tokenType: 'API Token', message: 'توکن فعال است؛ اما پاسخ Permissionها قابل‌خواندن نبود.',
    })
  }
}

/** Verify a BotFather token with Telegram's official, read-only getMe method. */
async function validateTelegramBotApiToken(token: string, fetchFn: Fetch, checkedAt: number): Promise<CredentialValidationReport> {
  const match = /^(\d{5,16}):[A-Za-z0-9_-]{20,}$/.exec(token)
  if (!match) return report('Telegram Bot API', 'invalid', 'not-exposed', checkedAt, {
    tokenType: 'Telegram Bot API token', message: 'قالب توکن Bot API تلگرام معتبر نیست.',
  })

  let response: Response
  try {
    response = await fetchFn('https://api.telegram.org/bot' + token + '/getMe', {
      method: 'GET', redirect: 'manual', headers: { accept: 'application/json' },
      signal: AbortSignal.timeout(8_000),
    })
  } catch {
    return report('Telegram Bot API', 'unavailable', 'service-adapter', checkedAt, {
      tokenType: 'Telegram Bot API token', message: 'اتصال به Telegram Bot API برقرار نشد؛ توکن نامعتبر اعلام نشده است.',
    })
  }

  if (response.status === 429 || response.status >= 500) return report('Telegram Bot API', 'unavailable', 'service-adapter', checkedAt, {
    tokenType: 'Telegram Bot API token', message: 'Telegram موقتاً در دسترس نیست یا درخواست را محدود کرده است؛ اعتبار توکن مشخص نشد.',
  })

  let body: { ok?: unknown; error_code?: unknown; result?: { id?: unknown; is_bot?: unknown; username?: unknown } }
  try { body = await response.json() as typeof body } catch {
    return report('Telegram Bot API', 'unavailable', 'service-adapter', checkedAt, {
      tokenType: 'Telegram Bot API token', message: 'پاسخ getMe قابل‌خواندن نبود؛ وضعیت توکن مشخص نشد.',
    })
  }

  if (response.status === 401 || body.error_code === 401 || body.error_code === 404) {
    return report('Telegram Bot API', 'invalid', 'service-adapter', checkedAt, {
      tokenType: 'Telegram Bot API token', message: 'Telegram Bot API این Bot Token را رد کرد.',
    })
  }
  if (!response.ok || body.ok !== true) return report('Telegram Bot API', 'unavailable', 'service-adapter', checkedAt, {
    tokenType: 'Telegram Bot API token', message: 'Telegram نتوانست هویت ربات را با getMe تأیید کند؛ وضعیت توکن نامشخص است.',
  })

  const id = body.result?.id
  if (body.result?.is_bot !== true || typeof id !== 'number' || !Number.isSafeInteger(id) || id <= 0) {
    return report('Telegram Bot API', 'unavailable', 'service-adapter', checkedAt, {
      tokenType: 'Telegram Bot API token', message: 'پاسخ getMe شامل شناسهٔ معتبر یک ربات نبود.',
    })
  }
  if (String(id) !== match[1]) return report('Telegram Bot API', 'invalid', 'service-adapter', checkedAt, {
    tokenType: 'Telegram Bot API token', message: 'شناسهٔ ربات برگشتی از getMe با شناسهٔ داخل توکن مطابقت ندارد.',
  })

  const username = typeof body.result?.username === 'string' && /^[A-Za-z0-9_]{5,32}$/.test(body.result.username)
    ? body.result.username : undefined
  return report('Telegram Bot API', 'valid', 'service-adapter', checkedAt, {
    identity: username ? '@' + username : 'Telegram bot ' + String(id),
    providerAccountId: String(id),
    tokenType: 'Telegram Bot API token',
    message: 'توکن با getMe تأیید شد؛ شناسهٔ عددی ربات' + (username ? ' و username آن' : '') + ' استخراج شد.',
  })
}

/**
 * Validates supported provider tokens without ever returning or logging the
 * submitted value. Unsupported providers are clearly marked instead of being
 * falsely described as valid.
 */
export async function validateProviderToken(
  provider: string,
  token: string,
  fetchFn: Fetch = fetch,
  checkedAt = Date.now(),
  cloudflareAccountId?: string,
  adapter?: ServiceAdapter | null,
  allowedHosts?: string[],
  authFields: Record<string, string> = {},
): Promise<CredentialValidationReport> {
  const value = token.trim()
  if (!value || new TextEncoder().encode(value).byteLength > 10_000 || /[\r\n\u0000]/.test(value)) {
    return report(provider, 'invalid', 'not-exposed', checkedAt, {
      message: 'مقدار توکن خالی یا دارای قالب نامعتبر است.',
    })
  }
  const normalized = provider.trim().toLowerCase().replace(/[^a-z0-9]/g, '')
  if (normalized === 'github') return validateGithub(value, fetchFn, checkedAt)
  if (normalized === 'telegrambotapi' || normalized === 'telegram') return validateTelegramBotApiToken(value, fetchFn, checkedAt)
  if (normalized === 'cloudflare') {
    if (cloudflareAccountId && !/^[a-f0-9]{32}$/i.test(cloudflareAccountId)) {
      return report('Cloudflare', 'invalid', 'not-readable', checkedAt, {
        tokenType: 'Account API Token', message: 'شناسه Account باید دقیقاً ۳۲ کاراکتر هگزادسیمال باشد.',
      })
    }
    return validateCloudflare(value, fetchFn, checkedAt, cloudflareAccountId)
  }
  if (adapter && allowedHosts) {
    return validateWithServiceAdapter(provider, value, adapter, allowedHosts, fetchFn, checkedAt, authFields)
  }
  return report(provider, 'unsupported', 'not-supported', checkedAt, {
    tokenType: 'unknown',
    message: 'برای این سرویس Adapter اعتبارسنجی مستند وجود ندارد؛ توکن بدون تأیید معتبر تلقی نمی‌شود.',
  })
}

const SAFE_BACKEND_CODES = new Set([
  'invalid_name', 'reserved_name', 'exists', 'invalid_hosts', 'hosts_required',
  'invalid_auth_style', 'invalid_expiry', 'invalid_value', 'invalid_doc',
  'not_found', 'not_available', 'invalid_link', 'expired', 'unauthorized',
])

const SAFE_PROVIDER_MESSAGES = [
  /^توکن GitHub /,
  /^توکن User API Token /,
  /^توکن Cloudflare /,
  /^توکن Account /,
  /^Cloudflare /,
  /^GitHub /,
  /^اتصال به GitHub /,
  /^اتصال به Cloudflare /,
  /^شناسه Account Cloudflare /,
  /^این مقدار Global API Key /,
]

/**
 * Server actions should return validation errors as serializable data. Throwing
 * from a production server action causes React to redact the original message,
 * leaving the client with an unhelpful generic error.
 */
export function publicCredentialActionError(error: unknown): string {
  if (error && typeof error === 'object' && 'issues' in error && Array.isArray((error as { issues?: unknown }).issues)) {
    const issue = (error as { issues: Array<{ path?: unknown[] }> }).issues[0]
    const field = Array.isArray(issue?.path) ? issue.path.join('.') : ''
    if (field.endsWith('cloudflareAccountId')) return 'شناسه حساب Cloudflare را دقیقاً با ۳۲ کاراکتر هگزادسیمال وارد کن.'
    if (field.endsWith('value')) return 'مقدار توکن خالی یا دارای قالب نامعتبر است.'
    if (field === 'name') return 'نام Credential را بررسی کن.'
    return 'یکی از مقادیر فرم معتبر نیست؛ فیلدهای مشخص‌شده را بررسی کن.'
  }

  const message = error instanceof Error ? error.message.trim() : ''
  const code = message.split(':', 1)[0] ?? ''
  if (SAFE_BACKEND_CODES.has(code)) return message.slice(0, 360)
  if (message.length <= 360 && SAFE_PROVIDER_MESSAGES.some((pattern) => pattern.test(message))) return message
  return code === 'Unauthorized' ? 'unauthorized' : 'internal_error'
}
